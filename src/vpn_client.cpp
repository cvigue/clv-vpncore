// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "vpn_client.h"

#include "cpu_affinity.h"
#include "data_path_stats.h"
#include "dco_netlink_ops.h"
#include "dco_utils.h"
#include "iface_utils.h"
#include "openvpn/vpn_config.h"
#include "route_utils.h"
#include "udp_receive_loop.h"
#include "openvpn/config_exchange.h"
#include "openvpn/control_channel.h"
#include "openvpn/control_plane_helpers.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/data_channel.h"
#include "openvpn/key_derivation.h"
#include "openvpn/ovpn_config_parser.h"
#include "openvpn/ovpn_dco.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/tls_context.h"
#include "openvpn/tls_crypt.h"
#include "transport/batch_constants.h"
#include "transport/connector.h"
#include "transport/packet_arena.h"
#include "transport/transport.h"
#include "transport/udp_batch.h"
#include "util/nla_helpers.h"
#include <array>
#include <cctype>
#include <cerrno>
#include <initializer_list>
#include <memory>
#include <span>
#include <stdio.h>
#include <stdlib.h>
#include <tun/tun_device.h>
#include <tuple>
#include <util/netlink_helper.h>
#include <scope_guard.h>

#include <algorithm>
#include <openssl/rand.h>

#include <asio/experimental/awaitable_operators.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <limits>
#include <nlohmann/json.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

// Linux-specific headers for DCO / socket tuning
#include <arpa/inet.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#include <asio/posix/stream_descriptor.hpp>
#include <asio/use_awaitable.hpp>
#include <unique_fd.h>
#include <util/ipv4_utils.h>

namespace clv::vpn {

// ============================================================================
// VpnClientConfig Convenience Loaders
// ============================================================================

VpnConfig VpnClientConfig::ParseJson(const nlohmann::json &json)
{
    return VpnConfigParser::ParseJson(json);
}

VpnConfig VpnClientConfig::LoadFromFile(const std::string &path)
{
    return VpnConfigParser::ParseFile(path);
}

VpnConfig VpnClientConfig::LoadFromOvpnFile(const std::string &path)
{
    auto ovpn = OvpnConfigParser::ParseFile(path);
    OvpnConfigParser::Validate(ovpn);

    VpnConfig config;

    // Client role
    VpnConfig::ClientConfig cli;
    cli.server_host = ovpn.remote.host;
    cli.server_port = ovpn.remote.port;
    cli.protocol = ovpn.remote.proto;
    cli.keepalive_interval = ovpn.keepalive_interval;
    cli.keepalive_timeout = ovpn.keepalive_timeout;
    cli.dev_name = ""; // auto
    cli.reconnect_delay_seconds = ovpn.connect_retry_delay;
    cli.max_reconnect_attempts = ovpn.connect_retry_max;

    // Client identity — inline PEM from the .ovpn
    if (std::holds_alternative<std::string>(ovpn.client_cert))
        cli.cert_pem = std::get<std::string>(ovpn.client_cert);
    if (std::holds_alternative<std::string>(ovpn.client_key))
        cli.key_pem = std::get<std::string>(ovpn.client_key);

    config.client = std::move(cli);

    // Client crypto from .ovpn
    config.client->cipher = ovpn.cipher;
    config.client->auth = ovpn.auth;

    if (std::holds_alternative<std::string>(ovpn.ca_cert))
        config.client->ca_cert_pem = std::get<std::string>(ovpn.ca_cert);

    if (std::holds_alternative<std::string>(ovpn.tls_crypt))
        config.client->tls_crypt_key_pem = std::get<std::string>(ovpn.tls_crypt);
    else if (std::holds_alternative<std::string>(ovpn.tls_auth))
        config.client->tls_crypt_key_pem = std::get<std::string>(ovpn.tls_auth);

    // Performance
    constexpr int kDefaultSocketBuf = 4 * 1024 * 1024;
    config.performance.socket_send_buffer = ovpn.sndbuf > 0 ? ovpn.sndbuf : kDefaultSocketBuf;
    config.performance.socket_recv_buffer = ovpn.rcvbuf > 0 ? ovpn.rcvbuf : kDefaultSocketBuf;
    config.performance.enable_dco = !ovpn.disable_dco;

    if (ovpn.process_quanta >= 0)
        config.performance.process_quanta = ovpn.process_quanta;
    if (ovpn.stats_interval >= 0)
        config.performance.stats_interval_seconds = ovpn.stats_interval;

    // Logging
    config.logging.verbosity = std::to_string(ovpn.verbosity);

    return config;
}

VpnConfig VpnClientConfig::Load(const std::string &path)
{
    std::filesystem::path p(path);
    auto ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    if (ext == ".ovpn")
        return LoadFromOvpnFile(path);
    else
        return LoadFromFile(path);
}

// ============================================================================
// State Helpers
// ============================================================================

const char *VpnClientStateToString(VpnClientState state)
{
    switch (state)
    {
    case VpnClientState::Disconnected:
        return "Disconnected";
    case VpnClientState::Connecting:
        return "Connecting";
    case VpnClientState::TlsHandshake:
        return "TlsHandshake";
    case VpnClientState::Authenticating:
        return "Authenticating";
    case VpnClientState::Connected:
        return "Connected";
    case VpnClientState::Reconnecting:
        return "Reconnecting";
    case VpnClientState::Error:
        return "Error";
    default:
        return "Unknown";
    }
}

// ============================================================================
// VpnClient Implementation
// ============================================================================

std::size_t VpnClient::EffectiveBatchSize() const
{
    if (config_.performance.batch_size <= 0)
        return transport::kDefaultBatchSize;
    return std::min(static_cast<std::size_t>(config_.performance.batch_size),
                    transport::kMaxBatchSize);
}

VpnClient::VpnClient(asio::io_context &io_context, const VpnConfig &config)
    : io_context_(io_context),
      config_(config),
      logger_(spdlog::stdout_color_mt("vpn_client")),
      control_channel_(*logger_),
      data_channel_(*logger_),
      inbound_arena_(config.performance.enable_dco
                         ? 16 // DCO: small arena for control packets only
                         : EffectiveBatchSize()),
      outbound_arena_(config.performance.enable_dco
                          ? 1 // DCO: no userspace TUN path
                          : EffectiveBatchSize())
{
    // Set log level from config (verbosity is a string: level name or numeric)
    auto log_level = spdlog::level::from_str(config_.logging.verbosity);
    // If from_str returns "off" for an unrecognised string, try numeric parse
    if (log_level == spdlog::level::off && config_.logging.verbosity != "off")
    {
        try
        {
            int v = std::stoi(config_.logging.verbosity);
            // Map 0=off, 1=critical, 2=error, ... 6=trace (OpenVPN-style)
            log_level = static_cast<spdlog::level::level_enum>(
                std::max(0, static_cast<int>(spdlog::level::off) - v));
        }
        catch (...)
        {
        } // leave as "off" on parse failure
    }
    logger_->set_level(log_level);

    currentBatchSize_ = inbound_arena_.BatchSize();
    processQuanta_ = static_cast<std::size_t>(std::max(0, config.performance.process_quanta));

    logger_->info("VPN client initialized (batch_size={}, process_quanta={}, dco={}, stats_interval={}s)",
                  currentBatchSize_,
                  processQuanta_,
                  config.performance.enable_dco,
                  config.performance.stats_interval_seconds);
}

VpnClient::~VpnClient()
{
    if (running_)
    {
        Disconnect();
    }
}

void VpnClient::Connect()
{
    if (running_)
    {
        logger_->warn("Connect() called while already running");
        return;
    }

    logger_->info("Connecting to {}:{}", config_.client->server_host, config_.client->server_port);
    SetState(VpnClientState::Connecting);

    // Create transport via connector (resolves address and opens socket)
    // When DCO is enabled for UDP, open a native AF_INET socket so the
    // ovpn-dco kernel module can attach correctly (it cannot handle
    // v4-mapped IPv6 addresses on AF_INET6 sockets).
    const bool dco_mode = config_.performance.enable_dco
                          && config_.client->protocol != "tcp"
                          && dco::IsAvailable();
    transport::ClientConnector connector = (config_.client->protocol == "tcp")
                                               ? transport::ClientConnector(transport::TcpConnector(io_context_))
                                               : transport::ClientConnector(transport::UdpConnector(io_context_));

    auto transport = connector.Connect(config_.client->server_host, config_.client->server_port, dco_mode);
    auto peer = transport.GetPeer();
    logger_->info("Connected to server via {}: {}:{}",
                  transport.IsTcp() ? "TCP" : "UDP",
                  peer.addr.to_string(),
                  peer.port);
    transport_.emplace(std::move(transport));

    // Apply socket buffer sizes for UDP
    if (auto *udp = std::get_if<transport::UdpTransport>(&*transport_))
    {
        udp->ApplySocketBuffers(config_.performance.socket_recv_buffer,
                                config_.performance.socket_send_buffer,
                                *logger_);
    }

    // Pin CPU if configured
    SetThreadAffinity(config_.process.cpu_affinity, *logger_);

    // Initialize data channel strategy
    if (config_.performance.enable_dco && config_.client->protocol != "tcp" && dco::IsAvailable())
    {
        try
        {
            data_channel_strategy_.emplace(DcoDataPath{this});
            InitializeDco();
            logger_->info("Data channel mode: DCO (kernel offload) - ovpn-dco-v2 P2P");
        }
        catch (const std::exception &e)
        {
            logger_->warn("DCO initialization failed, falling back to userspace: {}", e.what());
            data_channel_strategy_.emplace(UserspaceDataPath{this, transport_->IsUdp()});
        }
    }
    else
    {
        data_channel_strategy_.emplace(UserspaceDataPath{this, transport_->IsUdp()});
        logger_->info("Data channel mode: Userspace (TUN-based, batch_size={}, quanta={})",
                      currentBatchSize_,
                      processQuanta_);
    }

    // Generate session ID
    local_session_id_ = openvpn::SessionId::Generate().value;
    logger_->debug("Generated session ID: {:016x}", local_session_id_);

    // Load TLS-Crypt key (inline PEM takes priority over file path)
    if (!config_.client->tls_crypt_key_pem.empty())
    {
        auto tls_crypt_opt = openvpn::TlsCrypt::FromKeyString(config_.client->tls_crypt_key_pem, *logger_);
        if (!tls_crypt_opt)
        {
            logger_->error("Failed to load inline TLS-Crypt key");
            SetState(VpnClientState::Error);
            return;
        }
        tls_crypt_.emplace(std::move(*tls_crypt_opt));
        logger_->debug("Loaded TLS-Crypt key from inline content");
    }
    else if (!config_.client->tls_crypt_key.empty())
    {
        auto tls_crypt_opt = openvpn::TlsCrypt::FromKeyFile(config_.client->tls_crypt_key.string(), *logger_);
        if (!tls_crypt_opt)
        {
            logger_->error("Failed to load TLS-Crypt key from: {}", config_.client->tls_crypt_key.string());
            SetState(VpnClientState::Error);
            return;
        }
        tls_crypt_.emplace(std::move(*tls_crypt_opt));
        logger_->debug("Loaded TLS-Crypt key from: {}", config_.client->tls_crypt_key.string());
    }

    // Initialize ControlChannel with client TLS certificates
    // Inline PEM fields take priority over file paths
    openvpn::TlsCertConfig cert_config{
        .ca_cert = config_.client->ca_cert.string(),
        .local_cert = config_.client->cert.string(),
        .local_key = config_.client->key.string(),
        .ca_cert_pem = config_.client->ca_cert_pem,
        .local_cert_pem = config_.client->cert_pem,
        .local_key_pem = config_.client->key_pem};

    // Initialize as client (is_server = false)
    openvpn::SessionId session_id{local_session_id_};
    if (!control_channel_.Initialize(false, session_id, cert_config))
    {
        logger_->error("Failed to initialize control channel");
        SetState(VpnClientState::Error);
        return;
    }
    logger_->debug("Initialized TLS control channel (client mode)");

    running_ = true;

    // Initialize last-rx timestamp so the keepalive timeout doesn't fire
    // immediately before any packets have arrived.
    last_rx_time_ = std::chrono::steady_clock::now();

    // Start connection coroutine
    asio::co_spawn(io_context_, ConnectionLoop(), asio::detached);
}

void VpnClient::Disconnect()
{
    // Allow Disconnect() to be called even after running_ has been cleared
    // (e.g. from ReconnectLoop) — guard on state instead to prevent double-teardown.
    if (state_ == VpnClientState::Disconnected)
    {
        return;
    }

    logger_->info("Disconnecting...");
    running_ = false;

    // Cancel the handshake retransmit timer so operator|| in ConnectionLoop
    // can complete immediately instead of waiting for the 2s expiry.
    handshake_timer_.cancel();

    // Close the underlying socket to cancel pending async operations (e.g.
    // async_receive_from in ConnectionLoop).  Must happen before reset()
    // because the socket is shared_ptr — reset alone may not close it if
    // the coroutine frame still holds an internal reference.
    if (transport_)
    {
        if (auto *udp = std::get_if<transport::UdpTransport>(&*transport_))
        {
            asio::error_code ec;
            [[maybe_unused]] auto _1 = udp->RawSocket().close(ec);
            logger_->debug("Closed UDP socket: {}", ec ? ec.message() : "ok");
        }
        else if (auto *tcp = std::get_if<transport::TcpTransport>(&*transport_))
        {
            tcp->Close();
        }
    }

    // Close transport
    transport_.reset();

    // Close TUN device (userspace mode only)
    if (tun_device_)
    {
        tun_device_->Close();
        tun_device_.reset();
    }

    // Clean up data channel strategy (DCO device, etc.)
    if (data_channel_strategy_)
    {
        data_channel_strategy_->Cleanup();
        data_channel_strategy_.reset();
    }

    // Reset the control channel so it can be re-initialized on reconnect.
    // Without this, ControlChannel::Initialize() returns false the second
    // time because tls_context_ is still set from the previous session.
    control_channel_.Reset();
    tls_crypt_.reset();

    // Clear all per-session state so the next Connect() starts completely fresh.
    // Most critically, client_random_ must be empty or ProcessTlsHandshake()
    // will never be called on the new connection (guarded by client_random_.empty()).
    client_random_.clear();
    server_random_.clear();
    derived_key_material_.clear();
    key_id_ = 0;
    remote_session_id_ = 0;
    server_peer_id_ = 0;
    config_exchange_.Reset();

    // Wake any long-sleeping loops (StatsLoop, KeepaliveLoop) so they exit
    // promptly instead of waiting out their full timer intervals.
    stats_timer_.cancel();
    keepalive_timer_.cancel();

    SetState(VpnClientState::Disconnected);
    logger_->info("Disconnected");
}

std::chrono::seconds VpnClient::GetUptime() const
{
    if (state_ != VpnClientState::Connected)
    {
        return std::chrono::seconds(0);
    }
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - connected_at_);
}

void VpnClient::SetState(VpnClientState new_state)
{
    if (state_ != new_state)
    {
        auto old_state = state_;
        logger_->info("State: {} -> {}",
                      VpnClientStateToString(old_state),
                      VpnClientStateToString(new_state));
        state_ = new_state;

        if (state_callback_)
            state_callback_(old_state, new_state);

        if (new_state == VpnClientState::Connected)
        {
            reconnect_attempts_ = 0; // Successful connection — reset retry counter
            connected_at_ = std::chrono::steady_clock::now();

            // Start stats logging if configured (works for both DCO and userspace)
            if (config_.performance.stats_interval_seconds > 0)
            {
                asio::co_spawn(io_context_, StatsLoop(), asio::detached);
            }

            // Delegate data-path coroutine startup to the active strategy
            if (data_channel_strategy_)
            {
                data_channel_strategy_->StartDataPath();
            }
        }
    }
}



// ============================================================================
// Connection Flow
// ============================================================================

asio::awaitable<void> VpnClient::ConnectionLoop()
{
    using namespace asio::experimental::awaitable_operators;

    // Retransmit interval for the handshake phase.  When the receive times
    // out we drive ProcessRetransmissions() so that lost control-channel
    // packets (ClientHello, key-method-2, …) are re-sent automatically.
    static constexpr auto kHandshakeRetransmitInterval = std::chrono::seconds(2);

    // Maximum time allowed for the TLS handshake to complete.  If no state
    // transition to Connected is observed within this window the ConnectionLoop
    // throws, which triggers a fresh reconnect attempt via ReconnectLoop.
    static constexpr auto kHandshakeTimeout = std::chrono::seconds(30);

    try
    {
        // Step 1: Send hard reset
        co_await SendHardReset();

        // Record when the handshake phase started so we can enforce kHandshakeTimeout.
        auto handshake_start = std::chrono::steady_clock::now();

        // Step 2: Receive and process packets
        // For UDP in connected state, UdpReceiveLoop takes over the data path.
        // This loop handles the handshake phase and TCP fallback.
        while (running_)
        {
            // Once connected, delegate to the strategy's post-connect loop.
            // - UserspaceUDP: immediately returns (UdpReceiveLoop handles data)
            // - UserspaceTCP: runs the receive loop inline (data arrives here)
            // - DCO: runs DcoReceiveLoop (control packets only)
            if (state_ == VpnClientState::Connected && data_channel_strategy_)
            {
                co_await data_channel_strategy_->RunConnectedLoop();
                co_return;
            }

            // During TLS handshake, race the receive against a retransmit
            // timer so that lost packets are recovered even when the peer
            // is silent.
            if (state_ == VpnClientState::TlsHandshake)
            {
                // Enforce an overall handshake deadline so that a silent or
                // unresponsive server doesn't keep the client stuck forever.
                if (std::chrono::steady_clock::now() - handshake_start > kHandshakeTimeout)
                    throw std::runtime_error("TLS handshake timed out (30s)");

                auto timer_wait = [&]() -> asio::awaitable<void>
                {
                    handshake_timer_.expires_after(kHandshakeRetransmitInterval);
                    co_await handshake_timer_.async_wait(asio::use_awaitable);
                };

                // operator|| completes when EITHER operand finishes and
                // cancels the other.  Result is variant<vector<uint8_t>,
                // monostate>.
                auto result = co_await (transport_->Receive() || timer_wait());

                if (result.index() == 0)
                {
                    // Receive completed — process the packet normally
                    auto &data = std::get<0>(result);
                    if (!data.empty())
                        co_await ProcessServerPacket(std::move(data));
                }
                else
                {
                    // Timer fired — drive retransmissions
                    auto retransmits = control_channel_.ProcessRetransmissions();
                    for (auto &pkt : retransmits)
                    {
                        co_await SendWrappedPacket(std::move(pkt));
                        logger_->debug("Retransmitted control packet (handshake timeout)");
                    }
                }
            }
            else
            {
                // Post-handshake: plain blocking receive (no retransmit needed)
                auto data = co_await transport_->Receive();
                if (data.empty())
                    continue;
                co_await ProcessServerPacket(std::move(data));
            }
        }
    }
    catch (const std::exception &e)
    {
        logger_->error("Connection error: {}", e.what());
        // If running_ is still true the failure was unexpected (handshake
        // timeout, protocol error, etc.) and not a deliberate user disconnect —
        // schedule a reconnect.  ReconnectLoop handles back-off and retry limits.
        if (running_ && state_ != VpnClientState::Reconnecting)
        {
            SetState(VpnClientState::Reconnecting);
            asio::co_spawn(io_context_, ReconnectLoop(), asio::detached);
        }
        else
        {
            SetState(VpnClientState::Error);
        }
    }
}

asio::awaitable<void> VpnClient::ReconnectLoop()
{
    const int max_attempts = config_.client->max_reconnect_attempts; // 0 = unlimited

    while (max_attempts == 0 || reconnect_attempts_ < max_attempts)
    {
        ++reconnect_attempts_;
        logger_->info("Reconnecting (attempt {}/{})",
                      reconnect_attempts_,
                      max_attempts == 0 ? std::string("unlimited") : std::to_string(max_attempts));

        // Tear down the existing connection before reconnecting.
        // Disconnect() is guarded by state != Disconnected so it's safe to
        // call here even though running_ was already cleared.
        Disconnect();

        // Back-off before the next attempt
        asio::steady_timer timer(io_context_);
        timer.expires_after(std::chrono::seconds(config_.client->reconnect_delay_seconds));
        co_await timer.async_wait(asio::use_awaitable);

        try
        {
            Connect(); // Spawns a new ConnectionLoop; reconnect_attempts_ reset on Connected
            co_return;
        }
        catch (const std::exception &e)
        {
            logger_->error("Reconnect attempt {} failed: {}", reconnect_attempts_, e.what());
            SetState(VpnClientState::Reconnecting);
            // Loop continues to next attempt
        }
    }

    logger_->error("Max reconnect attempts ({}) reached, giving up", max_attempts);
    SetState(VpnClientState::Error);
}

asio::awaitable<void> VpnClient::SendHardReset()
{
    logger_->debug("Sending HARD_RESET_CLIENT_V2");

    // Consume packet_id 0 from the control channel so that subsequent
    // calls to GetNextPacketId() (e.g. InitiateTlsHandshake) return 1+.
    // Without this, both the hard reset and the ClientHello would use
    // packet_id 0, and the server would reject the ClientHello as a
    // duplicate.
    std::uint32_t pkt_id = control_channel_.GetNextPacketId();

    auto packet = openvpn::OpenVpnPacket::HardReset(
        true, // is_client
        2,    // version (V2)
        key_id_,
        local_session_id_,
        pkt_id);

    auto serialized = packet.Serialize();

    if (tls_crypt_)
    {
        auto wrapped = tls_crypt_->Wrap(serialized, false);
        if (!wrapped)
        {
            logger_->error("Failed to wrap hard reset packet");
            SetState(VpnClientState::Error);
            co_return;
        }
        serialized = std::move(*wrapped);
    }

    co_await SendRawPacket(serialized);
    SetState(VpnClientState::TlsHandshake);
}

asio::awaitable<void> VpnClient::ProcessServerPacket(std::vector<std::uint8_t> data)
{
    if (data.empty())
        co_return;

    // Track last received time for keepalive timeout detection.
    last_rx_time_ = std::chrono::steady_clock::now();

    auto packet = UnwrapAndParse(data, tls_crypt_, /*is_server=*/false, *logger_);
    if (!packet)
        co_return;

    if (openvpn::IsDataPacket(packet->opcode_))
    {
        co_await HandleDataPacket(*packet);
    }
    else
    {
        co_await HandleControlPacket(*packet);
    }
}

asio::awaitable<void> VpnClient::HandleControlPacket(const openvpn::OpenVpnPacket &packet)
{
    logger_->debug("Received control packet: opcode={}", static_cast<int>(packet.opcode_));

    // Hard resets are orchestrator-level — they're part of session init,
    // not the per-session state machine.
    if (packet.opcode_ == openvpn::Opcode::P_CONTROL_HARD_RESET_SERVER_V2
        || packet.opcode_ == openvpn::Opcode::P_CONTROL_HARD_RESET_SERVER_V3)
    {
        remote_session_id_ = packet.session_id_.value_or(0);
        logger_->debug("Received HARD_RESET_SERVER, remote_session_id={:016x}", remote_session_id_);

        control_channel_.HandleHardReset(packet);

        auto ack = control_channel_.GenerateExplicitAck();
        if (!ack.empty())
        {
            co_await SendWrappedPacket(std::move(ack));
        }

        SetState(VpnClientState::TlsHandshake);
        auto client_hello = control_channel_.InitiateTlsHandshake();
        if (client_hello && !client_hello->empty())
        {
            logger_->debug("Sending TLS ClientHello ({} bytes)", client_hello->size());
            co_await SendWrappedPacket(std::move(*client_hello));
        }

        // Flush queued fragments and process retransmissions.
        co_await FlushControlQueue(control_channel_, tls_crypt_,
                                   /*is_server=*/false,
                                   *transport_,
                                   *logger_);
        co_return;
    }

    // All other control opcodes dispatched through the shared handler.
    co_await DispatchSessionControlPacket(
        control_channel_, tls_crypt_, /*is_server=*/false, *transport_, packet, *logger_, {
                                                                                              .on_soft_reset = nullptr,
                                                                                              .on_plaintext = [this](std::vector<std::uint8_t> plaintext) -> asio::awaitable<void>
    {
        co_await ProcessReceivedPlaintext(std::move(plaintext));
    },
                                                                                              .on_handshake_complete = [this]() -> asio::awaitable<void>
    {
        if (client_random_.empty())
        {
            logger_->debug("TLS handshake complete, processing key exchange");
            co_await ProcessTlsHandshake();
        }
    },
                                                                                          });

    co_return;
}

asio::awaitable<void> VpnClient::HandleDataPacket(const openvpn::OpenVpnPacket &packet)
{
    // Allocating path — used during handshake phase and TCP mode
    auto plaintext = data_channel_.DecryptPacket(packet);

    if (plaintext.empty())
    {
        logger_->warn("Failed to decrypt data packet");
        co_return;
    }

    // Check for raw keepalive magic (no compress byte)
    if (openvpn::IsKeepalivePing(plaintext))
    {
        logger_->trace("Received keepalive PING from server");
        co_return;
    }

    // Intelligent compress byte detection (symmetric with server)
    std::uint8_t first_byte = plaintext[0];
    std::uint8_t version_nibble = (first_byte >> openvpn::IP_VERSION_SHIFT) & openvpn::IP_VERSION_MASK;
    if (version_nibble != openvpn::IP_VERSION_4 && version_nibble != openvpn::IP_VERSION_6)
    {
        if (first_byte == openvpn::COMPRESS_NONE || first_byte == openvpn::COMPRESS_STUB_LZO)
        {
            plaintext.erase(plaintext.begin());
        }
        else
        {
            logger_->warn("Unknown non-IP byte 0x{:02x} in {} byte packet, dropping",
                          first_byte,
                          plaintext.size());
            co_return;
        }
    }

    // Check for keepalive after compress strip
    if (openvpn::IsKeepalivePing(plaintext))
    {
        logger_->trace("Received keepalive PING from server");
        co_return;
    }
    stats_.packetsDecrypted++;

    if (tun_device_)
    {
        try
        {
            tun::IpPacket ip_packet;
            ip_packet.data = std::move(plaintext);
            co_await tun_device_->WritePacket(ip_packet);
            stats_.tunWrites++;
        }
        catch (const std::exception &e)
        {
            logger_->warn("Failed to write to TUN: {}", e.what());
        }
    }

    co_return;
}

asio::awaitable<void> VpnClient::ProcessTlsHandshake()
{
    if (control_channel_.GetState() == openvpn::ControlChannel::State::KeyMaterialReady)
    {
        logger_->debug("TLS handshake complete, starting key-method 2 exchange");

        client_random_.resize(openvpn::CLIENT_KEY_SOURCE_SIZE);
        if (RAND_bytes(client_random_.data(), static_cast<int>(client_random_.size())) != 1)
            throw std::runtime_error("RAND_bytes failed generating client random");

        // Map transport protocol to OpenVPN wire-format proto string.
        std::string proto_str = "UDPv4";
        if (config_.client->protocol == "tcp")
            proto_str = "TCPv4_CLIENT";
        else if (config_.client->protocol == "udp6")
            proto_str = "UDPv6";

        std::string options = "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto " + proto_str;
        if (!config_.client->cipher.empty())
        {
            options += ",cipher " + config_.client->cipher;
        }
        options += ",key-method 2,tls-client";

        auto key_method_msg = openvpn::BuildKeyMethod2Message(client_random_, options, "", "");

        logger_->debug("Sending client key-method 2 message: {} bytes", key_method_msg.size());

        co_await SendTlsControlData(control_channel_, tls_crypt_, std::span<const uint8_t>(key_method_msg),
                                    /*is_server=*/false,
                                    *transport_,
                                    *logger_,
                                    "key-method 2");
    }

    co_return;
}

asio::awaitable<void> VpnClient::ProcessReceivedPlaintext(std::vector<std::uint8_t> plaintext)
{
    if (plaintext.empty())
    {
        co_return;
    }

    // Strip trailing null terminator if present (OpenVPN control messages are C-strings).
    auto view_len = plaintext.size();
    if (plaintext.back() == 0)
    {
        --view_len;
    }

    std::string_view data_view(reinterpret_cast<const char *>(plaintext.data()), view_len);

    if (data_view.empty())
    {
        logger_->trace("Received empty plaintext (was a bare null terminator)");
        co_return;
    }

    if (data_view.starts_with("PUSH_REPLY"))
    {
        std::string reply(data_view.substr(11));
        HandlePushReply(reply);
        co_return;
    }

    if (plaintext.size() > 1 && plaintext[0] == 0x00)
    {
        logger_->debug("Received server key-method 2 message: {} bytes", plaintext.size());

        auto parsed = openvpn::ParseKeyMethod2Message(plaintext, true);
        if (!parsed)
        {
            logger_->error("Failed to parse server key-method 2 message");
            SetState(VpnClientState::Error);
            co_return;
        }

        auto &[server_random, server_options, username, password] = *parsed;
        logger_->debug("Parsed server key-method 2:");
        logger_->debug("  Random: {} bytes", server_random.size());
        logger_->debug("  Options: {}", server_options);

        server_random_ = std::move(server_random);

        // NCP: adopt the server's cipher from its key-method 2 options.
        // The server's cipher is authoritative for the data channel.
        // NOTE: The PUSH_REPLY cipher (handled in HandlePushReply) is the
        // definitive NCP mechanism and will re-key if needed.  We no longer
        // parse the cipher ad-hoc here — DeriveAndInstallKeys uses whatever
        // cipher is currently configured, and HandlePushReply corrects it.

        if (!DeriveAndInstallKeys())
        {
            logger_->error("Failed to derive keys");
            SetState(VpnClientState::Error);
            co_return;
        }

        co_await SendPushRequest();
        SetState(VpnClientState::Authenticating);
        co_return;
    }

    logger_->warn("Unknown plaintext received: {} bytes", plaintext.size());
    co_return;
}

asio::awaitable<void> VpnClient::SendPushRequest()
{
    logger_->debug("Sending PUSH_REQUEST");

    std::string push_request = "PUSH_REQUEST";
    std::vector<std::uint8_t> message(push_request.begin(), push_request.end());
    message.push_back(0);

    co_await SendTlsControlData(control_channel_, tls_crypt_, std::span<const std::uint8_t>(message),
                                /*is_server=*/false,
                                *transport_,
                                *logger_,
                                "PUSH_REQUEST");
    co_return;
}

void VpnClient::HandlePushReply(const std::string &reply)
{
    logger_->debug("Received PUSH_REPLY");
    logger_->debug("PUSH_REPLY content: {}", reply);

    config_exchange_.ProcessPushReply(reply);

    const auto &config = config_exchange_.GetNegotiatedConfig();

    // NCP: if the PUSH_REPLY carries a different cipher than what we derived
    // keys with, re-derive and re-install with the authoritative cipher.
    if (!config.cipher.empty() && config.cipher != config_.client->cipher)
    {
        logger_->info("NCP: PUSH_REPLY cipher '{}' overrides current cipher '{}' – re-keying",
                      config.cipher,
                      config_.client->cipher);
        config_.client->cipher = config.cipher;
        if (!DeriveAndInstallKeys())
        {
            logger_->error("Re-keying with negotiated cipher failed");
            SetState(VpnClientState::Error);
            return;
        }
    }

    // Store server-assigned peer_id for DATA_V2 packet headers
    if (config.peer_id >= 0)
    {
        server_peer_id_ = static_cast<std::uint32_t>(config.peer_id);
        logger_->info("Server assigned peer-id: {}", server_peer_id_);
    }

    // Log pushed configuration
    if (!config.ifconfig.first.empty())
        logger_->info("Assigned IP: {} / {}", config.ifconfig.first, config.ifconfig.second);

    for (const auto &[network, gw, metric] : config.routes)
        logger_->info("Route: {} via {} metric {}", network, gw, metric);

    for (const auto &[type, value] : config.dhcp_options)
        if (type == "DNS")
            logger_->info("DNS: {}", value);

    if (data_channel_strategy_)
    {
        data_channel_strategy_->ConfigureDevice();
    }

    SetState(VpnClientState::Connected);
}

void VpnClient::DcoDataPath::ConfigureDevice()
{
    // DCO mode: configure IP on the DCO interface, create peer, push keys
    client_->ConfigureDcoInterface();

    // Install pushed routes on the DCO interface
    client_->InstallRoutes();

    if (!client_->CreateDcoPeer())
    {
        client_->logger_->error("DCO: Failed to create peer for server");
        client_->SetState(VpnClientState::Error);
        return;
    }

    // Push the saved key material to the kernel
    if (!client_->derived_key_material_.empty())
    {
        std::uint8_t current_key_id = client_->control_channel_.GetKeyId();
        if (!client_->PushKeysToKernel(client_->derived_key_material_, cipher_algo_, current_key_id, OVPN_KEY_SLOT_PRIMARY))
        {
            client_->logger_->error("DCO: Failed to push keys to kernel");
            client_->SetState(VpnClientState::Error);
            return;
        }
        primary_key_id_ = current_key_id;
        client_->data_channel_.SetDcoKeysInstalled(true);

        // Set keepalive timers in kernel
        client_->SetDcoPeerKeepalive();
    }
}

// ============================================================================
// UserspaceDataPath implementation
// ============================================================================

void VpnClient::UserspaceDataPath::ConfigureDevice()
{
    client_->ConfigureTunDevice();
}

void VpnClient::UserspaceDataPath::StartDataPath()
{
    if (is_udp_)
    {
        // Batch UDP path
        asio::co_spawn(client_->io_context_, client_->UdpReceiveLoop(), asio::detached);
        asio::co_spawn(client_->io_context_, client_->TunToServerBatch(), asio::detached);
    }
    else
    {
        // TCP or simple path
        asio::co_spawn(client_->io_context_, client_->TunToServer(), asio::detached);
    }

    // Keepalive sender
    if (client_->config_.client->keepalive_interval > 0)
    {
        asio::co_spawn(client_->io_context_, client_->KeepaliveLoop(), asio::detached);
    }
}

std::string VpnClient::UserspaceDataPath::GetDeviceName() const
{
    if (client_->tun_device_ && client_->tun_device_->IsOpen())
        return client_->tun_device_->GetName();
    return {};
}

DataPathStats VpnClient::UserspaceDataPath::ElapsedStats()
{
    return client_->stats_observer_.Elapsed();
}

void VpnClient::UserspaceDataPath::Cleanup()
{
    // TUN device cleanup is handled by VpnClient::Disconnect()
}

asio::awaitable<void> VpnClient::UserspaceDataPath::RunConnectedLoop()
{
    if (is_udp_)
    {
        // UDP batch mode: UdpReceiveLoop was already spawned — exit ConnectionLoop
        co_return;
    }

    // TCP mode: ConnectionLoop stays alive to receive data + control packets
    while (client_->running_ && client_->state_ == VpnClientState::Connected)
    {
        auto data = co_await client_->transport_->Receive();
        if (data.empty())
            continue;
        co_await client_->ProcessServerPacket(std::move(data));
    }
}

// ============================================================================
// DcoDataPath implementation (dispatch methods)
// ============================================================================

void VpnClient::DcoDataPath::StartDataPath()
{
    asio::co_spawn(client_->io_context_, client_->DcoKeepaliveMonitor(), asio::detached);
}

DataPathStats VpnClient::DcoDataPath::ElapsedStats()
{
    auto cur = client_->QueryDcoStats();
    auto delta = DataPathStats::Delta(cur, prev_stats_);
    prev_stats_ = cur;
    return delta;
}

void VpnClient::DcoDataPath::Cleanup()
{
    if (initialized_)
    {
        client_->DestroyDcoDevice();
        initialized_ = false;
        peer_created_ = false;
    }
}

asio::awaitable<void> VpnClient::DcoDataPath::RunConnectedLoop()
{
    co_await client_->DcoReceiveLoop();
}

void VpnClient::ConfigureTunDevice()
{
    const auto &negotiated = config_exchange_.GetNegotiatedConfig();
    const auto &assigned_ip = negotiated.ifconfig.first;
    const auto &assigned_netmask = negotiated.ifconfig.second;

    if (assigned_ip.empty())
    {
        logger_->warn("No IP assigned - TUN device not configured");
        return;
    }

    logger_->info("Configuring TUN device with IP: {}", assigned_ip);

    try
    {
        tun_device_ = std::make_unique<tun::TunDevice>(io_context_);

        std::string created_name = tun_device_->Create(config_.client->dev_name);
        if (created_name.empty())
        {
            logger_->error("Failed to create TUN device");
            return;
        }
        logger_->info("Created TUN device: {}", created_name);

        // Determine IPv4 prefix length based on topology.
        // For "net30" / "p2p": ifconfig <local> <remote_peer> -> point-to-point
        // For "subnet":       ifconfig <local> <netmask>       -> compute from netmask
        if (negotiated.topology == "subnet" && !assigned_netmask.empty())
        {
            auto prefix_length = ipv4::MaskToPrefix(asio::ip::make_address_v4(assigned_netmask).to_uint());
            tun_device_->SetAddress(assigned_ip, prefix_length);
            logger_->debug("TUN device configured: {} with {}/{} (subnet)",
                           tun_device_->GetName(),
                           assigned_ip,
                           prefix_length);
        }
        else
        {
            // net30 / p2p topology: configure as point-to-point link.
            // assigned_netmask holds the remote peer IP (e.g., "10.8.0.1").
            std::string remote_ip = assigned_netmask.empty() ? "255.255.255.255" : assigned_netmask;

            iface::SetPointToPoint(tun_device_->GetName().c_str(), assigned_ip, remote_ip);

            logger_->debug("TUN device configured: {} with {} peer {} (net30/p2p)",
                           tun_device_->GetName(),
                           assigned_ip,
                           remote_ip);
        }

        // Set MTU — use 1400 as a safe default for VPN tunnels
        constexpr int DEFAULT_TUN_MTU = 1400;
        tun_device_->SetMtu(static_cast<std::uint16_t>(DEFAULT_TUN_MTU));

        tun_device_->BringUp();

        logger_->debug("TUN device up: {} mtu={}", tun_device_->GetName(), DEFAULT_TUN_MTU);

        // Add IPv6 address if pushed by server
        if (!negotiated.ifconfig_ipv6.first.empty())
        {
            auto prefix6 = static_cast<std::uint8_t>(negotiated.ifconfig_ipv6.second);
            tun_device_->AddIpv6Address(negotiated.ifconfig_ipv6.first, prefix6);
            logger_->debug("Added IPv6 address: {}/{}",
                           negotiated.ifconfig_ipv6.first,
                           prefix6);
        }

        // Install pushed routes
        InstallRoutes();

        // Dump TUN interface and routing state for diagnostics.
        // Uses fork/execvp (no shell) to avoid command-injection risk from popen().
        auto exec_and_log = [&](const std::string &label,
                                std::initializer_list<const char *>
                                    argv_init)
        {
            int pipe_fd[2];
            if (::pipe(pipe_fd) != 0)
                return;

            pid_t pid = ::fork();
            if (pid < 0)
            {
                ::close(pipe_fd[0]);
                ::close(pipe_fd[1]);
                return;
            }
            if (pid == 0)
            {
                // Child: redirect stdout+stderr into the pipe, exec.
                ::close(pipe_fd[0]);
                ::dup2(pipe_fd[1], STDOUT_FILENO);
                ::dup2(pipe_fd[1], STDERR_FILENO);
                ::close(pipe_fd[1]);
                std::vector<const char *> argv(argv_init);
                argv.push_back(nullptr);
                ::execvp(argv[0], const_cast<char *const *>(argv.data()));
                ::_exit(127);
            }
            // Parent: read child output, then reap.
            ::close(pipe_fd[1]);
            FILE *fp = ::fdopen(pipe_fd[0], "r");
            if (fp)
            {
                char line[256];
                while (::fgets(line, sizeof(line), fp))
                {
                    auto len = std::strlen(line);
                    if (len > 0 && line[len - 1] == '\n')
                        line[len - 1] = '\0';
                    logger_->debug("[{}] {}", label, line);
                }
                ::fclose(fp); // also closes pipe_fd[0]
            }
            else
            {
                ::close(pipe_fd[0]);
            }
            int status;
            ::waitpid(pid, &status, 0);
        };

        std::string dev_name = tun_device_->GetName();
        exec_and_log("iface", {"ip", "addr", "show", "dev", dev_name.c_str()});
        exec_and_log("route4", {"ip", "route", "show", "table", "main"});
        exec_and_log("route6", {"ip", "-6", "route", "show", "table", "main"});
    }
    catch (const std::exception &e)
    {
        logger_->error("Failed to configure TUN device: {}", e.what());
        tun_device_.reset();
    }
}

void VpnClient::InstallRoutes()
{
    // Determine device name via strategy
    std::string dev;
    if (data_channel_strategy_)
    {
        dev = data_channel_strategy_->GetDeviceName();
    }
    if (dev.empty())
        return;

    const auto &negotiated = config_exchange_.GetNegotiatedConfig();

    // Install IPv4 routes
    for (const auto &[network, gw, metric] : negotiated.routes)
    {
        // "route 192.168.50.0 255.255.255.0" → need to convert netmask to CIDR
        // network may be "x.x.x.x" with the mask as second push arg, or already CIDR
        std::string cidr;
        if (network.find('/') != std::string::npos)
        {
            cidr = network;
        }
        else if (!gw.empty())
        {
            // gw is actually the netmask in OpenVPN's route push format:
            //   route <network> <netmask> [gateway] [metric]
            // The config_exchange parser puts (network, netmask, metric) in the tuple.
            // We treat second element as netmask for conversion.
            try
            {
                auto prefix = ipv4::MaskToPrefix(
                    asio::ip::make_address_v4(gw).to_uint());
                cidr = network + "/" + std::to_string(prefix);
            }
            catch (...)
            {
                cidr = network + "/32";
            }
        }
        else
        {
            cidr = network + "/32";
        }

        // Determine gateway — userspace TUN has a P2P destination, DCO does not.
        std::string via;
        if (!IsDco() && !negotiated.route_gateway.empty())
            via = negotiated.route_gateway;

        logger_->info("Installing route: {} dev {}{}", cidr, dev, via.empty() ? "" : " via " + via);
        try
        {
            route::ReplaceRoute4(dev, cidr, via);
        }
        catch (const std::exception &e)
        {
            logger_->error("Route install failed for {}: {}", cidr, e.what());
        }
    }

    // Install IPv6 routes
    for (const auto &[network, gw, metric] : negotiated.routes_ipv6)
    {
        logger_->info("Installing IPv6 route: {} dev {}", network, dev);
        try
        {
            route::ReplaceRoute6(dev, network);
        }
        catch (const std::exception &e)
        {
            logger_->error("IPv6 route install failed for {}: {}", network, e.what());
        }
    }
}

bool VpnClient::DeriveAndInstallKeys()
{
    logger_->debug("Deriving data channel keys");

    auto result = DeriveDataChannelKeys(control_channel_,
                                        client_random_,
                                        server_random_,
                                        config_.client->cipher,
                                        /*is_server=*/false,
                                        *logger_);
    if (!result)
        return false;

    // Save key material and cipher for DCO key push (deferred until after PUSH_REPLY)
    derived_key_material_ = result->key_material;
    if (IsDco())
    {
        Dco().cipher_algo_ = result->cipher_algo;
    }

    // Always install in userspace DataChannel (needed for handshake-phase data
    // packets and as fallback; DCO installs to kernel separately)
    std::uint8_t current_key_id = control_channel_.GetKeyId();
    return openvpn::KeyDerivation::InstallKeys(data_channel_,
                                               result->key_material,
                                               result->cipher_algo,
                                               result->hmac_algo,
                                               current_key_id,
                                               openvpn::KEY_TRANSITION_WINDOW_SECONDS,
                                               openvpn::PeerRole::Client);
}

// ============================================================================
// Packet Sending
// ============================================================================

asio::awaitable<void> VpnClient::SendWrappedPacket(std::vector<std::uint8_t> data)
{
    co_await WrapAndSend(tls_crypt_, std::move(data), /*is_server=*/false, *transport_, *logger_);
}

asio::awaitable<void> VpnClient::SendRawPacket(std::span<const std::uint8_t> data)
{
    co_await transport_->Send(data);
}

// ============================================================================
// High-Performance Userspace Data Path
// ============================================================================

asio::awaitable<void> VpnClient::UdpReceiveLoop()
{
    if (!transport_ || !transport_->IsUdp())
        co_return;

    auto &udpT = std::get<transport::UdpTransport>(*transport_);
    int socketFd = udpT.RawSocket().native_handle();

    // Determine TUN fd for synchronous batch writes
    int tunFd = -1;
    if (tun_device_ && tun_device_->IsOpen())
        tunFd = tun_device_->NativeHandle();

    // ---- Data fast-path callback ----
    auto onData = [&](transport::IncomingSlot &slot) -> std::span<std::uint8_t>
    {
        // Track last received time for keepalive timeout detection.
        last_rx_time_ = std::chrono::steady_clock::now();

        auto plaintext = data_channel_.DecryptPacketInPlace(
            std::span<std::uint8_t>(slot.buf, slot.len));

        if (!plaintext.empty())
        {
            stats_.packetsDecrypted++;

            // Check for raw keepalive magic (no compress byte)
            if (openvpn::IsKeepalivePing(plaintext))
            {
                logger_->trace("Received keepalive PING");
                return {};
            }

            // Intelligent compress byte detection (symmetric with server)
            std::span<std::uint8_t> ip_data = plaintext;
            std::uint8_t first_byte = ip_data[0];
            std::uint8_t version_nibble = (first_byte >> openvpn::IP_VERSION_SHIFT) & openvpn::IP_VERSION_MASK;
            if (version_nibble != openvpn::IP_VERSION_4 && version_nibble != openvpn::IP_VERSION_6)
            {
                if (first_byte == openvpn::COMPRESS_NONE || first_byte == openvpn::COMPRESS_STUB_LZO)
                {
                    ip_data = ip_data.subspan(1);
                }
                else
                {
                    logger_->warn("Unknown non-IP byte 0x{:02x} in {} byte packet, dropping",
                                  first_byte,
                                  plaintext.size());
                    return {};
                }
            }

            // Check for keepalive after compress strip
            if (openvpn::IsKeepalivePing(ip_data))
            {
                logger_->trace("Received keepalive PING");
                return {};
            }

            if (ip_data.size() >= openvpn::IPV4_MIN_HEADER_SIZE)
                return ip_data;
        }
        else
        {
            stats_.decryptFailures++;
        }
        return {};
    };

    // ---- Control slow-path callback ----
    auto onControl = [&](transport::IncomingSlot &slot)
    {
        std::vector<std::uint8_t> data(slot.buf, slot.buf + slot.len);
        asio::co_spawn(io_context_,
                       ProcessServerPacket(std::move(data)),
                       asio::detached);
    };

    co_await UdpReceiveLoopSkeleton(
        udpT.RawSocket(),
        socketFd,
        tunFd,
        currentBatchSize_,
        processQuanta_,
        inbound_slots_,
        inbound_arena_,
        stats_,
        stats_observer_,
        tun_device_.get(),
        io_context_,
        logger_,
        [&]
    { return running_ && state_ == VpnClientState::Connected; },
        onData,
        onControl);

    logger_->info("UdpReceiveLoop stopped");
}

asio::awaitable<void> VpnClient::TunToServerBatch()
{
    if (!tun_device_ || !transport_ || !transport_->IsUdp())
        co_return;

    auto &udpT = std::get<transport::UdpTransport>(*transport_);
    int socketFd = udpT.RawSocket().native_handle();
    auto serverPeer = transport_->GetPeer();

    const auto batchSize = currentBatchSize_;

    // Prepare TUN read slots pointing into outbound arena at offset kDataV2Overhead
    // (leave room for wire header; no compress byte — DCO kernel expects raw IP)
    constexpr std::size_t kPayloadOffset = openvpn::kDataV2Overhead; // 24
    tun_slots_.resize(batchSize);
    arena_entries_.resize(batchSize);

    for (std::size_t i = 0; i < batchSize; ++i)
    {
        auto *slot_base = outbound_arena_.Slot(i);
        tun_slots_[i].buf = slot_base + kPayloadOffset;
        tun_slots_[i].capacity = outbound_arena_.SlotSize() - kPayloadOffset;
        tun_slots_[i].len = 0;
    }

    // Pre-allocate send entry batch
    std::vector<transport::SendEntry> sendEntries;
    sendEntries.reserve(batchSize);

    logger_->info("TunToServerBatch: zero-copy arena (batch_size={}, arena={}KB)",
                  batchSize,
                  outbound_arena_.TotalSize() / 1024);

    openvpn::SessionId session_id{static_cast<std::uint64_t>(server_peer_id_)};
    std::size_t total_tun_reads = 0;

    logger_->info("TunToServerBatch: entering read loop (peer_id={}, tun_fd={})",
                  server_peer_id_,
                  tun_device_ ? tun_device_->NativeHandle() : -1);

    while (running_ && state_ == VpnClientState::Connected && tun_device_)
    {
        try
        {
            // Reset lengths
            for (auto &s : tun_slots_)
                s.len = 0;

            // Batch read from TUN directly into arena
            auto count = co_await tun_device_->ReadBatchInto(
                std::span<tun::TunDevice::SlotBuffer>(tun_slots_.data(), batchSize));

            if (count == 0)
                continue;

            total_tun_reads += count;
            logger_->trace("TunToServerBatch: read {} pkts from TUN (total={})", count, total_tun_reads);

            stats_.tunReads += count;
            stats_observer_.RecordTxBatchHistogram(count);

            // quanta == 0 → process the full batch in one pass (no intermediate yields).
            // quanta  > 0 → chunk into quanta-sized pieces, yielding between chunks.
            const std::size_t quanta = processQuanta_;
            const std::size_t effectiveQuanta = (quanta == 0) ? count : quanta;

            for (std::size_t chunk_start = 0; chunk_start < count; chunk_start += effectiveQuanta)
            {
                const std::size_t chunk_end = std::min(chunk_start + effectiveQuanta, count);
                sendEntries.clear();

                for (std::size_t i = chunk_start; i < chunk_end; ++i)
                {
                    auto &tslot = tun_slots_[i];
                    if (tslot.len == 0)
                        continue;

                    // The arena slot layout:
                    // [0..23]  = kDataV2Overhead (header + pkt_id + tag)
                    // [24..]   = IP packet data (written by TUN read)
                    // No compression framing byte — raw IP is required for
                    // DCO kernel compat; our server auto-detects both formats.

                    auto *slot_base = outbound_arena_.Slot(i);

                    std::size_t payload_len = tslot.len;

                    // In-place encrypt: writes header, tag, ciphertext
                    auto wire_len = data_channel_.EncryptPacketInPlace(
                        std::span<std::uint8_t>(slot_base, openvpn::kDataV2Overhead + payload_len + 16),
                        payload_len,
                        session_id);

                    if (wire_len == 0)
                    {
                        logger_->warn("Failed to encrypt packet in-place");
                        continue;
                    }

                    stats_.packetsEncrypted++;
                    stats_.bytesSent += tslot.len;

                    sendEntries.push_back({.data = std::span<const std::uint8_t>(slot_base, wire_len),
                                           .dest = serverPeer});
                }

                // Batch send via sendmmsg — retry unsent entries after waiting
                // for socket writability to handle EAGAIN backpressure.
                if (!sendEntries.empty())
                {
                    auto remaining = std::span<const transport::SendEntry>(sendEntries);
                    while (!remaining.empty())
                    {
                        auto sent = transport::SendBatch(socketFd, remaining);
                        stats_.packetsSent += sent;
                        if (sent >= remaining.size())
                            break; // all sent

                        // Partial send — wait for socket to become writable
                        remaining = remaining.subspan(sent);
                        co_await udpT.RawSocket().async_wait(
                            asio::ip::udp::socket::wait_write,
                            asio::use_awaitable);
                    }
                }

                if (chunk_end < count)
                    co_await asio::post(io_context_, asio::use_awaitable);
            }

            // Always yield once after processing — gives UdpReceiveLoop a
            // chance to drain incoming packets (ACKs).
            co_await asio::post(io_context_, asio::use_awaitable);
        }
        catch (const asio::system_error &e)
        {
            if (e.code() != asio::error::operation_aborted && running_)
            {
                logger_->error("TunToServerBatch error: {}", e.what());
            }
        }
        catch (const std::exception &e)
        {
            logger_->error("TunToServerBatch error: {}", e.what());
        }
    }

    logger_->info("TunToServerBatch stopped");
}

asio::awaitable<void> VpnClient::TunToServer()
{
    // Simple single-packet path (TCP fallback)
    logger_->info("Starting TUN -> Server forwarding (single-packet mode)");

    try
    {
        while (running_ && state_ == VpnClientState::Connected && tun_device_)
        {
            auto ip_packet = co_await tun_device_->ReadPacket();
            if (ip_packet.data.empty())
                continue;

            openvpn::SessionId session_id{static_cast<std::uint64_t>(server_peer_id_)};
            auto encrypted = data_channel_.EncryptPacket(
                std::span<const std::uint8_t>(ip_packet.data), session_id);

            if (encrypted.empty())
            {
                logger_->warn("Failed to encrypt packet");
                continue;
            }

            co_await SendRawPacket(encrypted);
            stats_.bytesSent += ip_packet.data.size();
            stats_.packetsSent++;
        }
    }
    catch (const asio::system_error &e)
    {
        if (e.code() != asio::error::operation_aborted)
            logger_->error("TUN read error: {}", e.what());
    }
    catch (const std::exception &e)
    {
        logger_->error("TUN -> Server error: {}", e.what());
    }

    logger_->info("TUN -> Server forwarding stopped");
}

asio::awaitable<void> VpnClient::KeepaliveLoop()
{
    logger_->info("Starting keepalive loop (interval={}s)", config_.client->keepalive_interval);

    while (running_ && state_ == VpnClientState::Connected)
    {
        keepalive_timer_.expires_after(std::chrono::seconds(config_.client->keepalive_interval));
        try
        {
            co_await keepalive_timer_.async_wait(asio::use_awaitable);
        }
        catch (const asio::system_error &e)
        {
            if (e.code() == asio::error::operation_aborted)
                break;
            throw;
        }

        if (!running_ || state_ != VpnClientState::Connected)
            break;

        // ---- Keepalive timeout detection (userspace mode) ----
        // In DCO mode the kernel delivers peer-death via netlink, but in
        // userspace mode we must poll.  If no packet has arrived within
        // keepalive_timeout seconds the server is considered unreachable.
        if (config_.client->keepalive_timeout > 0 && !IsDco())
        {
            auto silence = std::chrono::steady_clock::now() - last_rx_time_;
            if (silence >= std::chrono::seconds(config_.client->keepalive_timeout))
            {
                logger_->warn("Keepalive timeout ({:.0f}s): server unreachable",
                              std::chrono::duration<double>(silence).count());
                running_ = false;
                SetState(VpnClientState::Reconnecting);
                asio::co_spawn(io_context_, ReconnectLoop(), asio::detached);
                co_return;
            }
        }

        // Send keepalive PING via data channel
        try
        {
            // Build keepalive payload: raw magic (no compress byte — DCO compat)
            std::vector<std::uint8_t> payload(
                std::begin(openvpn::KEEPALIVE_PING_PAYLOAD),
                std::end(openvpn::KEEPALIVE_PING_PAYLOAD));

            openvpn::SessionId session_id{static_cast<std::uint64_t>(server_peer_id_)};
            auto encrypted = data_channel_.EncryptPacket(
                std::span<const std::uint8_t>(payload), session_id);

            if (!encrypted.empty())
            {
                co_await SendRawPacket(encrypted);
                logger_->trace("Sent keepalive PING");
            }
        }
        catch (const std::exception &e)
        {
            logger_->warn("Failed to send keepalive PING: {}", e.what());
        }
    }

    logger_->info("Keepalive loop stopped");
}

// ============================================================================
// DCO (Data Channel Offload) Implementation
// ============================================================================



void VpnClient::InitializeDco()
{
    auto &dco = Dco();
    logger_->info("DCO: Initializing P2P device {}", dco.ifname_);

    // Check if device already exists
    clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, dco.ifname_.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock.get(), SIOCGIFINDEX, &ifr) < 0)
    {
        // Create the device in P2P mode
        CreateDcoDevice();

        auto device_guard = scope_fail([this]()
        { DestroyDcoDevice(); });

        sock = clv::UniqueFd(::socket(AF_INET, SOCK_DGRAM, 0));
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, dco.ifname_.c_str(), IFNAMSIZ - 1);
        if (ioctl(sock.get(), SIOCGIFINDEX, &ifr) < 0)
            throw std::system_error(errno, std::system_category(), "DCO client: Failed to get ifindex");
        dco.ifindex_ = ifr.ifr_ifindex;
    }
    else
    {
        dco.ifindex_ = ifr.ifr_ifindex;
    }

    // Open generic netlink socket
    dco.netlink_helper_.Open();

    dco.genl_family_id_ = dco.netlink_helper_.ResolveFamilyId(OVPN_NL_NAME);
    if (dco.genl_family_id_ == 0)
        throw std::runtime_error("DCO client: Failed to resolve generic netlink family '" + std::string(OVPN_NL_NAME) + "'");

    logger_->debug("DCO: Resolved family '{}' to ID {}", OVPN_NL_NAME, dco.genl_family_id_);

    dco.initialized_ = true;
    logger_->info("DCO: P2P device {} initialized (ifindex={})", dco.ifname_, dco.ifindex_);
}

void VpnClient::CreateDcoDevice()
{
    dco::CreateDcoDevice(Dco().ifname_, OVPN_MODE_P2P, *logger_);
}

void VpnClient::DestroyDcoDevice()
{
    auto &dco = Dco();
    dco::DestroyDcoDevice(dco.ifindex_, dco.ifname_, *logger_);
    dco.ifindex_ = -1;
}

void VpnClient::ConfigureDcoInterface()
{
    const auto &negotiated = config_exchange_.GetNegotiatedConfig();
    const auto &assigned_ip = negotiated.ifconfig.first;
    const auto &assigned_netmask = negotiated.ifconfig.second;

    if (assigned_ip.empty())
    {
        logger_->warn("DCO: No IP assigned - cannot configure interface");
        return;
    }

    auto &dco = Dco();
    logger_->info("DCO: Configuring interface {} with IP {}", dco.ifname_, assigned_ip);

    if (negotiated.topology == "subnet" && !assigned_netmask.empty())
    {
        // Subnet topology: assigned_netmask is an actual netmask (e.g. "255.255.255.0").
        clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));

        iface::SetIpAddress(sock.get(), dco.ifname_.c_str(), assigned_ip);

        // Convert dotted-decimal netmask to host-order uint32_t
        uint32_t mask = asio::ip::make_address_v4(assigned_netmask).to_uint();
        iface::SetNetmask(sock.get(), dco.ifname_.c_str(), mask);

        iface::BringUp(sock.get(), dco.ifname_.c_str());

        logger_->debug("DCO: Interface {} configured with {}/{} (subnet)", dco.ifname_, assigned_ip, ipv4::MaskToPrefix(mask));
    }
    else
    {
        // net30 / P2P topology: assigned_netmask holds the remote peer IP
        // (e.g. "10.8.0.1"), NOT a netmask.  Configure as a point-to-point link
        // so that the connected route is a /32 host route for the peer, which
        // avoids a /0 default route that would capture tunnel traffic.
        std::string remote_ip = assigned_netmask.empty() ? "255.255.255.255" : assigned_netmask;

        iface::SetPointToPoint(dco.ifname_.c_str(), assigned_ip, remote_ip);

        logger_->debug("DCO: Interface {} configured with {} peer {} (net30/p2p)", dco.ifname_, assigned_ip, remote_ip);
    }

    // Add IPv6 address if pushed by server (mirrors ConfigureTunDevice logic)
    if (!negotiated.ifconfig_ipv6.first.empty())
    {
        auto prefix6 = static_cast<std::uint8_t>(negotiated.ifconfig_ipv6.second);
        iface::AddIpv6Address(dco.ifname_.c_str(),
                              negotiated.ifconfig_ipv6.first,
                              prefix6);
        logger_->debug("DCO: Added IPv6 address: {}/{} on {}",
                       negotiated.ifconfig_ipv6.first,
                       prefix6,
                       dco.ifname_);
    }
}

bool VpnClient::CreateDcoPeer()
{
    auto &dco = Dco();
    if (!dco.initialized_ || !dco.netlink_helper_.IsOpen())
        return false;

    if (dco.peer_created_)
    {
        logger_->debug("DCO: Peer already exists");
        return true;
    }

    auto serverPeer = transport_->GetPeer();
    // Use the server-assigned peer_id so the kernel stamps the correct
    // value in outgoing P_DATA_V2 headers (server uses it to look up session).
    uint32_t peer_id = server_peer_id_;

    logger_->debug("DCO: Creating peer for server {}:{}", serverPeer.addr.to_string(), serverPeer.port);

    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        char attrs[512];
    } req{};

    req.nlh.nlmsg_type = dco.genl_family_id_;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.genlh.cmd = OVPN_CMD_NEW_PEER;
    req.genlh.version = 0;

    char *buf = req.attrs;
    size_t offset = 0;
    constexpr size_t kAttrsCap = sizeof(req.attrs);

    // OVPN_ATTR_IFINDEX
    {
        uint32_t ifidx = static_cast<uint32_t>(dco.ifindex_);
        NlaPut(buf, offset, kAttrsCap, OVPN_ATTR_IFINDEX, &ifidx, sizeof(ifidx));
    }

    // OVPN_ATTR_NEW_PEER (nested)
    size_t peer_attr_start = offset;
    struct nlattr *peer_attr = NlaBeginNested(buf, offset, kAttrsCap, OVPN_ATTR_NEW_PEER);
    if (!peer_attr)
    {
        logger_->error("DCO: Buffer overflow in NEW_PEER");
        return false;
    }

    // PEER_ID
    NlaPut(buf, offset, kAttrsCap, OVPN_NEW_PEER_ATTR_PEER_ID, &peer_id, sizeof(peer_id));

    // SOCKADDR_REMOTE
    // In DCO mode the connector opens a native AF_INET socket for IPv4
    // servers, so peerAddr is native IPv4 and we pass sockaddr_in.
    // For IPv6 servers (or non-DCO fallback) the address is already v6.
    const auto &peerAddr = serverPeer.addr;
    if (peerAddr.is_v4())
    {
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(serverPeer.port);
        sa.sin_addr.s_addr = htonl(peerAddr.to_v4().to_uint());
        NlaPut(buf, offset, kAttrsCap, OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE, &sa, sizeof(sa));
        logger_->debug("DCO: Peer sockaddr: AF_INET {}:{}", peerAddr.to_string(), serverPeer.port);
    }
    else
    {
        struct sockaddr_in6 sa6{};
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons(serverPeer.port);
        auto v6bytes = peerAddr.to_v6().to_bytes();
        std::memcpy(&sa6.sin6_addr, v6bytes.data(), 16);
        NlaPut(buf, offset, kAttrsCap, OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE, &sa6, sizeof(sa6));
        logger_->debug("DCO: Peer sockaddr: AF_INET6 [{}]:{}", peerAddr.to_string(), serverPeer.port);
    }

    // SOCKET FD
    {
        auto &udpT = std::get<transport::UdpTransport>(*transport_);
        uint32_t sockfd = static_cast<uint32_t>(udpT.RawSocket().native_handle());
        NlaPut(buf, offset, kAttrsCap, OVPN_NEW_PEER_ATTR_SOCKET, &sockfd, sizeof(sockfd));
    }

    // VPN IP (assigned to us)
    const auto &vpn_ip = config_exchange_.GetNegotiatedConfig().ifconfig.first;
    if (!vpn_ip.empty())
    {
        struct in_addr addr;
        if (inet_pton(AF_INET, vpn_ip.c_str(), &addr) == 1)
        {
            NlaPut(buf, offset, kAttrsCap, OVPN_NEW_PEER_ATTR_IPV4, &addr.s_addr, sizeof(addr.s_addr));
        }
    }

    peer_attr->nla_len = static_cast<decltype(peer_attr->nla_len)>(offset - peer_attr_start);
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)) + static_cast<decltype(req.nlh.nlmsg_len)>(offset);

    std::vector<uint8_t> response;
    if (!dco.netlink_helper_.SendAndReceive(&req.nlh, req.nlh.nlmsg_len, response))
    {
        logger_->error("DCO: Failed to send/receive OVPN_CMD_NEW_PEER");
        return false;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)response.data();
    if (nlh->nlmsg_type == NLMSG_ERROR)
    {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        if (err->error != 0)
        {
            logger_->error("DCO: OVPN_CMD_NEW_PEER failed: {} ({})", std::strerror(-err->error), err->error);
            return false;
        }
    }

    dco.peer_created_ = true;
    logger_->info("DCO: Peer created for server {}:{}", serverPeer.addr.to_string(), serverPeer.port);
    return true;
}

bool VpnClient::PushKeysToKernel(const std::vector<std::uint8_t> &key_material,
                                 openvpn::CipherAlgorithm cipher_algo,
                                 std::uint8_t key_id,
                                 std::uint8_t key_slot)
{
    auto &dco = Dco();
    if (!dco.initialized_ || !dco.netlink_helper_.IsOpen())
    {
        logger_->error("DCO: Cannot push keys - not initialized");
        return false;
    }

    return dco::PushKeysToKernel(dco.ifindex_, dco.genl_family_id_, server_peer_id_, key_material, cipher_algo, key_id, key_slot, openvpn::PeerRole::Client, dco.netlink_helper_, *logger_);
}

bool VpnClient::SwapDcoKeys()
{
    auto &dco = Dco();
    if (!dco.initialized_ || !dco.netlink_helper_.IsOpen())
        return false;

    return dco::SwapDcoKeys(dco.ifindex_, dco.genl_family_id_, server_peer_id_, dco.netlink_helper_, *logger_);
}

bool VpnClient::SetDcoPeerKeepalive()
{
    auto &dco = Dco();
    if (!dco.initialized_ || !dco.netlink_helper_.IsOpen())
        return false;

    if (config_.client->keepalive_interval <= 0 && config_.client->keepalive_timeout <= 0)
    {
        logger_->debug("DCO: Keepalive disabled");
        return true;
    }

    uint32_t interval = static_cast<uint32_t>(std::max(0, config_.client->keepalive_interval));
    uint32_t timeout = static_cast<uint32_t>(std::max(0, config_.client->keepalive_timeout));

    return dco::SetDcoPeerKeepalive(dco.ifindex_, dco.genl_family_id_, server_peer_id_, interval, timeout, dco.netlink_helper_, *logger_);
}

DataPathStats VpnClient::QueryDcoStats() const
{
    DataPathStats stats{};

    const auto &dco = Dco();
    if (!dco.initialized_ || dco.genl_family_id_ == 0)
    {
        logger_->debug("DCO QueryDcoStats: skipped (init={} fam={})",
                       dco.initialized_,
                       dco.genl_family_id_);
        return stats;
    }

    // Open a temporary netlink socket (the member socket may be busy with multicast)
    NetlinkHelper nl;
    nl.Open(NETLINK_GENERIC);

    uint16_t fam = nl.ResolveFamilyId(OVPN_NL_NAME);
    if (fam == 0)
    {
        logger_->warn("DCO QueryDcoStats: failed to resolve family ID");
        return stats;
    }

    logger_->debug("DCO QueryDcoStats: fam={} ifindex={} peer_id={}",
                   fam,
                   dco.ifindex_,
                   server_peer_id_);

    // In P2P mode the kernel stores the peer in ovpn->peer (not the hash
    // table), so NLM_F_DUMP (.dumpit) returns an empty set.  Use a direct
    // .doit query with OVPN_ATTR_GET_PEER containing the specific peer_id.
    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        char attrs[128];
    } req{};

    req.nlh.nlmsg_type = fam;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq = 0;
    req.nlh.nlmsg_pid = 0;
    req.genlh.cmd = OVPN_CMD_GET_PEER;
    req.genlh.version = 0;

    char *buf = req.attrs;
    size_t offset = 0;
    constexpr size_t kAttrsCap = sizeof(req.attrs);

    {
        uint32_t ifidx = static_cast<uint32_t>(dco.ifindex_);
        NlaPut(buf, offset, kAttrsCap, OVPN_ATTR_IFINDEX, &ifidx, sizeof(ifidx));
    }

    // Nested OVPN_ATTR_GET_PEER with PEER_ID — triggers .doit path
    {
        size_t get_start = offset;
        struct nlattr *get_attr = NlaBeginNested(buf, offset, kAttrsCap, OVPN_ATTR_GET_PEER);
        if (!get_attr)
        {
            logger_->warn("DCO QueryDcoStats: buffer overflow building GET_PEER");
            return stats;
        }
        uint32_t pid = server_peer_id_;
        NlaPut(buf, offset, kAttrsCap, OVPN_GET_PEER_ATTR_PEER_ID, &pid, sizeof(pid));
        get_attr->nla_len = static_cast<decltype(get_attr->nla_len)>(offset - get_start);
    }

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr))
                        + static_cast<decltype(req.nlh.nlmsg_len)>(offset);

    if (::send(nl.RawFd(), &req, req.nlh.nlmsg_len, 0) < 0)
    {
        logger_->warn("DCO QueryDcoStats: send failed ({})", std::strerror(errno));
        return stats;
    }

    // .doit reply: single message (not multipart) with the peer stats
    std::array<char, 16384> rbuf;
    ssize_t len = ::recv(nl.RawFd(), rbuf.data(), rbuf.size(), 0);
    if (len <= 0)
    {
        logger_->debug("DCO QueryDcoStats: recv returned {} ({})",
                       len,
                       len < 0 ? std::strerror(errno) : "EOF");
        return stats;
    }

    auto *nlh = reinterpret_cast<struct nlmsghdr *>(rbuf.data());

    if (nlh->nlmsg_type == NLMSG_ERROR)
    {
        auto *err = static_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
        if (err->error != 0)
        {
            logger_->warn("DCO QueryDcoStats: kernel error {}",
                          std::strerror(-err->error));
            return stats;
        }
        // error=0 means ACK with no payload — shouldn't happen for GET
        logger_->debug("DCO QueryDcoStats: got ACK with no data");
        return stats;
    }

    // Parse genlmsghdr + top-level attrs
    auto *genlh = static_cast<struct genlmsghdr *>(NLMSG_DATA(nlh));
    auto *attr = reinterpret_cast<struct nlattr *>(
        reinterpret_cast<char *>(genlh) + GENL_HDRLEN);
    int attrlen = static_cast<int>(
        nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));

    bool foundPeerAttr = false;

    while (NLA_OK(attr, attrlen))
    {
        if ((attr->nla_type & ~NLA_F_NESTED) == OVPN_ATTR_GET_PEER)
        {
            foundPeerAttr = true;
            auto *inner = reinterpret_cast<struct nlattr *>(NLA_DATA(attr));
            int innerlen = attr->nla_len - NLA_HDRLEN;

            while (NLA_OK(inner, innerlen))
            {
                switch (inner->nla_type)
                {
                case OVPN_GET_PEER_RESP_ATTR_LINK_RX_BYTES:
                    stats.bytesReceived += *reinterpret_cast<const uint64_t *>(NLA_DATA(inner));
                    break;
                case OVPN_GET_PEER_RESP_ATTR_LINK_TX_BYTES:
                    stats.bytesSent += *reinterpret_cast<const uint64_t *>(NLA_DATA(inner));
                    break;
                case OVPN_GET_PEER_RESP_ATTR_VPN_RX_PACKETS:
                    {
                        auto pkts = static_cast<uint64_t>(
                            *reinterpret_cast<const uint32_t *>(NLA_DATA(inner)));
                        stats.packetsReceived += pkts;
                        break;
                    }
                case OVPN_GET_PEER_RESP_ATTR_VPN_TX_PACKETS:
                    {
                        auto pkts = static_cast<uint64_t>(
                            *reinterpret_cast<const uint32_t *>(NLA_DATA(inner)));
                        stats.packetsSent += pkts;
                        break;
                    }
                default:
                    break;
                }
                inner = NLA_NEXT(inner, innerlen);
            }
        }
        attr = NLA_NEXT(attr, attrlen);
    }

    logger_->debug("DCO QueryDcoStats: foundPeer={} "
                   "rxBytes={} txBytes={} rxPkts={} txPkts={}",
                   foundPeerAttr,
                   stats.bytesReceived,
                   stats.bytesSent,
                   stats.packetsReceived,
                   stats.packetsSent);
    return stats;
}

asio::awaitable<void> VpnClient::StatsLoop()
{
    auto interval = std::chrono::seconds(config_.performance.stats_interval_seconds);

    // Query actual kernel socket buffer sizes once
    int actualRcvBuf = 0, actualSndBuf = 0;
    if (transport_)
    {
        if (auto *udp = std::get_if<transport::UdpTransport>(&*transport_))
            std::tie(actualRcvBuf, actualSndBuf) = udp->GetSocketBufferSizes();
    }

    logger_->info("[stats] enabled (interval={}s, mode={})",
                  config_.performance.stats_interval_seconds,
                  IsDco() ? "dco" : "userspace");

    while (running_ && state_ == VpnClientState::Connected)
    {
        stats_timer_.expires_after(interval);
        try
        {
            co_await stats_timer_.async_wait(asio::use_awaitable);
        }
        catch (const asio::system_error &e)
        {
            if (e.code() == asio::error::operation_aborted)
                break;
            throw;
        }

        if (!running_ || state_ != VpnClientState::Connected)
            break;

        DataPathStats delta = data_channel_strategy_
                                  ? data_channel_strategy_->ElapsedStats()
                                  : DataPathStats{};

        double elapsed = static_cast<double>(config_.performance.stats_interval_seconds);
        double rxBps = elapsed > 0 ? static_cast<double>(delta.bytesReceived) / elapsed : 0;
        double txBps = elapsed > 0 ? static_cast<double>(delta.bytesSent) / elapsed : 0;
        double rxMbps = rxBps * 8.0 / 1e6;
        double txMbps = txBps * 8.0 / 1e6;

        double rxBufMs = rxBps > 0 ? static_cast<double>(actualRcvBuf) / rxBps * 1000.0
                                   : std::numeric_limits<double>::infinity();
        double txBufMs = txBps > 0 ? static_cast<double>(actualSndBuf) / txBps * 1000.0
                                   : std::numeric_limits<double>::infinity();

        if (IsDco())
        {
            logger_->info("[stats/dco] {:.1f}s: "
                          "rx={} pkts ({:.1f} Mbps) "
                          "tx={} pkts ({:.1f} Mbps) "
                          "buf={:.0f}/{:.0f}ms",
                          elapsed,
                          delta.packetsReceived,
                          rxMbps,
                          delta.packetsSent,
                          txMbps,
                          rxBufMs,
                          txBufMs);
        }
        else
        {
            // Userspace: include batch histogram
            auto rxH = FormatBatchHist(delta.batchHist, delta.batchSaturations);
            auto txH = FormatBatchHist(delta.txBatchHist, delta.txBatchSaturations);

            logger_->info("[stats] {:.1f}s: "
                          "rx={} ({:.0f}M) tx={} ({:.0f}M) "
                          "rx{} tx{} "
                          "buf={:.0f}/{:.0f}ms "
                          "dec={}/{} tun=r{}/w{} serr={}",
                          elapsed,
                          delta.packetsReceived,
                          rxMbps,
                          delta.packetsSent,
                          txMbps,
                          rxH,
                          txH,
                          rxBufMs,
                          txBufMs,
                          delta.packetsDecrypted,
                          delta.decryptFailures,
                          delta.tunReads,
                          delta.tunWrites,
                          delta.sendErrors);
        }
    }

    logger_->info("[stats] loop stopped");
}

asio::awaitable<void> VpnClient::DcoKeepaliveMonitor()
{
    logger_->info("DCO: Starting keepalive monitor (netlink multicast)");

    try
    {
        // Resolve multicast group "peers"
        auto group_id = Dco().netlink_helper_.ResolveMulticastGroupId(OVPN_NL_NAME, OVPN_NL_MULTICAST_GROUP_PEERS);
        if (group_id == 0)
        {
            logger_->error("DCO: Could not resolve multicast group 'peers'");
            co_return;
        }

        // Open separate netlink socket for multicast (don't interfere with command socket)
        NetlinkHelper mcast_nl;
        mcast_nl.Open();
        if (!mcast_nl.JoinMulticastGroup(group_id))
        {
            logger_->error("DCO: Failed to join multicast group");
            co_return;
        }

        // Wrap the fd in asio for async read
        asio::posix::stream_descriptor stream(io_context_, mcast_nl.RawFd());

        // Capture the family ID locally so the loop body never touches
        // data_channel_strategy_ (which may be reset by Disconnect()).
        const auto genl_family_id = Dco().genl_family_id_;

        std::array<char, 4096> buf;
        while (running_)
        {
            auto bytes = co_await stream.async_read_some(
                asio::buffer(buf), asio::use_awaitable);

            // Re-check after suspend — Disconnect() may have run while we
            // were waiting, and the notification we just received could be
            // from our own device teardown rather than a real peer death.
            if (!running_)
                break;

            if (bytes < sizeof(struct nlmsghdr))
                continue;

            auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf.data());
            if (nlh->nlmsg_type != genl_family_id)
                continue;

            auto *genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
            if (genlh->cmd == OVPN_CMD_DEL_PEER)
            {
                logger_->warn("DCO: Peer death notification from kernel - server unreachable");
                running_ = false;
                SetState(VpnClientState::Reconnecting);
                asio::co_spawn(io_context_, ReconnectLoop(), asio::detached);
            }
        }

        // Release the fd before mcast_nl destructor closes it
        stream.release();
    }
    catch (const std::exception &e)
    {
        if (running_)
            logger_->error("DCO: Keepalive monitor error: {}", e.what());
    }
}

asio::awaitable<void> VpnClient::DcoReceiveLoop()
{
    // In DCO mode, the kernel handles data packets.
    // We only need to receive control packets (key renegotiation, etc.)
    logger_->info("DCO: Starting control-only receive loop");

    try
    {
        while (running_ && state_ == VpnClientState::Connected)
        {
            auto data = co_await transport_->Receive();
            if (data.empty())
                continue;

            auto opcode = openvpn::GetOpcode(data[0]);
            if (openvpn::IsDataPacket(opcode))
            {
                // Data packets should be handled by kernel — drop
                continue;
            }

            // Control packet: process normally
            co_await ProcessServerPacket(std::move(data));
        }
    }
    catch (const std::exception &e)
    {
        if (running_)
            logger_->error("DCO receive loop error: {}", e.what());
    }

    logger_->info("DCO: Receive loop stopped");
}

} // namespace clv::vpn
