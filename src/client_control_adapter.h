// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CLIENT_CONTROL_ADAPTER_H
#define CLV_VPN_CLIENT_CONTROL_ADAPTER_H

/**
 * @file client_control_adapter.h
 * @brief CRTP control-side adapter for the VPN client.
 *
 * Contains the full OpenVPN client protocol engine: connection flow,
 * TLS handshake, key derivation, PUSH_REQUEST/PUSH_REPLY exchange,
 * keepalive, reconnect logic, TUN device configuration, and stats.
 *
 * Transport-specific details — socket binding, TUN vs DCO device setup,
 * route installation, keepalive semantics, and teardown — are fully
 * encapsulated in the channel type via the hooks above.  This adapter
 * provides only the shared OpenVPN protocol intelligence.
 *
 * CRTP hooks called on Derived (via derived()):
 *   - channel()                    — access to the underlying data channel
 *   - StartDataPath()              — begin data-path RX loop
 *   - StopDataPath()               — stop data-path RX loop
 *   - SnapshotStats()              — merge TX/RX counters into DataPathStats
 *   - SendKeepalivePing()          — transmit a keepalive ping packet
 *
 * Channel hooks (called on derived().channel(), implemented by each channel
 * type — ClientUdpChannel, ClientTcpChannel, ClientDcoChannel):
 *   - AttachTransport(handle, peer, peer_id)
 *   - InstallDataPathKeys(material, cipher, hmac, key_id, data_channel)
 *   - ConfigureNetworkInterface(negotiated, config, io_ctx)
 *   - InstallNegotiatedRoutes(negotiated)
 *   - OnTeardown()
 *   - LaunchKeepalive(io_ctx, loop_fn, interval_seconds)
 *
 * @tparam Derived  The concrete DataTransport instantiation.
 */

#include "data_path_stats.h"
#include "keepalive_loop.h"
#include "openvpn/config_exchange.h"
#include "openvpn/connection.h"
#include "openvpn/control_channel.h"
#include "openvpn/control_plane_helpers.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/data_channel.h"
#include "openvpn/key_derivation.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/push_exchange_helpers.h"
#include "openvpn/tls_context.h"
#include "openvpn/tls_crypt.h"
#include "openvpn/tls_crypt_v2.h"
#include "openvpn/vpn_config.h"
#include "transport/connector.h"
#include "transport/transport.h"

#include <not_null.h>

#include <array>
#include <exception>

#include <log_utils.h>
#include <tuple>
#include <net/ipv4_utils.h>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <openssl/rand.h>

#include <spdlog/logger.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace clv::vpn {

namespace ipv4 = clv::net::ipv4;

/**
 * @brief Connection state for the VPN client.
 */
enum class VpnClientState
{
    Disconnected,
    Connecting,
    TlsHandshake,
    Authenticating,
    Connected,
    Reconnecting,
    Error
};

const char *VpnClientStateToString(VpnClientState state);

/**
 * @brief Configuration struct passed to ClientControlAdapter::Initialize.
 */
struct ClientControlConfig
{
    asio::io_context &io_context;
    const VpnConfig &config;
    spdlog::logger &logger;
    std::atomic<bool> &running;
};

/**
 * @brief Client control adapter — full protocol engine.
 *
 * CRTP base — `Derived` is `DataTransport<..., ClientDataAdapter, ClientControlAdapter>`.
 * Owns all client-side protocol state: control channel, data channel,
 * TLS-Crypt, config exchange, session IDs, key material, timers, etc.
 *
 * VpnClient (the factory shell) calls Initialize → Connect → Disconnect.
 * The protocol engine runs autonomously once connected.
 */
template <typename Derived>
class ClientControlAdapter
{
  public:
    explicit ClientControlAdapter(ClientControlConfig cfg);

    // -- Public accessors (used by VpnClient shell) ---------------------------

    asio::io_context &io_context() noexcept;
    VpnClientState GetState() const;
    bool IsConnected() const;
    const VpnConfig &GetConfig() const;
    std::string GetAssignedIp() const;
    std::vector<std::string> GetRoutes() const;
    std::vector<std::string> GetDnsServers() const;
    std::vector<std::string> GetDnsSearchDomains() const;
    DataPathStats GetStats() const;
    std::chrono::seconds GetUptime() const;

    using StateCallback = std::function<void(VpnClientState, VpnClientState)>;
    void SetStateCallback(StateCallback cb);

    /// Record last-RX timestamp (called from data adapter, thread-safe).
    void TouchLastRx();

  public:
    void Connect();
    void Disconnect();

    // -- Called from DataAdapter (marshalled to control thread) ---------------

    void OnControlPacketFromDataPath(std::vector<std::uint8_t> data);

  private:
    Derived &derived() noexcept;
    const Derived &derived() const noexcept;

    // -- Connection flow -----------------------------------------------------

    asio::awaitable<void> ConnectionLoop();
    asio::awaitable<void> ReconnectLoop();

    // -- Handshake -----------------------------------------------------------

    asio::awaitable<void> SendHardReset();
    asio::awaitable<void> ProcessServerPacket(std::vector<std::uint8_t> data);
    asio::awaitable<void> HandleControlPacket(const openvpn::OpenVpnPacket &packet);
    asio::awaitable<void> HandleSoftResetFromServer(const openvpn::OpenVpnPacket &packet);
    asio::awaitable<void> ClientRekeyLoop(std::uint32_t reneg_seconds, std::uint64_t generation);
    asio::awaitable<void> HandleDataPacket(const openvpn::OpenVpnPacket &packet);
    asio::awaitable<void> ProcessTlsHandshake();
    asio::awaitable<void> ProcessReceivedPlaintext(std::vector<std::uint8_t> plaintext);
    asio::awaitable<void> SendPushRequest();
    asio::awaitable<void> HandlePushReply(const std::string &reply);

    // -- TUN device configuration --------------------------------------------

    void ApplyNegotiatedNetworkConfig();

    // -- Packet sending ------------------------------------------------------

    asio::awaitable<void> SendWrappedPacket(std::vector<std::uint8_t> data);
    asio::awaitable<void> SendRawPacket(std::span<const std::uint8_t> data);

    // -- State machine -------------------------------------------------------

    void SetState(VpnClientState new_state);
    void StartDataPath();

    // -- Keepalive -----------------------------------------------------------

    asio::awaitable<void> KeepaliveLoop();

    // -- Stats ---------------------------------------------------------------

    asio::awaitable<void> StatsLoop();
    void LogStats(const DataPathStats &delta, double elapsedSec);

    // -- Helpers (transport, TLS) --------------------------------------------

  protected:
    auto ChannelArgs();

  private:
    void InitializeTransport();
    bool LoadTlsCryptKey();
    bool InitializeControlChannel();
    std::chrono::steady_clock::time_point LastRxTime() const;

    // -- Key derivation ------------------------------------------------------

    void DeriveAndInstallKeys();

    // -- State ---------------------------------------------------------------

    not_null<asio::io_context *> io_context_; ///< Borrowed — owned by the caller of Initialize
    not_null<const VpnConfig *> config_;      ///< Borrowed — owned by VpnClient
    not_null<spdlog::logger *> logger_;       ///< Borrowed — owned by VpnClient
    not_null<std::atomic<bool> *> running_;   ///< Shared run-flag; set false by Disconnect/reconnect

    VpnClientState state_ = VpnClientState::Disconnected; ///< Current protocol state (control thread only)
    StateCallback state_callback_;                        ///< Optional user-supplied state-change notification
    int reconnect_attempts_ = 0;                          ///< Number of reconnect attempts in the current session

    std::optional<transport::TransportHandle> transport_; ///< Active UDP or TCP transport; reset on Disconnect

    std::uint64_t local_session_id_ = 0;  ///< Our randomly generated session ID (sent in P_CONTROL_HARD_RESET)
    std::uint64_t remote_session_id_ = 0; ///< Server session ID received in P_CONTROL_HARD_RESET_SERVER
    std::uint32_t server_peer_id_ = 0;    ///< Peer ID pushed by server in PUSH_REPLY (used for DCO/mssfix)
    std::uint8_t key_id_ = 0;             ///< Current OpenVPN key ID (cycles on rekey)

    std::optional<openvpn::ControlChannel> control_channel_; ///< TLS + reliability layer for control messages
    std::optional<openvpn::DataChannel> data_channel_;       ///< Symmetric-key encrypt/decrypt for data packets
    std::optional<openvpn::TlsCrypt> tls_crypt_;             ///< TLS-Crypt HMAC wrapper (V1 or V2 client key)
    std::vector<std::uint8_t> tls_crypt_v2_wkc_;             ///< TLS-Crypt-V2 wrapped-client-key blob appended to HARD_RESET
    openvpn::ConfigExchange config_exchange_;                ///< PUSH_REQUEST / PUSH_REPLY negotiated-config state

    std::vector<std::uint8_t> client_random_; ///< 64-byte client key-source random (key-method 2)
    std::vector<std::uint8_t> server_random_; ///< 64-byte server key-source random (key-method 2)

    DataPathStats stats_;                                ///< Cumulative stats updated by data/control paths
    std::chrono::steady_clock::time_point connected_at_; ///< Time at which Connected state was entered

    std::atomic<std::int64_t> last_rx_ns_{0}; ///< Last-received packet timestamp in ns (written by data adapter)

    std::optional<asio::steady_timer> stats_timer_;     ///< Fires every stats_interval_seconds to log throughput
    std::optional<asio::steady_timer> keepalive_timer_; ///< Drives the keepalive send/timeout loop
    std::optional<asio::steady_timer> handshake_timer_; ///< Retransmit timer during TLS handshake phase

    bool rekey_timer_armed_ = false;                             ///< Client-side rekey timer guard (control thread only)
    std::uint64_t rekey_generation_ = 0;                         ///< Incremented on each Disconnect to invalidate stale ClientRekeyLoop coroutines
    std::chrono::steady_clock::time_point last_server_rekey_at_; ///< Time of last server-initiated rekey (control thread only)
    std::vector<std::string> effective_data_ciphers_;            ///< Effective operator policy used for IV_CIPHERS and PUSH_REPLY validation
    std::string negotiated_cipher_;                              ///< NCP cipher pushed by server; empty until first PUSH_REPLY (session-scoped, reset on Disconnect)
};

// =============================================================================
// ClientControlAdapter — out-of-line member function definitions
// =============================================================================

template <typename Derived>
Derived &ClientControlAdapter<Derived>::derived() noexcept
{
    return static_cast<Derived &>(*this);
}

template <typename Derived>
const Derived &ClientControlAdapter<Derived>::derived() const noexcept
{
    return static_cast<const Derived &>(*this);
}

template <typename Derived>
asio::io_context &ClientControlAdapter<Derived>::io_context() noexcept
{
    return *io_context_;
}

template <typename Derived>
VpnClientState ClientControlAdapter<Derived>::GetState() const
{
    return state_;
}

template <typename Derived>
bool ClientControlAdapter<Derived>::IsConnected() const
{
    return state_ == VpnClientState::Connected;
}

template <typename Derived>
const VpnConfig &ClientControlAdapter<Derived>::GetConfig() const
{
    return *config_;
}

template <typename Derived>
std::string ClientControlAdapter<Derived>::GetAssignedIp() const
{
    return config_exchange_.GetNegotiatedConfig().ifconfig.first;
}

template <typename Derived>
std::vector<std::string> ClientControlAdapter<Derived>::GetRoutes() const
{
    std::vector<std::string> result;
    for (const auto &[network, gw, metric] : config_exchange_.GetNegotiatedConfig().routes)
        result.push_back(network);
    return result;
}

template <typename Derived>
std::vector<std::string> ClientControlAdapter<Derived>::GetDnsServers() const
{
    const auto &cfg = config_exchange_.GetNegotiatedConfig();

    // Prefer structured dns_servers (IV_PROTO_DNS_OPTION_V2 path) when present.
    if (!cfg.dns_servers.empty())
    {
        std::vector<std::string> result;
        for (const auto &entry : cfg.dns_servers)
            for (const auto &addr : entry.addresses)
                result.push_back(addr);
        return result;
    }

    // Fall back to legacy dhcp-option DNS entries.
    std::vector<std::string> result;
    for (const auto &[type, value] : cfg.dhcp_options)
        if (type == "DNS")
            result.push_back(value);
    return result;
}

template <typename Derived>
std::vector<std::string> ClientControlAdapter<Derived>::GetDnsSearchDomains() const
{
    return config_exchange_.GetNegotiatedConfig().dns_search_domains;
}

template <typename Derived>
DataPathStats ClientControlAdapter<Derived>::GetStats() const
{
    return stats_;
}

template <typename Derived>
std::chrono::seconds ClientControlAdapter<Derived>::GetUptime() const
{
    if (state_ != VpnClientState::Connected)
        return std::chrono::seconds(0);
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - connected_at_);
}

template <typename Derived>
void ClientControlAdapter<Derived>::SetStateCallback(StateCallback cb)
{
    state_callback_ = std::move(cb);
}

template <typename Derived>
void ClientControlAdapter<Derived>::TouchLastRx()
{
    last_rx_ns_.store(
        std::chrono::steady_clock::now().time_since_epoch().count(),
        std::memory_order_relaxed);
}

template <typename Derived>
ClientControlAdapter<Derived>::ClientControlAdapter(ClientControlConfig cfg)
    : io_context_(&cfg.io_context),
      config_(&cfg.config),
      logger_(&cfg.logger),
      running_(&cfg.running)
{
    // Timers
    stats_timer_.emplace(*io_context_);
    keepalive_timer_.emplace(*io_context_);
    handshake_timer_.emplace(*io_context_);

    control_channel_.emplace(*logger_);
    data_channel_.emplace(*logger_);
}

template <typename Derived>
auto ClientControlAdapter<Derived>::ChannelArgs()
{
    return std::forward_as_tuple(*io_context_, *logger_, *config_, *running_);
}

template <typename Derived>
void ClientControlAdapter<Derived>::Connect()
{
    logger_->info("Connecting to {}:{}", config_->client->server_host, config_->client->server_port);
    SetState(VpnClientState::Connecting);

    auto resolved = openvpn::ResolveDataCipherPolicy(config_->client->data_ciphers,
                                                     config_->client->allow_deprecated_data_ciphers);
    effective_data_ciphers_ = std::move(resolved.effective_ciphers);
    for (const auto &cipher : resolved.deprecated_ciphers)
        logger_->warn("Deprecated data-cipher '{}' enabled by explicit operator policy", cipher);

    InitializeTransport();

    local_session_id_ = openvpn::SessionId::Generate().value;

    if (!LoadTlsCryptKey())
        return;
    if (!InitializeControlChannel())
        return;

    *running_ = true;
    TouchLastRx();

    asio::co_spawn(*io_context_, ConnectionLoop(), asio::detached);
}

template <typename Derived>
void ClientControlAdapter<Derived>::Disconnect()
{
    if (state_ == VpnClientState::Disconnected)
        return;

    logger_->info("Disconnecting...");
    *running_ = false;

    derived().StopDataPath();

    if (handshake_timer_)
        handshake_timer_->cancel();

    // Close the socket to unblock pending receives
    if (transport_)
    {
        if (auto *udp = std::get_if<transport::UdpTransport>(&*transport_))
        {
            asio::error_code ec;
            [[maybe_unused]] auto _ = udp->RawSocket().close(ec);
        }
        else if (auto *tcp = std::get_if<transport::TcpTransport>(&*transport_))
        {
            tcp->Close();
        }
    }
    transport_.reset();

    derived().channel().OnTeardown();

    if (control_channel_)
        control_channel_->Reset();
    tls_crypt_.reset();

    client_random_.clear();
    server_random_.clear();
    key_id_ = 0;
    remote_session_id_ = 0;
    server_peer_id_ = 0;
    config_exchange_.Reset();

    if (stats_timer_)
        stats_timer_->cancel();
    if (keepalive_timer_)
        keepalive_timer_->cancel();

    rekey_timer_armed_ = false;
    ++rekey_generation_;
    effective_data_ciphers_.clear();
    negotiated_cipher_.clear();

    SetState(VpnClientState::Disconnected);
    logger_->info("Disconnected");
}

template <typename Derived>
void ClientControlAdapter<Derived>::OnControlPacketFromDataPath(std::vector<std::uint8_t> data)
{
    asio::co_spawn(*io_context_,
                   ProcessServerPacket(std::move(data)),
                   asio::detached);
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::ConnectionLoop()
{
    using namespace asio::experimental::awaitable_operators;
    static constexpr auto kHandshakeRetransmitInterval = std::chrono::seconds(2);
    static constexpr auto kHandshakeTimeout = std::chrono::seconds(30);

    try
    {
        co_await SendHardReset();
        auto handshake_start = std::chrono::steady_clock::now();

        while (*running_)
        {
            if (state_ == VpnClientState::Connected)
                co_return;

            if (state_ == VpnClientState::TlsHandshake)
            {
                if (std::chrono::steady_clock::now() - handshake_start > kHandshakeTimeout)
                    throw std::runtime_error("TLS handshake timed out (30s)");

                auto timer_wait = [&]() -> asio::awaitable<void>
                {
                    handshake_timer_->expires_after(kHandshakeRetransmitInterval);
                    co_await handshake_timer_->async_wait(asio::use_awaitable);
                };

                auto result = co_await (transport_->Receive() || timer_wait());

                if (result.index() == 0)
                {
                    auto &data = std::get<0>(result);
                    if (!data.empty())
                        co_await ProcessServerPacket(std::move(data));
                }
                else
                {
                    auto retransmits = control_channel_->ProcessRetransmissions();
                    for (auto &pkt : retransmits)
                    {
                        co_await SendWrappedPacket(std::move(pkt));
                        logger_->debug("Retransmitted control packet");
                    }
                }
            }
            else
            {
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
        if (*running_ && state_ != VpnClientState::Reconnecting)
        {
            SetState(VpnClientState::Reconnecting);
            asio::co_spawn(*io_context_, ReconnectLoop(), asio::detached);
        }
        else
        {
            SetState(VpnClientState::Error);
        }
    }
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::ReconnectLoop()
{
    const int max_attempts = config_->client->max_reconnect_attempts;

    while (max_attempts == 0 || reconnect_attempts_ < max_attempts)
    {
        ++reconnect_attempts_;
        logger_->info("Reconnecting (attempt {}/{})",
                      reconnect_attempts_,
                      max_attempts == 0 ? std::string("unlimited") : std::to_string(max_attempts));

        Disconnect();

        asio::steady_timer timer(*io_context_);
        timer.expires_after(std::chrono::seconds(config_->client->reconnect_delay_seconds));
        co_await timer.async_wait(asio::use_awaitable);

        try
        {
            Connect();
            co_return;
        }
        catch (const std::exception &e)
        {
            logger_->error("Reconnect attempt {} failed: {}", reconnect_attempts_, e.what());
            SetState(VpnClientState::Reconnecting);
        }
    }

    logger_->error("Max reconnect attempts ({}) reached", max_attempts);
    SetState(VpnClientState::Error);
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::SendHardReset()
{
    const bool v2_mode = !tls_crypt_v2_wkc_.empty();
    const int reset_version = v2_mode ? 3 : 2;

    logger_->debug("Sending HARD_RESET_CLIENT_V{}", reset_version);
    std::uint32_t pkt_id = control_channel_->GetNextPacketId();

    auto packet = openvpn::OpenVpnPacket::HardReset(
        true, reset_version, key_id_, local_session_id_, pkt_id);

    auto serialized = packet.Serialize();

    if (tls_crypt_)
    {
        auto wrapped = tls_crypt_->Wrap(serialized, false);
        if (!wrapped)
        {
            logger_->error("Failed to wrap hard reset");
            SetState(VpnClientState::Error);
            co_return;
        }
        serialized = std::move(*wrapped);
    }

    if (v2_mode)
        serialized.insert(serialized.end(), tls_crypt_v2_wkc_.begin(), tls_crypt_v2_wkc_.end());

    co_await SendRawPacket(serialized);
    SetState(VpnClientState::TlsHandshake);
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::ProcessServerPacket(std::vector<std::uint8_t> data)
{
    if (data.empty())
        co_return;

    TouchLastRx();

    auto packet = UnwrapAndParse(data, tls_crypt_, openvpn::PeerRole::Client, *logger_);
    if (!packet)
        co_return;

    if (openvpn::IsDataPacket(packet->opcode_))
        co_await HandleDataPacket(*packet);
    else
        co_await HandleControlPacket(*packet);
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::HandleControlPacket(const openvpn::OpenVpnPacket &packet)
{
    logger_->debug("Control packet: opcode={}", static_cast<int>(packet.opcode_));

    if (packet.opcode_ == openvpn::Opcode::P_CONTROL_HARD_RESET_SERVER_V2
        || packet.opcode_ == openvpn::Opcode::P_CONTROL_HARD_RESET_SERVER_V3)
    {
        remote_session_id_ = packet.session_id_.value_or(0);
        control_channel_->HandleHardReset(packet);

        auto ack = control_channel_->GenerateExplicitAck();
        if (!ack.empty())
            co_await SendWrappedPacket(std::move(ack));

        SetState(VpnClientState::TlsHandshake);
        auto client_hello = control_channel_->InitiateTlsHandshake();
        if (client_hello && !client_hello->empty())
            co_await SendWrappedPacket(std::move(*client_hello));

        co_await FlushControlQueue(*control_channel_,
                                   tls_crypt_,
                                   openvpn::PeerRole::Client,
                                   *transport_,
                                   *logger_);
        co_return;
    }

    SessionControlCallbacks callbacks{
        .on_soft_reset = [this](const openvpn::OpenVpnPacket &pkt) -> asio::awaitable<void>
    {
        co_await HandleSoftResetFromServer(pkt);
    },
        .on_plaintext = [this](std::vector<std::uint8_t> plaintext) -> asio::awaitable<void>
    {
        co_await ProcessReceivedPlaintext(std::move(plaintext));
    },
        .on_handshake_complete = [this]() -> asio::awaitable<void>
    {
        if (client_random_.empty())
            co_await ProcessTlsHandshake();
    },
    };

    co_await DispatchSessionControlPacket(*control_channel_,
                                          tls_crypt_,
                                          openvpn::PeerRole::Client,
                                          *transport_,
                                          packet,
                                          *logger_,
                                          callbacks);
}

template <typename Derived>
asio::awaitable<void>
ClientControlAdapter<Derived>::HandleSoftResetFromServer(const openvpn::OpenVpnPacket &packet)
{
    logger_->info("Received soft reset from server — starting key renegotiation");
    last_server_rekey_at_ = std::chrono::steady_clock::now();

    openvpn::TlsCertConfig cert_config{
        .ca_cert = config_->client->ca_cert.string(),
        .local_cert = config_->client->cert.string(),
        .local_key = config_->client->key.string(),
        .ca_cert_pem = config_->client->ca_cert_pem,
        .local_cert_pem = config_->client->cert_pem,
        .local_key_pem = config_->client->key_pem};

    auto response = control_channel_->RespondToSoftReset(packet, cert_config);
    if (!response.empty())
        co_await SendWrappedPacket(std::move(response));

    // Reset key exchange state so on_handshake_complete fires for the new session.
    client_random_.clear();
    server_random_.clear();

    // Kick off the new TLS ClientHello.
    auto client_hello = control_channel_->InitiateTlsHandshake();
    if (client_hello && !client_hello->empty())
        co_await SendWrappedPacket(std::move(*client_hello));
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::ClientRekeyLoop(std::uint32_t reneg_seconds,
                                                                     std::uint64_t generation)
{
    asio::steady_timer timer(*io_context_);
    timer.expires_after(std::chrono::seconds(reneg_seconds));
    try
    {
        co_await timer.async_wait(asio::use_awaitable);
    }
    catch (const asio::system_error &)
    {
        rekey_timer_armed_ = false;
        co_return;
    }

    if (!*running_ || state_ != VpnClientState::Connected || rekey_generation_ != generation)
    {
        rekey_timer_armed_ = false;
        co_return;
    }

    // Suppress client-initiated rekey if the server has driven one within the rekey window.
    auto elapsed = std::chrono::steady_clock::now() - last_server_rekey_at_;
    if (elapsed < std::chrono::seconds(reneg_seconds))
    {
        logger_->info("Client rekey suppressed: server rekeyed {}s ago, re-arming in {}s",
                      std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(),
                      reneg_seconds);
        asio::co_spawn(*io_context_, ClientRekeyLoop(reneg_seconds, generation), asio::detached);
        co_return;
    }

    try
    {
        openvpn::TlsCertConfig cert_config{
            .ca_cert = config_->client->ca_cert.string(),
            .local_cert = config_->client->cert.string(),
            .local_key = config_->client->key.string(),
            .ca_cert_pem = config_->client->ca_cert_pem,
            .local_cert_pem = config_->client->cert_pem,
            .local_key_pem = config_->client->key_pem};

        auto soft_reset = control_channel_->RequestSoftReset(openvpn::PeerRole::Client, cert_config);
        if (soft_reset.empty())
        {
            logger_->warn("Client rekey: RequestSoftReset not ready, deferring");
            asio::co_spawn(*io_context_, ClientRekeyLoop(reneg_seconds, generation), asio::detached);
            co_return;
        }

        client_random_.clear();
        server_random_.clear();

        co_await SendWrappedPacket(std::move(soft_reset));
        logger_->debug("Client rekey: sent P_CONTROL_SOFT_RESET_V1");

        // The VPN client is always TLS client — send the ClientHello to start
        // the renegotiation handshake.
        auto client_hello = control_channel_->InitiateTlsHandshake();
        if (client_hello && !client_hello->empty())
            co_await SendWrappedPacket(std::move(*client_hello));
    }
    catch (const std::exception &e)
    {
        logger_->warn("Client rekey: exception: {}", e.what());
    }

    // Rearm for next cycle regardless of outcome.
    asio::co_spawn(*io_context_, ClientRekeyLoop(reneg_seconds, generation), asio::detached);
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::HandleDataPacket(const openvpn::OpenVpnPacket &packet)
{
    auto plaintext = data_channel_->DecryptPacket(packet);
    if (plaintext.empty())
    {
        logger_->warn("Failed to decrypt data packet");
        co_return;
    }

    if (openvpn::IsKeepalivePing(plaintext))
        co_return;

    stats_.packetsDecrypted++;

    co_await derived().DeliverDecryptedPacket(std::move(plaintext));
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::ProcessTlsHandshake()
{
    if (control_channel_->GetState() == openvpn::ControlChannel::State::KeyMaterialReady)
    {
        client_random_.resize(openvpn::CLIENT_KEY_SOURCE_SIZE);
        if (RAND_bytes(client_random_.data(), static_cast<int>(client_random_.size())) != 1)
            throw std::runtime_error("RAND_bytes failed");

        std::string options = BuildKeyMethod2Options(
            openvpn::PeerRole::Client,
            config_->client->proto,
            config_->client->cipher,
            kDefaultTunMtu,
            config_->client->ipv6_only);

        auto peer_info = openvpn::BuildClientPeerInfo("clv-vpncore/1.0.0", effective_data_ciphers_);
        auto key_method_msg = openvpn::BuildKeyMethod2Message(client_random_, options, "", "", peer_info);

        co_await SendTlsControlData(
            *control_channel_, tls_crypt_, std::span<const uint8_t>(key_method_msg), openvpn::PeerRole::Client, *transport_, *logger_, "key-method 2");
    }
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::ProcessReceivedPlaintext(std::vector<std::uint8_t> plaintext)
{
    if (plaintext.empty())
        co_return;

    auto view_len = plaintext.size();
    if (plaintext.back() == 0)
        --view_len;

    std::string_view data_view(reinterpret_cast<const char *>(plaintext.data()), view_len);
    if (data_view.empty())
        co_return;

    if (data_view.starts_with("PUSH_REPLY"))
    {
        co_await HandlePushReply(std::string(data_view.substr(11)));
        co_return;
    }

    if (plaintext.size() > 1 && plaintext[0] == 0x00)
    {
        auto parsed = openvpn::ParseKeyMethod2Message(plaintext, true);
        if (!parsed)
        {
            logger_->error("Failed to parse server key-method 2");
            SetState(VpnClientState::Error);
            co_return;
        }

        auto &[server_random, server_options, username, password, peer_info_ignored] = *parsed;
        server_random_ = std::move(server_random);

        DeriveAndInstallKeys();

        if (state_ == VpnClientState::Connected)
        {
            // Renegotiation — keys are installed; tunnel stays up as-is.
            logger_->info("Rekey complete — new data channel keys installed");
            co_return;
        }

        co_await SendPushRequest();
        SetState(VpnClientState::Authenticating);
        co_return;
    }

    logger_->warn("Unknown plaintext: {} bytes", plaintext.size());
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::SendPushRequest()
{
    std::string push_request = "PUSH_REQUEST";
    std::vector<std::uint8_t> message(push_request.begin(), push_request.end());
    message.push_back(0);

    co_await SendTlsControlData(
        *control_channel_, tls_crypt_, std::span<const std::uint8_t>(message), openvpn::PeerRole::Client, *transport_, *logger_, "PUSH_REQUEST");
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::HandlePushReply(const std::string &reply)
{
    struct Actions
    {
        ClientControlAdapter &self;
        void DeriveAndInstallKeys() { self.DeriveAndInstallKeys(); }
        void ApplyNetworkConfig()   { self.ApplyNegotiatedNetworkConfig(); }
        void MarkConnected()        { self.SetState(VpnClientState::Connected); }
        void ScheduleRekey(std::uint32_t r, std::uint64_t g)
        {
            asio::co_spawn(*self.io_context_, self.ClientRekeyLoop(r, g), asio::detached);
        }
    };

    ClientPushReplyData data{
        .config_exchange            = config_exchange_,
        .allowed_ciphers            = effective_data_ciphers_,
        .current_cipher             = config_->client->cipher,
        .client_renegotiate_seconds = static_cast<std::uint32_t>(config_->client->renegotiate_seconds),
        .negotiated_cipher          = negotiated_cipher_,
        .server_peer_id             = server_peer_id_,
        .is_connected               = (state_ == VpnClientState::Connected),
        .rekey_timer_armed          = rekey_timer_armed_,
        .rekey_generation           = rekey_generation_,
        .logger                     = *logger_,
    };

    Actions actions{*this};
    co_await HandleClientPushReply(reply, data, actions);
}

template <typename Derived>
void ClientControlAdapter<Derived>::ApplyNegotiatedNetworkConfig()
{
    const auto &negotiated = config_exchange_.GetNegotiatedConfig();
    if (negotiated.ifconfig.first.empty())
        throw std::runtime_error("No IP assigned by server");

    auto &ch = derived().channel();
    ch.ConfigureNetworkInterface(negotiated, *config_, *io_context_);
    ch.InstallNegotiatedRoutes(negotiated);
}

template <typename Derived>
void ClientControlAdapter<Derived>::DeriveAndInstallKeys()
{
    const std::string &cipher = negotiated_cipher_.empty() ? config_->client->cipher : negotiated_cipher_;
    auto result = DeriveDataChannelKeys(*control_channel_,
                                        client_random_,
                                        server_random_,
                                        cipher,
                                        openvpn::PeerRole::Client,
                                        *logger_);
    if (!result)
        throw std::runtime_error("DeriveDataChannelKeys failed");

    std::uint8_t current_key_id = control_channel_->GetKeyId();

    derived().channel().InstallDataPathKeys(result->key_material,
                                            result->cipher_algo,
                                            result->hmac_algo,
                                            current_key_id,
                                            *data_channel_);
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::SendWrappedPacket(std::vector<std::uint8_t> data)
{
    co_await WrapAndSend(tls_crypt_, std::move(data), openvpn::PeerRole::Client, *transport_, *logger_);
}

template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::SendRawPacket(std::span<const std::uint8_t> data)
{
    co_await transport_->Send(data);
}

template <typename Derived>
void ClientControlAdapter<Derived>::SetState(VpnClientState new_state)
{
    if (state_ == new_state)
        return;

    auto old_state = state_;
    logger_->info("State: {} -> {}", VpnClientStateToString(old_state), VpnClientStateToString(new_state));
    state_ = new_state;

    if (state_callback_)
        state_callback_(old_state, new_state);

    if (new_state == VpnClientState::Connected)
    {
        reconnect_attempts_ = 0;
        connected_at_ = std::chrono::steady_clock::now();

        if (config_->performance.stats_interval_seconds > 0)
            asio::co_spawn(*io_context_, StatsLoop(), asio::detached);

        StartDataPath();
    }
}

template <typename Derived>
void ClientControlAdapter<Derived>::StartDataPath()
{
    auto &ch = derived().channel();

    try
    {
        ch.AttachTransport(*transport_, transport_->GetPeer(), server_peer_id_);
    }
    catch (const std::exception &e)
    {
        logger_->error("AttachTransport: {}", e.what());
        SetState(VpnClientState::Error);
        return;
    }

    asio::co_spawn(*io_context_, derived().StartDataPath(), asio::detached);

    ch.LaunchKeepalive(*io_context_,
                       [this]()
    { return KeepaliveLoop(); },
                       config_->client->keepalive_interval);

    logger_->info("Data path started");
}

// TODO: OK but not elegant.
template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::KeepaliveLoop()
{
    // Thin session wrapper so the generic KeepaliveLoop can drive the client
    // without knowing about the client/server distinction.
    using tp = std::chrono::steady_clock::time_point;
    struct SelfSession
    {
        Derived &ctrl;
        bool HasValidKeys() const noexcept
        {
            return true;
        }
        tp GetLastActivity() const
        {
            return ctrl.LastRxTime();
        }
        tp GetLastOutbound() const
        {
            return ctrl.LastTxTime();
        }
        void UpdateLastOutbound() noexcept
        {
        } // TX path already updates last_tx_ns_
    };

    return ::clv::vpn::KeepaliveLoop(
        "Client",
        *running_,
        *keepalive_timer_,
        std::chrono::seconds(config_->client->keepalive_interval),
        std::chrono::seconds(config_->client->keepalive_timeout),
        *logger_,
        [this]()
    { return std::array<SelfSession, 1>{SelfSession{derived()}}; },
        [this](SelfSession &)
    { return derived().SendKeepalivePing(); },
        [this](SelfSession &)
    {
        *running_ = false;
        SetState(VpnClientState::Reconnecting);
        asio::co_spawn(*io_context_, ReconnectLoop(), asio::detached);
    });
}

// TODO: This is ugly but it's OK for the moment
template <typename Derived>
asio::awaitable<void> ClientControlAdapter<Derived>::StatsLoop()
{
    auto interval = std::chrono::seconds(config_->performance.stats_interval_seconds);
    DataPathStats previousSnapshot = derived().SnapshotStats();

    while (*running_ && state_ == VpnClientState::Connected)
    {
        stats_timer_->expires_after(interval);
        try
        {
            co_await stats_timer_->async_wait(asio::use_awaitable);
        }
        catch (const asio::system_error &e)
        {
            if (e.code() == asio::error::operation_aborted)
                break;
            throw;
        }

        if (!*running_ || state_ != VpnClientState::Connected)
            break;

        DataPathStats currentSnapshot;
        try
        {
            currentSnapshot = derived().SnapshotStats();
        }
        catch (const std::exception &e)
        {
            logger_->warn("StatsLoop: SnapshotStats threw ({}); skipping interval", e.what());
            continue;
        }
        catch (...)
        {
            logger_->warn("StatsLoop: SnapshotStats threw unknown exception; skipping interval");
            continue;
        }
        auto delta = DataPathStats::Delta(currentSnapshot, previousSnapshot);
        previousSnapshot = currentSnapshot;

        double elapsedSec = static_cast<double>(config_->performance.stats_interval_seconds);
        LogStats(delta, elapsedSec);
    }
}

template <typename Derived>
void ClientControlAdapter<Derived>::LogStats(const DataPathStats &delta, double elapsedSec)
{
    int actualRcvBuf = 0, actualSndBuf = 0;
    if (transport_)
    {
        if (auto *udp = std::get_if<transport::UdpTransport>(&*transport_))
            std::tie(actualRcvBuf, actualSndBuf) = udp->GetSocketBufferSizes();
    }

    decltype(delta.batchHist) batchHist;
    if constexpr (requires { derived().channel().GetRxBatchWindow(); })
    {
        try
        {
            batchHist = derived().channel().GetRxBatchWindow().SnapshotAndReset();
        }
        catch (...)
        {
        }
    }

    auto rxH = FormatBatchHist(batchHist, delta.batchSaturations);
    auto rates = ComputeStatsRates(delta, elapsedSec, actualRcvBuf, actualSndBuf);

    std::string txBstStr = "---";
    if constexpr (requires { derived().channel().GetTxBurstAvgWindow(); })
    {
        try
        {
            auto [bTotal, bCount] = derived().channel().GetTxBurstAvgWindow().SnapshotAndReset();
            txBstStr = FormatAvgBurst(bTotal, bCount);
        }
        catch (...)
        {
        }
    }

    logger_->info("[stats] {:.1f}s: "
                  "rx={} ({:.0f}M) tx={} ({:.0f}M) "
                  "rx{} bst={} "
                  "buf={}/{}ms "
                  "dec={}/{} tun=r{}/w{} serr={} spf={}",
                  elapsedSec,
                  delta.packetsReceived,
                  rates.rxMbps,
                  delta.packetsSent,
                  rates.txMbps,
                  rxH,
                  txBstStr,
                  FormatBufMs(rates.rxBufMs),
                  FormatBufMs(rates.txBufMs),
                  delta.packetsDecrypted,
                  delta.decryptFailures,
                  delta.tunReads,
                  delta.tunWrites,
                  delta.sendErrors,
                  delta.txSmallPktFlush);
}

template <typename Derived>
void ClientControlAdapter<Derived>::InitializeTransport()
{
    transport::ClientConnector connector = (config_->client->proto == "tcp")
                                               ? transport::ClientConnector(transport::TcpConnector(*io_context_))
                                               : transport::ClientConnector(transport::UdpConnector(*io_context_));

    auto transport = connector.Connect(config_->client->server_host,
                                       config_->client->server_port,
                                       false,
                                       config_->client->ipv6_only);
    auto peer = transport.GetPeer();
    logger_->info("Connected via {}: {}:{}",
                  transport.IsTcp() ? "TCP" : "UDP",
                  peer.addr.to_string(),
                  peer.port);
    transport_.emplace(std::move(transport));

    if (auto *udp = std::get_if<transport::UdpTransport>(&*transport_))
    {
        udp->ApplySocketBuffers(config_->performance.socket_recv_buffer,
                                config_->performance.socket_send_buffer,
                                *logger_);
    }
}

template <typename Derived>
bool ClientControlAdapter<Derived>::LoadTlsCryptKey()
{
    // TLS-Crypt-V2 (per-client key) takes priority
    if (!config_->client->tls_crypt_v2_key_pem.empty())
    {
        auto client_key = openvpn::TlsCryptV2::LoadClientKeyString(config_->client->tls_crypt_v2_key_pem, *logger_);
        if (!client_key)
        {
            SetState(VpnClientState::Error);
            return false;
        }
        auto tc = openvpn::TlsCrypt::FromKeyData(client_key->client_key, *logger_);
        if (!tc)
        {
            SetState(VpnClientState::Error);
            return false;
        }
        tls_crypt_.emplace(std::move(*tc));
        tls_crypt_v2_wkc_ = std::move(client_key->wkc_blob);
        return true;
    }

    if (!config_->client->tls_crypt_v2_key.empty())
    {
        auto client_key = openvpn::TlsCryptV2::LoadClientKeyFile(config_->client->tls_crypt_v2_key.string(), *logger_);
        if (!client_key)
        {
            SetState(VpnClientState::Error);
            return false;
        }
        auto tc = openvpn::TlsCrypt::FromKeyData(client_key->client_key, *logger_);
        if (!tc)
        {
            SetState(VpnClientState::Error);
            return false;
        }
        tls_crypt_.emplace(std::move(*tc));
        tls_crypt_v2_wkc_ = std::move(client_key->wkc_blob);
        return true;
    }

    // TLS-Crypt V1
    if (!config_->client->tls_crypt_key_pem.empty())
    {
        auto tc = openvpn::TlsCrypt::FromKeyString(config_->client->tls_crypt_key_pem, *logger_);
        if (!tc)
        {
            SetState(VpnClientState::Error);
            return false;
        }
        tls_crypt_.emplace(std::move(*tc));
    }
    else if (!config_->client->tls_crypt_key.empty())
    {
        auto tc = openvpn::TlsCrypt::FromKeyFile(config_->client->tls_crypt_key.string(), *logger_);
        if (!tc)
        {
            SetState(VpnClientState::Error);
            return false;
        }
        tls_crypt_.emplace(std::move(*tc));
    }
    return true;
}

template <typename Derived>
bool ClientControlAdapter<Derived>::InitializeControlChannel()
{
    openvpn::TlsCertConfig cert_config{
        .ca_cert = config_->client->ca_cert.string(),
        .local_cert = config_->client->cert.string(),
        .local_key = config_->client->key.string(),
        .ca_cert_pem = config_->client->ca_cert_pem,
        .local_cert_pem = config_->client->cert_pem,
        .local_key_pem = config_->client->key_pem};

    openvpn::SessionId session_id{local_session_id_};
    if (!control_channel_->Initialize(openvpn::PeerRole::Client, session_id, cert_config))
    {
        SetState(VpnClientState::Error);
        return false;
    }
    return true;
}

template <typename Derived>
std::chrono::steady_clock::time_point ClientControlAdapter<Derived>::LastRxTime() const
{
    return std::chrono::steady_clock::time_point(
        std::chrono::steady_clock::duration(last_rx_ns_.load(std::memory_order_relaxed)));
}


} // namespace clv::vpn

#endif // CLV_VPN_CLIENT_CONTROL_ADAPTER_H
