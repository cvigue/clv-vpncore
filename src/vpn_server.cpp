// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "vpn_server.h"
#include "data_path_stats.h"
#include "dco_utils.h"
#include "openvpn/data_path_engine.h"
#include "udp_receive_loop.h"
#include "ip_pool_manager.h"
#include "log_subsystems.h"
#include "openvpn/protocol_constants.h"
#include "transport/listener.h"
#include "transport/transport.h"
#include <algorithm>
#include <log_utils.h>
#include "openvpn/connection.h"
#include "openvpn/config_exchange.h"
#include "openvpn/control_channel.h"
#include "openvpn/control_plane_helpers.h"
#include "openvpn/data_channel.h"
#include "openvpn/dco_data_channel.h"
#include "openvpn/packet.h"
#include "openvpn/session_manager.h"
#include "openvpn/tls_context.h"
#include "openvpn/tls_crypt.h"
#include "openvpn/userspace_data_channel.h"
#include "openvpn/vpn_config.h"
#include "spdlog/common.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"     // Required for spdlog::stdout_color_mt()
#include "spdlog/sinks/stdout_color_sinks-inl.h" // Required for template instantiation

#include <stdlib.h>
#include <tun/tun_device.h>

#include "cpu_affinity.h"
#include "transport/udp_batch.h"

#include <sys/uio.h>  // struct iovec for TUN batch writes
#include <sys/wait.h> // waitpid
#include <fcntl.h>    // open, O_WRONLY

#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/udp.hpp>
#include <asio/use_awaitable.hpp>

#include <chrono>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <openssl/rand.h>

#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <variant>
#include <vector>

#include <util/ipv4_utils.h>
#include <util/ipv6_utils.h>

namespace clv::vpn {

namespace {

using std::chrono_literals::operator""s;

std::string DeriveServerIp(const VpnConfig::ServerConfig &srv)
{
    if (!srv.bridge_ip.empty())
        return srv.bridge_ip;

    auto parsed = ipv4::ParseCidr(srv.network);
    if (!parsed)
        throw std::invalid_argument("Invalid server network CIDR: " + srv.network);

    auto [network_addr, prefix_length] = *parsed;
    uint32_t gateway_ip = network_addr + 1; // .1 is typically the gateway
    return ipv4::Ipv4ToString(gateway_ip);
}

std::string DeriveServerIpv6(const VpnConfig::ServerConfig &srv)
{
    auto parsed = ipv6::ParseCidr6(srv.network_v6);
    if (!parsed)
        throw std::invalid_argument("Invalid server IPv6 network CIDR: " + srv.network_v6);

    auto [net_v6, prefix_v6] = *parsed;
    ipv6::Ipv6Address server_v6 = net_v6;
    server_v6[15] += 1;
    return ipv6::Ipv6ToString(server_v6);
}

/// Parse a log level string: accepts spdlog names ("trace","debug","info","warn",
/// "err","critical","off") or numeric strings ("0"=trace .. "6"=off).
spdlog::level::level_enum ParseLogLevel(const std::string &str)
{
    // Try numeric first
    if (!str.empty() && str.find_first_not_of("0123456789") == std::string::npos)
    {
        int n = std::stoi(str);
        if (n >= 0 && n <= static_cast<int>(spdlog::level::off))
            return static_cast<spdlog::level::level_enum>(n);
    }
    // Fall back to spdlog name lookup (returns "off" for unrecognised strings)
    return spdlog::level::from_str(str);
}

} // namespace

VpnServer::VpnServer(asio::io_context &io_context, const VpnConfig &config)
    : io_context_(io_context),
      config_(config),
      listener_(config.server->proto == "tcp"
                    ? transport::ServerListener(transport::TcpListener(io_context, config.server->port))
                    : transport::ServerListener(transport::UdpListener(io_context, config.server->port))),
      logger_(spdlog::stdout_color_mt("vpn_server")),
      data_channel_strategy_(
          (config.performance.enable_dco && dco::IsAvailable()
           && config.server->proto != "tcp")
              ? DataPathEngine(std::in_place_type<DcoDataChannel>,
                               io_context_,
                               std::get<transport::UdpListener>(listener_).RawSocket(),
                               DcoDataChannel::NetworkConfig{
                                   config.server->network,
                                   DeriveServerIp(*config.server),
                                   config.server->network_v6,
                                   static_cast<uint32_t>(std::max(0, config.server->keepalive.first)),
                                   static_cast<uint32_t>(std::max(0, config.server->keepalive.second))},
                               *logger_manager_.GetLogger(logging::Subsystem::dataio),
                               running_)
              : DataPathEngine(std::in_place_type<UserspaceDataChannel>, io_context_,
                               routing_table_, routing_table_v6_, session_manager_, *logger_manager_.GetLogger(logging::Subsystem::dataio), stats_,
                               stats_observer_,
                               transport::EffectiveBatchSize(config.performance.batch_size),
                               static_cast<std::size_t>(std::max(0, config.performance.process_quanta)),
                               config.server->keepalive.first,
                               config.server->keepalive.second,
                               running_)),
      inbound_arena_(config.performance.enable_dco
                         ? 16 // DCO: small buffer for TLS control packets only
                         : transport::EffectiveBatchSize(config.performance.batch_size)),
      cleanup_timer_(io_context),
      stats_timer_(io_context)
{
    currentBatchSize_ = inbound_arena_.BatchSize();
    processQuanta_ = static_cast<std::size_t>(std::max(0, config.performance.process_quanta));

    // Set log level from config (env var VPN_LOG_LEVEL overrides config)
    auto env_level = std::getenv("VPN_LOG_LEVEL");
    spdlog::level::level_enum log_level;
    if (env_level)
    {
        log_level = ParseLogLevel(env_level);
    }
    else
    {
        log_level = ParseLogLevel(config_.logging.verbosity);
    }
    logger_->set_level(log_level);
    logger_manager_.SetDefaultLevel(log_level);

    // Apply per-subsystem level overrides from config (env vars already handled by SubsystemLoggerManager ctor)
    for (const auto &[name, level_str] : config_.logging.subsystem_levels)
    {
        auto subsys = logging::SubsystemFromString(name);
        // Only override if no env var is set for this subsystem
        std::string env_key = "SPDLOG_LEVEL_vpn_" + name;
        if (!std::getenv(env_key.c_str()))
        {
            logger_manager_.SetSubsystemLevel(subsys, ParseLogLevel(level_str));
        }
    }

    // Log which data channel strategy is active
    if (!data_channel_strategy_.RequiresTunDevice())
    {
        logger_->info("Data channel mode: DCO (kernel offload) - ovpn-dco-v2");
    }
    else
    {
        logger_->info("Data channel mode: Userspace (TUN-based)");
        if (config.performance.enable_dco && config.server->proto == "tcp")
        {
            logger_->warn("DCO requested but not available with TCP transport - using userspace mode");
        }
    }

    // Apply socket buffer sizes for UDP listeners.
    if (auto *udp = std::get_if<transport::UdpListener>(&listener_))
    {
        udp->ApplySocketBuffers(config.performance.socket_recv_buffer,
                                config.performance.socket_send_buffer,
                                *logger_);
    }
}

VpnServer::~VpnServer()
{
    Stop();
}

void VpnServer::Start()
{
    if (running_)
    {
        throw std::logic_error("Server already running");
    }

    logger_->info("Starting VPN server on {}:{}", config_.server->host, config_.server->port);
    logger_->info("  cipher={} tun_mtu={} proto={}",
                  config_.server->cipher,
                  config_.server->tun_mtu,
                  config_.server->proto);
    logger_->info("  dco={} socket_recv_buf={} socket_send_buf={} batch_size={} process_quanta={} stats_interval={}s cpu_affinity={}",
                  config_.performance.enable_dco,
                  config_.performance.socket_recv_buffer,
                  config_.performance.socket_send_buffer,
                  EffectiveBatchSize(),
                  processQuanta_,
                  config_.performance.stats_interval_seconds,
                  AffinityModeString(config_.process.cpu_affinity));

    // Pin reactor thread to a CPU core (if configured)
    SetThreadAffinity(config_.process.cpu_affinity, *logger_);

    // Initialize TUN device only if strategy requires it (userspace mode)
    if (data_channel_strategy_.RequiresTunDevice())
    {
        InitializeTunDevice();
    }

    // Initialize IP pool (capped by max_clients)
    const auto max_clients = config_.server->max_clients;
    ip_pool_ = std::make_unique<IpPoolManager>(config_.server->network, true, max_clients);
    logger_->info("IP pool initialized: {} IPv4 addresses available (max_clients={})",
                  ip_pool_->AvailableCount(),
                  max_clients);

    // Initialize IPv6 pool if configured
    if (!config_.server->network_v6.empty())
    {
        ip_pool_->EnableIpv6Pool(config_.server->network_v6, true, max_clients);
        logger_->info("IPv6 pool initialized: {} addresses available ({})",
                      ip_pool_->Ipv6AvailableCount(),
                      config_.server->network_v6);
    }

    // TLS-Crypt is mandatory - reject connections without it
    if (config_.server->tls_crypt_key.empty())
    {
        throw std::runtime_error("TLS-Crypt key is required. This server only supports tls-crypt or tls-crypt-v2. Configure 'tls_crypt_key' in server config.");
    }

    auto tls_crypt = openvpn::TlsCrypt::FromKeyFile(config_.server->tls_crypt_key.string(), *logger_);
    if (!tls_crypt)
    {
        throw std::runtime_error("Failed to load TLS-Crypt key from: " + config_.server->tls_crypt_key.string());
    }

    tls_crypt_ = std::move(*tls_crypt);
    logger_->info("TLS-Crypt enabled with key: {}", config_.server->tls_crypt_key.string());
    logger_->info("Note: Only tls-crypt/tls-crypt-v2 clients are supported. tls-auth and unencrypted connections will be rejected.");


    // Create config exchange
    config_exchange_ = std::make_unique<openvpn::ConfigExchange>();

    // Configure host networking (RAII — reverted on shutdown/destruction)
    ip_forward_guard_.emplace(*logger_);
    if (!config_.server->network_v6.empty())
    {
        ip6_forward_guard_.emplace(*logger_);
    }
    masquerade_guard_.emplace(config_.server->network, *logger_);
    if (!config_.server->network_v6.empty())
    {
        masquerade6_guard_.emplace(config_.server->network_v6, *logger_);
    }

    // SessionManager handles per-client control and data channels

    running_ = true;

    // Start async operations — choose receive loop based on protocol
    if (std::holds_alternative<transport::TcpListener>(listener_))
    {
        asio::co_spawn(io_context_, TcpAcceptLoop(), asio::detached);
    }
    else
    {
        asio::co_spawn(io_context_, UdpReceiveLoop(), asio::detached);
    }
    asio::co_spawn(io_context_, SessionCleanupLoop(), asio::detached);
    asio::co_spawn(io_context_, KeepAliveLoop(), asio::detached);

    // Start TUN receiver via data channel strategy
    if (data_channel_strategy_.RequiresTunDevice())
    {
        asio::co_spawn(io_context_, data_channel_strategy_.StartTunReceiver(), asio::detached);
    }

    logger_->info("VPN server started successfully");

    // Start stats logging if configured
    if (config_.performance.stats_interval_seconds > 0)
    {
        logger_->info("Data-path stats enabled (interval: {}s)", config_.performance.stats_interval_seconds);
        asio::co_spawn(io_context_, StatsLoop(), asio::detached);
    }

    // Log TUN device info only if using userspace mode
    if (data_channel_strategy_.RequiresTunDevice())
    {
        logger_->info("TUN device: {}", data_channel_strategy_.tun_device()->GetName());
    }

    logger_->info("Waiting for client connections...");
}



void VpnServer::Stop()
{
    if (!running_)
        return;

    logger_->info("Stopping VPN server...");

    running_ = false;

    // Cancel periodic timers so their coroutines can exit
    cleanup_timer_.cancel();
    stats_timer_.cancel();
    data_channel_strategy_.StopKeepaliveMonitor();

    // Stop the data channel TUN receiver loop
    data_channel_strategy_.StopTunReceiver();

    // Release all allocated IP addresses
    if (ip_pool_)
    {
        auto session_ids = session_manager_.GetAllSessionIds();
        for (const auto &sid : session_ids)
        {
            ip_pool_->ReleaseIpv4(sid.value);
            ip_pool_->ReleaseIpv6(sid.value);
        }
    }

    // Clear all sessions
    session_manager_.ClearAllSessions();

    // Close listener (UDP socket or TCP acceptor)
    listener_.Close();

    // Revert host networking changes (reverse order of setup)
    masquerade6_guard_.reset();
    masquerade_guard_.reset();
    ip6_forward_guard_.reset();
    ip_forward_guard_.reset();

    // Close TUN device
    data_channel_strategy_.CloseTunDevice();

    logger_->info("VPN server stopped");
}

void VpnServer::InitializeTunDevice()
{
    data_channel_strategy_.CreateTunDevice(io_context_);
    auto *tun = data_channel_strategy_.tun_device();

    // Create TUN device with name from config (or let kernel assign)
    std::string dev_name = config_.server->dev;
    if (dev_name == "tun")
    {
        dev_name = ""; // Let kernel assign tun0, tun1, etc.
    }

    std::string actual_name = tun->Create(dev_name);
    logger_->info("Created TUN device: {}", actual_name);

    // Parse server network (e.g., "10.8.0.0/24") and derive server IP
    std::string server_ip = DeriveServerIp(*config_.server);
    auto parsed = ipv4::ParseCidr(config_.server->network);
    if (!parsed)
    {
        throw std::invalid_argument("Invalid server network CIDR: " + config_.server->network);
    }
    std::uint8_t prefix_len = parsed->second;

    tun->SetAddress(server_ip, prefix_len);
    logger_->info("Set TUN address: {}/{}", server_ip, static_cast<int>(prefix_len));

    tun->SetMtu(config_.server->tun_mtu);

    if (config_.server->tun_txqueuelen > 0)
    {
        tun->SetTxQueueLen(config_.server->tun_txqueuelen);
        logger_->info("Set TUN txqueuelen: {}", config_.server->tun_txqueuelen);
    }

    tun->BringUp();
    logger_->info("TUN device is up");

    // Add IPv6 address to TUN if configured
    if (!config_.server->network_v6.empty())
    {
        auto parsed_v6 = ipv6::ParseCidr6(config_.server->network_v6);
        if (parsed_v6)
        {
            auto prefix_v6 = parsed_v6->second;
            std::string server_v6_str = DeriveServerIpv6(*config_.server);
            tun->AddIpv6Address(server_v6_str, prefix_v6);
            logger_->info("Set TUN IPv6 address: {}/{}", server_v6_str, prefix_v6);
        }
    }
}

asio::awaitable<void> VpnServer::UdpReceiveLoop()
{
    auto &udpListener = std::get<transport::UdpListener>(listener_);
    int socketFd = udpListener.RawSocket().native_handle();

    // Determine TUN fd for synchronous batch writes (userspace mode only)
    int tunFd = -1;
    auto *tun = data_channel_strategy_.tun_device();
    if (data_channel_strategy_.RequiresTunDevice() && tun && tun->IsOpen())
        tunFd = tun->NativeHandle();

    // ---- Data fast-path callback ----
    auto onData = [&](transport::IncomingSlot &slot) -> std::span<std::uint8_t>
    {
        return ProcessInboundDataSlot(slot);
    };

    // ---- Control slow-path callback ----
    auto onControl = [&](transport::IncomingSlot &slot)
    {
        std::vector<std::uint8_t> data(slot.buf, slot.buf + slot.len);
        auto transport = transport::TransportHandle(
            udpListener.TransportFor(slot.sender));
        asio::co_spawn(io_context_,
                       ProcessNetworkPacket(std::move(data),
                                            slot.sender,
                                            std::move(transport)),
                       asio::detached);
    };

    co_await UdpReceiveLoopSkeleton(
        udpListener.RawSocket(),
        socketFd,
        tunFd,
        EffectiveBatchSize(),
        processQuanta_,
        inbound_slots_,
        inbound_arena_,
        stats_,
        stats_observer_,
        data_channel_strategy_.tun_device(),
        io_context_,
        logger_,
        [&]
    { return running_.load(); },
        onData,
        onControl);
}

std::span<std::uint8_t> VpnServer::ProcessInboundDataSlot(transport::IncomingSlot &slot)
{
    Connection::Endpoint ep{
        .addr = slot.sender.addr,
        .port = slot.sender.port};
    auto *session = session_manager_.FindSessionByEndpoint(ep);
    if (!session)
    {
        logger_->warn("Data packet from unknown endpoint {}:{}",
                      slot.sender.addr.to_string(),
                      slot.sender.port);
        return {};
    }

    session->UpdateLastActivity();

    auto ip_data = data_channel_strategy_.DecryptAndStripInPlace(
        session, std::span<std::uint8_t>(slot.buf, slot.len));

    if (ip_data.empty())
    {
        logger_->debug("ProcessInboundDataSlot: decrypt returned empty ({} wire bytes from {}:{})",
                       slot.len,
                       slot.sender.addr.to_string(),
                       slot.sender.port);
    }
    else
    {
        uint8_t ver = ip_data[0] >> 4;
        logger_->debug("ProcessInboundDataSlot: decrypted {} bytes, IPv{} ({} wire bytes)",
                       ip_data.size(),
                       ver,
                       slot.len);
    }

    return ip_data;
}

asio::awaitable<void> VpnServer::TcpAcceptLoop()
{
    auto &tcpListener = std::get<transport::TcpListener>(listener_);
    logger_->info("TCP accept loop started on port {}", tcpListener.LocalPort());

    while (running_)
    {
        try
        {
            auto tcpTransport = co_await tcpListener.AcceptNext();
            auto peer = tcpTransport.GetPeer();
            logger_->info("Accepted TCP connection from {}:{}",
                          peer.addr.to_string(),
                          peer.port);

            // Spawn a per-client receive coroutine
            asio::co_spawn(io_context_,
                           TcpClientReceiveLoop(std::move(tcpTransport)),
                           asio::detached);
        }
        catch (const std::exception &e)
        {
            if (running_)
            {
                logger_->error("TCP accept error: {}", e.what());
            }
        }
    }
}

asio::awaitable<void> VpnServer::TcpClientReceiveLoop(transport::TcpTransport tcpTransport)
{
    auto peer = tcpTransport.GetPeer();
    logger_->debug("TCP client receive loop started for {}:{}",
                   peer.addr.to_string(),
                   peer.port);

    while (running_)
    {
        try
        {
            auto data = co_await tcpTransport.Receive();
            if (data.empty())
            {
                logger_->info("TCP client disconnected (empty read): {}:{}",
                              peer.addr.to_string(),
                              peer.port);
                break;
            }

            logger_->debug("Received TCP packet: {} bytes from {}:{}",
                           data.size(),
                           peer.addr.to_string(),
                           peer.port);

            co_await ProcessNetworkPacket(std::move(data), peer, transport::TransportHandle(tcpTransport));
        }
        catch (const asio::system_error &e)
        {
            if (e.code() == asio::error::eof || e.code() == asio::error::connection_reset)
            {
                logger_->info("TCP client disconnected: {}:{} ({})",
                              peer.addr.to_string(),
                              peer.port,
                              e.what());
            }
            else if (running_)
            {
                logger_->error("TCP receive error from {}:{}: {}",
                               peer.addr.to_string(),
                               peer.port,
                               e.what());
            }
            break;
        }
        catch (const std::exception &e)
        {
            if (running_)
            {
                logger_->error("TCP receive error from {}:{}: {}",
                               peer.addr.to_string(),
                               peer.port,
                               e.what());
            }
            break;
        }
    }

    // Clean up session on disconnect
    Connection::Endpoint ep{.addr = peer.addr, .port = peer.port};
    auto *session = session_manager_.FindSessionByEndpoint(ep);
    if (session)
    {
        auto sid = session->GetSessionId();
        if (ip_pool_)
        {
            ip_pool_->ReleaseIpv4(sid.value);
            ip_pool_->ReleaseIpv6(sid.value);
        }
        routing_table_v6_.RemoveSessionRoutes(sid.value);
        session_manager_.RemoveSession(sid);
        auto sessions_logger = logger_manager_.GetLogger(logging::Subsystem::sessions);
        sessions_logger->info("Cleaned up session on TCP disconnect for {}:{}",
                              peer.addr.to_string(),
                              peer.port);
    }
}

asio::awaitable<void> VpnServer::SessionCleanupLoop()
{
    using namespace std::chrono_literals;
    constexpr auto cleanup_interval = 30s;
    // Match config.server.keepalive[1] (ping-restart timeout) for handshake stall detection
    auto session_timeout = std::chrono::seconds(config_.server->keepalive.second > 0 ? config_.server->keepalive.second : 120);

    while (running_)
    {
        cleanup_timer_.expires_after(cleanup_interval);
        try
        {
            co_await cleanup_timer_.async_wait(asio::use_awaitable);
        }
        catch (const asio::system_error &e)
        {
            if (e.code() == asio::error::operation_aborted)
            {
                break; // Timer cancelled, exit loop
            }
            throw;
        }

        if (!running_)
            break;

        // Only clean up sessions that have NOT completed the TLS handshake
        // (no valid data channel keys). Established sessions are monitored
        // by RunKeepaliveMonitor — userspace polls, DCO gets kernel notifications.
        auto now = std::chrono::steady_clock::now();
        auto session_ids = session_manager_.GetAllSessionIds();
        size_t removed = 0;

        for (const auto &sid : session_ids)
        {
            auto *session = session_manager_.FindSession(sid);
            if (!session)
                continue;

            // Skip established sessions — RunKeepaliveMonitor handles them
            if (session->GetDataChannel().HasValidKeys())
                continue;

            // Stale handshake: no activity within timeout
            if ((now - session->GetLastActivity()) > session_timeout)
            {
                session_manager_.RemoveSession(sid);
                ++removed;
            }
        }

        if (removed > 0)
        {
            auto sessions_logger = logger_manager_.GetLogger(logging::Subsystem::sessions);
            sessions_logger->info("Cleaned up {} stale handshake session(s)", removed);
        }
    }
}

asio::awaitable<void> VpnServer::StatsLoop()
{
    auto interval = std::chrono::seconds(config_.performance.stats_interval_seconds);

    const bool isDco = !data_channel_strategy_.RequiresTunDevice();
    DataPathStats previousSnapshot = data_channel_strategy_.SnapshotStats();

    // Query actual kernel socket buffer sizes once (kernel may double requested value)
    int actualRcvBuf = 0, actualSndBuf = 0;
    if (auto *udp = std::get_if<transport::UdpListener>(&listener_))
    {
        std::tie(actualRcvBuf, actualSndBuf) = udp->GetSocketBufferSizes();
    }

    while (running_)
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

        if (!running_)
            break;

        // Snapshot via the strategy API — works for both userspace and DCO
        auto currentSnapshot = data_channel_strategy_.SnapshotStats();
        auto delta = DataPathStats::Delta(currentSnapshot, previousSnapshot);
        previousSnapshot = currentSnapshot;

        double elapsedSec = static_cast<double>(config_.performance.stats_interval_seconds);
        auto rates = ComputeStatsRates(delta, elapsedSec, actualRcvBuf, actualSndBuf);

        if (isDco)
        {
            // DCO mode: kernel handles batching; show simplified stats
            logger_->info("[stats/dco] {:.1f}s: "
                          "rx={} pkts ({:.1f} Mbps) "
                          "tx={} pkts ({:.1f} Mbps) "
                          "buf_rx={:.0f}ms buf_tx={:.0f}ms "
                          "peers={}",
                          elapsedSec,
                          delta.packetsReceived,
                          rates.rxMbps,
                          delta.packetsSent,
                          rates.txMbps,
                          rates.rxBufMs,
                          rates.txBufMs,
                          session_manager_.GetSessionCount());
        }
        else
        {
            // Userspace mode: per-window batch histograms from the observer
            auto observerDelta = stats_observer_.Elapsed();

            auto rxHistStr = FormatBatchHist(observerDelta.batchHist, delta.batchSaturations);
            auto txHistStr = FormatBatchHist(observerDelta.txBatchHist, delta.txBatchSaturations);

            logger_->info("[stats] {:.1f}s: "
                          "rx={} ({:.0f}M) tx={} ({:.0f}M) "
                          "rx{} tx{} "
                          "buf={:.0f}/{:.0f}ms "
                          "dec={}/{} rmiss={} serr={}",
                          elapsedSec,
                          delta.packetsReceived,
                          rates.rxMbps,
                          delta.packetsSent,
                          rates.txMbps,
                          rxHistStr,
                          txHistStr,
                          rates.rxBufMs,
                          rates.txBufMs,
                          delta.packetsDecrypted,
                          delta.decryptFailures,
                          delta.routeLookupMisses,
                          delta.sendErrors);
        }
    }
}

asio::awaitable<void> VpnServer::KeepAliveLoop()
{
    auto keepalive_logger = logger_manager_.GetLogger(logging::Subsystem::keepalive);

    // Callback invoked by the strategy when a peer is considered dead.
    // Handles session cleanup: release IP, remove routes, remove session.
    auto on_dead_peer = [this, keepalive_logger](openvpn::SessionId sid)
    {
        auto *session = session_manager_.FindSession(sid);
        if (!session)
            return;

        // Release VPN IP back to pool
        if (ip_pool_)
        {
            ip_pool_->ReleaseIpv4(sid.value);
            ip_pool_->ReleaseIpv6(sid.value);
        }

        // Remove routing table entries
        if (auto vpn_ip = session->GetAssignedIpv4())
            routing_table_.RemoveRoute(*vpn_ip, 32);
        routing_table_v6_.RemoveSessionRoutes(sid.value);

        session_manager_.RemoveSession(sid);
        keepalive_logger->info("Peer dead: removed session {}", sid);
    };

    co_await data_channel_strategy_.RunKeepaliveMonitor(on_dead_peer);
}

asio::awaitable<void> VpnServer::HandleControlPacket(Connection *session,
                                                     const openvpn::OpenVpnPacket &packet,
                                                     const transport::PeerEndpoint &sender,
                                                     const Connection::Endpoint &endpoint,
                                                     transport::TransportHandle transport)
{
    logger_->debug("Received control packet (opcode {})", static_cast<int>(packet.opcode_));

    // Hard reset is orchestrator-level — manages session creation.
    if (packet.opcode_ == openvpn::Opcode::P_CONTROL_HARD_RESET_CLIENT_V2 || packet.opcode_ == openvpn::Opcode::P_CONTROL_HARD_RESET_CLIENT_V3)
    {
        session = co_await HandleHardReset(packet, sender, endpoint, std::move(transport));
        co_return; // Hard reset fully handled - no further processing needed
    } // "I can pop these no problem" - 28 Days Later (2002)

    if (session)
    {
        // Update session activity
        session->UpdateLastActivity();
        logger_->debug("HandleControlPacket: Updated last_activity for opcode {}",
                       static_cast<int>(packet.opcode_));

        // Dispatch through shared per-session control-packet handler.
        auto sess_transport = session->GetTransport();
        co_await DispatchSessionControlPacket(
            session->GetControlChannel(), tls_crypt_, /*is_server=*/true, sess_transport, packet, *logger_, {
                                                                                                                .on_soft_reset = [this, session](const openvpn::OpenVpnPacket &pkt) -> asio::awaitable<void>
        {
            co_await HandleSoftReset(session, pkt);
        },
                                                                                                                .on_plaintext = [this, session](std::vector<std::uint8_t> plaintext) -> asio::awaitable<void>
        {
            co_await ProcessPlaintext(session, std::move(plaintext));
        },
                                                                                                                .on_handshake_complete = [this, session]() -> asio::awaitable<void>
        {
            EnsureIpAllocated(session);
            co_return;
        },
                                                                                                            });
    }
    else if (packet.opcode_ != openvpn::Opcode::P_CONTROL_HARD_RESET_CLIENT_V2
             && packet.opcode_ != openvpn::Opcode::P_CONTROL_HARD_RESET_CLIENT_V3)
    {
        // Received control packet without active session (other than hard reset)
        logger_->warn("Received control packet without active session");
    } // "Ooo Baracuda" - Heart, Baracuda (1977)

    co_return;
}

asio::awaitable<Connection *> VpnServer::HandleHardReset(const openvpn::OpenVpnPacket &packet,
                                                         const transport::PeerEndpoint &sender,
                                                         const Connection::Endpoint &endpoint,
                                                         transport::TransportHandle transport)
{
    logger_->info("Client initiating handshake from {}:{}",
                  sender.addr.to_string(),
                  sender.port);

    // Client must provide a session ID
    if (!packet.session_id_)
    {
        logger_->warn("Hard reset missing session ID from client");
        co_return nullptr;
    }

    openvpn::SessionId client_session_id{packet.session_id_.value()};

    // Check if we already have a session for this endpoint (retransmission handling)
    Connection *session = session_manager_.FindSessionByEndpoint(endpoint);
    if (session)
    {
        // Check if this is the same client session ID
        auto peer_session = session->GetControlChannel().GetPeerSessionId();
        if (peer_session && peer_session->value == client_session_id.value)
        {
            logger_->debug("Hard reset retransmission from existing session, resending response");
            // Regenerate hard reset response for retransmitted request
            auto hard_reset_response = session->GetControlChannel().GenerateHardResetResponse(packet.opcode_);
            if (!hard_reset_response.empty())
            {
                co_await SendWrappedPacket(std::move(hard_reset_response), session);
                logger_->debug("Resent hard reset server response");
            }
            co_return session;
        }
        else
        {
            // Different client session ID - client is reconnecting, remove old session
            logger_->info("New client session ID, replacing existing session");
            session_manager_.RemoveSession(session->GetSessionId());
            session = nullptr;
        }
    }

    // Generate a new SERVER session ID for new connection
    openvpn::SessionId server_session_id = openvpn::SessionId::Generate();

    logger_->debug("Client session ID: {:016x}, Server session ID: {:016x}",
                   client_session_id.value,
                   server_session_id.value);

    // Prepare TLS certificate configuration
    openvpn::TlsCertConfig cert_config{
        .ca_cert = config_.server->ca_cert,
        .local_cert = config_.server->cert,
        .local_key = config_.server->key};

    // Create fresh session with SERVER session ID
    session = &session_manager_.GetOrCreateSession(server_session_id, endpoint, true, cert_config, *logger_);

    // Assign transport handle for this session (passed in from receive loop)
    session->SetTransport(std::move(transport));

    // Handle hard reset in control channel - stores client's session ID as peer_session_id_
    if (session->GetControlChannel().HandleHardReset(packet))
    {
        // Send hard reset server response (empty payload) to complete handshake initiation
        auto hard_reset_response = session->GetControlChannel().GenerateHardResetResponse(packet.opcode_);

        if (!hard_reset_response.empty())
        {
            co_await SendWrappedPacket(std::move(hard_reset_response), session);
            logger_->debug("Sent hard reset server response");
        }
    }

    logger_->info("Created/updated session {:016x}", server_session_id.value);
    co_return session;
}

asio::awaitable<void> VpnServer::HandleSoftReset(Connection *session,
                                                 const openvpn::OpenVpnPacket &packet)
{
    logger_->info("Received soft reset (key renegotiation) request");

    // Store the old key_id before soft reset (for future key transition grace period)
    [[maybe_unused]] std::uint8_t old_key_id = session->GetControlChannel().GetKeyId();

    // Create TLS certificate configuration for new handshake
    openvpn::TlsCertConfig cert_config{
        .ca_cert = config_.server->ca_cert,
        .local_cert = config_.server->cert,
        .local_key = config_.server->key};

    // Handle soft reset - this transitions to TlsHandshake state
    auto response = session->GetControlChannel().HandleSoftReset(packet, cert_config);
    if (!response.empty())
    {
        co_await SendWrappedPacket(std::move(response), session);
        logger_->debug("Sent soft reset ACK");

        // Reset session state for new key exchange
        // The key-method 2 exchange needs to happen again after soft reset TLS completes
        session->SetSentKeyMethod2(false);
        session->SetClientRandom({});
        session->SetServerRandom({});
        logger_->debug("Reset session state for key renegotiation");
    }
    else
    {
        logger_->error("Failed to handle soft reset");
    }

    co_return;
}

asio::awaitable<void> VpnServer::ProcessPlaintext(Connection *session,
                                                  std::vector<std::uint8_t> plaintext)
{
    logger_->debug("Received plaintext from client: {} bytes", plaintext.size());

    // First plaintext after handshake is key-method 2 exchange
    if (!session->HasSentKeyMethod2())
    {
        co_await HandleKeyMethod2(session, plaintext);
    }
    else
    {
        // Key-method 2 complete - handle application control messages
        std::string_view msg(reinterpret_cast<const char *>(plaintext.data()), plaintext.size());
        // Remove null terminator if present
        if (!msg.empty() && msg.back() == '\0')
            msg.remove_suffix(1);

        logger_->debug("Received control message: {}", msg);

        if (msg == "PUSH_REQUEST")
        {
            co_await HandlePushRequest(session);
        }
        else
        {
            logger_->warn("Unhandled control message: {}", msg);
        }
    }

    // Ensure IP is allocated after handshake completion
    EnsureIpAllocated(session);

    co_return;
}

asio::awaitable<void> VpnServer::HandleKeyMethod2(Connection *session,
                                                  const std::vector<uint8_t> &plaintext)
{
    // Parse client's key-method 2 message
    logger_->trace("About to parse key-method 2 message...");
    auto parsed = openvpn::ParseKeyMethod2Message(plaintext);
    logger_->trace("Parse returned, has_value={}", parsed.has_value());
    if (!parsed)
    {
        if (logger_->should_log(spdlog::level::trace))
        {
            logger_->error("Failed to parse client key-method 2 message. Raw data ({} bytes): {}",
                           plaintext.size(),
                           HexDump(plaintext, 20));
        }
        else
        {
            logger_->error("Failed to parse client key-method 2 message ({} bytes)", plaintext.size());
        }
        co_return;
    }

    auto &[client_random, client_options, username, password] = *parsed;
    logger_->debug("Parsed client key-method 2:");
    logger_->debug("  Random: {} bytes", client_random.size());
    logger_->debug("  Options: {}", client_options);
    logger_->debug("  Username: {}", username);

    // Store client random for key derivation
    session->SetClientRandom(client_random);

    // Generate server random data: 32 bytes random1 + 32 bytes random2
    std::vector<uint8_t> server_random(openvpn::SERVER_KEY_SOURCE_SIZE);
    if (RAND_bytes(server_random.data(), static_cast<int>(server_random.size())) != 1)
        throw std::runtime_error("RAND_bytes failed generating server random");

    // Build options string for key-method 2
    std::string options = BuildKeyMethod2Options(
        /*is_server=*/true,
        config_.server->proto,
        config_.server->cipher,
        config_.server->tun_mtu);

    // Build and send key-method 2 message
    auto key_method_msg = openvpn::BuildKeyMethod2Message(server_random, options, "", "");

    logger_->trace("Built server key-method 2 message: {} bytes", key_method_msg.size());

    // Ensure VPN IPs are allocated BEFORE creating the DCO peer.
    // DeriveAndInstallKeys → InstallKeys → CreateDcoPeer registers the peer's VPN
    // addresses with the kernel.  In MP mode the kernel uses those addresses to
    // route reply packets back to the correct peer.  If we defer allocation to
    // after peer creation, the kernel peer has no VPN IPs and replies are dropped.
    //
    // This can happen when the TLS Finished and key-method-2 arrive in the same
    // control packet: on_plaintext fires (not on_handshake_complete), so the
    // EnsureIpAllocated in on_handshake_complete is skipped.
    EnsureIpAllocated(session);

    // Install decrypt (and encrypt) keys BEFORE sending the key-method 2 response.
    // The co_await below yields to the event loop, during which the DCO client may
    // already be sending data packets with the new key_id.  By installing keys first
    // we close the renegotiation window that previously caused "no key found" errors.
    session->SetServerRandom(server_random);
    if (DeriveAndInstallKeys(session))
    {
        logger_->info("Key-method 2 exchange complete, keys derived and installed");
    }
    else
    {
        logger_->error("Key-method 2 exchange complete but key derivation failed");
    }

    if (co_await SendTlsControlData(session, key_method_msg, "server key-method 2"))
    {
        session->SetSentKeyMethod2(true);
    }

    co_return;
}

asio::awaitable<void> VpnServer::HandlePushRequest(Connection *session)
{
    logger_->info("Client sent PUSH_REQUEST, sending PUSH_REPLY");

    // Keys should already be installed right after key-method 2 exchange
    // Just verify they exist
    if (!session->GetDataChannel().HasValidKeys())
    {
        logger_->warn("PUSH_REQUEST received but keys not yet installed - attempting key derivation");
        if (session->GetClientRandom().size() > 0 && session->GetServerRandom().size() > 0)
        {
            DeriveAndInstallKeys(session);
        }
        else
        {
            logger_->error("Cannot derive keys - missing random data");
        }
    }

    // Build negotiated configuration for this session
    openvpn::NegotiatedConfig push_config;

    // Derive server IP once for use in ifconfig and route-gateway
    std::string server_ip = DeriveServerIp(*config_.server);

    // ifconfig (assigned IPv4 and gateway)
    if (session->GetAssignedIpv4())
    {
        push_config.ifconfig = {ipv4::Ipv4ToString(session->GetAssignedIpv4().value()), server_ip};
    }
    else
    {
        logger_->error("No IP assigned to session - IP pool exhausted or not initialized");
        throw std::runtime_error("Failed to allocate IP for client session");
    }

    // ifconfig-ipv6
    if (session->GetAssignedIpv6())
    {
        auto parsed_v6 = ipv6::ParseCidr6(config_.server->network_v6);
        if (parsed_v6)
        {
            auto prefix_v6 = parsed_v6->second;
            std::string ipv6_str = ipv6::Ipv6ToString(session->GetAssignedIpv6().value());
            std::string server_v6_str = DeriveServerIpv6(*config_.server);
            push_config.ifconfig_ipv6 = {ipv6_str + "/" + std::to_string(prefix_v6)
                                             + " " + server_v6_str,
                                         0};
            logger_->debug("Pushing IPv6 config: {} -> server {}", ipv6_str, server_v6_str);
        }
    }

    push_config.topology = "net30";
    push_config.route_gateway = server_ip;

    // When client_to_client is enabled, inject the tunnel subnet as a pushed route
    // so clients can reach each other directly through the VPN.
    if (config_.server->client_to_client && config_.server->push_routes)
    {
        auto parsed_net = ipv4::ParseCidr(config_.server->network);
        if (parsed_net)
        {
            auto [net_addr, prefix_len] = *parsed_net;
            std::string net_str = ipv4::Ipv4ToString(net_addr);
            std::string mask_str = ipv4::Ipv4ToString(ipv4::CreateMask(prefix_len));
            push_config.routes.push_back({net_str, mask_str, 0});
            logger_->debug("Pushing tunnel subnet route (client_to_client): {} {}", net_str, mask_str);
        }
    }

    // Push routes from config
    if (config_.server->push_routes)
    {
        for (const auto &route_cidr : config_.server->routes)
        {
            auto parsed_route = ipv4::ParseCidr(route_cidr);
            if (parsed_route)
            {
                auto [net_addr, prefix_len] = *parsed_route;
                std::string net_str = ipv4::Ipv4ToString(net_addr);
                std::string mask_str = ipv4::Ipv4ToString(ipv4::CreateMask(prefix_len));
                push_config.routes.push_back({net_str, mask_str, 0});
                logger_->debug("Pushing route: {} {}", net_str, mask_str);
            }
            else
            {
                logger_->warn("Invalid route CIDR in config, skipping: {}", route_cidr);
            }
        }

        for (const auto &route_v6 : config_.server->routes_v6)
        {
            auto parsed_v6_route = ipv6::ParseCidr6(route_v6);
            if (parsed_v6_route)
            {
                push_config.routes_ipv6.push_back({route_v6, "", 0});
                logger_->debug("Pushing IPv6 route: {}", route_v6);
            }
            else
            {
                logger_->warn("Invalid IPv6 route CIDR in config, skipping: {}", route_v6);
            }
        }
    }

    // cipher is required
    if (config_.server->cipher.empty())
    {
        throw std::runtime_error("cipher not configured - this is required for data channel encryption");
    }
    push_config.cipher = config_.server->cipher;
    push_config.tun_mtu = static_cast<std::uint16_t>(config_.server->tun_mtu);
    push_config.ping_interval = static_cast<std::uint32_t>(config_.server->keepalive.first);
    push_config.ping_restart = static_cast<std::uint32_t>(config_.server->keepalive.second);

    // peer-id: lower 24 bits of session ID (same algorithm as DcoDataChannel::GetPeerId)
    push_config.peer_id = static_cast<std::int32_t>(
        session->GetSessionId().value & openvpn::PEER_ID_MASK);

    std::string push_reply = openvpn::ConfigExchange::Serialize(push_config);
    logger_->info("PUSH_REPLY: {}", push_reply);

    // Send through TLS (null-terminated)
    std::vector<uint8_t> reply_data(push_reply.begin(), push_reply.end());
    reply_data.push_back(0);
    co_await SendTlsControlData(session, reply_data, "PUSH_REPLY");

    co_return;
}

asio::awaitable<void> VpnServer::HandleDataPacket(Connection *session,
                                                  const openvpn::OpenVpnPacket &packet)
{
    // Update session activity
    auto now = std::chrono::steady_clock::now();
    session->UpdateLastActivity();
    logger_->debug("HandleDataPacket: Updated last_activity, packet_id={}, size={} bytes",
                   packet.packet_id_.value_or(0),
                   packet.payload_.size());

    logger_->debug("Received data packet from client (key_id={}, packet_id={}, {} bytes)",
                   packet.key_id_,
                   packet.packet_id_.value_or(0),
                   packet.payload_.size());

    // Debug: Log AAD hex
    logger_->debug("AAD ({} bytes): {}", packet.aad_.size(), HexDump(packet.aad_, 16, ""));

    // Delegate to data channel strategy
    co_await data_channel_strategy_.ProcessIncomingDataPacket(session, packet);

    co_return;
}

void VpnServer::EnsureIpAllocated(Connection *session)
{
    // Allocate IPv4 if not already assigned
    if (!session->GetAssignedIpv4())
    {
        auto ip_opt = ip_pool_->AllocateIpv4(session->GetSessionId().value);
        if (ip_opt)
        {
            uint32_t assigned_ipv4 = *ip_opt;
            session->SetAssignedIpv4(assigned_ipv4);

            // Add route to routing table
            routing_table_.AddRoute(assigned_ipv4, 32, session->GetSessionId().value);

            logger_->info("Assigned IPv4 {} to session {:016x}",
                          ipv4::Ipv4ToString(assigned_ipv4),
                          session->GetSessionId().value);
        }
        else
        {
            logger_->warn("IP pool exhausted - cannot assign IPv4 to client");
        }
    }

    // Allocate IPv6 if pool is enabled and not already assigned
    if (ip_pool_->HasIpv6Pool() && !session->GetAssignedIpv6())
    {
        auto ipv6_opt = ip_pool_->AllocateIpv6(session->GetSessionId().value);
        if (ipv6_opt)
        {
            session->SetAssignedIpv6(*ipv6_opt);

            // Add /128 host route to IPv6 routing table
            routing_table_v6_.AddRoute(*ipv6_opt, 128, session->GetSessionId().value);

            logger_->info("Assigned IPv6 {} to session {:016x}",
                          ipv6::Ipv6ToString(*ipv6_opt),
                          session->GetSessionId().value);
        }
        else
        {
            logger_->warn("IPv6 pool exhausted - cannot assign IPv6 to client");
        }
    }
}

asio::awaitable<void> VpnServer::ProcessNetworkPacket(std::vector<std::uint8_t> data,
                                                      transport::PeerEndpoint sender,
                                                      transport::TransportHandle transport)
{
    // Unwrap TLS-Crypt (control packets) and parse into OpenVpnPacket.
    auto packet_opt = UnwrapAndParse(data, tls_crypt_, /*is_server=*/true, *logger_);
    if (!packet_opt)
    {
        co_return;
    }

    auto &packet = *packet_opt;

    // Convert PeerEndpoint to Connection::Endpoint
    Connection::Endpoint endpoint{
        .addr = sender.addr,
        .port = sender.port};

    // Find or create session based on endpoint
    // Note: packet.session_id_ is the CLIENT's session ID, not ours
    // We store sessions by SERVER session ID, so look up by endpoint
    Connection *session = session_manager_.FindSessionByEndpoint(endpoint);

    // Ensure session has a transport handle (may be missing if session was just
    // created without one, e.g., on reconnect edge cases)
    if (session && !session->HasTransport())
    {
        session->SetTransport(transport);
    }

    logger_->debug("Session lookup: endpoint={}:{}, found={}",
                   sender.addr.to_string(),
                   sender.port,
                   session != nullptr);

    // Route to appropriate handler based on packet type
    if (openvpn::IsControlPacket(packet.opcode_))
    {
        co_await HandleControlPacket(session, packet, sender, endpoint, std::move(transport));
    }
    else if (openvpn::IsDataPacket(packet.opcode_))
    {
        // Data packet - requires active session
        if (!session)
        {
            logger_->warn("Received data packet without active session");
            co_return;
        }

        co_await HandleDataPacket(session, packet);
    }

    co_return;
}

asio::awaitable<void> VpnServer::SendWrappedPacket(std::vector<std::uint8_t> data,
                                                   Connection *session)
{
    if (!session || !session->HasTransport())
    {
        logger_->error("SendWrappedPacket: session has no transport handle");
        co_return;
    }

    auto transport = session->GetTransport();
    co_await WrapAndSend(tls_crypt_, std::move(data), /*is_server=*/true, transport, *logger_);
    session->UpdateLastOutbound();
}

asio::awaitable<bool> VpnServer::SendTlsControlData(Connection *session,
                                                    std::span<const std::uint8_t> data,
                                                    std::string_view description)
{
    if (!session || !session->HasTransport())
    {
        logger_->error("{}: session has no transport", description);
        co_return false;
    }

    auto transport = session->GetTransport();
    bool ok = co_await clv::vpn::SendTlsControlData(
        session->GetControlChannel(), tls_crypt_, data,
        /*is_server=*/true,
        transport,
        *logger_,
        description);

    if (ok)
        session->UpdateLastOutbound();

    co_return ok;
}

bool VpnServer::DeriveAndInstallKeys(Connection *session)
{
    const auto &client_random = session->GetClientRandom();
    const auto &server_random = session->GetServerRandom();

    auto result = DeriveDataChannelKeys(session->GetControlChannel(),
                                        client_random,
                                        server_random,
                                        config_.server->cipher,
                                        /*is_server=*/true,
                                        *logger_);
    if (!result)
        return false;

    // Get current key_id from control channel
    std::uint8_t current_key_id = session->GetControlChannel().GetKeyId();

    // Delegate key installation to data channel strategy.
    // lame_duck_seconds: >0 = expire after N seconds, 0 = no expiry (lives until next rekey)
    int lame_duck = config_.server->lame_duck_seconds;
    return data_channel_strategy_.InstallKeys(
        session,
        result->key_material,
        result->cipher_algo,
        result->hmac_algo,
        current_key_id,
        lame_duck);
}

} // namespace clv::vpn
