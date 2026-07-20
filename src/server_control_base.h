// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SERVER_CONTROL_BASE_H
#define CLV_VPN_SERVER_CONTROL_BASE_H

/**
 * @file server_control_base.h
 * @brief Shared CRTP base for all server control-side adapters.
 *
 * Contains the full OpenVPN control-protocol engine: session management,
 * TLS handshake dispatch chain, key derivation, IP allocation, routing,
 * keepalive, stats timer, and TLS-Crypt unwrapping.
 *
 * Transport-specific adapters (ServerUdpControlAdapter, ServerTcpControlAdapter)
 * inherit this base and provide Initialize/Start/Stop plus a LogStats hook.
 *
 * CRTP hooks called on Derived (via derived()):
 *   - StopKeepaliveMonitor(), StopDataPath()
 *   - SnapshotStats(), RunKeepaliveMonitor()
 *   - ProcessIncomingDataPacket(), InstallKeys()
 *   - LogStats(delta, elapsedSec)
 *
 * Channel hooks (via derived().channel()) for data-plane setup:
 *   - ConfigureDataPlane(server_config, io_context) → std::string (device name)
 *
 * @tparam Derived  The concrete DataTransport instantiation.
 */

#include "data_path_stats.h"
#include "ip_pool_manager.h"
#include "log_subsystems.h"
#include "openvpn/config_exchange.h"
#include "openvpn/connection.h"
#include "openvpn/control_channel.h"
#include "openvpn/control_plane_helpers.h"
#include "openvpn/crypto_context.h"
#include "openvpn/key_derivation.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/psid_cookie.h"
#include "openvpn/push_exchange_helpers.h"
#include "openvpn/session_manager.h"
#include "openvpn/tls_context.h"
#include "openvpn/tls_crypt.h"
#include "openvpn/tls_crypt_v2.h"
#include "openvpn/vpn_config.h"
#include "routing_table.h"
#include "traffic_policy.h"
#include "tunnel_zone.h"
#include "udp_engine_types.h"
#include "transport/transport.h"

#include <exception>
#include <log_utils.h>
#include <net/ipv4_utils.h>
#include <net/ipv6_utils.h>

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <openssl/rand.h>

#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <future>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace clv::vpn {

namespace ipv4 = clv::net::ipv4;
namespace ipv6 = clv::net::ipv6;

// ---- Shared helpers --------------------------------------------------------

namespace detail {

/**
 * @brief Extract and validate the WKc blob length from a V3 hard reset packet.
 *
 * The WKc blob length is encoded as a big-endian uint16 in the last two bytes
 * of the packet and counts the blob itself (including those two bytes).
 * Returns the validated length, or std::nullopt if the packet is too short,
 * the length field is outside [MIN_WKC_LEN, MAX_WKC_LEN], or the blob would
 * consume the entire packet leaving no prefix.
 */
inline std::optional<std::uint16_t> ExtractV3WKcLength(std::span<const std::uint8_t> data)
{
    if (data.size() < openvpn::TLS_CRYPT_V2_MIN_WKC_LEN + 1)
        return std::nullopt;

    std::uint16_t wkc_len = (static_cast<std::uint16_t>(data[data.size() - 2]) << 8)
                            | static_cast<std::uint16_t>(data[data.size() - 1]);

    if (wkc_len < openvpn::TLS_CRYPT_V2_MIN_WKC_LEN
        || wkc_len > openvpn::TLS_CRYPT_V2_MAX_WKC_LEN
        || wkc_len >= data.size())
        return std::nullopt;

    return wkc_len;
}

} // namespace detail

// ---- Config bundle ---------------------------------------------------------

/**
 * @brief Configuration bundle passed to server control adapters at init.
 *
 * Aggregates the external resources the adapter needs but does not own
 * (io_context, config, loggers, running flag).
 */
struct ServerControlConfig
{
    asio::io_context &io_context;
    const VpnConfig &config;
    logging::SubsystemLoggerManager &logger_manager;
    std::shared_ptr<spdlog::logger> logger;
    std::atomic<bool> &running;
    TunnelZone *zone = nullptr;
};

// ---- Shared CRTP base ------------------------------------------------------

/**
 * @brief Protocol engine shared by all server control adapters.
 *
 * Owns: SessionManager, RoutingTables, IpPoolManager, TlsCrypt/V2,
 * ConfigExchange, UdpEngineContext (nullable), stats counters,
 * timers, and all control-plane dispatch methods.
 */
template <typename Derived>
class ServerControlBase
{
  protected:
    // -- CRTP helpers --------------------------------------------------------
    Derived &derived() noexcept;
    const Derived &derived() const noexcept;
    auto &ch() noexcept;
    const auto &ch() const noexcept;

  public:
    ServerControlBase() = default;

    // -- Accessors (public — used by DataTransport callers) ------------------

    asio::io_context &io_context() noexcept;

    SessionManager &session_manager() noexcept;
    RoutingTableIpv4 &routing_table() noexcept;
    RoutingTableIpv6 &routing_table_v6() noexcept;

    // -- Called from DataAdapter (marshalled to control thread) ---------------

    void HandleDeadPeer(openvpn::SessionId sid);

  protected:
    // -- Two-phase init helper (called by derived Initialize) ----------------

    void InitializeBase(ServerControlConfig cfg);

    // -- Transport-common start/stop helpers ---------------------------------

    void StartBase();

    void StopBase();

    // -- Data plane ----------------------------------------------------------

    void ConfigureDataPlane();

    // -- Supervisory coroutines ----------------------------------------------

    asio::awaitable<void> SessionCleanupLoop();

    asio::awaitable<void> KeepAliveLoop();

    asio::awaitable<void> StatsLoop();

    // -- Control-packet dispatch chain ---------------------------------------

    asio::awaitable<void> ProcessNetworkPacket(std::vector<std::uint8_t> data,
                                               transport::PeerEndpoint sender,
                                               transport::TransportHandle transport);

    [[nodiscard]] bool PsidCookieEnabled() const;

    [[nodiscard]] bool ForceV2Cookie() const;

    asio::awaitable<void> SendCookieChallenge(const openvpn::OpenVpnPacket &client_hr,
                                              openvpn::SessionId client_sid,
                                              openvpn::SessionId server_sid,
                                              const transport::PeerEndpoint &sender,
                                              transport::TransportHandle &transport,
                                              std::optional<openvpn::TlsCrypt> &wrap_key,
                                              bool v2_early_negotiation);

    asio::awaitable<Connection *> TryAcceptCookieSession(
        const openvpn::OpenVpnPacket &packet,
        const transport::PeerEndpoint &sender,
        const Connection::Endpoint &endpoint,
        transport::TransportHandle transport,
        std::optional<openvpn::TlsCrypt> v2_session_key,
        std::optional<openvpn::TlsCryptReplayState> replay_seed);

    asio::awaitable<void> HandleControlPacket(Connection *session,
                                              const openvpn::OpenVpnPacket &packet,
                                              const transport::PeerEndpoint &sender,
                                              const Connection::Endpoint &endpoint,
                                              transport::TransportHandle transport,
                                              std::optional<openvpn::TlsCrypt> v2_session_key,
                                              std::optional<openvpn::TlsCryptReplayState> replay_seed,
                                              bool early_negotiation);

    asio::awaitable<Connection *> HandleHardReset(
        const openvpn::OpenVpnPacket &packet,
        const transport::PeerEndpoint &sender,
        const Connection::Endpoint &endpoint,
        transport::TransportHandle transport,
        std::optional<openvpn::TlsCrypt> v2_session_key,
        std::optional<openvpn::TlsCryptReplayState> replay_seed,
        bool early_negotiation);

    asio::awaitable<void> HandleSoftReset(Connection *session,
                                          const openvpn::OpenVpnPacket &packet);

    asio::awaitable<void> ProcessPlaintext(Connection *session,
                                           std::vector<std::uint8_t> plaintext);

    asio::awaitable<void> HandleKeyMethod2(Connection *session,
                                           const std::vector<uint8_t> &plaintext);

    asio::awaitable<void> HandlePushRequest(Connection *session);

    void DisarmRekeyTimer(openvpn::SessionId sid);

    void RearmRekeyTimer(openvpn::SessionId sid, std::uint32_t reneg_seconds);

    // -- Per-session rekey timer ------------------------------------------

    asio::awaitable<void> RekeyLoop(openvpn::SessionId sid, std::uint32_t reneg_seconds);

    asio::awaitable<void> HandleDataPacket(Connection *session,
                                           const openvpn::OpenVpnPacket &packet);

    // -- Session / key helpers -----------------------------------------------

    void EnsureIpAllocated(Connection *session);

    bool DeriveAndInstallKeys(Connection *session);

    asio::awaitable<void> SendWrappedPacket(std::vector<std::uint8_t> data,
                                            Connection *session);

    asio::awaitable<bool> SendTlsControlData(Connection *session,
                                             std::span<const std::uint8_t> data,
                                             std::string_view description);

    // -- Split-datapath helpers (null-safe — no-op when split_ctx_ is null) --

    void SplitPublishRoutes();

    void SplitPublishSessions();

    // Publish the RX decrypt snapshot immediately after key derivation.
    // TX snapshot is NOT updated here — TX stays on the old key until
    // SplitPublishSessions() is called after the client ACKs KEY_METHOD_2.
    void SplitPublishSessionsRx();

    void RemoveSessionSafe(openvpn::SessionId sid);

    // -- State ---------------------------------------------------------------

    asio::io_context *io_context_ = nullptr;
    const VpnConfig *config_ = nullptr;
    logging::SubsystemLoggerManager *logger_manager_ = nullptr;
    std::shared_ptr<spdlog::logger> logger_;
    std::atomic<bool> *running_ = nullptr;

    SessionManager session_manager_;
    RoutingTableIpv4 routing_table_;
    RoutingTableIpv6 routing_table_v6_;
    std::unique_ptr<IpPoolManager> ip_pool_;
    std::unique_ptr<openvpn::ConfigExchange> config_exchange_;
    std::optional<openvpn::TlsCrypt> tls_crypt_;
    std::optional<openvpn::TlsCryptV2> tls_crypt_v2_;
    std::optional<openvpn::PsidCookieKey> psid_cookie_key_;

    DataPathStats::RxCounters rx_counters_{};
    DataPathStats::TxCounters tx_counters_{};

    std::unique_ptr<UdpEngineContext> split_ctx_;
    std::optional<asio::steady_timer> cleanup_timer_;
    std::optional<asio::steady_timer> stats_timer_;
    std::future<void> cleanup_future_;
    std::future<void> keepalive_future_;
    std::future<void> stats_future_;

    TunnelZone *zone_ = nullptr;
    std::optional<std::string> registered_hub_ifname_;

  private:
    void LoadTlsCryptKeys();
};

// =============================================================================
// ServerControlBase — out-of-line member function definitions
// =============================================================================

template <typename Derived>
Derived &ServerControlBase<Derived>::derived() noexcept
{
    return static_cast<Derived &>(*this);
}

template <typename Derived>
const Derived &ServerControlBase<Derived>::derived() const noexcept
{
    return static_cast<const Derived &>(*this);
}

template <typename Derived>
auto &ServerControlBase<Derived>::ch() noexcept
{
    return derived().channel();
}

template <typename Derived>
const auto &ServerControlBase<Derived>::ch() const noexcept
{
    return derived().channel();
}

template <typename Derived>
asio::io_context &ServerControlBase<Derived>::io_context() noexcept
{
    return *io_context_;
}

template <typename Derived>
SessionManager &ServerControlBase<Derived>::session_manager() noexcept
{
    return session_manager_;
}

template <typename Derived>
RoutingTableIpv4 &ServerControlBase<Derived>::routing_table() noexcept
{
    return routing_table_;
}

template <typename Derived>
RoutingTableIpv6 &ServerControlBase<Derived>::routing_table_v6() noexcept
{
    return routing_table_v6_;
}

template <typename Derived>
void ServerControlBase<Derived>::HandleDeadPeer(openvpn::SessionId sid)
{
    auto &keepalive_logger = logger_manager_->GetLogger(logging::Subsystem::keepalive);

    auto *session = session_manager_.FindSession(sid);
    if (!session)
        return;

    if (ip_pool_)
    {
        ip_pool_->ReleaseIpv4(sid.value);
        ip_pool_->ReleaseIpv6(sid.value);
    }

    if (auto vpn_ip = session->GetAssignedIpv4())
        routing_table_.RemoveRoute(*vpn_ip, 32);
    routing_table_v6_.RemoveSessionRoutes(sid.value);

    RemoveSessionSafe(sid);
    SplitPublishRoutes();
    SplitPublishSessions();
    keepalive_logger.info("Peer dead: removed session {}", sid);
}

template <typename Derived>
void ServerControlBase<Derived>::InitializeBase(ServerControlConfig cfg)
{
    io_context_ = &cfg.io_context;
    config_ = &cfg.config;
    logger_manager_ = &cfg.logger_manager;
    logger_ = std::move(cfg.logger);
    running_ = &cfg.running;
    zone_ = cfg.zone;

    const auto &server_cfg = *config_->server;

    // IP pool
    const auto max_clients = server_cfg.max_clients;
    ip_pool_ = std::make_unique<IpPoolManager>(server_cfg.network, true, max_clients);
    if (!server_cfg.network_v6.empty())
    {
        ip_pool_->EnableIpv6Pool(server_cfg.network_v6, true, max_clients);
    }

    // TLS-Crypt keys
    LoadTlsCryptKeys();

    // Psid cookie HMAC key (UDP DoS defense; unused when psid_cookie is off)
    if (server_cfg.psid_cookie)
        psid_cookie_key_ = openvpn::PsidCookieKey::Generate();

    // Config exchange
    config_exchange_ = std::make_unique<openvpn::ConfigExchange>();

    // Timers
    cleanup_timer_.emplace(*io_context_);
    stats_timer_.emplace(*io_context_);
}

template <typename Derived>
void ServerControlBase<Derived>::StartBase()
{
    cleanup_future_ = asio::co_spawn(*io_context_, SessionCleanupLoop(), asio::use_future);
    keepalive_future_ = asio::co_spawn(*io_context_, KeepAliveLoop(), asio::use_future);

    if (config_->performance.stats_interval_seconds > 0)
    {
        logger_->info("Data-path stats enabled (interval: {}s)",
                      config_->performance.stats_interval_seconds);
        stats_future_ = asio::co_spawn(*io_context_, StatsLoop(), asio::use_future);
    }
}

template <typename Derived>
void ServerControlBase<Derived>::StopBase()
{
    using WorkGuard = asio::executor_work_guard<asio::io_context::executor_type>;
    std::optional<WorkGuard> work_guard;
    if (split_ctx_)
        work_guard.emplace(io_context_->get_executor());

    if (zone_ && registered_hub_ifname_)
    {
        zone_->UnregisterHubAttachment(*registered_hub_ifname_);
        registered_hub_ifname_.reset();
    }

    // Cancel rekey timers FIRST so their operation_aborted completions are
    // queued before the supervisory-loop cancellations.  The io_context
    // processes completions in FIFO order.
    session_manager_.CancelAllRekeyTimers();
    cleanup_timer_->cancel();
    stats_timer_->cancel();
    derived().StopKeepaliveMonitor();
    derived().StopDataPath(); // channel owns teardown, incl. TUN close if applicable

    // Wait for supervisory coroutines to finish: all stop signals are issued above
    if (cleanup_future_.valid())
        cleanup_future_.get();
    if (keepalive_future_.valid())
        keepalive_future_.get();
    if (stats_future_.valid())
        stats_future_.get();

    // Release all IPs
    if (ip_pool_)
    {
        auto session_ids = session_manager_.GetAllSessionIds();
        for (const auto &sid : session_ids)
        {
            ip_pool_->ReleaseIpv4(sid.value);
            ip_pool_->ReleaseIpv6(sid.value);
        }
    }
    session_manager_.ClearAllSessions();

    if (split_ctx_)
    {
        std::promise<void> done;
        auto fut = done.get_future();
        // Move the work guard into the lambda: it is released on the IO thread
        // after ForceReclaimAll() completes, allowing run() to finish naturally.
        asio::dispatch(*io_context_,
                       [ctx = split_ctx_.get(), wg = std::move(*work_guard), &done]() mutable
        {
            ctx->ForceReclaimAll();
            wg.reset();
            done.set_value();
        });
        work_guard.reset(); // already moved; make optional empty
        fut.wait();
    }
    split_ctx_.reset();
}

template <typename Derived>
void ServerControlBase<Derived>::ConfigureDataPlane()
{
    std::string dev = derived().channel().ConfigureDataPlane(*config_->server, *io_context_);
    if (dev.empty())
        return;

    logger_->info("Data plane ready: {}", dev);
    if (!zone_)
        return;

    zone_->RegisterHubAttachment(BuildHubAttachmentSpec(*config_->server, dev));
    registered_hub_ifname_ = dev;
}

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::SessionCleanupLoop()
{
    using namespace std::chrono_literals;
    constexpr auto cleanup_interval = 30s;
    auto session_timeout = std::chrono::seconds(
        config_->server->keepalive.second > 0 ? config_->server->keepalive.second : 120);

    while (*running_)
    {
        cleanup_timer_->expires_after(cleanup_interval);
        try
        {
            co_await cleanup_timer_->async_wait(asio::use_awaitable);
        }
        catch (const asio::system_error &e)
        {
            if (e.code() == asio::error::operation_aborted)
                break;
            throw;
        }
        if (!*running_)
            break;

        auto now = std::chrono::steady_clock::now();
        auto session_ids = session_manager_.GetAllSessionIds();
        size_t removed = 0;

        for (const auto &sid : session_ids)
        {
            auto *session = session_manager_.FindSession(sid);
            if (!session)
                continue;
            if (session->GetCryptoContext().HasValidKeys())
                continue;
            if ((now - session->GetLastActivity()) > session_timeout)
            {
                RemoveSessionSafe(sid);
                ++removed;
            }
        }

        if (removed > 0)
        {
            auto &sessions_logger = logger_manager_->GetLogger(logging::Subsystem::sessions);
            sessions_logger.info("Cleaned up {} stale handshake session(s)", removed);
        }
    }
}

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::KeepAliveLoop()
{
    co_await derived().RunKeepaliveMonitor();
}

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::StatsLoop()
{
    auto interval = std::chrono::seconds(config_->performance.stats_interval_seconds);
    DataPathStats previousSnapshot = derived().SnapshotStats();

    while (*running_)
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
        if (!*running_)
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

        // CRTP hook — each transport adapter formats its own stats line
        derived().LogStats(delta, elapsedSec);
    }
}

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::ProcessNetworkPacket(std::vector<std::uint8_t> data,
                                                                       transport::PeerEndpoint sender,
                                                                       transport::TransportHandle transport)
{
    if (data.empty())
        co_return;

    openvpn::Opcode raw_opcode = openvpn::GetOpcode(data[0]);

    Connection::Endpoint endpoint{.addr = sender.addr, .port = sender.port};

    // V2 hard-reset / WKc-resend: extract WKc, derive per-session key
    std::optional<openvpn::TlsCrypt> v2_session_key;
    const bool needs_wkc = tls_crypt_v2_
                           && (raw_opcode == openvpn::Opcode::P_CONTROL_HARD_RESET_CLIENT_V3
                               || raw_opcode == openvpn::Opcode::P_CONTROL_WKC_V1);
    if (needs_wkc)
    {
        auto wkc_len_opt = detail::ExtractV3WKcLength(data);
        if (!wkc_len_opt)
        {
            logger_->warn("V2 WKc packet: too short or invalid WKc length (opcode={}, packet={} bytes)",
                          static_cast<int>(raw_opcode),
                          data.size());
            co_return;
        }
        std::uint16_t wkc_len = *wkc_len_opt;

        std::size_t split = data.size() - wkc_len;
        std::vector<std::uint8_t> wkc_blob(data.begin() + split, data.end());
        data.resize(split);

        auto unwrap_result = tls_crypt_v2_->UnwrapClientKey(wkc_blob);
        if (!unwrap_result)
        {
            logger_->warn("V2 WKc unwrap failed (opcode={})", static_cast<int>(raw_opcode));
            co_return;
        }

        auto tls_crypt_opt = openvpn::TlsCrypt::FromKeyData(unwrap_result->client_key, *logger_);
        if (!tls_crypt_opt)
        {
            logger_->error("Failed to construct TlsCrypt from unwrapped V2 Kc");
            co_return;
        }
        v2_session_key.emplace(std::move(*tls_crypt_opt));
        logger_->info("V2 handshake: unwrapped WKc ({} bytes metadata) from {}:{}",
                      unwrap_result->metadata.size(),
                      sender.addr.to_string(),
                      sender.port);
    }

    // Peek early-negotiation advertisement from tls-crypt wrapper counter (before unwrap).
    // Done here: counter is cleartext, and HandleHardReset needs the flag after unwrap.
    const bool early_negotiation = [&]()
    {
        auto counter = openvpn::PeekWireTlsCryptCounter(data);
        return counter && openvpn::SupportsEarlyNegotiation(*counter);
    }();

    // Choose the correct TlsCrypt for unwrapping, and resolve the session
    // before unwrap so the peer-id gate can select the replay window.
    Connection *session = session_manager_.FindSessionByEndpoint(endpoint);
    std::optional<openvpn::TlsCrypt> *unwrap_key = &tls_crypt_;

    if (tls_crypt_v2_)
    {
        if (v2_session_key)
        {
            unwrap_key = &v2_session_key;
        }
        else if (session)
        {
            unwrap_key = &session->GetSessionTlsCrypt();
        }
    }

    // Peer-id gate: use Connection's window only when the cleartext wire
    // session_id matches the established peer id. Otherwise scratch
    // (first packet, or same-endpoint new client session id).
    openvpn::TlsCryptReplayState scratch;
    openvpn::TlsCryptReplayState *replay = &scratch;
    bool used_scratch = true;
    if (*unwrap_key)
    {
        auto wire_sid = openvpn::PeekWireSessionId(data);
        auto peer = session ? session->GetControlChannel().GetPeerSessionId() : std::nullopt;
        if (session && peer && wire_sid && *wire_sid == peer->value)
        {
            replay = &session->TlsCryptReplay();
            used_scratch = false;
        }
    }

    auto packet_opt = UnwrapAndParse(data, *unwrap_key, openvpn::PeerRole::Server, *logger_, *replay);
    if (!packet_opt)
        co_return;

    auto &packet = *packet_opt;

    if (session && !session->HasTransport())
        session->SetTransport(transport);

    logger_->debug("Session lookup: endpoint={}:{}, found={}",
                   sender.addr.to_string(),
                   sender.port,
                   session != nullptr);

    if (openvpn::IsControlPacket(packet.opcode_))
    {
        // Only the first-packet / peer-mismatch path needs the scratch for move-seed.
        std::optional<openvpn::TlsCryptReplayState> seed;
        if (used_scratch)
            seed.emplace(std::move(scratch));
        co_await HandleControlPacket(session,
                                     packet,
                                     sender,
                                     endpoint,
                                     std::move(transport),
                                     std::move(v2_session_key),
                                     std::move(seed),
                                     early_negotiation);
    }
    else if (openvpn::IsDataPacket(packet.opcode_))
    {
        // Slow path: TCP still posts all frames here (see TcpDataChannel
        // ClientReceiveLoop REVIEW). UDP split-datapath handles data on the
        // RX thread; DCO keeps data in-kernel. After TCP demux, treat this
        // as unexpected (warn + drop), matching DCO.
        if (!session)
        {
            logger_->warn("Received data packet without active session");
            co_return;
        }
        co_await HandleDataPacket(session, packet);
    }
}

template <typename Derived>
[[nodiscard]] bool ServerControlBase<Derived>::PsidCookieEnabled() const
{
    if (!config_ || !config_->server || !psid_cookie_key_)
        return false;
    if (!config_->server->psid_cookie)
        return false;
    // UDP-oriented anti-spoof defense; TCP keeps eager create.
    return config_->server->proto == "udp" || config_->server->proto == "udp6";
}

template <typename Derived>
[[nodiscard]] bool ServerControlBase<Derived>::ForceV2Cookie() const
{
    return config_ && config_->server
           && config_->server->tls_crypt_v2_cookie_mode == "force-cookie";
}

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::SendCookieChallenge(const openvpn::OpenVpnPacket &client_hr,
                                                                      openvpn::SessionId client_sid,
                                                                      openvpn::SessionId server_sid,
                                                                      const transport::PeerEndpoint &sender,
                                                                      transport::TransportHandle &transport,
                                                                      std::optional<openvpn::TlsCrypt> &wrap_key,
                                                                      bool v2_early_negotiation)
{
    const std::uint32_t ack_id = client_hr.packet_id_.value_or(0);
    std::vector<std::uint8_t> payload;
    if (v2_early_negotiation)
        payload = openvpn::BuildEarlyNegFlagsTlv(openvpn::EARLY_NEG_FLAG_RESEND_WKC);

    auto pkt = openvpn::BuildCookieHardResetResponse(client_hr.opcode_,
                                                     server_sid.value,
                                                     client_sid.value,
                                                     ack_id,
                                                     client_hr.key_id_,
                                                     std::move(payload),
                                                     /*our_packet_id=*/0,
                                                     /*force_server_v2=*/v2_early_negotiation);
    auto serialized = pkt.Serialize();
    if (serialized.empty())
    {
        logger_->warn("Failed to serialize psid cookie challenge");
        co_return;
    }

    if (!wrap_key)
    {
        logger_->warn("psid cookie challenge: no tls-crypt key to wrap with");
        co_return;
    }

    auto wrapped = wrap_key->Wrap(serialized, /*server_mode=*/true);
    if (!wrapped)
    {
        logger_->warn("psid cookie challenge: tls-crypt wrap failed");
        co_return;
    }

    try
    {
        co_await transport.Send(*wrapped);
    }
    catch (const std::exception &e)
    {
        logger_->error("psid cookie challenge send failed: {}", e.what());
        co_return;
    }

    // Stable log line for IT17 / IT20 assertions.
    logger_->info("psid cookie challenge sent to {}:{} (server_sid={:016x})",
                  sender.addr.to_string(),
                  sender.port,
                  server_sid.value);
}

template <typename Derived>
asio::awaitable<Connection *> ServerControlBase<Derived>::TryAcceptCookieSession(
    const openvpn::OpenVpnPacket &packet,
    const transport::PeerEndpoint &sender,
    const Connection::Endpoint &endpoint,
    transport::TransportHandle transport,
    std::optional<openvpn::TlsCrypt> v2_session_key,
    std::optional<openvpn::TlsCryptReplayState> replay_seed)
{
    if (!PsidCookieEnabled() || !packet.session_id_ || !packet.remote_session_id_)
        co_return nullptr;

    const bool has_own_pid = packet.opcode_ != openvpn::Opcode::P_ACK_V1;
    if (!openvpn::IsEarlyHandshakeCookieEcho(packet, has_own_pid))
        co_return nullptr;

    openvpn::SessionId client_sid{packet.session_id_.value()};
    openvpn::SessionId cookie_sid{packet.remote_session_id_.value()};
    openvpn::PsidCookieEndpoint pep{.addr = sender.addr, .port = sender.port};
    const auto now = static_cast<std::uint32_t>(std::time(nullptr));
    const int handwindow = config_->server->handshake_window;

    if (!openvpn::CheckSessionIdHmac(
            *psid_cookie_key_, cookie_sid, client_sid, pep, handwindow, now))
    {
        logger_->warn("psid cookie reject from {}:{} (invalid HMAC session id)",
                      sender.addr.to_string(),
                      sender.port);
        co_return nullptr;
    }

    // M4: only replace an existing endpoint session after cookie proof.
    if (Connection *existing = session_manager_.FindSessionByEndpoint(endpoint))
    {
        logger_->info("Cookie-proven new client; replacing session {:016x}",
                      existing->GetSessionId().value);
        RemoveSessionSafe(existing->GetSessionId());
        SplitPublishSessions();
    }

    openvpn::TlsCertConfig cert_config{
        .ca_cert = config_->server->ca_cert,
        .local_cert = config_->server->cert,
        .local_key = config_->server->key};

    Connection *session = &session_manager_.GetOrCreateSession(
        cookie_sid, endpoint, true, cert_config, *logger_);
    session->SetTransport(std::move(transport));
    if (replay_seed)
        session->SetTlsCryptReplay(std::move(*replay_seed));
    if (v2_session_key)
        session->SetSessionTlsCrypt(std::move(*v2_session_key));

    if (!session->GetControlChannel().CompleteCookieHandshake(client_sid, packet.key_id_))
    {
        logger_->error("CompleteCookieHandshake failed for {:016x}", cookie_sid.value);
        RemoveSessionSafe(cookie_sid);
        SplitPublishSessions();
        co_return nullptr;
    }

    logger_->info("psid cookie accepted, creating session {:016x} from {}:{}",
                  cookie_sid.value,
                  sender.addr.to_string(),
                  sender.port);
    co_return session;
}

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::HandleControlPacket(Connection *session,
                                                                      const openvpn::OpenVpnPacket &packet,
                                                                      const transport::PeerEndpoint &sender,
                                                                      const Connection::Endpoint &endpoint,
                                                                      transport::TransportHandle transport,
                                                                      std::optional<openvpn::TlsCrypt> v2_session_key,
                                                                      std::optional<openvpn::TlsCryptReplayState> replay_seed,
                                                                      bool early_negotiation)
{
    logger_->debug("Received control packet (opcode {})", static_cast<int>(packet.opcode_));

    if (packet.opcode_ == openvpn::Opcode::P_CONTROL_HARD_RESET_CLIENT_V2
        || packet.opcode_ == openvpn::Opcode::P_CONTROL_HARD_RESET_CLIENT_V3)
    {
        session = co_await HandleHardReset(packet,
                                           sender,
                                           endpoint,
                                           std::move(transport),
                                           std::move(v2_session_key),
                                           std::move(replay_seed),
                                           early_negotiation);
        co_return;
    }

    // Pre-session cookie echo (ACK / CONTROL / WKC).
    if (!session
        && (packet.opcode_ == openvpn::Opcode::P_ACK_V1
            || packet.opcode_ == openvpn::Opcode::P_CONTROL_V1
            || packet.opcode_ == openvpn::Opcode::P_CONTROL_WKC_V1))
    {
        session = co_await TryAcceptCookieSession(packet,
                                                  sender,
                                                  endpoint,
                                                  std::move(transport),
                                                  std::move(v2_session_key),
                                                  std::move(replay_seed));
        if (!session)
            co_return;
        // Fall through to dispatch the same packet into the new session.
    }

    if (session)
    {
        session->UpdateLastActivity();

        auto &session_crypt = session->GetSessionTlsCrypt().has_value()
                                  ? session->GetSessionTlsCrypt()
                                  : tls_crypt_;
        auto sess_transport = session->GetTransport();

        // WKC is CONTROL_V1 for dispatch purposes (same layout after WKc strip).
        openvpn::OpenVpnPacket dispatch_pkt = packet;
        if (dispatch_pkt.opcode_ == openvpn::Opcode::P_CONTROL_WKC_V1)
            dispatch_pkt.opcode_ = openvpn::Opcode::P_CONTROL_V1;

        SessionControlCallbacks callbacks{
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
        };

        co_await DispatchSessionControlPacket(session->GetControlChannel(),
                                              session_crypt,
                                              openvpn::PeerRole::Server,
                                              sess_transport,
                                              dispatch_pkt,
                                              *logger_,
                                              callbacks);

        // Activate the new TX key snapshot as soon as the client has ACKed
        // our KEY_METHOD_2.  Until then, SplitPublishSessions() is withheld so
        // the server data path does not encrypt with a key_id unknown to the client.
        // This check fires on the P_ACK_V1 (or any piggybacked ACK in a
        // P_CONTROL_V1) that drains the last unacknowledged control packet.
        if (session->IsKeysPendingActivation()
            && !session->GetControlChannel().HasPendingOutbound())
        {
            session->SetKeysPendingActivation(false);
            SplitPublishSessions();
            logger_->info("TX keys activated (client ACKed KEY_METHOD_2)");
        }
    }
    else
    {
        logger_->warn("Received control packet without active session");
    }
}

template <typename Derived>
asio::awaitable<Connection *> ServerControlBase<Derived>::HandleHardReset(
    const openvpn::OpenVpnPacket &packet,
    const transport::PeerEndpoint &sender,
    const Connection::Endpoint &endpoint,
    transport::TransportHandle transport,
    std::optional<openvpn::TlsCrypt> v2_session_key,
    std::optional<openvpn::TlsCryptReplayState> replay_seed,
    bool early_negotiation)
{
    logger_->info("Client initiating handshake from {}:{}",
                  sender.addr.to_string(),
                  sender.port);

    if (!packet.session_id_)
    {
        logger_->warn("Hard reset missing session ID from client");
        co_return nullptr;
    }

    openvpn::SessionId client_session_id{packet.session_id_.value()};

    Connection *session = session_manager_.FindSessionByEndpoint(endpoint);
    if (session)
    {
        auto peer_session = session->GetControlChannel().GetPeerSessionId();
        if (peer_session && peer_session->value == client_session_id.value)
        {
            logger_->debug("Hard reset retransmission, resending response");
            auto hard_reset_response = session->GetControlChannel().GenerateHardResetResponse(packet.opcode_);
            if (!hard_reset_response.empty())
                co_await SendWrappedPacket(std::move(hard_reset_response), session);
            co_return session;
        }

        // Different client sid on same endpoint.
        // Without cookies: replace (legacy). With cookies: drop — do not
        // challenge or evict. OpenVPN only runs the cookie path when no
        // instance exists for the real address; challenging here would
        // reflect a HARD_RESET_SERVER at a live peer (spoofed source).
        // Legitimate reuse of the endpoint waits for dead-peer cleanup.
        if (!PsidCookieEnabled())
        {
            logger_->info("New client session ID, replacing existing session");
            RemoveSessionSafe(session->GetSessionId());
            SplitPublishSessions();
            session = nullptr;
        }
        else
        {
            logger_->warn(
                "Ignoring HARD_RESET with new client sid {:016x} from {}:{} — "
                "endpoint already has session {:016x} (peer sid {:016x})",
                client_session_id.value,
                sender.addr.to_string(),
                sender.port,
                session->GetSessionId().value,
                peer_session ? peer_session->value : 0);
            co_return session;
        }
    }

    const bool is_v2_hr = packet.opcode_ == openvpn::Opcode::P_CONTROL_HARD_RESET_CLIENT_V3;

    if (PsidCookieEnabled())
    {
        // tls-crypt-v2 without early negotiation: force-cookie drops; allow-noncookie eager-creates.
        if (is_v2_hr && !early_negotiation)
        {
            if (ForceV2Cookie())
            {
                logger_->warn(
                    "V2 hard reset without early negotiation rejected (force-cookie) from {}:{}",
                    sender.addr.to_string(),
                    sender.port);
                co_return nullptr;
            }
            // allow-noncookie: fall through to eager create below
        }
        else
        {
            // Shared-key tls-crypt, or V2 with early negotiation: send cookie, no state.
            openvpn::PsidCookieEndpoint pep{.addr = sender.addr, .port = sender.port};
            const auto now = static_cast<std::uint32_t>(std::time(nullptr));
            openvpn::SessionId cookie_sid = openvpn::CalculateSessionIdHmac(
                *psid_cookie_key_,
                client_session_id,
                pep,
                config_->server->handshake_window,
                /*offset=*/0,
                now);

            std::optional<openvpn::TlsCrypt> *wrap_key = &tls_crypt_;
            if (v2_session_key)
                wrap_key = &v2_session_key;

            co_await SendCookieChallenge(packet,
                                         client_session_id,
                                         cookie_sid,
                                         sender,
                                         transport,
                                         *wrap_key,
                                         /*v2_early_negotiation=*/is_v2_hr && early_negotiation);
            co_return nullptr;
        }
    }

    openvpn::SessionId server_session_id = openvpn::SessionId::Generate();
    logger_->debug("Client session ID: {:016x}, Server session ID: {:016x}",
                   client_session_id.value,
                   server_session_id.value);

    openvpn::TlsCertConfig cert_config{
        .ca_cert = config_->server->ca_cert,
        .local_cert = config_->server->cert,
        .local_key = config_->server->key};

    session = &session_manager_.GetOrCreateSession(
        server_session_id, endpoint, true, cert_config, *logger_);
    session->SetTransport(std::move(transport));
    // Move-seed: scratch holds the post-accept state from packet #1.
    if (replay_seed)
        session->SetTlsCryptReplay(std::move(*replay_seed));

    if (v2_session_key)
    {
        session->SetSessionTlsCrypt(std::move(*v2_session_key));
        logger_->debug("Installed V2 per-session TlsCrypt on session {:016x}",
                       server_session_id.value);
    }

    if (session->GetControlChannel().HandleHardReset(packet))
    {
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

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::HandleSoftReset(Connection *session,
                                                                  const openvpn::OpenVpnPacket &packet)
{
    logger_->info("Received soft reset (key renegotiation) request");
    [[maybe_unused]] std::uint8_t old_key_id = session->GetControlChannel().GetKeyId();

    openvpn::TlsCertConfig cert_config{
        .ca_cert = config_->server->ca_cert,
        .local_cert = config_->server->cert,
        .local_key = config_->server->key};

    auto response = session->GetControlChannel().HandleSoftReset(packet, cert_config);
    if (!response.empty())
    {
        co_await SendWrappedPacket(std::move(response), session);
        session->SetSentKeyMethod2(false);
        session->SetClientRandom({});
        session->SetServerRandom({});
        logger_->debug("Reset session state for key renegotiation");
        // The VPN server is always the TLS server; the remote client will send
        // its ClientHello next (via P_CONTROL_V1 packets).
    }
    else
    {
        logger_->error("Failed to handle soft reset");
    }
}

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::ProcessPlaintext(Connection *session,
                                                                   std::vector<std::uint8_t> plaintext)
{
    logger_->debug("Received plaintext from client: {} bytes", plaintext.size());

    if (!session->HasSentKeyMethod2())
    {
        co_await HandleKeyMethod2(session, plaintext);
    }
    else
    {
        std::string_view msg(reinterpret_cast<const char *>(plaintext.data()), plaintext.size());
        if (!msg.empty() && msg.back() == '\0')
            msg.remove_suffix(1);

        if (msg == "PUSH_REQUEST")
            co_await HandlePushRequest(session);
        else
            logger_->warn("Unhandled control message: {}", msg);
    }

    EnsureIpAllocated(session);
}

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::HandleKeyMethod2(Connection *session,
                                                                   const std::vector<uint8_t> &plaintext)
{
    auto parsed = openvpn::ParseKeyMethod2Message(plaintext);
    if (!parsed)
    {
        logger_->error("Failed to parse client key-method 2 message ({} bytes)", plaintext.size());
        RemoveSessionSafe(session->GetSessionId());
        co_return;
    }

    auto &[client_random, client_options, username, password, peer_info] = *parsed;
    logger_->debug("Parsed client key-method 2: random={} bytes, options={}",
                   client_random.size(),
                   client_options);

    session->SetClientRandom(client_random);
    session->SetClientIvProto(openvpn::ParseClientIvProto(peer_info));

    std::vector<uint8_t> server_random(openvpn::SERVER_KEY_SOURCE_SIZE);
    if (RAND_bytes(server_random.data(), static_cast<int>(server_random.size())) != 1)
        throw std::runtime_error("RAND_bytes failed generating server random");

    std::string options = BuildKeyMethod2Options(openvpn::PeerRole::Server,
                                                 config_->server->proto,
                                                 config_->server->cipher,
                                                 config_->server->tun_mtu);

    auto key_method_msg = openvpn::BuildKeyMethod2Message(server_random, options, "", "");

    EnsureIpAllocated(session);
    SplitPublishRoutes();

    session->SetServerRandom(server_random);
    if (!DeriveAndInstallKeys(session))
    {
        logger_->error("Key-method 2 exchange complete but key derivation failed");
        RemoveSessionSafe(session->GetSessionId());
        co_return;
    }

    // Publish new decrypt key to RX immediately: the client may start sending
    // with the new key_id as soon as it receives KEY_METHOD_2.  RxDecryptState
    // will move the old primary to lame duck and accept both key_ids.
    // TX stays on the old key until the client ACKs (keys_pending_activation_).
    SplitPublishSessionsRx();
    session->SetKeysPendingActivation(true);
    logger_->info("Key-method 2 exchange complete, keys derived; RX activated, awaiting ACK for TX");

    if (co_await SendTlsControlData(session, key_method_msg, "server key-method 2"))
        session->SetSentKeyMethod2(true);
}

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::HandlePushRequest(Connection *session)
{
    struct Actions
    {
        ServerControlBase &self;
        void DeriveAndInstallKeys(Connection *s)
        {
            self.DeriveAndInstallKeys(s);
        }
        void ScheduleRekey(openvpn::SessionId sid, std::uint32_t sec)
        {
            asio::co_spawn(*self.io_context_, self.RekeyLoop(sid, sec), asio::detached);
        }
    };
    Actions actions{*this};
    co_await HandleServerPushRequest(session, *config_->server, tls_crypt_, *logger_, actions);
}

template <typename Derived>
void ServerControlBase<Derived>::DisarmRekeyTimer(openvpn::SessionId sid)
{
    if (auto *session = session_manager_.FindSession(sid))
        session->SetRekeyTimerArmed(false);
}

template <typename Derived>
void ServerControlBase<Derived>::RearmRekeyTimer(openvpn::SessionId sid, std::uint32_t reneg_seconds)
{
    if (!*running_ || reneg_seconds == 0)
    {
        DisarmRekeyTimer(sid);
        return;
    }

    auto *session = session_manager_.FindSession(sid);
    if (!session)
        return;

    session->SetRekeyTimerArmed(true);
    asio::co_spawn(
        *io_context_,
        RekeyLoop(sid, reneg_seconds),
        asio::detached);
}

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::RekeyLoop(openvpn::SessionId sid, std::uint32_t reneg_seconds)
{
    // Randomize to 80-95% of the configured interval so the server reliably
    // fires before a client running the same reneg_sec value.
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<std::uint32_t> pct_dist(80, 95);
    const std::uint32_t jittered = (reneg_seconds * pct_dist(rng)) / 100;

    if (!session_manager_.FindSession(sid))
    {
        DisarmRekeyTimer(sid);
        co_return;
    }

    // Wait until jittered deadline or a limit-driven rekey request (80% GCM /
    // packet-ID wrap).  Poll every ≤1 s so TakeRekeyRequest() is noticed and
    // so !running_ is observed promptly on shutdown (does not use
    // Connection::RekeyTimer — see connection.h).
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(jittered);
    asio::steady_timer poll_timer(*io_context_);
    try
    {
        while (std::chrono::steady_clock::now() < deadline)
        {
            auto *session = session_manager_.FindSession(sid);
            if (!session)
            {
                DisarmRekeyTimer(sid);
                co_return;
            }
            if (session->GetCryptoContext().TakeRekeyRequest())
                break;

            auto remaining = deadline - std::chrono::steady_clock::now();
            if (remaining <= std::chrono::seconds(0))
                break;

            const auto one_second = std::chrono::seconds(1);
            poll_timer.expires_after(remaining < one_second ? remaining : one_second);
            co_await poll_timer.async_wait(asio::use_awaitable);

            if (!*running_)
            {
                DisarmRekeyTimer(sid);
                co_return;
            }
        }
    }
    catch (const asio::system_error &)
    {
        DisarmRekeyTimer(sid);
        co_return; // Server stopped or poll_timer cancelled
    }

    if (!*running_)
    {
        DisarmRekeyTimer(sid);
        co_return;
    }

    auto *session = session_manager_.FindSession(sid);
    if (!session)
    {
        DisarmRekeyTimer(sid);
        co_return;
    }

    if (!session->GetCryptoContext().HasValidKeys())
    {
        logger_->debug("Rekey {:016x}: skipped (data keys not ready)", sid.value);
        RearmRekeyTimer(sid, reneg_seconds);
        co_return;
    }

    try
    {
        openvpn::TlsCertConfig cert_config{
            .ca_cert = config_->server->ca_cert,
            .local_cert = config_->server->cert,
            .local_key = config_->server->key};

        // Crossed soft-reset (plan §4.8 RK2): client may already have put
        // the channel into TlsHandshake. RequestSoftReset returns empty in
        // that state — yield and let the in-flight renegotiation finish.
        auto soft_reset = session->GetControlChannel().RequestSoftReset(openvpn::PeerRole::Server, cert_config);
        if (soft_reset.empty())
        {
            const auto st = session->GetControlChannel().GetState();
            if (st == openvpn::ControlChannel::State::TlsHandshake)
                logger_->info("Rekey {:016x}: skipped — already renegotiating (client-driven)",
                              sid.value);
            else
                logger_->warn("Rekey {:016x}: RequestSoftReset failed (state={})",
                              sid.value,
                              static_cast<int>(st));
            RearmRekeyTimer(sid, reneg_seconds);
            co_return;
        }

        // Reset per-session key exchange state so the upcoming key-method-2
        // exchange is processed fresh (same as client-initiated rekey path).
        session->SetSentKeyMethod2(false);
        session->SetClientRandom({});
        session->SetServerRandom({});

        co_await SendWrappedPacket(std::move(soft_reset), session);
        logger_->debug("Rekey {:016x}: sent P_CONTROL_SOFT_RESET_V1", sid.value);
    }
    catch (const std::exception &e)
    {
        logger_->warn("Rekey {:016x}: exception during rekey trigger: {}",
                      sid.value,
                      e.what());
    }

    RearmRekeyTimer(sid, reneg_seconds);
}

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::HandleDataPacket(Connection *session,
                                                                   const openvpn::OpenVpnPacket &packet)
{
    session->UpdateLastActivity();
    co_await derived().ProcessIncomingDataPacket(session, packet);
}

template <typename Derived>
void ServerControlBase<Derived>::EnsureIpAllocated(Connection *session)
{
    if (!session->GetAssignedIpv4())
    {
        auto ip_opt = ip_pool_->AllocateIpv4(session->GetSessionId().value);
        if (ip_opt)
        {
            session->SetAssignedIpv4(*ip_opt);
            routing_table_.AddRoute(*ip_opt, 32, session->GetSessionId().value);
            logger_->info("Assigned IPv4 {} to session {:016x}",
                          ipv4::Ipv4ToString(*ip_opt),
                          session->GetSessionId().value);
        }
        else
        {
            logger_->warn("IP pool exhausted - cannot assign IPv4");
        }
    }

    if (ip_pool_->HasIpv6Pool() && !session->GetAssignedIpv6())
    {
        auto ipv6_opt = ip_pool_->AllocateIpv6(session->GetSessionId().value);
        if (ipv6_opt)
        {
            session->SetAssignedIpv6(*ipv6_opt);
            routing_table_v6_.AddRoute(*ipv6_opt, 128, session->GetSessionId().value);
            logger_->info("Assigned IPv6 {} to session {:016x}",
                          ipv6::Ipv6ToString(*ipv6_opt),
                          session->GetSessionId().value);
        }
        else
        {
            logger_->warn("IPv6 pool exhausted");
        }
    }
}

template <typename Derived>
bool ServerControlBase<Derived>::DeriveAndInstallKeys(Connection *session)
{
    const auto &client_random = session->GetClientRandom();
    const auto &server_random = session->GetServerRandom();

    auto result = DeriveDataChannelKeys(
        session->GetControlChannel(), client_random, server_random, config_->server->cipher, openvpn::PeerRole::Server, *logger_);
    if (!result)
        return false;

    std::uint8_t current_key_id = session->GetControlChannel().GetKeyId();
    return derived().InstallKeys(session, result->key_material, result->cipher_algo, result->hmac_algo, current_key_id);
}

template <typename Derived>
asio::awaitable<void> ServerControlBase<Derived>::SendWrappedPacket(std::vector<std::uint8_t> data,
                                                                    Connection *session)
{
    if (!session || !session->HasTransport())
    {
        logger_->error("SendWrappedPacket: session has no transport handle");
        co_return;
    }

    auto &crypt = session->GetSessionTlsCrypt().has_value()
                      ? session->GetSessionTlsCrypt()
                      : tls_crypt_;
    auto transport = session->GetTransport();
    co_await WrapAndSend(crypt, std::move(data), openvpn::PeerRole::Server, transport, *logger_);
    session->UpdateLastOutbound();
}

template <typename Derived>
asio::awaitable<bool> ServerControlBase<Derived>::SendTlsControlData(Connection *session,
                                                                     std::span<const std::uint8_t> data,
                                                                     std::string_view description)
{
    if (!session || !session->HasTransport())
    {
        logger_->error("{}: session has no transport", description);
        co_return false;
    }

    auto &crypt = session->GetSessionTlsCrypt().has_value()
                      ? session->GetSessionTlsCrypt()
                      : tls_crypt_;
    auto transport = session->GetTransport();
    bool ok = co_await clv::vpn::SendTlsControlData(session->GetControlChannel(),
                                                    crypt,
                                                    data,
                                                    openvpn::PeerRole::Server,
                                                    transport,
                                                    *logger_,
                                                    description);
    if (ok)
        session->UpdateLastOutbound();
    co_return ok;
}

template <typename Derived>
void ServerControlBase<Derived>::SplitPublishRoutes()
{
    if (split_ctx_)
        split_ctx_->PublishRoutes(routing_table_, routing_table_v6_);
}

template <typename Derived>
void ServerControlBase<Derived>::SplitPublishSessions()
{
    if (split_ctx_)
    {
        split_ctx_->PublishSessions(session_manager_);
        split_ctx_->ReclaimDeferred();
    }
}

template <typename Derived>
void ServerControlBase<Derived>::SplitPublishSessionsRx()
{
    if (split_ctx_)
        split_ctx_->PublishSessionsRx(session_manager_);
}

template <typename Derived>
void ServerControlBase<Derived>::RemoveSessionSafe(openvpn::SessionId sid)
{
    if (split_ctx_)
    {
        auto conn = session_manager_.ExtractSession(sid);
        if (conn)
            split_ctx_->DeferDestruction(std::move(conn));
    }
    else
    {
        session_manager_.RemoveSession(sid);
    }
}

template <typename Derived>
void ServerControlBase<Derived>::LoadTlsCryptKeys()
{
    const auto &srv = *config_->server;
    const bool has_v1 = !srv.tls_crypt_key.empty();
    const bool has_v2 = !srv.tls_crypt_v2_key.empty();

    if (!has_v1 && !has_v2)
        throw std::runtime_error("TLS-Crypt key is required.");
    if (has_v1 && has_v2)
        throw std::runtime_error("Cannot configure both tls_crypt_key and tls_crypt_v2_key.");

    if (has_v2)
    {
        auto v2 = openvpn::TlsCryptV2::FromKeyFile(srv.tls_crypt_v2_key.string(), *logger_);
        if (!v2)
            throw std::runtime_error("Failed to load TLS-Crypt-V2 key: " + srv.tls_crypt_v2_key.string());
        tls_crypt_v2_ = std::move(*v2);
        logger_->info("TLS-Crypt-V2 enabled: {}", srv.tls_crypt_v2_key.string());
    }
    else
    {
        auto tc = openvpn::TlsCrypt::FromKeyFile(srv.tls_crypt_key.string(), *logger_);
        if (!tc)
            throw std::runtime_error("Failed to load TLS-Crypt key: " + srv.tls_crypt_key.string());
        tls_crypt_ = std::move(*tc);
        logger_->info("TLS-Crypt enabled: {}", srv.tls_crypt_key.string());
    }
}

} // namespace clv::vpn

#endif // CLV_VPN_SERVER_CONTROL_BASE_H
