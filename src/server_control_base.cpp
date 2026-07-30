// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "server_control_base.h"
#include "data_path_stats.h"
#include "ip_pool_manager.h"
#include "log_subsystems.h"
#include "net/ipv4_utils.h"
#include "net/ipv6_utils.h"
#include "openvpn/config_exchange.h"
#include "openvpn/connection.h"
#include "openvpn/control_channel.h"
#include "openvpn/control_plane_helpers.h"
#include "openvpn/key_derivation.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/psid_cookie.h"
#include "openvpn/push_exchange_helpers.h"
#include "openvpn/session_manager.h"
#include "openvpn/tls_context.h"
#include "openvpn/tls_crypt.h"
#include "openvpn/tls_crypt_v2.h"
#include "routing_table.h"
#include "transport/transport.h"

#include <atomic>
#include <bits/chrono.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <exception>
#include <future>
#include <memory>
#include <openssl/rand.h>
#include <optional>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace clv::vpn {

// =============================================================================
// ServerControlBase — out-of-line member function definitions
// =============================================================================

template <typename Leaf>
asio::io_context &ServerControlBase<Leaf>::io_context() noexcept
{
    return *io_context_;
}

template <typename Leaf>
SessionManager &ServerControlBase<Leaf>::session_manager() noexcept
{
    return session_manager_;
}

template <typename Leaf>
RoutingTableIpv4 &ServerControlBase<Leaf>::routing_table() noexcept
{
    return routing_table_;
}

template <typename Leaf>
RoutingTableIpv6 &ServerControlBase<Leaf>::routing_table_v6() noexcept
{
    return routing_table_v6_;
}

template <typename Leaf>
void ServerControlBase<Leaf>::HandleDeadPeer(openvpn::SessionId sid)
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

template <typename Leaf>
void ServerControlBase<Leaf>::OnControlPacketFromDataPath(std::vector<std::uint8_t> /*data*/,
                                                          transport::PeerEndpoint /*sender*/)
{
    logger_->warn("OnControlPacketFromDataPath(2-arg) not implemented for this transport");
}

template <typename Leaf>
void ServerControlBase<Leaf>::OnControlPacketFromDataPath(std::vector<std::uint8_t> /*data*/,
                                                          transport::PeerEndpoint /*sender*/,
                                                          transport::TransportHandle /*transport*/)
{
    logger_->warn("OnControlPacketFromDataPath(3-arg) not implemented for this transport");
}

template <typename Leaf>
void ServerControlBase<Leaf>::HandleTcpDisconnect(transport::PeerEndpoint /*sender*/)
{
    // UDP/DCO: no-op
}

template <typename Leaf>
ServerControlBase<Leaf>::ServerControlBase(ServerControlConfig cfg)
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
    handshake_timer_.emplace(*io_context_);
}

template <typename Leaf>
void ServerControlBase<Leaf>::StartBase()
{
    cleanup_future_ = asio::co_spawn(*io_context_, SessionCleanupLoop(), asio::use_future);
    keepalive_future_ = asio::co_spawn(*io_context_, KeepAliveLoop(), asio::use_future);
    handshake_future_ = asio::co_spawn(*io_context_, HandshakeRetransmitLoop(), asio::use_future);

    if (config_->performance.stats_interval_seconds > 0)
    {
        logger_->info("Data-path stats enabled (interval: {}s)",
                      config_->performance.stats_interval_seconds);
        stats_future_ = asio::co_spawn(*io_context_, StatsLoop(), asio::use_future);
    }
}

template <typename Leaf>
void ServerControlBase<Leaf>::StopBase()
{
    using WorkGuard = asio::executor_work_guard<asio::io_context::executor_type>;
    std::optional<WorkGuard> work_guard;
    if (split_ctx_)
        work_guard.emplace(io_context_->get_executor());

    // Cancel rekey timers FIRST so their operation_aborted completions are
    // queued before the supervisory-loop cancellations.  The io_context
    // processes completions in FIFO order.
    session_manager_.CancelAllRekeyTimers();
    cleanup_timer_->cancel();
    stats_timer_->cancel();
    if (handshake_timer_)
        handshake_timer_->cancel();
    ch().StopKeepaliveMonitor();
    // Channel releases hub attachment (guard) then tears down data path / TUN.
    ch().StopDataPath();

    // Wait for supervisory coroutines to finish: all stop signals are issued above
    if (cleanup_future_.valid())
        cleanup_future_.get();
    if (keepalive_future_.valid())
        keepalive_future_.get();
    if (stats_future_.valid())
        stats_future_.get();
    if (handshake_future_.valid())
        handshake_future_.get();

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

template <typename Leaf>
void ServerControlBase<Leaf>::ConfigureDataPlane()
{
    std::string dev = ch().ConfigureDataPlane(*config_->server, *io_context_, zone_);
    if (dev.empty())
        return;

    logger_->info("Data plane ready: {}", dev);
}

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::SessionCleanupLoop()
{
    using namespace std::chrono_literals;
    constexpr auto cleanup_interval = 30s;
    auto session_timeout = std::chrono::seconds(
        config_->server->keepalive.second > 0 ? config_->server->keepalive.second : 120);

    while (*running_)
    {
        cleanup_timer_->expires_after(cleanup_interval);
        auto [ec] = co_await cleanup_timer_->async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec == asio::error::operation_aborted)
            break;
        if (ec)
            throw asio::system_error(ec);
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

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::KeepAliveLoop()
{
    co_await ch().RunKeepaliveMonitor();
}

template <typename Leaf>
void ServerControlBase<Leaf>::ArmHandshakeRetransmit()
{
    if (handshake_timer_)
        handshake_timer_->cancel();
}

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::HandshakeRetransmitLoop()
{
    // Sleep until the earliest unacked control packet's RTO (OpenVPN folds
    // reliable_send_timeout into the per-instance select wakeup). When no
    // session has outstanding control traffic, wait idle until ArmHandshakeRetransmit
    // from a server outbound path cancels the far-future wait.
    while (*running_)
    {
        std::optional<std::chrono::steady_clock::time_point> earliest;
        auto session_ids = session_manager_.GetAllSessionIds();
        for (const auto &sid : session_ids)
        {
            Connection *session = session_manager_.FindSession(sid);
            if (!session || !session->HasTransport())
                continue;
            auto deadline = session->GetControlChannel().EarliestRetransmitAt();
            if (deadline && (!earliest || *deadline < *earliest))
                earliest = deadline;
        }

        if (earliest)
            handshake_timer_->expires_at(*earliest);
        else
            // Idle: far-future wait; ArmHandshakeRetransmit cancels this.
            handshake_timer_->expires_after(std::chrono::hours(24));

        auto [ec] = co_await handshake_timer_->async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec == asio::error::operation_aborted)
        {
            if (!*running_)
                break;
            continue; // kicked or stop: recompute earliest
        }
        if (ec)
            throw asio::system_error(ec);
        if (!*running_)
            break;

        const auto now = std::chrono::steady_clock::now();
        session_ids = session_manager_.GetAllSessionIds();
        for (const auto &sid : session_ids)
        {
            Connection *session = session_manager_.FindSession(sid);
            if (!session || !session->HasTransport())
                continue;

            auto &cc = session->GetControlChannel();
            auto deadline = cc.EarliestRetransmitAt();
            if (!deadline || *deadline > now)
                continue;

            auto &session_crypt = session->GetSessionTlsCrypt().has_value()
                                      ? session->GetSessionTlsCrypt()
                                      : tls_crypt_;
            auto transport = session->GetTransport();
            co_await FlushControlQueue(cc,
                                       session_crypt,
                                       openvpn::PeerRole::Server,
                                       transport,
                                       *logger_);
        }
    }
}

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::StatsLoop()
{
    co_await RunStatsLoop(
        *stats_timer_,
        std::chrono::seconds(config_->performance.stats_interval_seconds),
        *logger_,
        [this]
    { return running_->load(std::memory_order_relaxed); },
        [this]
    { return ch().SnapshotStats(); },
        [this](const DataPathStats &delta, double elapsedSec)
    { leaf().LogStats(delta, elapsedSec); });
}

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::ProcessNetworkPacket(std::vector<std::uint8_t> data,
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
        // Data opcodes belong on the data-plane RX path (UDP/TCP demux or DCO
        // kernel). Never decrypt or forward here — fail closed like DCO.
        if (unexpected_data_on_control_limiter_.Due())
        {
            const auto suppressed = unexpected_data_on_control_limiter_.SuppressedCount() + 1;
            if (!session)
            {
                logger_->warn(
                    "Dropping data packet on control plane (no session) ({}x)",
                    suppressed);
            }
            else
            {
                logger_->warn(
                    "Dropping data packet on control plane (session={:016x}) ({}x)",
                    session->GetSessionId().value,
                    suppressed);
            }
        }
        co_return;
    }
}

template <typename Leaf>
[[nodiscard]] bool ServerControlBase<Leaf>::PsidCookieEnabled() const
{
    if (!config_ || !config_->server || !psid_cookie_key_)
        return false;
    if (!config_->server->psid_cookie)
        return false;
    // UDP-oriented anti-spoof defense; TCP keeps eager create.
    return config_->server->proto == "udp" || config_->server->proto == "udp6";
}

template <typename Leaf>
[[nodiscard]] bool ServerControlBase<Leaf>::ForceV2Cookie() const
{
    return config_ && config_->server
           && config_->server->tls_crypt_v2_cookie_mode == "force-cookie";
}

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::SendCookieChallenge(const openvpn::OpenVpnPacket &client_hr,
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

template <typename Leaf>
asio::awaitable<Connection *> ServerControlBase<Leaf>::TryAcceptCookieSession(
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

    // Only replace an existing endpoint session after cookie proof.
    if (Connection *existing = session_manager_.FindSessionByEndpoint(endpoint))
    {
        logger_->info("Cookie-proven new client; replacing session {:016x}",
                      existing->GetSessionId().value);
        RemoveSessionSafe(existing->GetSessionId());
        SplitPublishSessions();
    }

    openvpn::TlsCertConfig cert_config = MakeTlsCertConfig();

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

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::HandleControlPacket(Connection *session,
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

        if (session->GetControlChannel().PeerSidMismatch(packet))
        {
            logger_->warn(
                "Dropping control opcode {} from {}:{} — wire sid {:016x} != peer sid {:016x}",
                static_cast<int>(packet.opcode_),
                sender.addr.to_string(),
                sender.port,
                packet.session_id_.value_or(0),
                session->GetControlChannel().GetPeerSessionId()->value);
            co_return;
        }

        auto &session_crypt = session->GetSessionTlsCrypt().has_value()
                                  ? session->GetSessionTlsCrypt()
                                  : tls_crypt_;
        auto sess_transport = session->GetTransport();

        // WKC is CONTROL_V1 for dispatch purposes (same layout after WKc strip).
        openvpn::OpenVpnPacket dispatch_pkt = packet;
        if (dispatch_pkt.opcode_ == openvpn::Opcode::P_CONTROL_WKC_V1)
            dispatch_pkt.opcode_ = openvpn::Opcode::P_CONTROL_V1;

        struct SessionActions
        {
            ServerControlBase<Leaf> &self;
            Connection *session;

            asio::awaitable<void> OnSoftReset(const openvpn::OpenVpnPacket &pkt)
            {
                co_await self.HandleSoftReset(session, pkt);
            }
            asio::awaitable<void> OnPlaintext(std::vector<std::uint8_t> plaintext)
            {
                co_await self.ProcessPlaintext(session, std::move(plaintext));
            }
            asio::awaitable<void> OnHandshakeComplete()
            {
                self.EnsureIpAllocated(session);
                co_return;
            }
        };
        SessionActions actions{*this, session};

        co_await DispatchSessionControlPacket(session->GetControlChannel(),
                                              session_crypt,
                                              openvpn::PeerRole::Server,
                                              sess_transport,
                                              dispatch_pkt,
                                              *logger_,
                                              actions);
        ArmHandshakeRetransmit();

        // Rekey only: activate the new TX snapshot once the client has ACKed
        // KEY_METHOD_2 (HasPendingOutbound drained). Initial key_id 0 already
        // published TX in HandleKeyMethod2.
        // Fires when ApplyAckIds (standalone P_ACK_V1 or piggybacked on P_CONTROL_V1)
        // drains the last unacknowledged control packet.
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

template <typename Leaf>
asio::awaitable<Connection *> ServerControlBase<Leaf>::HandleHardReset(
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

        // Do not challenge or evict: a spoofed HARD_RESET would kick a live
        // peer. Same-bind reconnect waits for dead-peer cleanup.
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

    openvpn::TlsCertConfig cert_config = MakeTlsCertConfig();

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

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::HandleSoftReset(Connection *session,
                                                               const openvpn::OpenVpnPacket &packet)
{
    logger_->info("Received soft reset (key renegotiation) request");
    [[maybe_unused]] std::uint8_t old_key_id = session->GetControlChannel().GetKeyId();

    openvpn::TlsCertConfig cert_config = MakeTlsCertConfig();

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

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::ProcessPlaintext(Connection *session,
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

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::HandleKeyMethod2(Connection *session,
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

    // Publish decrypt keys to RX immediately: the client may start sending with
    // the new key_id as soon as it receives KEY_METHOD_2.
    //
    // Initial handshake (key_id 0): also publish TX now. There is no prior data
    // key to protect, and withholding TX until control ACKs clear races with
    // IV_PROTO_REQUEST_PUSH + client traffic under latency (routes/RX live,
    // EncryptSlot misses the TX snapshot → silent drop). DCO installs both
    // directions in-kernel at this same point.
    //
    // Rekey (key_id != 0): keep TX on the old key until the client ACKs KM2
    // (keys_pending_activation_), matching OpenVPN's reliable_empty invariant.
    const std::uint8_t key_id = session->GetControlChannel().GetKeyId();
    if (key_id == 0)
    {
        SplitPublishSessions();
        session->SetKeysPendingActivation(false);
        logger_->info("Key-method 2 exchange complete, keys derived; RX+TX activated (initial)");
    }
    else
    {
        SplitPublishSessionsRx();
        session->SetKeysPendingActivation(true);
        logger_->info("Key-method 2 exchange complete, keys derived; RX activated, awaiting ACK for TX (rekey)");
    }

    if (co_await SendTlsControlData(session, key_method_msg, "server key-method 2"))
    {
        session->SetSentKeyMethod2(true);
        // Match OpenVPN multi_client_connect_post: clients advertising
        // IV_PROTO_REQUEST_PUSH expect an immediate PUSH_REPLY. Without it they
        // sit on wait_for_connect (~1s) before sending PUSH_REQUEST.
        if (session->GetClientIvProto() & openvpn::IV_PROTO_REQUEST_PUSH)
        {
            logger_->info("IV_PROTO_REQUEST_PUSH set — sending PUSH_REPLY immediately");
            co_await HandlePushRequest(session);
        }
    }
}

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::HandlePushRequest(Connection *session)
{
    struct Actions
    {
        ServerControlBase<Leaf> &self;
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
    co_await HandleServerPushRequest(session,
                                     *config_->server,
                                     tls_crypt_,
                                     *logger_,
                                     actions);
    ArmHandshakeRetransmit();
}

template <typename Leaf>
void ServerControlBase<Leaf>::DisarmRekeyTimer(openvpn::SessionId sid)
{
    if (auto *session = session_manager_.FindSession(sid))
        session->SetRekeyTimerArmed(false);
}

template <typename Leaf>
void ServerControlBase<Leaf>::RearmRekeyTimer(openvpn::SessionId sid, std::uint32_t reneg_seconds)
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

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::RekeyLoop(openvpn::SessionId sid, std::uint32_t reneg_seconds)
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
    const auto poll = co_await PollUntilRekey(
        *io_context_,
        deadline,
        [this, sid]
    {
        return *running_ && session_manager_.FindSession(sid) != nullptr;
    },
        [this, sid]
    {
        auto *session = session_manager_.FindSession(sid);
        return session && session->GetCryptoContext().TakeRekeyRequest();
    });

    if (poll == RekeyPollResult::Cancelled)
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
        const openvpn::TlsCertConfig cert_config = MakeTlsCertConfig();

        // Crossed soft-reset: client may already have put
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

template <typename Leaf>
openvpn::TlsCertConfig ServerControlBase<Leaf>::MakeTlsCertConfig() const
{
    return openvpn::TlsCertConfig{
        .ca_cert = config_->server->ca_cert.string(),
        .local_cert = config_->server->cert.string(),
        .local_key = config_->server->key.string()};
}

template <typename Leaf>
void ServerControlBase<Leaf>::EnsureIpAllocated(Connection *session)
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

template <typename Leaf>
bool ServerControlBase<Leaf>::DeriveAndInstallKeys(Connection *session)
{
    const auto &client_random = session->GetClientRandom();
    const auto &server_random = session->GetServerRandom();

    auto result = DeriveDataChannelKeys(
        session->GetControlChannel(), client_random, server_random, config_->server->cipher, openvpn::PeerRole::Server, *logger_);
    if (!result)
        return false;

    std::uint8_t current_key_id = session->GetControlChannel().GetKeyId();
    return ch().InstallKeys(session, result->key_material, result->cipher_algo, result->hmac_algo, current_key_id);
}

template <typename Leaf>
asio::awaitable<void> ServerControlBase<Leaf>::SendWrappedPacket(std::vector<std::uint8_t> data,
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
    ArmHandshakeRetransmit();
}

template <typename Leaf>
asio::awaitable<bool> ServerControlBase<Leaf>::SendTlsControlData(Connection *session,
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
    {
        session->UpdateLastOutbound();
        ArmHandshakeRetransmit();
    }
    co_return ok;
}

template <typename Leaf>
void ServerControlBase<Leaf>::SplitPublishRoutes()
{
    if (split_ctx_)
        split_ctx_->PublishRoutes(routing_table_, routing_table_v6_);
}

template <typename Leaf>
void ServerControlBase<Leaf>::SplitPublishSessions()
{
    if (split_ctx_)
    {
        split_ctx_->PublishSessions(session_manager_);
        split_ctx_->ReclaimDeferred();
    }
}

template <typename Leaf>
void ServerControlBase<Leaf>::SplitPublishSessionsRx()
{
    if (split_ctx_)
        split_ctx_->PublishSessionsRx(session_manager_);
}

template <typename Leaf>
void ServerControlBase<Leaf>::RemoveSessionSafe(openvpn::SessionId sid)
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

template <typename Leaf>
void ServerControlBase<Leaf>::LoadTlsCryptKeys()
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

#include "channel_concept.h"
#include "server_dco_control_adapter.h"
#include "server_tcp_control_adapter.h"
#include "server_udp_control_adapter.h"

namespace clv::vpn {

static_assert(ServerTransportLeaf<ServerUdpTransport>);
static_assert(ServerTransportLeaf<ServerDcoTransport>);
static_assert(ServerTransportLeaf<ServerTcpTransport>);

template class ServerControlBase<ServerUdpTransport>;
template class ServerControlBase<ServerDcoTransport>;
template class ServerControlBase<ServerTcpTransport>;

} // namespace clv::vpn
