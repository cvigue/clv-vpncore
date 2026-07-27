// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SERVER_CONTROL_BASE_H
#define CLV_VPN_SERVER_CONTROL_BASE_H

/**
 * @file server_control_base.h
 * @brief Shared OpenVPN server control-protocol engine (template DI on Leaf).
 *
 * Parameterized on the concrete transport leaf. Channel access and LogStats
 * go through leaf() (static). Method bodies live in server_control_base.cpp
 * with explicit instantiation for the three leaves.
 *
 * @tparam Leaf  ServerUdpTransport / ServerDcoTransport / ServerTcpTransport
 */

#include "data_path_stats.h"
#include "ip_pool_manager.h"
#include "log_subsystems.h"
#include "openvpn/config_exchange.h"
#include "openvpn/connection.h"
#include "openvpn/control_channel.h"
#include "openvpn/control_plane_helpers.h"
#include "openvpn/crypto_algorithms.h"
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
#include "tunnel_zone.h"
#include "udp_engine_types.h"
#include "transport/transport.h"

#include <exception>
#include <log_utils.h>
#include <net/ipv4_utils.h>
#include <net/ipv6_utils.h>
#include <rate_limiter.h>

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

// ---- Shared control engine -------------------------------------------------

/**
 * @brief Protocol engine shared by all server transports.
 *
 * @tparam Leaf  Concrete transport (CRTP / template DI). Must provide channel()
 *               and LogStats; assert ServerTransportLeaf after Leaf is complete.
 */
template <typename Leaf>
class ServerControlBase
{
  protected:
    Leaf &leaf() noexcept { return static_cast<Leaf &>(*this); }
    const Leaf &leaf() const noexcept { return static_cast<const Leaf &>(*this); }

    auto &ch() noexcept { return leaf().channel(); }
    const auto &ch() const noexcept { return leaf().channel(); }

  public:
    explicit ServerControlBase(ServerControlConfig cfg);
    ~ServerControlBase() = default;

    ServerControlBase(const ServerControlBase &) = delete;
    ServerControlBase &operator=(const ServerControlBase &) = delete;
    ServerControlBase(ServerControlBase &&) = delete;
    ServerControlBase &operator=(ServerControlBase &&) = delete;

    // -- Adapter / shell accessors -------------------------------------------

    asio::io_context &io_context() noexcept;

    void HandleDeadPeer(openvpn::SessionId sid);

    /** Default: warn. UDP/DCO leaves hide with a real implementation. */
    void OnControlPacketFromDataPath(std::vector<std::uint8_t> data,
                                     transport::PeerEndpoint sender);

    /** Default: warn. TCP leaf hides with a real implementation. */
    void OnControlPacketFromDataPath(std::vector<std::uint8_t> data,
                                     transport::PeerEndpoint sender,
                                     transport::TransportHandle transport);

    /** Default: no-op. TCP leaf hides with disconnect handling. */
    void HandleTcpDisconnect(transport::PeerEndpoint sender);

    SessionManager &session_manager() noexcept;
    RoutingTableIpv4 &routing_table() noexcept;
    RoutingTableIpv6 &routing_table_v6() noexcept;

  protected:
    void StartBase();
    void StopBase();
    void ConfigureDataPlane();

    // -- Supervisory coroutines ----------------------------------------------

    asio::awaitable<void> SessionCleanupLoop();
    asio::awaitable<void> KeepAliveLoop();
    asio::awaitable<void> StatsLoop();
    asio::awaitable<void> HandshakeRetransmitLoop();

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
    void ArmHandshakeRetransmit();

    asio::awaitable<void> RekeyLoop(openvpn::SessionId sid, std::uint32_t reneg_seconds);

    openvpn::TlsCertConfig MakeTlsCertConfig() const;
    void EnsureIpAllocated(Connection *session);
    bool DeriveAndInstallKeys(Connection *session);

    asio::awaitable<void> SendWrappedPacket(std::vector<std::uint8_t> data,
                                            Connection *session);

    asio::awaitable<bool> SendTlsControlData(Connection *session,
                                             std::span<const std::uint8_t> data,
                                             std::string_view description);

    void SplitPublishRoutes();
    void SplitPublishSessions();
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
    std::optional<asio::steady_timer> handshake_timer_;
    std::future<void> cleanup_future_;
    std::future<void> keepalive_future_;
    std::future<void> stats_future_;
    std::future<void> handshake_future_;

    TunnelZone *zone_ = nullptr;

    clv::RateLimiter<> unexpected_data_on_control_limiter_{std::chrono::seconds{1}};

  private:
    void LoadTlsCryptKeys();
};

} // namespace clv::vpn

#endif // CLV_VPN_SERVER_CONTROL_BASE_H
