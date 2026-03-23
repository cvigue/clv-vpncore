// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_VPN_SERVER_H
#define CLV_VPN_VPN_SERVER_H

#include "ip_pool_manager.h"
#include "cpu_affinity.h"
#include "data_path_stats.h"
#include "log_subsystems.h"
#include "openvpn/connection.h"
#include "openvpn/config_exchange.h"
#include "openvpn/data_path_engine.h"
#include "openvpn/packet.h"
#include "openvpn/session_manager.h"
#include "openvpn/tls_crypt.h"
#include "openvpn/vpn_config.h"
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <span>
#include <string_view>
#include <transport/udp_batch.h>
#include "routing_table.h"
#include "scoped_proc_toggle.h"
#include "scoped_masquerade.h"
#include "transport/batch_constants.h"
#include "transport/listener.h"
#include "transport/packet_arena.h"
#include "transport/transport.h"
#include <tun/tun_device.h>

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace clv::vpn {

/**
 * @brief OpenVPN server implementation
 *
 * Integrates all VPN components to create a working OpenVPN server:
 * - UDP socket for client connections
 * - Control channel for TLS handshake
 * - Data channel for encrypted packets
 * - Configuration exchange
 * - TUN device for IP packet forwarding
 */
class VpnServer
{
  public:
    /**
     * @brief Construct VPN server
     * @param io_context ASIO I/O context
     * @param config Server configuration
     */
    VpnServer(asio::io_context &io_context, const VpnConfig &config);

    /**
     * @brief Destructor - cleanup resources
     */
    ~VpnServer();

    // Non-copyable, non-move
    VpnServer(const VpnServer &) = delete;
    VpnServer &operator=(const VpnServer &) = delete;
    VpnServer(VpnServer &&) noexcept = delete;
    VpnServer &operator=(VpnServer &&) noexcept = delete;

    /**
     * @brief Start the VPN server
     *
     * Initializes:
     * - UDP socket listening on configured port
     * - TUN device with server IP
     * - TLS context with certificates
     *
     * @throws std::system_error on initialization failure
     */
    void Start();

    /**
     * @brief Stop the VPN server
     *
     * Gracefully shuts down connections and releases resources.
     */
    void Stop();

    /**
     * @brief Check if server is running
     */
    bool IsRunning() const
    {
        return running_;
    }

    /**
     * @brief Get server configuration
     */
    const VpnConfig &GetConfig() const
    {
        return config_;
    }

  private:
    /**
     * @brief Compute the effective batch size from a raw config value.
     *
     * Returns the configured batch_size clamped to kMaxBatchSize,
     * or kDefaultBatchSize if the value is 0 or negative.
     * Static so it can be used in the constructor initializer list.
     */
    static std::size_t EffectiveBatchSize(int configValue)
    {
        if (configValue <= 0)
            return transport::kDefaultBatchSize;
        return std::min(static_cast<std::size_t>(configValue), transport::kMaxBatchSize);
    }

    /// @brief Convenience overload returning the current batch depth.
    std::size_t EffectiveBatchSize() const
    {
        return currentBatchSize_;
    }

    /**
     * @brief Initialize TUN device with server configuration
     */
    void InitializeTunDevice();



    /**
     * @brief Start receiving UDP packets from network
     */
    asio::awaitable<void> UdpReceiveLoop();

    /**
     * @brief Accept incoming TCP connections and spawn per-client receivers
     */
    asio::awaitable<void> TcpAcceptLoop();

    /**
     * @brief Per-client TCP receive loop
     * @param tcpTransport The accepted TCP transport for this client
     */
    asio::awaitable<void> TcpClientReceiveLoop(transport::TcpTransport tcpTransport);

    /**
     * @brief Periodic cleanup of stale sessions
     */
    asio::awaitable<void> SessionCleanupLoop();

    /**
     * @brief Periodic keepalive PING for active sessions
     */
    asio::awaitable<void> KeepAliveLoop();

    /**
     * @brief Periodic data-path stats logging (when enabled via config)
     */
    asio::awaitable<void> StatsLoop();

    /**
     * @brief Process incoming packet from network
     * @param data Packet data
     * @param sender Peer endpoint (transport-agnostic)
     * @param transport Transport handle for responding to this peer
     */
    asio::awaitable<void> ProcessNetworkPacket(std::vector<std::uint8_t> data,
                                               transport::PeerEndpoint sender,
                                               transport::TransportHandle transport);

    /**
     * @brief Wrap packet with TLS-Crypt and send via session's transport
     * @param data Packet data to send
     * @param session Client session (provides transport handle)
     */
    asio::awaitable<void> SendWrappedPacket(std::vector<std::uint8_t> data,
                                            Connection *session);

    /**
     * @brief Encrypt data via a session's TLS tunnel and send
     *
     * Handles the full send path: TLS encrypt → split into control packets → wrap → send.
     * Sends fragments sequentially (required for TCP stream ordering).
     *
     * @param session Client session (provides the control channel and transport)
     * @param data Plaintext data to encrypt and send
     * @param description Human-readable label for log messages (e.g., "PUSH_REPLY")
     * @return true if at least one packet was sent
     */
    asio::awaitable<bool> SendTlsControlData(Connection *session,
                                             std::span<const std::uint8_t> data,
                                             std::string_view description);

    /**
     * @brief Derive and install data channel keys for a session
     * @param session Client session
     * @return true if keys were derived and installed successfully
     */
    bool DeriveAndInstallKeys(Connection *session);

    /**
     * @brief Handle control packet dispatching and TLS handshake flow
     * @param session Session pointer (may be nullptr on entry)
     * @param packet Parsed OpenVPN control packet
     * @param sender Peer endpoint
     * @param endpoint Connection endpoint
     */
    asio::awaitable<void> HandleControlPacket(Connection *session,
                                              const openvpn::OpenVpnPacket &packet,
                                              const transport::PeerEndpoint &sender,
                                              const Connection::Endpoint &endpoint,
                                              transport::TransportHandle transport);

    /**
     * @brief Handle hard reset (connection initiation)
     * @param packet Parsed OpenVPN packet
     * @param sender Peer endpoint
     * @param endpoint Connection endpoint
     * @return Session pointer (new or existing)
     */
    asio::awaitable<Connection *> HandleHardReset(const openvpn::OpenVpnPacket &packet,
                                                     const transport::PeerEndpoint &sender,
                                                     const Connection::Endpoint &endpoint,
                                                     transport::TransportHandle transport);

    /**
     * @brief Handle soft reset (key renegotiation)
     * @param session Client session
     * @param packet Parsed OpenVPN packet
     */
    asio::awaitable<void> HandleSoftReset(Connection *session,
                                          const openvpn::OpenVpnPacket &packet);

    /**
     * @brief Process TLS plaintext received via DispatchSessionControlPacket.
     *
     * Dispatches to HandleKeyMethod2 (first plaintext after handshake)
     * or HandlePushRequest (subsequent application messages).
     * Always calls EnsureIpAllocated after processing.
     *
     * @param session Client session
     * @param plaintext Decrypted plaintext from TLS engine
     */
    asio::awaitable<void> ProcessPlaintext(Connection *session,
                                           std::vector<std::uint8_t> plaintext);

    /**
     * @brief Handle key-method 2 exchange
     * @param session Client session
     * @param plaintext Plaintext data from TLS
     */
    asio::awaitable<void> HandleKeyMethod2(Connection *session,
                                           const std::vector<uint8_t> &plaintext);

    /**
     * @brief Handle PUSH_REQUEST
     * @param session Client session
     */
    asio::awaitable<void> HandlePushRequest(Connection *session);

    /**
     * @brief Process a single inbound data-path slot from the UDP arena.
     *
     * Performs session lookup, decrypt-in-place, and returns the plaintext
     * span for TUN write.  Called from the hot loop in UdpReceiveLoop.
     *
     * @param slot  The arena slot containing a received datagram.
     * @return Span to decrypted plaintext within the slot, or empty on skip/error.
     */
    std::span<std::uint8_t> ProcessInboundDataSlot(transport::IncomingSlot &slot);

    /**
     * @brief Handle encrypted data packets
     * @param session Client session
     * @param packet Parsed OpenVPN packet
     */
    asio::awaitable<void> HandleDataPacket(Connection *session,
                                           const openvpn::OpenVpnPacket &packet);

    /**
     * @brief Ensure client has an IP address allocated
     * @param session Client session
     */
    void EnsureIpAllocated(Connection *session);

  private:                                                     // Data members
    asio::io_context &io_context_;                             ///< ASIO I/O context
    VpnConfig config_;                                         ///< Server configuration
    logging::SubsystemLoggerManager logger_manager_;           ///< Subsystem logger management
    transport::ServerListener listener_;                       ///< Network listener (UDP or TCP)
    SessionManager session_manager_;                           ///< Multi-client session management
    RoutingTableIpv4 routing_table_;                           ///< IPv4 routing table for client sessions
    RoutingTableIpv6 routing_table_v6_;                        ///< IPv6 routing table for client sessions
    std::unique_ptr<IpPoolManager> ip_pool_;                   ///< IP address pool manager
    std::unique_ptr<openvpn::ConfigExchange> config_exchange_; ///< Configuration exchange handler
    std::optional<openvpn::TlsCrypt> tls_crypt_;               ///< TLS-Crypt for control channel encryption (mandatory, always initialized)
    std::shared_ptr<spdlog::logger> logger_;                   ///< Structured logger (must be initialized before data_channel_strategy_)

    DataPathStats stats_;                                          ///< Data-path performance counters (single-threaded, no locking)
    StatsObserver stats_observer_{stats_};                         ///< Windowed stats observer (single-thread, shared by StatsLoop + UdpReceiveLoop)
    std::size_t currentBatchSize_ = 0;                             ///< Current recvmmsg batch depth
    std::size_t processQuanta_ = transport::kDefaultProcessQuanta; ///< Max packets per event-loop yield

    std::atomic<bool> running_ = false; ///< Server running flag

    // Data channel strategy (userspace vs DCO)
    DataPathEngine data_channel_strategy_;

    // Zero-copy inbound arena: recvmmsg → decrypt-in-place → writev to TUN
    transport::PacketArena inbound_arena_;
    std::vector<transport::IncomingSlot> inbound_slots_;

    // RAII network configuration guards (order matters: destroyed in reverse)
    std::optional<ScopedMasquerade> masquerade_guard_;   ///< IPv4 NAT masquerade rule
    std::optional<ScopedMasquerade> masquerade6_guard_;  ///< IPv6 NAT masquerade rule
    std::optional<ScopedIpForward> ip_forward_guard_;    ///< IPv4 forwarding
    std::optional<ScopedIpv6Forward> ip6_forward_guard_; ///< IPv6 forwarding

    // Timers for periodic coroutines (members so Stop() can cancel them)
    asio::steady_timer cleanup_timer_; ///< Timer for SessionCleanupLoop
    asio::steady_timer stats_timer_;   ///< Timer for StatsLoop
};

} // namespace clv::vpn

#endif // CLV_VPN_VPN_SERVER_H
