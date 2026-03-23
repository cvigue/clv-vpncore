// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_USERSPACE_DATA_CHANNEL_H
#define CLV_VPN_USERSPACE_DATA_CHANNEL_H

#include "client_session.h"
#include "openvpn/packet.h"
#include "session_manager.h"
#include "../routing_table.h"
#include "../data_path_stats.h"
#include "transport/batch_constants.h"
#include "util/ipv6_utils.h"
#include <atomic>
#include <cstddef>
#include <span>
#include <tun/tun_device.h>
#include <transport/transport.h>
#include <transport/udp_batch.h>
#include <transport/packet_arena.h>

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <spdlog/logger.h>
#include <not_null.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace clv::vpn {

namespace openvpn {
struct OpenVpnPacket;
enum class CipherAlgorithm;
enum class HmacAlgorithm;
} // namespace openvpn

/**
 * @brief Userspace data channel implementation (TUN-based)
 *
 * Handles data packet encryption/decryption in userspace and forwards
 * to/from TUN device. This is the traditional OpenVPN data path.
 */
class UserspaceDataChannel
{
  public:
    /**
     * Callback invoked when a peer is considered dead (keepalive timeout).
     * Parameter is the dead peer's SessionId.
     */
    using DeadPeerCallback = std::function<void(openvpn::SessionId)>;

    /**
     * @brief Construct userspace data channel
     * @param io_context ASIO I/O context
     * @param tun_device TUN device for IP packet forwarding
     * @param routing_table Routing table for session lookup
     * @param session_manager Session manager for session lookup
     * @param logger Logger instance
     * @param stats Data-path stats
     * @param stats_observer Windowed stats observer for histogram tracking
     * @param batchSize Batch depth for TUN read / UDP send
     * @param processQuanta Max packets per event-loop yield (0 = default 128)
     * @param keepalive_interval Keepalive ping interval (seconds, 0 = disabled)
     * @param keepalive_timeout Keepalive timeout before peer considered dead (seconds)
     * @param running_flag Reference to the server's running flag
     */
    UserspaceDataChannel(asio::io_context &io_context,
                         std::unique_ptr<tun::TunDevice> &tun_device,
                         RoutingTableIpv4 &routing_table,
                         RoutingTableIpv6 &routing_table_v6,
                         SessionManager &session_manager,
                         spdlog::logger &logger,
                         DataPathStats &stats,
                         StatsObserver &stats_observer,
                         std::size_t batchSize,
                         std::size_t processQuanta,
                         int keepalive_interval,
                         int keepalive_timeout,
                         const std::atomic<bool> &running_flag);

    /**
     * @brief Process incoming data packet from network
     * @param session Client session
     * @param packet Parsed OpenVPN data packet
     */
    asio::awaitable<void> ProcessIncomingDataPacket(ClientSession *session,
                                                    const openvpn::OpenVpnPacket &packet);

    /**
     * @brief Decrypt and strip compression framing in-place (synchronous)
     *
     * Like ProcessIncomingDataPacketInPlace but does NOT write to TUN.
     * Returns the plaintext IP span within the datagram buffer, ready for
     * batch TUN writing by the caller. No coroutine overhead.
     *
     * Handles: decrypt, anti-replay, keepalive detection, compression strip.
     *
     * @param session Client session (must have valid data channel keys)
     * @param datagram Raw UDP datagram buffer (P_DATA_V2 wire format).
     *                 Modified in-place.
     * @return Span over decrypted IP data within datagram, or empty on
     *         error / keepalive / too-small packet.
     */
    std::span<std::uint8_t> DecryptAndStripInPlace(ClientSession *session,
                                                   std::span<std::uint8_t> datagram);

    /**
     * @brief Process outgoing packet from TUN device
     * @param packet IP packet from TUN device
     */
    asio::awaitable<void> ProcessOutgoingTunPacket(tun::IpPacket packet);

    /**
     * @brief Start receiving packets from TUN device
     */
    asio::awaitable<void> StartTunReceiver();

    /**
     * @brief Install session keys for data channel encryption
     * @param session Client session
     * @param key_material Derived key material
     * @param cipher_algo Cipher algorithm to use
     * @param hmac_algo HMAC algorithm to use
     * @param key_id Key ID for this key set
     * @param lame_duck_seconds Grace period for old keys
     * @return true if keys were installed successfully
     */
    bool InstallKeys(ClientSession *session,
                     const std::vector<uint8_t> &key_material,
                     openvpn::CipherAlgorithm cipher_algo,
                     openvpn::HmacAlgorithm hmac_algo,
                     std::uint8_t key_id,
                     int lame_duck_seconds);

    /**
     * @brief Send encrypted keepalive PING to a client
     *
     * Encrypts the raw 16-byte KEEPALIVE_PING magic as a P_DATA_V2 packet
     * and sends it directly over the session's transport. No IPv4 wrapping,
     * no TUN roundtrip — the client decrypts and recognises the magic bytes.
     *
     * @param session Client session (must have transport and valid keys)
     */
    asio::awaitable<void> SendKeepAlivePing(ClientSession *session);

    /**
     * @brief Run the keepalive monitor coroutine
     *
     * Periodically iterates all sessions, sends keepalive PINGs to idle ones,
     * and detects dead peers by checking GetLastActivity() against the timeout.
     * Dead peers are reported via @p on_dead_peer.
     *
     * This coroutine runs for the lifetime of the server.
     *
     * @param on_dead_peer Callback invoked with the SessionId of each dead peer
     */
    asio::awaitable<void> RunKeepaliveMonitor(DeadPeerCallback on_dead_peer);

    /**
     * @brief Cancel the keepalive monitor's blocking timer.
     *
     * Wakes the RunKeepaliveMonitor coroutine so it can observe running_==false
     * and exit cleanly. Safe to call before RunKeepaliveMonitor has started.
     */
    void StopKeepaliveMonitor();

    /**
     * @brief Stop the TUN receiver loop
     *
     * Sets internal flag and closes the TUN device to interrupt any
     * pending async read, causing the StartTunReceiver coroutine to
     * observe operation_aborted and exit cleanly.
     * Safe to call multiple times.
     */
    void StopTunReceiver()
    {
        tun_running_ = false;
        if (tun_device_)
            tun_device_->Close();
    }

    /**
     * @brief Update the batch size at runtime.
     *
     * Takes effect on the next TUN read iteration. Clamped to kMaxBatchSize.
     */
    void SetBatchSize(std::size_t newSize)
    {
        batchSize_ = std::min(newSize, transport::kMaxBatchSize);
    }

    /// @brief Get the current batch size.
    std::size_t GetBatchSize() const
    {
        return batchSize_;
    }

    /// @brief Return a point-in-time copy of the live stats counters.
    DataPathStats SnapshotStats() const
    {
        return stats_; // copy of the monotonic counters
    }

    /**
     * @brief Check if this strategy requires TUN device
     */
    static constexpr bool RequiresTunDevice()
    {
        return true;
    }

  private:
    /// @brief Result of encrypting a TUN packet for outbound UDP sending.
    struct PreparedPacket
    {
        std::vector<std::uint8_t> encrypted; ///< Encrypted OpenVPN datagram
        transport::PeerEndpoint dest;        ///< Client UDP endpoint
        int socketFd = -1;                   ///< Socket fd for sendmmsg
    };

    /// @brief Intermediate result from EncryptTunPacket — encrypted data + owning session.
    struct EncryptedResult
    {
        std::vector<std::uint8_t> encrypted;
        ClientSession *session; ///< Non-owning pointer; valid for lifetime of this event-loop tick
    };

    /**
     * @brief Route-lookup + session-validate + compress + encrypt a TUN packet.
     *
     * Shared logic extracted from ProcessOutgoingTunPacket (coroutine) and
     * PrepareOutgoingPacket (synchronous batch path).
     *
     * @param packet IP packet from TUN (data may be moved-from on success)
     * @return Encrypted result, or nullopt on any failure (logged inside)
     */
    std::optional<EncryptedResult> EncryptTunPacket(tun::IpPacket &packet);

    /**
     * @brief Encrypt a TUN packet for a specific client, without sending.
     *
     * Performs route lookup, session lookup, compression framing, and
     * encryption. Returns the fully-formed encrypted datagram + destination
     * so the caller can batch multiple packets into a single sendmmsg.
     *
     * @param packet IP packet from TUN
     * @return Encrypted packet + destination, or nullopt on any failure
     */
    std::optional<PreparedPacket> PrepareOutgoingPacket(tun::IpPacket &packet);

    /**
     * @brief Extract destination IPv4 address from packet
     * @param packet IP packet
     * @return Destination IP in host byte order, or nullopt if invalid
     */
    static std::optional<uint32_t> ExtractDestIpv4(const tun::IpPacket &packet);

    /**
     * @brief Extract destination IPv6 address from an IP packet
     * @param packet TUN IP packet
     * @return Destination IPv6 (16 bytes, network byte order), or nullopt if not IPv6
     */
    static std::optional<ipv6::Ipv6Address> ExtractDestIpv6(const tun::IpPacket &packet);

    /**
     * @brief Send packet to TUN device
     * @param packet IP packet
     */
    asio::awaitable<void> SendToTun(const tun::IpPacket &packet);

  private:
    asio::io_context &io_context_;
    std::unique_ptr<tun::TunDevice> &tun_device_;
    RoutingTableIpv4 &routing_table_;
    RoutingTableIpv6 &routing_table_v6_;
    SessionManager &session_manager_;
    clv::not_null<spdlog::logger *> logger_;
    DataPathStats &stats_;
    StatsObserver &stats_observer_;
    std::size_t batchSize_;     ///< Runtime batch depth for TUN read / UDP send
    std::size_t processQuanta_; ///< Max packets per event-loop yield
    std::chrono::seconds keepalive_interval_;
    std::chrono::seconds keepalive_timeout_;
    const std::atomic<bool> &running_; ///< Reference to server's running flag
    bool tun_running_ = true;
    asio::steady_timer keepalive_timer_; ///< Timer for RunKeepaliveMonitor (member for cancellation)

    // Pre-allocated vectors reused every batch iteration to avoid heap churn
    // on the hot path.  Cleared (but not freed) at the start of each loop.
    std::vector<PreparedPacket> prepared_;
    std::vector<transport::SendEntry> sendEntries_;

    // Zero-copy arena: contiguous memory for TUN read → encrypt → sendmmsg
    transport::PacketArena outbound_arena_;
    std::vector<tun::TunDevice::SlotBuffer> tun_slots_;

    // Per-slot metadata for the outbound arena batch (tracks wire length + dest)
    struct ArenaEntry
    {
        std::size_t wire_len = 0;         ///< Total wire packet length in arena slot
        transport::PeerEndpoint dest;     ///< UDP destination
        int socketFd = -1;                ///< Socket fd
        ClientSession *session = nullptr; ///< For UpdateLastOutbound
    };
    std::vector<ArenaEntry> arena_entries_;
};

} // namespace clv::vpn

#endif // CLV_VPN_USERSPACE_DATA_CHANNEL_H
