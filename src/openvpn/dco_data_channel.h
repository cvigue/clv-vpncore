// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_DCO_DATA_CHANNEL_H
#define CLV_VPN_DCO_DATA_CHANNEL_H

#include "client_session.h"
#include "data_path_stats.h"
#include <cstddef>
#include <span>
#include <util/netlink_helper.h>
#include "openvpn/packet.h"
#include "session_manager.h"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <spdlog/logger.h>
#include <not_null.h>

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace clv::vpn {

namespace openvpn {
struct OpenVpnPacket;
enum class CipherAlgorithm;
enum class HmacAlgorithm;
} // namespace openvpn

namespace tun {
struct IpPacket;
class TunDevice;
} // namespace tun

/**
 * @brief Data Channel Offload (DCO) implementation using ovpn-dco kernel module
 *
 * Offloads data packet encryption/decryption to the Linux kernel for improved
 * performance. Control channel remains in userspace.
 *
 * Benefits:
 * - 2-5x+ throughput via kernel fast path
 * - Hardware crypto acceleration (AES-NI)
 * - Zero-copy packet forwarding
 * - Lower CPU usage
 *
 * Requirements:
 * - Linux kernel 5.4+ with ovpn-dco module
 * - Netlink for kernel communication
 */
class DcoDataChannel
{
  public:
    /**
     * @brief Network configuration for DCO interface
     */
    struct NetworkConfig
    {
        std::string server_network;    ///< CIDR notation, e.g., "10.8.0.0/24"
        std::string server_ip;         ///< Server's VPN IP, e.g., "10.8.0.1"
        std::string server_network_v6; ///< IPv6 CIDR notation, e.g., "fd00::/112" (empty = disabled)
        uint32_t keepalive_interval;   ///< Keepalive ping interval in seconds (0 = disabled)
        uint32_t keepalive_timeout;    ///< Keepalive timeout in seconds (0 = disabled)
    };

    /**
     * Callback invoked when a peer is considered dead (kernel notification).
     * Parameter is the dead peer's SessionId.
     */
    using DeadPeerCallback = std::function<void(openvpn::SessionId)>;

    /**
     * @brief Construct DCO data channel
     * @param io_context ASIO I/O context (for async multicast listener)
     * @param socket UDP socket for peer socket FD extraction
     * @param network_config Network configuration for DCO interface
     * @param logger Logger instance
     * @param running_flag Reference to the server's running flag
     */
    DcoDataChannel(asio::io_context &io_context,
                   asio::ip::udp::socket &socket,
                   const NetworkConfig &network_config,
                   spdlog::logger &logger,
                   const bool &running_flag);

    /**
     * @brief Destructor - cleans up DCO device and sockets
     */
    ~DcoDataChannel();

    // Non-copyable, non-movable (owns kernel resources)
    DcoDataChannel(const DcoDataChannel &) = delete;
    DcoDataChannel &operator=(const DcoDataChannel &) = delete;
    DcoDataChannel(DcoDataChannel &&) = delete;
    DcoDataChannel &operator=(DcoDataChannel &&) = delete;

    /**
     * @brief Process incoming data packet from network
     * @param session Client session
     * @param packet Parsed OpenVPN data packet
     *
     * In DCO mode, this is a no-op since kernel handles decryption.
     */
    asio::awaitable<void> ProcessIncomingDataPacket(ClientSession *session,
                                                    const openvpn::OpenVpnPacket &packet);

    /**
     * @brief Synchronous in-place decrypt (DCO mode — no-op)
     *
     * DCO handles decryption in kernel space. Returns empty span.
     */
    std::span<std::uint8_t> DecryptAndStripInPlace(ClientSession * /*session*/,
                                                   std::span<std::uint8_t> /*datagram*/)
    {
        return {}; // no-op in DCO mode
    }

    /**
     * @brief Process outgoing packet from TUN device
     * @param packet IP packet from TUN device
     *
     * In DCO mode, this is a no-op since kernel handles encryption.
     */
    asio::awaitable<void> ProcessOutgoingTunPacket(tun::IpPacket packet);

    /**
     * @brief Start receiving packets from TUN device
     *
     * In DCO mode, no userspace TUN receiver needed (kernel handles it).
     */
    asio::awaitable<void> StartTunReceiver();

    /**
     * @brief Stop the TUN receiver loop
     *
     * In DCO mode, this is a no-op since there is no userspace receiver loop.
     */
    void StopTunReceiver()
    { /* no-op in DCO mode */
    }

    /// @brief No-op — DCO handles batching in kernel.
    void SetBatchSize(std::size_t)
    { /* no-op */
    }

    /// @brief DCO doesn't have a userspace batch size — returns 0.
    std::size_t GetBatchSize() const
    {
        return 0;
    }

    /**
     * @brief Query kernel for aggregate per-peer traffic stats.
     *
     * Sends OVPN_CMD_GET_PEER with NLM_F_DUMP to fetch all peers,
     * sums their counters, and returns a DataPathStats with the
     * link-level and VPN-level byte / packet totals.
     *
     * Fields that DCO doesn't track (batch metrics, route misses, etc.)
     * are left at zero.
     */
    DataPathStats SnapshotStats() const;

    /**
     * @brief Install session keys for data channel encryption
     * @param session Client session
     * @param key_material Derived key material
     * @param cipher_algo Cipher algorithm to use
     * @param hmac_algo HMAC algorithm to use
     * @param key_id Key ID for this key set
     * @param lame_duck_seconds Grace period for old keys
     * @return true if keys were installed successfully
     *
     * Uses netlink to push keys to ovpn-dco kernel module.
     */
    bool InstallKeys(ClientSession *session,
                     const std::vector<uint8_t> &key_material,
                     openvpn::CipherAlgorithm cipher_algo,
                     openvpn::HmacAlgorithm hmac_algo,
                     std::uint8_t key_id,
                     int lame_duck_seconds);

    /**
     * @brief Send keepalive PING (DCO mode — no-op)
     *
     * In DCO mode the kernel sends PINGs autonomously via the timers set
     * by SetPeerKeepalive(). This method exists only to satisfy the
     * DataChannelStrategy interface.
     *
     * @param session Client session
     */
    asio::awaitable<void> SendKeepAlivePing(ClientSession *session);

    /**
     * @brief Run the keepalive monitor coroutine (DCO mode)
     *
     * Subscribes to the ovpn-dco-v2 generic netlink multicast group "peers"
     * and awaits OVPN_CMD_DEL_PEER notifications. When the kernel reports a
     * peer death (timeout, transport error, etc.), invokes @p on_dead_peer
     * with the corresponding SessionId.
     *
     * @param on_dead_peer Callback invoked with the SessionId of each dead peer
     */
    asio::awaitable<void> RunKeepaliveMonitor(DeadPeerCallback on_dead_peer);

    /**
     * @brief Check if this strategy requires TUN device
     *
     * DCO manages its own network device in kernel space.
     */
    static constexpr bool RequiresTunDevice()
    {
        return false;
    }

  private:
    /**
     * @brief Initialize ovpn-dco kernel module communication
     * @throws std::system_error on socket/ioctl failures
     * @throws std::runtime_error on netlink/config failures
     */
    void InitializeDco();

    /**
     * @brief Create DCO peer for client session
     * @param session Client session
     * @return true if peer was created successfully
     */
    bool CreateDcoPeer(ClientSession *session);

    /**
     * @brief Remove DCO peer for client session
     * @param session Client session
     */
    void RemoveDcoPeer(ClientSession *session);

    /**
     * @brief Create DCO device via rtnetlink
     * @throws std::system_error on socket/netlink failures
     * @throws std::runtime_error on buffer overflow
     */
    void CreateDcoDevice();

    /**
     * @brief Destroy DCO device via rtnetlink
     */
    void DestroyDcoDevice();

    /**
     * @brief Configure DCO interface (IP address, bring up)
     * @throws std::system_error on socket/ioctl failures
     * @throws std::runtime_error on CIDR parse failure
     */
    void ConfigureDcoInterface();

    /**
     * @brief Push encryption keys to kernel via generic netlink
     * @param session Client session
     * @param key_material Derived key material
     * @param cipher_algo Cipher algorithm
     * @param key_id Key ID
     * @return true if keys were pushed successfully
     */
    bool PushKeysToKernel(ClientSession *session,
                          const std::vector<uint8_t> &key_material,
                          openvpn::CipherAlgorithm cipher_algo,
                          std::uint8_t key_id,
                          uint8_t key_slot);

    /**
     * @brief Swap primary and secondary key slots for a peer
     * @param session Client session
     * @return true if swap succeeded
     */
    bool SwapKeys(ClientSession *session);

    /**
     * @brief Configure kernel keepalive timers for a DCO peer
     *
     * Sends OVPN_CMD_SET_PEER with keepalive interval/timeout.
     * The kernel then autonomously sends KEEPALIVE_PING using
     * its own packet ID counter.
     *
     * @param session Client session (peer must already exist)
     * @return true if the netlink command succeeded
     */
    bool SetPeerKeepalive(ClientSession *session);

  public:
    /**
     * @brief Get the DCO peer ID for a session
     * @param session Client session
     * @return Peer ID (derived from session ID)
     */
    uint32_t GetPeerId(ClientSession *session) const;

  private:
    asio::io_context &io_context_;
    asio::ip::udp::socket &socket_;
    NetworkConfig network_config_; ///< Network configuration for DCO interface
    clv::not_null<spdlog::logger *> logger_;
    const bool &running_;

    bool dco_initialized_ = false;
    int dco_ifindex_ = -1;                                             ///< DCO network interface index
    std::string dco_ifname_ = "ovpn-dco0";                             ///< DCO network interface name
    uint16_t genl_family_id_ = 0;                                      ///< Generic netlink family ID for ovpn-dco-v2
    NetlinkHelper netlink_helper_;                                     ///< Generic netlink helper for DCO communication
    std::unordered_set<uint32_t> created_peers_;                       ///< Track created peer IDs
    std::unordered_map<uint32_t, uint8_t> peer_primary_key_;           ///< Track current primary key_id per peer
    std::unordered_map<uint32_t, openvpn::SessionId> peer_to_session_; ///< Reverse map: peer_id → SessionId
};

} // namespace clv::vpn

#endif // CLV_VPN_DCO_DATA_CHANNEL_H
