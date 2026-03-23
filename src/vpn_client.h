// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_VPN_CLIENT_H
#define CLV_VPN_VPN_CLIENT_H

#include "openvpn/crypto_algorithms.h"
#include "openvpn/vpn_config.h"
#include "openvpn/control_channel.h"
#include "openvpn/data_channel.h"
#include "openvpn/config_exchange.h"
#include "openvpn/packet.h"
#include "openvpn/tls_crypt.h"
#include "data_path_stats.h"

#include "transport/packet_arena.h"
#include "transport/udp_batch.h"
#include "transport/transport.h"
#include <tun/tun_device.h>
#include <util/netlink_helper.h>

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <atomic>
#include <span>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace clv::vpn {

// Forward declarations
class SslHandshakeContext;

/**
 * @brief Convenience loader — produces a VpnConfig with client role populated.
 *
 * Static methods load from JSON, .ovpn, or auto-detect format.
 * The returned VpnConfig always has client populated; crypto, performance,
 * and logging are filled from the same source file.
 */
struct VpnClientConfig
{
    /// Parse client configuration from a JSON object.
    static VpnConfig ParseJson(const nlohmann::json &json);

    /// Load configuration from JSON file.
    static VpnConfig LoadFromFile(const std::string &path);

    /// Load configuration from .ovpn file.
    static VpnConfig LoadFromOvpnFile(const std::string &path);

    /// Auto-detect format (.ovpn vs JSON) and load.
    static VpnConfig Load(const std::string &path);
};

/**
 * @brief Connection state for the VPN client
 */
enum class VpnClientState
{
    Disconnected,   ///< Not connected
    Connecting,     ///< Connection in progress
    TlsHandshake,   ///< TLS handshake in progress
    Authenticating, ///< Waiting for PUSH_REPLY
    Connected,      ///< Fully connected, data channel active
    Reconnecting,   ///< Connection lost, attempting reconnect
    Error           ///< Connection failed
};

/**
 * @brief Convert state to string for logging
 */
const char *VpnClientStateToString(VpnClientState state);

/**
 * @brief OpenVPN client implementation with high-performance data path
 *
 * Connects to an OpenVPN server using the same protocol components as VpnServer:
 * - ControlChannel for TLS handshake (client role)
 * - DataChannel for encrypted packets (AEAD, in-place crypto)
 * - TlsCrypt for control channel encryption
 * - TunDevice for IP packet forwarding
 *
 * ## Data Path Modes
 *
 * **Userspace mode** (default):
 * - Zero-copy arena-based receive: recvmmsg -> in-place decrypt -> writev to TUN
 * - Batch TUN read: ReadBatchInto -> in-place encrypt -> sendmmsg to server
 * - Configurable batch depth and process quanta
 *
 * **DCO mode** (when enabled and available):
 * - Creates ovpn-dco device in P2P mode
 * - Kernel handles encrypt/decrypt and TUN forwarding
 * - Userspace only processes control channel (TLS handshake, keepalive)
 * - 2-5x+ throughput improvement
 *
 * ## Connection Flow
 *
 * 1. Send P_CONTROL_HARD_RESET_CLIENT_V2
 * 2. Receive P_CONTROL_HARD_RESET_SERVER_V2
 * 3. TLS handshake (client role)
 * 4. Key-method 2 exchange -> derive data channel keys
 * 5. Send PUSH_REQUEST
 * 6. Receive PUSH_REPLY with IP/routes/DNS
 * 7. Configure TUN/DCO device
 * 8. Start data channel (batch loops or kernel offload)
 */
class VpnClient
{
  public:
    /**
     * @brief Construct VPN client
     * @param io_context ASIO I/O context
     * @param config Client configuration
     */
    VpnClient(asio::io_context &io_context, const VpnConfig &config);

    /**
     * @brief Destructor - cleanup resources
     */
    ~VpnClient();

    // Non-copyable, non-movable
    VpnClient(const VpnClient &) = delete;
    VpnClient &operator=(const VpnClient &) = delete;
    VpnClient(VpnClient &&) noexcept = delete;
    VpnClient &operator=(VpnClient &&) noexcept = delete;

    /// Callback type for state changes: (old_state, new_state).
    using StateCallback = std::function<void(VpnClientState, VpnClientState)>;

    /**
     * @brief Register a callback invoked on every state transition.
     * @param cb Callback receiving (old_state, new_state). Called on the
     *           io_context thread; keep it lightweight.
     */
    void SetStateCallback(StateCallback cb)
    {
        state_callback_ = std::move(cb);
    }

    /**
     * @brief Connect to the VPN server
     *
     * Initiates connection and runs until connected or failed.
     * Returns immediately; use state callbacks or poll GetState().
     *
     * @throws std::system_error on initialization failure
     */
    void Connect();

    /**
     * @brief Disconnect from the VPN server
     *
     * Gracefully closes the connection and releases resources.
     */
    void Disconnect();

    /**
     * @brief Get current connection state
     */
    VpnClientState GetState() const
    {
        return state_;
    }

    /**
     * @brief Check if client is connected
     */
    bool IsConnected() const
    {
        return state_ == VpnClientState::Connected;
    }

    /**
     * @brief Get assigned VPN IP address (after connected)
     * @return Assigned IP, or empty if not connected
     */
    std::string GetAssignedIp() const
    {
        return config_exchange_.GetNegotiatedConfig().ifconfig.first;
    }

    /**
     * @brief Get server-pushed routes (after connected)
     */
    std::vector<std::string> GetRoutes() const
    {
        std::vector<std::string> result;
        for (const auto &[network, gw, metric] : config_exchange_.GetNegotiatedConfig().routes)
            result.push_back(network);
        return result;
    }

    /**
     * @brief Get server-pushed DNS servers (after connected)
     */
    std::vector<std::string> GetDnsServers() const
    {
        std::vector<std::string> result;
        for (const auto &[type, value] : config_exchange_.GetNegotiatedConfig().dhcp_options)
            if (type == "DNS")
                result.push_back(value);
        return result;
    }

    /**
     * @brief Get configuration
     */
    const VpnConfig &GetConfig() const
    {
        return config_;
    }

    // ========== Statistics ==========

    /**
     * @brief Get bytes sent through data channel
     */
    std::uint64_t GetBytesSent() const
    {
        return stats_.bytesSent;
    }

    /**
     * @brief Get bytes received through data channel
     */
    std::uint64_t GetBytesReceived() const
    {
        return stats_.bytesReceived;
    }

    /**
     * @brief Get connection uptime
     */
    std::chrono::seconds GetUptime() const;

    /**
     * @brief Get data-path stats snapshot
     */
    DataPathStats GetStats() const
    {
        return stats_;
    }

  private:
    // ========== Connection Flow ==========

    /**
     * @brief Main connection coroutine
     */
    asio::awaitable<void> ConnectionLoop();

    /**
     * @brief Reconnect coroutine — waits, tears down existing state, and calls Connect().
     *
     * Spawned when a peer-death or connection error is detected while the client
     * should remain running.  Respects config_.reconnect_delay_seconds and
     * config_.max_reconnect_attempts (0 = unlimited).
     */
    asio::awaitable<void> ReconnectLoop();

    /**
     * @brief Send hard reset to initiate connection
     */
    asio::awaitable<void> SendHardReset();

    /**
     * @brief Process incoming packet from server
     */
    asio::awaitable<void> ProcessServerPacket(std::vector<std::uint8_t> data);

    /**
     * @brief Handle control packet from server
     */
    asio::awaitable<void> HandleControlPacket(const openvpn::OpenVpnPacket &packet);

    /**
     * @brief Handle data packet from server (allocating path, used during handshake or TCP)
     */
    asio::awaitable<void> HandleDataPacket(const openvpn::OpenVpnPacket &packet);

    /**
     * @brief Process TLS handshake data
     */
    asio::awaitable<void> ProcessTlsHandshake();

    /**
     * @brief Process received plaintext from TLS tunnel
     *
     * Handles key-method 2 messages and PUSH_REPLY.
     */
    asio::awaitable<void> ProcessReceivedPlaintext(std::vector<std::uint8_t> plaintext);

    /**
     * @brief Send PUSH_REQUEST after TLS handshake complete
     */
    asio::awaitable<void> SendPushRequest();

    /**
     * @brief Handle PUSH_REPLY from server
     */
    void HandlePushReply(const std::string &reply);

    /**
     * @brief Configure TUN device with pushed settings (userspace mode)
     */
    void ConfigureTunDevice();

    /**
     * @brief Install pushed routes into the OS routing table
     */
    void InstallRoutes();

    /**
     * @brief Derive and install data channel keys
     *
     * In userspace mode, installs keys into DataChannel.
     * In DCO mode, also pushes keys to kernel via netlink.
     */
    bool DeriveAndInstallKeys();

    // ========== High-Performance Data Path (Userspace) ==========

    /**
     * @brief Zero-copy UDP receive loop using recvmmsg + arena
     *
     * Hot path: recvmmsg -> classify packets -> data: in-place decrypt ->
     * batch writev to TUN; control: copy out -> coroutine dispatch.
     * Processes in quanta-sized chunks, yielding between chunks.
     */
    asio::awaitable<void> UdpReceiveLoop();

    /**
     * @brief Batch TUN->Server forwarding loop
     *
     * Hot path: ReadBatchInto arena -> in-place encrypt -> sendmmsg to server.
     * Zero allocations on the data path.
     */
    asio::awaitable<void> TunToServerBatch();

    /**
     * @brief Simple TUN->Server forwarding (TCP fallback / single-packet)
     */
    asio::awaitable<void> TunToServer();

    /**
     * @brief Periodic keepalive PING sender
     */
    asio::awaitable<void> KeepaliveLoop();

    // ========== Connect() Helpers ==========

    /**
     * @brief Create transport (TCP or UDP), connect to server, apply socket buffers
     */
    void InitializeTransport();

    /**
     * @brief Select DCO or userspace data path (with DCO fallback)
     */
    void InitializeDataPath();

    /**
     * @brief Load TLS-Crypt key from inline PEM or file path
     * @return true on success, false on error (state set to Error)
     */
    bool LoadTlsCryptKey();

    /**
     * @brief Initialize TLS control channel with client certificates
     * @return true on success, false on error (state set to Error)
     */
    bool InitializeControlChannel();

    // ========== DCO (Data Channel Offload) ==========



    /**
     * @brief Initialize DCO device in P2P mode
     *
     * Creates the ovpn-dco network device and opens generic netlink
     * for kernel communication. Called during Connect() if DCO is enabled.
     *
     * @throws std::runtime_error on failure
     */
    void InitializeDco();

    /**
     * @brief Create DCO device via rtnetlink (P2P mode)
     */
    void CreateDcoDevice();

    /**
     * @brief Destroy DCO device via rtnetlink
     */
    void DestroyDcoDevice();

    /**
     * @brief Configure DCO interface with assigned IP (called after PUSH_REPLY)
     */
    void ConfigureDcoInterface();

    /**
     * @brief Create DCO peer for the server endpoint
     * @return true on success
     */
    bool CreateDcoPeer();

    /**
     * @brief Push encryption keys to kernel via generic netlink
     * @param key_material Derived key material (256 bytes)
     * @param cipher_algo Cipher algorithm
     * @param key_id Key ID
     * @param key_slot PRIMARY or SECONDARY
     * @return true on success
     */
    bool PushKeysToKernel(const std::vector<std::uint8_t> &key_material,
                          openvpn::CipherAlgorithm cipher_algo,
                          std::uint8_t key_id,
                          std::uint8_t key_slot);

    /**
     * @brief Swap primary and secondary key slots in kernel
     * @return true on success
     */
    bool SwapDcoKeys();

    /**
     * @brief Configure kernel keepalive timers for the server peer
     * @return true on success
     */
    bool SetDcoPeerKeepalive();

    /**
     * @brief Query per-peer traffic counters from kernel (DCO mode)
     * @return Monotonic DataPathStats from the kernel
     */
    DataPathStats QueryDcoStats() const;

    /**
     * @brief Monitor for kernel peer-death notifications (DCO mode)
     */
    asio::awaitable<void> DcoKeepaliveMonitor();

    /**
     * @brief Minimal receive loop for DCO mode (control packets only)
     */
    asio::awaitable<void> DcoReceiveLoop();

    /**
     * @brief Periodic data-path stats logger
     */
    asio::awaitable<void> StatsLoop();

    // ========== Packet Sending ==========

    /**
     * @brief Wrap packet with TLS-Crypt and send to server
     */
    asio::awaitable<void> SendWrappedPacket(std::vector<std::uint8_t> data);

    /**
     * @brief Send raw packet to server (no wrapping)
     */
    asio::awaitable<void> SendRawPacket(std::span<const std::uint8_t> data);

    // ========== State Management ==========

    /**
     * @brief Set connection state and trigger data-path startup when Connected
     */
    void SetState(VpnClientState new_state);

    /// User-registered state-change callback (may be empty).
    StateCallback state_callback_;

    /**
     * @brief Compute the effective batch size from config
     */
    std::size_t EffectiveBatchSize() const;

  private:
    // Configuration
    asio::io_context &io_context_;
    VpnConfig config_;

    // Logger MUST be declared before any member that uses it
    std::shared_ptr<spdlog::logger> logger_;

    // Connection state
    VpnClientState state_ = VpnClientState::Disconnected;
    std::atomic<bool> running_ = false;
    int reconnect_attempts_ = 0; ///< Consecutive reconnect attempts since last successful connect

    // Network
    std::optional<transport::TransportHandle> transport_;

    // Session
    std::uint64_t local_session_id_ = 0;
    std::uint64_t remote_session_id_ = 0;
    std::uint32_t server_peer_id_ = 0; ///< Server-assigned peer ID for DATA_V2 packets
    std::uint8_t key_id_ = 0;

    // Protocol handlers
    openvpn::ControlChannel control_channel_;
    openvpn::DataChannel data_channel_;
    std::optional<openvpn::TlsCrypt> tls_crypt_;
    openvpn::ConfigExchange config_exchange_;

    // Key material from key-method 2 exchange
    std::vector<std::uint8_t> client_random_;
    std::vector<std::uint8_t> server_random_;
    std::vector<std::uint8_t> derived_key_material_; ///< Saved for DCO key push

    // TUN device (userspace mode only - DCO manages its own kernel netdev)
    std::unique_ptr<tun::TunDevice> tun_device_;

    // Statistics
    DataPathStats stats_;                  ///< Monotonic counters (userspace path)
    StatsObserver stats_observer_{stats_}; ///< Windowed stats for histograms
    std::chrono::steady_clock::time_point connected_at_;

    /// Time of last packet received from the server (any opcode).  Used by
    /// KeepaliveLoop to detect a silent server in userspace mode (DCO relies
    /// on kernel netlink notifications instead).
    std::chrono::steady_clock::time_point last_rx_time_;

    // ---- Performance / zero-copy data path ----

    // Zero-copy inbound arena: recvmmsg -> decrypt-in-place -> writev to TUN
    transport::PacketArena inbound_arena_;
    std::vector<transport::IncomingSlot> inbound_slots_;

    // Zero-copy outbound arena: TUN batch read -> encrypt-in-place -> sendmmsg
    transport::PacketArena outbound_arena_;
    std::vector<tun::TunDevice::SlotBuffer> tun_slots_;

    // Per-slot metadata for outbound arena batch
    struct ArenaEntry
    {
        std::size_t wire_len = 0;
    };
    std::vector<ArenaEntry> arena_entries_;

    std::size_t currentBatchSize_ = 0; ///< Runtime batch depth
    std::size_t processQuanta_ = 0;    ///< Packets per event-loop yield

    /// Timers used by StatsLoop, KeepaliveLoop and the handshake retransmit
    /// loop.  Stored as members so Disconnect() can cancel them, matching the
    /// server's shutdown pattern.
    asio::steady_timer stats_timer_{io_context_};
    asio::steady_timer keepalive_timer_{io_context_};
    asio::steady_timer handshake_timer_{io_context_};

  private: // ---- Data Channel Strategy (variant dispatch) ----
    /**
     * @brief Userspace data path (TUN-based)
     *
     * Handles both UDP batch and TCP single-packet modes.  The protocol
     * mode is fixed at construction and selects which coroutines to spawn.
     */
    struct UserspaceDataPath
    {
        VpnClient *client_;
        bool is_udp_; ///< true -> batch UDP loops, false -> single-packet TCP

        void ConfigureDevice();
        void StartDataPath();
        std::string GetDeviceName() const;
        DataPathStats ElapsedStats();
        void Cleanup();
        asio::awaitable<void> RunConnectedLoop();
        static constexpr bool RequiresTunDevice()
        {
            return true;
        }
    };

    /**
     * @brief DCO data path -- kernel-offloaded encrypt/decrypt via ovpn-dco-v2
     *
     * Owns all DCO-specific kernel state (netlink socket, interface, peer tracking).
     * Control channel remains in userspace; only data packets are offloaded.
     */
    struct DcoDataPath
    {
        VpnClient *client_;

        // DCO kernel state
        bool initialized_ = false;
        int ifindex_ = -1;
        std::string ifname_ = "ovpn-client0";    ///< DCO network interface name
        std::uint16_t genl_family_id_ = 0;       ///< Generic netlink family ID
        NetlinkHelper netlink_helper_;           ///< Generic netlink helper
        bool peer_created_ = false;              ///< Whether kernel peer exists
        std::uint8_t primary_key_id_ = 0xFF;     ///< Current primary key slot
        openvpn::CipherAlgorithm cipher_algo_{}; ///< Cached cipher for key push
        DataPathStats prev_stats_;               ///< Previous kernel snapshot for delta

        void ConfigureDevice();
        void StartDataPath();
        std::string GetDeviceName() const
        {
            return ifname_;
        }
        DataPathStats ElapsedStats();
        void Cleanup();
        asio::awaitable<void> RunConnectedLoop();
        static constexpr bool RequiresTunDevice()
        {
            return false;
        }
    };

    /**
     * @brief Data channel strategy -- dispatches to userspace or DCO implementation.
     *
     * Follows the same variant + visit pattern as VpnServer::DataChannelStrategy.
     */
    struct DataChannelStrategy : std::variant<UserspaceDataPath, DcoDataPath>
    {
        using std::variant<UserspaceDataPath, DcoDataPath>::variant;

        void ConfigureDevice();
        void StartDataPath();
        std::string GetDeviceName() const;
        DataPathStats ElapsedStats();
        void Cleanup();
        asio::awaitable<void> RunConnectedLoop();
        bool IsDco() const;
    };

    /// Check if the active strategy is DCO.
    bool IsDco() const
    {
        return data_channel_strategy_ && data_channel_strategy_->IsDco();
    }

    /// Access the DcoDataPath (only valid when IsDco() is true).
    DcoDataPath &Dco()
    {
        return std::get<DcoDataPath>(*data_channel_strategy_);
    }
    const DcoDataPath &Dco() const
    {
        return std::get<DcoDataPath>(*data_channel_strategy_);
    }

    // Data channel strategy (constructed during Connect)
    std::optional<DataChannelStrategy> data_channel_strategy_;
};

// ================= Inline DataChannelStrategy dispatchers =================

inline void VpnClient::DataChannelStrategy::ConfigureDevice()
{
    std::visit([](auto &s)
    { s.ConfigureDevice(); },
               *this);
}

inline void VpnClient::DataChannelStrategy::StartDataPath()
{
    std::visit([](auto &s)
    { s.StartDataPath(); },
               *this);
}

inline std::string VpnClient::DataChannelStrategy::GetDeviceName() const
{
    return std::visit([](const auto &s)
    { return s.GetDeviceName(); },
                      *this);
}

inline DataPathStats VpnClient::DataChannelStrategy::ElapsedStats()
{
    return std::visit([](auto &s)
    { return s.ElapsedStats(); },
                      *this);
}

inline void VpnClient::DataChannelStrategy::Cleanup()
{
    std::visit([](auto &s)
    { s.Cleanup(); },
               *this);
}

inline asio::awaitable<void> VpnClient::DataChannelStrategy::RunConnectedLoop()
{
    return std::visit([](auto &s)
    { return s.RunConnectedLoop(); },
                      *this);
}

inline bool VpnClient::DataChannelStrategy::IsDco() const
{
    return std::holds_alternative<DcoDataPath>(*this);
}

} // namespace clv::vpn

#endif // CLV_VPN_VPN_CLIENT_H
