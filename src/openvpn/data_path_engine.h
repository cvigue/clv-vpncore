// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_DATA_PATH_ENGINE_H
#define CLV_VPN_DATA_PATH_ENGINE_H

/**
 * @file data_path_engine.h
 * @brief Variant-dispatched data-path engine wrapping UserspaceDataChannel | DcoDataChannel.
 *
 * Extracted from VpnServer so it can be reused by PeerNode and, eventually,
 * VpnClient. Each method simply delegates to the active variant alternative
 * via std::visit — no vtable, no indirection cost on the hot path.
 *
 * Owns the TUN device (when in userspace mode). The variant alternatives
 * receive a reference at construction and use it for I/O when the device
 * is later created via CreateTunDevice().
 */

#include "openvpn/dco_data_channel.h"
#include "openvpn/session_manager.h"
#include "openvpn/userspace_data_channel.h"

#include "data_path_stats.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/packet.h"
#include "routing_table.h"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace clv::vpn {

class ClientSession;

/**
 * @brief Variant-dispatched data-path engine.
 *
 * Wraps `UserspaceDataChannel | DcoDataChannel` as an internal variant
 * member and delegates every call via `std::visit`.  Owns the TUN device
 * storage (populated later by CreateTunDevice) so that a future PeerNode
 * orchestrator can hold a single engine shared across all connections.
 *
 * Non-copyable, non-movable: the UserspaceDataChannel alternative holds
 * a reference to tun_device_, so the engine's address must be stable.
 */
class DataPathEngine
{
  public:
    /**
     * @brief Construct a userspace-mode engine.
     *
     * The TUN unique_ptr is owned here (initially null) and a reference is
     * forwarded to UserspaceDataChannel.  Call CreateTunDevice() later to
     * populate it.
     */
    DataPathEngine(std::in_place_type_t<UserspaceDataChannel>,
                   asio::io_context &io_context,
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
                   const std::atomic<bool> &running_flag)
        : tun_device_{}, impl_(std::in_place_type<UserspaceDataChannel>,
                               io_context, tun_device_, routing_table, routing_table_v6,
                               session_manager, logger, stats, stats_observer,
                               batchSize, processQuanta, keepalive_interval, keepalive_timeout,
                               running_flag)
    {
    }

    /**
     * @brief Construct a DCO-mode engine (no TUN device needed).
     */
    DataPathEngine(std::in_place_type_t<DcoDataChannel>,
                   asio::io_context &io_context,
                   asio::ip::udp::socket &socket,
                   const DcoDataChannel::NetworkConfig &network_config,
                   spdlog::logger &logger,
                   const std::atomic<bool> &running_flag)
        : tun_device_{}, impl_(std::in_place_type<DcoDataChannel>,
                               io_context, socket, network_config, logger, running_flag)
    {
    }

    // Non-copyable, non-movable (self-referential: UserspaceDataChannel
    // holds a reference to tun_device_).
    DataPathEngine(const DataPathEngine &) = delete;
    DataPathEngine &operator=(const DataPathEngine &) = delete;
    DataPathEngine(DataPathEngine &&) = delete;
    DataPathEngine &operator=(DataPathEngine &&) = delete;

    // ---- TUN device management ----

    /** @brief Create the TUN device (userspace mode only, populated later by caller). */
    void CreateTunDevice(asio::io_context &io_context)
    {
        tun_device_ = std::make_unique<tun::TunDevice>(io_context);
    }

    /** @brief Close and release the TUN device. */
    void CloseTunDevice()
    {
        if (tun_device_)
            tun_device_->Close();
    }

    /** @brief Raw observer pointer to the TUN device (may be nullptr). */
    tun::TunDevice *tun_device() const
    {
        return tun_device_.get();
    }

    // ---- Data-path dispatch ----

    /** @brief Check if strategy requires TUN device (runtime) */
    bool RequiresTunDevice() const;

    /** @brief Start TUN receiver coroutine */
    asio::awaitable<void> StartTunReceiver();

    /** @brief Stop TUN receiver loop */
    void StopTunReceiver();

    /** @brief Process incoming data packet from network */
    asio::awaitable<void> ProcessIncomingDataPacket(ClientSession *session,
                                                    const openvpn::OpenVpnPacket &packet);

    /** @brief Synchronous in-place decrypt + compress strip (no TUN write) */
    std::span<std::uint8_t> DecryptAndStripInPlace(ClientSession *session,
                                                   std::span<std::uint8_t> datagram);

    /** @brief Set batch size at runtime (delegates to active strategy) */
    void SetBatchSize(std::size_t newSize);

    /** @brief Get current batch size */
    std::size_t GetBatchSize() const;

    /**
     * @brief Install session keys for data channel encryption
     * @param session Client session
     * @param key_material Derived key material
     * @param cipher_algo Cipher algorithm to use
     * @param hmac_algo HMAC algorithm to use
     * @param key_id Key ID for this key set
     * @param lame_duck_seconds Grace period for old keys (0 = no expiry)
     * @return true if keys were installed successfully
     */
    bool InstallKeys(ClientSession *session,
                     const std::vector<uint8_t> &key_material,
                     openvpn::CipherAlgorithm cipher_algo,
                     openvpn::HmacAlgorithm hmac_algo,
                     std::uint8_t key_id,
                     int lame_duck_seconds);

    /** @brief Send encrypted keepalive PING packet (polymorphic) */
    asio::awaitable<void> SendKeepAlivePing(ClientSession *session);

    /** @brief Callback invoked when a peer is considered dead */
    using DeadPeerCallback = std::function<void(openvpn::SessionId)>;

    /** @brief Run keepalive monitor coroutine (polymorphic) */
    asio::awaitable<void> RunKeepaliveMonitor(DeadPeerCallback on_dead_peer);

    /** @brief Cancel the keepalive monitor's blocking I/O so it can exit */
    void StopKeepaliveMonitor();

    /**
     * @brief Snapshot aggregate data-path stats (polymorphic).
     *
     * For userspace mode returns a copy of the live counters;
     * for DCO mode queries the kernel via OVPN_CMD_GET_PEER.
     */
    DataPathStats SnapshotStats() const;

  private:
    std::unique_ptr<tun::TunDevice> tun_device_; ///< TUN device (userspace mode); declared first for init order
    std::variant<UserspaceDataChannel, DcoDataChannel> impl_;
};

// ================= Inline dispatchers =================

inline bool DataPathEngine::RequiresTunDevice() const
{
    return std::visit([](const auto &s)
    { return std::decay_t<decltype(s)>::RequiresTunDevice(); },
                      impl_);
}

inline asio::awaitable<void> DataPathEngine::StartTunReceiver()
{
    return std::visit([](auto &s)
    { return s.StartTunReceiver(); },
                      impl_);
}

inline void DataPathEngine::StopTunReceiver()
{
    std::visit([](auto &s)
    { s.StopTunReceiver(); },
               impl_);
}

inline asio::awaitable<void> DataPathEngine::ProcessIncomingDataPacket(
    ClientSession *session, const openvpn::OpenVpnPacket &packet)
{
    return std::visit([session, &packet](auto &s)
    { return s.ProcessIncomingDataPacket(session, packet); },
                      impl_);
}

inline std::span<std::uint8_t> DataPathEngine::DecryptAndStripInPlace(
    ClientSession *session, std::span<std::uint8_t> datagram)
{
    return std::visit([session, datagram](auto &s)
    { return s.DecryptAndStripInPlace(session, datagram); },
                      impl_);
}

inline void DataPathEngine::SetBatchSize(std::size_t newSize)
{
    std::visit([newSize](auto &s)
    { s.SetBatchSize(newSize); },
               impl_);
}

inline std::size_t DataPathEngine::GetBatchSize() const
{
    return std::visit([](const auto &s)
    { return s.GetBatchSize(); },
                      impl_);
}

inline bool DataPathEngine::InstallKeys(ClientSession *session,
                                        const std::vector<uint8_t> &key_material,
                                        openvpn::CipherAlgorithm cipher_algo,
                                        openvpn::HmacAlgorithm hmac_algo,
                                        std::uint8_t key_id,
                                        int lame_duck_seconds)
{
    return std::visit([=, &key_material](auto &s)
    {
        return s.InstallKeys(session, key_material, cipher_algo, hmac_algo, key_id, lame_duck_seconds);
    },
                      impl_);
}

inline asio::awaitable<void> DataPathEngine::SendKeepAlivePing(ClientSession *session)
{
    return std::visit([session](auto &s)
    { return s.SendKeepAlivePing(session); },
                      impl_);
}

inline asio::awaitable<void> DataPathEngine::RunKeepaliveMonitor(DeadPeerCallback on_dead_peer)
{
    return std::visit([cb = std::move(on_dead_peer)](auto &s) mutable
    { return s.RunKeepaliveMonitor(std::move(cb)); },
                      impl_);
}

inline void DataPathEngine::StopKeepaliveMonitor()
{
    std::visit([](auto &s)
    { s.StopKeepaliveMonitor(); },
               impl_);
}

inline DataPathStats DataPathEngine::SnapshotStats() const
{
    return std::visit([](const auto &s)
    { return s.SnapshotStats(); },
                      impl_);
}

} // namespace clv::vpn

#endif // CLV_VPN_DATA_PATH_ENGINE_H
