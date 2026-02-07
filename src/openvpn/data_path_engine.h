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
 */

#include "openvpn/dco_data_channel.h"
#include "openvpn/userspace_data_channel.h"

#include "data_path_stats.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/packet.h"

#include <asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <variant>
#include <vector>

namespace clv::vpn {

class ClientSession;

/**
 * @brief Variant-dispatched data-path engine.
 *
 * Wraps `UserspaceDataChannel | DcoDataChannel` and delegates every call
 * via `std::visit`.  Owns no infrastructure itself (TUN, routing tables,
 * session manager, etc. are injected into the variant alternatives at
 * construction time).
 *
 * This is the first step toward the full DataPathEngine described in the
 * factoring plan (§7d step 2b).  Future iterations will move infrastructure
 * ownership into this type so that PeerNode can hold a single engine
 * shared across all connections.
 */
struct DataPathEngine : std::variant<UserspaceDataChannel, DcoDataChannel>
{
    using std::variant<UserspaceDataChannel, DcoDataChannel>::variant;

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

    /**
     * @brief Snapshot aggregate data-path stats (polymorphic).
     *
     * For userspace mode returns a copy of the live counters;
     * for DCO mode queries the kernel via OVPN_CMD_GET_PEER.
     */
    DataPathStats SnapshotStats() const;
};

// ================= Inline dispatchers =================

inline bool DataPathEngine::RequiresTunDevice() const
{
    return std::visit([](const auto &s)
    { return std::decay_t<decltype(s)>::RequiresTunDevice(); },
                      *this);
}

inline asio::awaitable<void> DataPathEngine::StartTunReceiver()
{
    return std::visit([](auto &s)
    { return s.StartTunReceiver(); },
                      *this);
}

inline void DataPathEngine::StopTunReceiver()
{
    std::visit([](auto &s)
    { s.StopTunReceiver(); },
               *this);
}

inline asio::awaitable<void> DataPathEngine::ProcessIncomingDataPacket(
    ClientSession *session, const openvpn::OpenVpnPacket &packet)
{
    return std::visit([session, &packet](auto &s)
    { return s.ProcessIncomingDataPacket(session, packet); },
                      *this);
}

inline std::span<std::uint8_t> DataPathEngine::DecryptAndStripInPlace(
    ClientSession *session, std::span<std::uint8_t> datagram)
{
    return std::visit([session, datagram](auto &s)
    { return s.DecryptAndStripInPlace(session, datagram); },
                      *this);
}

inline void DataPathEngine::SetBatchSize(std::size_t newSize)
{
    std::visit([newSize](auto &s)
    { s.SetBatchSize(newSize); },
               *this);
}

inline std::size_t DataPathEngine::GetBatchSize() const
{
    return std::visit([](const auto &s)
    { return s.GetBatchSize(); },
                      *this);
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
                      *this);
}

inline asio::awaitable<void> DataPathEngine::SendKeepAlivePing(ClientSession *session)
{
    return std::visit([session](auto &s)
    { return s.SendKeepAlivePing(session); },
                      *this);
}

inline asio::awaitable<void> DataPathEngine::RunKeepaliveMonitor(DeadPeerCallback on_dead_peer)
{
    return std::visit([cb = std::move(on_dead_peer)](auto &s) mutable
    { return s.RunKeepaliveMonitor(std::move(cb)); },
                      *this);
}

inline DataPathStats DataPathEngine::SnapshotStats() const
{
    return std::visit([](const auto &s)
    { return s.SnapshotStats(); },
                      *this);
}

} // namespace clv::vpn

#endif // CLV_VPN_DATA_PATH_ENGINE_H
