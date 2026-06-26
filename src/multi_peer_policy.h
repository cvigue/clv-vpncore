// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_MULTI_PEER_POLICY_H
#define CLV_VPN_MULTI_PEER_POLICY_H

/**
 * @file multi_peer_policy.h
 * @brief Multi-peer dispatch policy for UdpCore (server-side).
 *
 * Provides the PeerPolicy hooks that UdpCore calls on the RX and TX
 * hot paths.  Unlike P2PPolicy (single peer, direct key posting), this
 * policy reads keys, sessions, and routes from QSBR snapshots published
 * by the control plane — exactly mirroring how kernel DCO operates.
 *
 * TX: TUN read → route lookup → per-session encrypt → sendmmsg.
 * RX: recvmmsg → endpoint lookup → per-session decrypt → TUN write.
 */

#include "openvpn/data_channel.h"
#include "openvpn/packet.h"
#include "routing_table.h"
#include "udp_engine_types.h"
#include "openvpn/connection.h"
#include "udp_engine_types.h"
#include "transport/transport.h"
#include "transport/udp_batch.h"

#include <not_null.h>
#include <net/ipv6_utils.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <unordered_map>

namespace spdlog {
class logger;
}

namespace clv::vpn {

namespace ipv6 = clv::net::ipv6;

// ============================================================================
// MultiPeerPolicy — multi-peer dispatch for server UdpCore
// ============================================================================

/**
 * @brief Peer policy for multi-peer (server) mode.
 *
 * Owns per-session TX crypto state and reads routing/session data from
 * QSBR snapshots.  Keys arrive via QSBR publication (not asio::post),
 * so ApplyDecryptSnapshot / ApplyEncryptKey / SetPeer are no-ops.
 */
struct MultiPeerPolicy
{
    explicit MultiPeerPolicy(spdlog::logger &log) noexcept
        : logger_(&log)
    {
    }

    // ---- Borrowed state (must be set before Start) ----
    UdpEngineContext *ctx = nullptr;
    int socket_fd = -1;

    // ---- TX-thread-local mutable state ----
    bool tx_registered_ = false;
    bool rx_registered_ = false;

    // Cached per-batch QSBR snapshots (valid for one TxLoop iteration)
    const SessionIndex *snap_sessions_ = nullptr;
    const RoutingTableIpv4 *snap_v4_ = nullptr;
    const RoutingTableIpv6 *snap_v6_ = nullptr;

    // Per-session TX-local encrypt state.  Keyed by session_id value.
    // Populated lazily from QSBR SessionIndex snapshots.
    struct TxSessionState
    {
        TxEncryptState encrypt;
        Connection *last_conn = nullptr; ///< Detect session replacement
    };
    std::unordered_map<std::uint64_t, TxSessionState> tx_states;

    // Per-session RX-local decrypt state.  Keyed by session_id value.
    struct RxSessionState
    {
        RxDecryptState decrypt;
        Connection *last_conn = nullptr;
    };
    std::unordered_map<std::uint64_t, RxSessionState> rx_states;

    // Policy-local counter (not in UdpCore's tx_counters_)
    std::uint64_t route_lookup_misses = 0;

    // ---- Thread lifecycle hooks ----

    void OnTxStart()
    {
        if (ctx)
        {
            ctx->core->register_thread();
            tx_registered_ = true;
        }
    }

    void OnTxStop()
    {
        if (tx_registered_ && ctx)
        {
            ctx->core->unregister_thread();
            tx_registered_ = false;
        }
    }

    void OnRxStart()
    {
        if (ctx)
        {
            ctx->core->register_thread();
            rx_registered_ = true;
        }
    }

    void OnRxStop()
    {
        if (rx_registered_ && ctx)
        {
            ctx->core->unregister_thread();
            rx_registered_ = false;
        }
    }

    // ---- RX hooks ----

    /**
     * @brief Endpoint → session → per-session decrypt.
     *
     * Mirrors VpnServer::UdpReceiveLoop::onData.  QSBR snapshot is acquired
     * once (valid until OnPostRecvBatch at the end of the batch).
     */
    std::span<std::uint8_t> DecryptInPlace(transport::IncomingSlot &slot)
    {
        const auto &snap = *ctx->sessions_rx.read_quiesced();

        const auto *entry = snap.FindByEndpoint(slot.sender);
        if (!entry || !entry->conn)
            return {};

        entry->conn->UpdateLastActivity();

        // Per-session RX decrypt state (lazy init from QSBR snapshot)
        auto &rxs = rx_states[entry->conn->GetSessionId().value];
        if (rxs.last_conn != entry->conn)
        {
            rxs.decrypt = RxDecryptState{*logger_};
            rxs.last_conn = entry->conn;
        }
        if (rxs.decrypt.NeedsReinit(entry->key_id))
        {
            RxDecryptSnapshot snap_key{
                .decrypt_key = entry->decrypt_key,
                .key_id = entry->key_id,
                .valid = true,
            };
            rxs.decrypt.ApplySnapshot(snap_key);
        }

        return rxs.decrypt.DecryptPacketInPlace(
            std::span<std::uint8_t>(slot.buf, slot.len));
    }

    void OnPostRecvBatch(std::size_t /*count*/)
    {
        if (ctx)
            ctx->core->quiescent_state();
    }

    // ---- TX hooks ----

    /**
     * @brief Acquire per-batch QSBR snapshots and report quiescent state.
     *
     * Called by TxLoop after ReadBatchInto, before the encrypt loop.
     * Returns false only if the QSBR context is not yet set.
     */
    bool TxReady() noexcept
    {
        if (!ctx)
            return false;
        // Report quiescent state for previous batch's snapshots
        ctx->core->quiescent_state();
        // Acquire fresh snapshots for this batch
        snap_sessions_ = &*ctx->sessions.read_quiesced();
        snap_v4_ = &*ctx->routes_v4.read_quiesced();
        snap_v6_ = &*ctx->routes_v6.read_quiesced();
        return true;
    }

    int TxSocketFd() const noexcept
    {
        return socket_fd;
    }

    /**
     * @brief Route-lookup → session-lookup → per-session encrypt.
     *
     * Route-lookup → session-lookup → per-session encrypt.
     * IP data sits at slot_span[kDataV2Overhead..].
     */
    std::size_t EncryptSlot(std::span<std::uint8_t> slot_span,
                            std::size_t payload_len,
                            transport::SendEntry &out,
                            Connection *&out_conn)
    {
        constexpr std::size_t kOff = openvpn::kDataV2Overhead;
        auto *ip_data = slot_span.data() + kOff;

        // ---- Route lookup (branch on IP version) ----
        std::optional<std::uint64_t> session_id_opt;
        const std::uint8_t ip_ver = ip_data[0] >> 4;

        if (ip_ver == 4)
        {
            std::uint32_t dst = (static_cast<std::uint32_t>(ip_data[16]) << 24)
                                | (static_cast<std::uint32_t>(ip_data[17]) << 16)
                                | (static_cast<std::uint32_t>(ip_data[18]) << 8)
                                | static_cast<std::uint32_t>(ip_data[19]);
            session_id_opt = snap_v4_->Lookup(dst);
        }
        else if (ip_ver == 6)
        {
            if (payload_len < 40)
                return 0;
            ipv6::Ipv6Address dst_v6;
            std::memcpy(dst_v6.data(), ip_data + 24, 16);
            session_id_opt = snap_v6_->Lookup(dst_v6);
        }
        else
        {
            return 0;
        }

        if (!session_id_opt)
        {
            route_lookup_misses++;
            return 0;
        }

        // ---- Session lookup via QSBR snapshot ----
        openvpn::SessionId session_id{*session_id_opt};
        const SessionEntry *entry = snap_sessions_->Find(session_id);
        if (!entry || !entry->conn)
            return 0;

        Connection *conn = entry->conn;
        if (!conn->HasTransport() || !conn->GetTransport().IsBatchingSupported())
            return 0; // TCP peers handled by the control-plane path

        // ---- Per-session encrypt (lazy init from QSBR snapshot) ----
        auto &txs = tx_states[session_id.value];
        if (txs.last_conn != conn)
        {
            txs.encrypt = TxEncryptState{};
            txs.last_conn = conn;
        }
        if (txs.encrypt.NeedsReinit(entry->key_id))
            txs.encrypt.ApplySnapshot(entry->encrypt_key, entry->key_id);

        // Claim the next packet-id from the shared per-session atomic counter.
        // This keeps the TX hot path and the control-plane keepalive ping path
        // on the same monotonic sequence so the peer's anti-replay window never
        // sees duplicate IDs regardless of which path sends next.
        auto packet_id = conn->GetAndIncrementOutboundPacketId();
        auto wire_len = txs.encrypt.EncryptInPlace(
            slot_span, payload_len, session_id, packet_id);
        if (wire_len == 0)
            return 0;

        out.data = slot_span.first(wire_len);
        out.dest = conn->GetTransport().GetPeer();
        out_conn = conn;
        return wire_len;
    }

    // ---- Key / peer management (no-ops: keys arrive via QSBR) ----

    void ApplyDecryptSnapshot(const RxDecryptSnapshot & /*snap*/)
    {
    }
    void ApplyEncryptKey(const openvpn::EncryptionKey & /*key*/, std::uint8_t /*key_id*/)
    {
    }
    void SetPeer(transport::PeerEndpoint /*peer*/, openvpn::SessionId /*sid*/, int /*fd*/)
    {
    }

    // Called by UdpCore::CoreStop() — required by the PeerPolicy contract.
    // For MultiPeerPolicy there is no reconnect path, so this is just cleanup
    // ahead of destruction; the maps would be destroyed anyway.
    void Reset()
    {
        tx_states.clear();
        rx_states.clear();
        snap_sessions_ = nullptr;
        snap_v4_ = nullptr;
        snap_v6_ = nullptr;
        route_lookup_misses = 0;
    }

  private:
    not_null<spdlog::logger *> logger_;
};

} // namespace clv::vpn

#endif // CLV_VPN_MULTI_PEER_POLICY_H
