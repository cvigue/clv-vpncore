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
 * by the control plane — mirroring how kernel DCO operates.
 *
 * TX: TUN read → route lookup → per-session encrypt → sendmmsg.
 * RX: recvmmsg → endpoint lookup → per-session decrypt → TUN write.
 */

#include "openvpn/crypto_context.h"
#include "openvpn/data_v2_wire.h"
#include "openvpn/packet.h"
#include "peer_slot_table.h"
#include "routing_table.h"
#include "udp_engine_types.h"
#include "openvpn/connection.h"
#include "transport/transport.h"
#include "transport/udp_batch.h"

#include <not_null.h>
#include <net/ipv6_utils.h>
#include <rate_limiter.h>
#include <util/byte_packer.h>

#include <chrono>
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
    /**
     * @brief Construct a multi-peer dispatch policy.
     * @param log Logger for decrypt error reporting
     */
    explicit MultiPeerPolicy(spdlog::logger &log) noexcept
        : logger_(&log)
    {
    }

    // ---- Borrowed state (must be set before Start) ----
    DataPlaneContext *ctx = nullptr;
    /// Peer-id → session demux and float destination. Immortal; outlives RX/TX.
    PeerSlotTable *slots = nullptr;
    /// Notified once per float so the control plane can follow the endpoint.
    PeerFloatSink *float_sink = nullptr;
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

    /// Per-peer minimum interval between control-plane float catch-ups.
    static constexpr std::chrono::seconds kFloatCatchupInterval{1};

    // Per-session RX-local decrypt state.  Keyed by session_id value.
    struct RxSessionState
    {
        RxDecryptState decrypt;
        Connection *last_conn = nullptr;
        /// Throttles the O(N) session republish; the data path follows the slot, not this.
        clv::RateLimiter<> float_catchup_limiter{kFloatCatchupInterval};
    };
    std::unordered_map<std::uint64_t, RxSessionState> rx_states;

    // Policy-local counter (not in UdpCore's tx_counters_)
    std::uint64_t route_lookup_misses = 0;

    // Rate-limits the log for decrypt attempts whose source does not match the
    // slot endpoint: a spoofed peer-id now costs one AEAD attempt, so this is
    // the one path an off-path attacker can drive.
    clv::RateLimiter<> float_reject_limiter{std::chrono::seconds{1}};

    // ---- Thread lifecycle hooks ----

    /** @brief Register the TX thread with QSBR on startup. */
    void OnTxStart()
    {
        if (ctx)
        {
            ctx->core->register_thread();
            tx_registered_ = true;
        }
    }

    /** @brief Unregister the TX thread from QSBR on shutdown. */
    void OnTxStop()
    {
        if (tx_registered_ && ctx)
        {
            ctx->core->unregister_thread();
            tx_registered_ = false;
        }
    }

    /** @brief Register the RX thread with QSBR on startup. */
    void OnRxStart()
    {
        if (ctx)
        {
            ctx->core->register_thread();
            rx_registered_ = true;
        }
    }

    /** @brief Unregister the RX thread from QSBR on shutdown. */
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
     * @brief Wire peer-id → session → per-session decrypt, with peer float.
     *
     * Demuxes on the authenticated-later peer-id rather than the source
     * address, so a client that changes address keeps decrypting. The float
     * itself is gated on a non-empty decrypt: AEAD alone would let a captured
     * datagram replayed from an attacker's address redirect server egress, so
     * the anti-replay verdict is part of the gate.
     *
     * QSBR snapshot is acquired once (valid until OnPostRecvBatch).
     */
    std::span<std::uint8_t> DecryptInPlace(transport::IncomingSlot &slot)
    {
        if (!slots || slot.len < openvpn::kDataV2HeaderLen)
            return {};
        if (openvpn::GetOpcode(slot.buf[0]) != openvpn::Opcode::P_DATA_V2)
            return {}; // P_DATA_V1 carries no peer-id; control keeps its endpoint index

        const std::uint32_t peer_id = clv::netcore::read_uint<3>(
            std::span<const std::uint8_t>(slot.buf + 1, 3));

        // Anything but an Occupied slot (unknown, reserved, retiring) is a drop.
        auto session_id = slots->LookupSession(peer_id);
        if (!session_id)
            return {};

        const auto &snap = *ctx->sessions_rx.read_quiesced();
        const auto *entry = snap.Find(openvpn::SessionId{*session_id});
        if (!entry || !entry->conn)
            return {};

        entry->conn->UpdateLastActivity();

        // Per-session RX decrypt state (lazy init from QSBR snapshot)
        auto &rxs = rx_states[*session_id];
        if (rxs.last_conn != entry->conn)
        {
            rxs.decrypt = RxDecryptState{*logger_};
            rxs.last_conn = entry->conn;
            rxs.float_catchup_limiter = clv::RateLimiter<>{kFloatCatchupInterval};
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

        auto plaintext = rxs.decrypt.DecryptPacketInPlace(
            std::span<std::uint8_t>(slot.buf, slot.len));

        MaybeFloat(peer_id, *session_id, slot.sender, !plaintext.empty(), rxs);
        return plaintext;
    }

    /** @brief Post-RX-batch QSBR quiescent-state report. */
    void OnPostRecvBatch(std::size_t /*count*/)
    {
        if (ctx)
            ctx->core->quiescent_state();
    }

    // ---- TX hooks ----

    /**
     * @brief Acquire per-batch QSBR snapshots and report quiescent state.
     *
     * Called by TxLoop after the TUN fill pass (`::read` into arena slots),
     * before the encrypt loop. Returns false only if the QSBR context is not
     * yet set.
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

    /**
     * @brief Socket file descriptor for outbound datagrams.
     * @return FD set before Start, or -1 if unset
     */
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
            const auto dst = clv::netcore::read_uint<4>(
                std::span<const std::uint8_t>(ip_data + 16, 4));
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

        // Destination comes from the slot, not the Connection: RX may have
        // floated the peer since this snapshot was published.
        transport::PeerEndpoint dest;
        if (!slots || !slots->ReadEndpoint(entry->peer_id, dest))
            return 0;

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
        auto packet_id = conn->TryAllocateOutboundPacketId();
        if (!packet_id)
            return 0;
        if (!conn->GetCryptoContext().TryReserveOutboundEncrypt(payload_len,
                                                                entry->encrypt_key.cipher_algorithm))
            return 0;
        auto wire_len = txs.encrypt.EncryptInPlace(
            slot_span, payload_len, entry->peer_id, *packet_id);
        if (wire_len == 0)
            return 0;

        out.data = slot_span.first(wire_len);
        out.dest = dest;
        out_conn = conn;
        return wire_len;
    }

    // ---- Key / peer management (no-ops: keys arrive via QSBR) ----

    /** @brief No-op; RX keys arrive via QSBR session snapshots. */
    void ApplyDecryptSnapshot(const RxDecryptSnapshot & /*snap*/)
    {
    }
    /** @brief No-op; TX keys arrive via QSBR session snapshots. */
    void ApplyEncryptKey(const openvpn::EncryptionKey & /*key*/, std::uint8_t /*key_id*/)
    {
    }
    /** @brief No-op; peer endpoints are resolved from QSBR session index. */
    void SetPeer(transport::PeerEndpoint /*peer*/, std::uint32_t /*peer_id*/, int /*fd*/)
    {
    }

    /** @brief Clear per-session crypto state and cached QSBR snapshots. */
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
    /**
     * @brief Move a live slot's egress endpoint after an authenticated packet.
     *
     * The whole float (slot move + control-plane catch-up) is gated by the
     * per-peer @c float_catchup_limiter. Throttling them together keeps the
     * slot and the control endpoint index in sync: a suppressed float leaves
     * the slot on the old endpoint, so a client that settles on a new source
     * is caught up within one interval instead of being stranded. This bounds
     * the O(N) session republish an authenticated peer can drive to one per
     * interval, per peer.
     *
     * @param peer_id Wire peer-id whose slot is being updated
     * @param session_id Session the slot resolves to
     * @param sender Source endpoint of the packet just processed
     * @param authenticated True when decrypt (AEAD + anti-replay) accepted
     * @param rxs Per-peer RX state holding the float throttle
     */
    void MaybeFloat(std::uint32_t peer_id,
                    std::uint64_t session_id,
                    const transport::PeerEndpoint &sender,
                    bool authenticated,
                    RxSessionState &rxs)
    {
        transport::PeerEndpoint current;
        if (!slots->ReadEndpoint(peer_id, current) || current == sender)
            return;

        if (!authenticated)
        {
            // Security-relevant: a valid peer-id whose datagram fails AEAD from
            // a new source is a spoof attempt or a corrupt path. 
            if (float_reject_limiter.Due())
            {
                logger_->warn("Peer {} float REJECTED: decrypt failed for datagram from {}:{} ({} more suppressed)",
                              peer_id,
                              sender.addr.to_string(),
                              sender.port,
                              float_reject_limiter.SuppressedCount());
            }
            return;
        }

        if (!rxs.float_catchup_limiter.Due())
            return;

        slots->PublishEndpoint(peer_id, sender);
        if (float_sink)
            float_sink->OnPeerFloat(session_id, sender);

        logger_->info("Peer {} floated {}:{} -> {}:{}",
                      peer_id,
                      current.addr.to_string(),
                      current.port,
                      sender.addr.to_string(),
                      sender.port);
    }

    not_null<spdlog::logger *> logger_;
};

} // namespace clv::vpn

#endif // CLV_VPN_MULTI_PEER_POLICY_H
