// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_P2P_POLICY_H
#define CLV_VPN_P2P_POLICY_H

/**
 * @file p2p_policy.h
 * @brief Single-peer dispatch policy for UDP client data channel.
 *
 * Owns per-peer RX/TX crypto state and provides the dispatch hooks that
 * UdpCore's RxLoop and TxLoop call on the hot path.  All methods are
 * trivially inlineable.
 */

#include "udp_engine_types.h"
#include "transport/transport.h"
#include "transport/udp_batch.h"

#include <not_null.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <array>

namespace spdlog {
class logger;
}

namespace clv::vpn {

struct P2PPolicy
{
    explicit P2PPolicy(spdlog::logger &log) noexcept
        : rx_decrypt(log),
          logger_(&log)
    {
    }

    // ---- Per-peer state (owned by policy) ----
    RxDecryptState rx_decrypt;
    TxEncryptState tx_encrypt;
    ClientTxSnapshot tx_snapshot;
    /// Monotonic outbound packet-ID counter shared between the TxSpsc hot
    /// path and the control-plane keepalive sender.  Both paths claim IDs
    /// with fetch_add(relaxed) — each call always gets a unique value.
    std::atomic<std::uint32_t> outbound_pkt_id_{1};

  private:
    // Double-buffered encrypt key for thread-safe handoff between the TX
    // io_context thread (ApplyEncryptKey) and the TxSpsc producer/consumer
    // threads (PreAssignSlot / EncryptPartition).
    //
    // Writer fills the *inactive* slot then release-stores active_key_slot_.
    // Readers acquire-load active_key_slot_ before touching key material,
    // ensuring they see a fully-written, consistent (key, key_id) pair.
    //
    // The inactive slot is only overwritten at the NEXT rekey, which is
    // ~120 s away — far longer than any partition lives in the TX ring.
    struct KeySlot
    {
        openvpn::EncryptionKey key{};
        std::uint8_t key_id = 0;
    };
    std::array<KeySlot, 2> key_slots_{};
    std::atomic<std::uint8_t> active_key_slot_{0};

    // Double-buffered decrypt snapshot for zero-window RX key handoff.
    //
    // ApplyDecryptSnapshot() writes directly to the inactive slot then
    // release-stores active_rx_slot_ — no asio::post required.  DecryptInPlace()
    // acquire-loads the active index and lazily applies the snapshot to
    // rx_decrypt on the first packet that sees the new key_id.  The same
    // ~120 s rekey interval guarantees the inactive slot is never overwritten
    // while the RX thread holds a reference to it.
    std::array<RxDecryptSnapshot, 2> rx_snap_slots_{};
    std::atomic<std::uint8_t> active_rx_slot_{0};

  public:
    // ---- RX hooks ----

    std::span<std::uint8_t> DecryptInPlace(transport::IncomingSlot &slot)
    {
        // Acquire-load pairs with the release-store in ApplyDecryptSnapshot.
        // If the control plane installed a new key since our last packet,
        // NeedsReinit() detects it and we apply the snapshot before decrypting.
        const std::uint8_t active = active_rx_slot_.load(std::memory_order_acquire);
        const RxDecryptSnapshot &snap = rx_snap_slots_[active];
        if (snap.valid && rx_decrypt.NeedsReinit(snap.key_id))
            rx_decrypt.ApplySnapshot(snap);

        return rx_decrypt.DecryptPacketInPlace(
            std::span<std::uint8_t>(slot.buf, slot.len));
    }

    void OnPostRecvBatch(std::size_t /*count*/)
    {
    }

    // ---- TX hooks ----

    bool TxReady() const noexcept
    {
        return tx_snapshot.valid && tx_snapshot.socket_fd >= 0;
    }

    int TxSocketFd() const noexcept
    {
        return tx_snapshot.socket_fd;
    }

    std::size_t EncryptSlot(std::span<std::uint8_t> slot_span,
                            std::size_t payload_len,
                            transport::SendEntry &out,
                            Connection *&out_conn)
    {
        const std::uint8_t active = active_key_slot_.load(std::memory_order_acquire);
        const KeySlot &slot = key_slots_[active];

        if (tx_encrypt.NeedsReinit(slot.key_id))
            tx_encrypt.ApplySnapshot(slot.key, slot.key_id);

        auto wire_len = tx_encrypt.EncryptInPlace(
            slot_span, payload_len, tx_snapshot.session_id, outbound_pkt_id_.fetch_add(1, std::memory_order_relaxed));
        if (wire_len == 0)
            return 0;

        out.data = slot_span.first(wire_len);
        out.dest = tx_snapshot.peer;
        out_conn = nullptr; // P2P: no per-conn tracking; OnBatchSent handles timestamp
        return wire_len;
    }

    void OnBatchSent(std::size_t sent) noexcept
    {
        if (sent > 0 && tx_ns_out_)
            tx_ns_out_->store(
                std::chrono::steady_clock::now().time_since_epoch().count(),
                std::memory_order_relaxed);
    }

    void SetTxNsOutput(std::atomic<std::int64_t> *p) noexcept
    {
        tx_ns_out_ = p;
    }

    // ---- Key / peer management (called from control plane) ----

    void ApplyDecryptSnapshot(const RxDecryptSnapshot &snap)
    {
        // Write to the *inactive* slot, then atomically flip the active index.
        // Safe to call from any thread — the RX thread only reads the active
        // slot; we only write the inactive one.
        const std::uint8_t inactive = active_rx_slot_.load(std::memory_order_relaxed) ^ 1u;
        rx_snap_slots_[inactive] = snap;
        active_rx_slot_.store(inactive, std::memory_order_release);
    }

    void ApplyEncryptKey(const openvpn::EncryptionKey &key, std::uint8_t key_id)
    {
        // Write to the *inactive* slot, then atomically flip the active index.
        // The release-store ensures the slot write is fully visible to any
        // thread that subsequently acquire-loads active_key_slot_.
        const std::uint8_t inactive = active_key_slot_.load(std::memory_order_relaxed) ^ 1u;
        key_slots_[inactive].key = key;
        key_slots_[inactive].key_id = key_id;
        active_key_slot_.store(inactive, std::memory_order_release);

        tx_snapshot.key_id = key_id; // Keep tx_snapshot in sync for direct reads
        tx_snapshot.valid = tx_snapshot.socket_fd >= 0;
    }

    void SetPeer(transport::PeerEndpoint peer,
                 openvpn::SessionId session_id,
                 int socket_fd)
    {
        tx_snapshot.peer = peer;
        tx_snapshot.session_id = session_id;
        tx_snapshot.socket_fd = socket_fd;
        tx_snapshot.valid = socket_fd >= 0;
    }

    void OnTxStart()
    {
    }
    void OnTxStop()
    {
    }
    void OnRxStart()
    {
    }
    void OnRxStop()
    {
    }

    void Reset()
    {
        rx_decrypt = RxDecryptState{*logger_};
        tx_snapshot = ClientTxSnapshot{};
        tx_encrypt = TxEncryptState{};
        outbound_pkt_id_.store(1, std::memory_order_relaxed);
        key_slots_[0] = KeySlot{};
        key_slots_[1] = KeySlot{};
        active_key_slot_.store(0, std::memory_order_relaxed);
        rx_snap_slots_[0] = RxDecryptSnapshot{};
        rx_snap_slots_[1] = RxDecryptSnapshot{};
        active_rx_slot_.store(0, std::memory_order_relaxed);
    }

  private:
    not_null<spdlog::logger *> logger_;

    // Set by the channel to receive TX timestamps for keepalive idle detection.
    std::atomic<std::int64_t> *tx_ns_out_ = nullptr;
};

} // namespace clv::vpn

#endif // CLV_VPN_P2P_POLICY_H
