// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_PACKET_ARENA_H
#define CLV_VPN_TRANSPORT_PACKET_ARENA_H

#include "batch_constants.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace clv::vpn::transport {

/**
 * @brief Pre-allocated contiguous arena for zero-copy packet processing
 *
 * Allocates batch_size × slot_size bytes once at construction. Each slot holds
 * a full datagram — TUN reads, encrypt/decrypt, and sendmmsg/recvmmsg all
 * operate directly on arena memory without intermediate heap allocations.
 *
 * Slot layout (outbound):
 * @code
 *   [0..3]   opcode/key_id + peer_id  (4B)     ─┐
 *   [4..7]   packet_id                (4B)      ├─ wire header = kDataV2Overhead (24B)
 *   [8..23]  AEAD tag                 (16B)    ─┘
 *   [24..]   plaintext → ciphertext   (in-place)
 * @endcode
 *
 * Slot layout (inbound):
 * @code
 *   [0..N]   raw UDP datagram from recvmmsg (wire format)
 * @endcode
 */
class PacketArena
{
  public:
    /**
     * @brief Construct arena with given batch size and slot size
     * @param batch_size Number of slots (packets per batch)
     * @param slot_size Bytes per slot (default: kMaxDatagram = 4096)
     * @note Total allocation = batch_size × slot_size bytes
     */
    explicit PacketArena(std::size_t batch_size, std::size_t slot_size = kMaxDatagram)
        : batch_size_(batch_size), slot_size_(slot_size), arena_(batch_size * slot_size)
    {
    }

    /// Pointer to the start of slot i
    [[nodiscard]] std::uint8_t *Slot(std::size_t i) noexcept
    {
        assert(i < batch_size_);
        return arena_.data() + (i * slot_size_);
    }

    /// Const pointer to the start of slot i
    [[nodiscard]] const std::uint8_t *Slot(std::size_t i) const noexcept
    {
        assert(i < batch_size_);
        return arena_.data() + (i * slot_size_);
    }

    /// Span over the full slot i
    [[nodiscard]] std::span<std::uint8_t> SlotSpan(std::size_t i) noexcept
    {
        return {Slot(i), slot_size_};
    }

    /// Span over a portion of slot i (e.g., for a received datagram of known length)
    [[nodiscard]] std::span<std::uint8_t> SlotSpan(std::size_t i, std::size_t len) noexcept
    {
        assert(len <= slot_size_);
        return {Slot(i), len};
    }

    /// Number of slots in the arena
    [[nodiscard]] std::size_t BatchSize() const noexcept
    {
        return batch_size_;
    }

    /// Size of each slot in bytes
    [[nodiscard]] std::size_t SlotSize() const noexcept
    {
        return slot_size_;
    }

    /// Raw pointer to the contiguous arena memory
    [[nodiscard]] std::uint8_t *Data() noexcept
    {
        return arena_.data();
    }

    /// Total arena size in bytes
    [[nodiscard]] std::size_t TotalSize() const noexcept
    {
        return arena_.size();
    }

  private:
    std::size_t batch_size_;
    std::size_t slot_size_;
    std::vector<std::uint8_t> arena_;
};

} // namespace clv::vpn::transport

#endif // CLV_VPN_TRANSPORT_PACKET_ARENA_H
