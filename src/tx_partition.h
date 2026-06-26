// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TX_PARTITION_H
#define CLV_VPN_TX_PARTITION_H

#include "openvpn/data_channel.h"
#include "transport/transport.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace clv::vpn {

class Connection;

// ============================================================================
// TxPartition — one batch of TUN-read slots with per-slot metadata
// ============================================================================

struct TxPartition
{
    /// Per-slot metadata populated during the fill+pre-assign phase.
    struct SlotMeta
    {
        bool valid = false;
        std::size_t payload_len = 0;
        std::size_t wire_len = 0;
        openvpn::SessionId session_id{};
        std::uint32_t packet_id = 0;
        std::uint8_t key_id = 0;
        const openvpn::EncryptionKey *encrypt_key = nullptr;
        Connection *conn = nullptr;
        transport::PeerEndpoint dest{};
    };

    std::size_t slot_count = 0; ///< Number of valid slots after fill
    std::size_t slot_size = 0;  ///< Bytes per slot (arena geometry)
    std::vector<SlotMeta> meta; ///< Per-slot metadata array

    /// Raw pointer to the start of slot i within this partition's arena.
    [[nodiscard]] std::uint8_t *Slot(std::size_t i) noexcept
    {
        assert(i < meta.size());
        return arena_base_ + (i * slot_size);
    }

    /// Span over the full slot i.
    [[nodiscard]] std::span<std::uint8_t> SlotSpan(std::size_t i) noexcept
    {
        return {Slot(i), slot_size};
    }

  private:
    friend class TxPartitionPool;
    std::uint8_t *arena_base_ = nullptr; ///< Set by TxPartitionPool
};

// ============================================================================
// TxPartitionPool — owns the contiguous arena and partitions
// ============================================================================

class TxPartitionPool
{
  public:
    /// @param partition_size  Slots per partition
    /// @param partition_count Number of partitions
    /// @param slot_size       Bytes per slot (e.g. kMaxDatagram)
    TxPartitionPool(std::size_t partition_size,
                    std::size_t partition_count,
                    std::size_t slot_size)
        : partition_size_(partition_size),
          partition_count_(partition_count),
          slot_size_(slot_size),
          arena_(partition_count * partition_size * slot_size)
    {
        partitions_.reserve(partition_count);
        for (std::size_t p = 0; p < partition_count; ++p)
        {
            auto part = std::make_unique<TxPartition>();
            part->slot_size = slot_size;
            part->meta.resize(partition_size);
            part->arena_base_ = arena_.data() + (p * partition_size * slot_size);
            partitions_.push_back(std::move(part));
        }
    }

    [[nodiscard]] TxPartition &At(std::size_t index) noexcept
    {
        return *partitions_[index % partition_count_];
    }

    [[nodiscard]] std::size_t Count() const noexcept
    {
        return partition_count_;
    }
    [[nodiscard]] std::size_t PartitionSize() const noexcept
    {
        return partition_size_;
    }
    [[nodiscard]] std::size_t SlotSize() const noexcept
    {
        return slot_size_;
    }

  private:
    std::size_t partition_size_;
    std::size_t partition_count_;
    std::size_t slot_size_;
    std::vector<std::uint8_t> arena_;
    std::vector<std::unique_ptr<TxPartition>> partitions_;
};

} // namespace clv::vpn

#endif // CLV_VPN_TX_PARTITION_H
