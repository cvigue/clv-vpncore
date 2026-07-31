// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include "peer_slot_table.h"

#include <cassert>
#include <cstring>
#include <stdexcept>

namespace clv::vpn {

namespace {

/// Bounded seqlock retries; a well-behaved single writer needs at most one.
constexpr int kSeqlockRetries = 8;

std::uint8_t Encode(PeerSlotState s) noexcept
{
    return static_cast<std::uint8_t>(s);
}

/// Validated in the member-init list so an absurd capacity never allocates.
std::size_t CheckedCapacity(std::size_t capacity)
{
    if (capacity == 0 || capacity >= kPeerIdUndef)
        throw std::invalid_argument("PeerSlotTable capacity must be in [1, 0xFFFFFF)");
    return capacity;
}

} // namespace

PackedEndpoint PackEndpoint(const transport::PeerEndpoint &ep)
{
    PackedEndpoint out;
    out.port = ep.port;
    out.is_v6 = ep.addr.is_v6();
    if (out.is_v6)
    {
        auto bytes = ep.addr.to_v6().to_bytes();
        std::memcpy(out.addr.data(), bytes.data(), bytes.size());
    }
    else
    {
        auto bytes = ep.addr.to_v4().to_bytes();
        std::memcpy(out.addr.data(), bytes.data(), bytes.size());
    }
    return out;
}

transport::PeerEndpoint UnpackEndpoint(const PackedEndpoint &packed)
{
    transport::PeerEndpoint out;
    out.port = packed.port;
    if (packed.is_v6)
    {
        asio::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), packed.addr.data(), bytes.size());
        out.addr = asio::ip::address_v6(bytes);
    }
    else
    {
        asio::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), packed.addr.data(), bytes.size());
        out.addr = asio::ip::address_v4(bytes);
    }
    return out;
}

PeerSlotTable::PeerSlotTable(std::size_t capacity)
    : capacity_(CheckedCapacity(capacity)),
      state_(capacity_),
      session_id_(capacity_),
      endpoint_(capacity_),
      kernel_peer_(capacity_, 0),
      free_count_(capacity_)
{
    for (auto &s : state_)
        s.store(Encode(PeerSlotState::Free), std::memory_order_relaxed);
}

void PeerSlotTable::AssertControlThread() const noexcept
{
#ifndef NDEBUG
    const auto self = std::this_thread::get_id();
    auto expected = std::thread::id{};
    if (owner_.compare_exchange_strong(expected, self, std::memory_order_relaxed))
        return;
    assert(expected == self && "PeerSlotTable mutated off the control thread");
#endif
}

std::optional<PeerSlotTable::Lease> PeerSlotTable::Reserve()
{
    AssertControlThread();

    if (free_count_ == 0)
        return std::nullopt;

    // Scan forward from the cursor so a freed id is not the next one handed
    // out. free_count_ guarantees this terminates.
    for (std::size_t probe = 0; probe < capacity_; ++probe)
    {
        const std::size_t idx = (cursor_ + probe) % capacity_;
        if (state_[idx].load(std::memory_order_relaxed) != Encode(PeerSlotState::Free))
            continue;

        session_id_[idx].store(0, std::memory_order_relaxed);
        state_[idx].store(Encode(PeerSlotState::Reserved), std::memory_order_relaxed);
        cursor_ = (idx + 1) % capacity_;
        --free_count_;
        return Lease{this, static_cast<std::uint32_t>(idx)};
    }

    // free_count_ disagreed with the state array.
    assert(false && "PeerSlotTable free_count_ out of sync with slot states");
    return std::nullopt;
}

void PeerSlotTable::Occupy(std::uint32_t id, std::uint64_t session_id,
                           const transport::PeerEndpoint &endpoint)
{
    AssertControlThread();
    if (!InRange(id))
        return;

    auto &cell = endpoint_[id];
    // No seqlock dance needed: the slot is not yet reachable from the data path.
    cell.value = PackEndpoint(endpoint);
    cell.seq.store(cell.seq.load(std::memory_order_relaxed) + 2, std::memory_order_relaxed);
    session_id_[id].store(session_id, std::memory_order_relaxed);

    // Release: readers that see Occupied also see the session id and endpoint.
    state_[id].store(Encode(PeerSlotState::Occupied), std::memory_order_release);
}

void PeerSlotTable::Retire(std::uint32_t id)
{
    AssertControlThread();
    if (!InRange(id))
        return;

    const auto current = state_[id].load(std::memory_order_relaxed);
    if (current == Encode(PeerSlotState::Free) || current == Encode(PeerSlotState::Retiring))
        return;

    state_[id].store(Encode(PeerSlotState::Retiring), std::memory_order_release);
}

void PeerSlotTable::Free(std::uint32_t id)
{
    AssertControlThread();
    if (!InRange(id))
        return;

    if (state_[id].load(std::memory_order_relaxed) == Encode(PeerSlotState::Free))
        return;

    session_id_[id].store(0, std::memory_order_relaxed);
    kernel_peer_[id] = 0;
    state_[id].store(Encode(PeerSlotState::Free), std::memory_order_release);
    ++free_count_;
}

void PeerSlotTable::SetKernelPeer(std::uint32_t id, bool present)
{
    AssertControlThread();
    if (InRange(id))
        kernel_peer_[id] = present ? 1 : 0;
}

bool PeerSlotTable::HasKernelPeer(std::uint32_t id) const
{
    return InRange(id) && kernel_peer_[id] != 0;
}

void PeerSlotTable::RebindControlThread() noexcept
{
    owner_.store(std::this_thread::get_id(), std::memory_order_relaxed);
}

std::optional<std::uint64_t> PeerSlotTable::LookupSession(std::uint32_t id) const
{
    if (!InRange(id))
        return std::nullopt;
    if (state_[id].load(std::memory_order_acquire) != Encode(PeerSlotState::Occupied))
        return std::nullopt;
    return session_id_[id].load(std::memory_order_relaxed);
}

bool PeerSlotTable::ReadEndpoint(std::uint32_t id, transport::PeerEndpoint &out) const
{
    if (!InRange(id))
        return false;
    if (state_[id].load(std::memory_order_acquire) != Encode(PeerSlotState::Occupied))
        return false;

    const auto &cell = endpoint_[id];
    for (int attempt = 0; attempt < kSeqlockRetries; ++attempt)
    {
        const auto before = cell.seq.load(std::memory_order_acquire);
        if (before & 1u)
            continue; // writer in progress

        PackedEndpoint packed = cell.value;

        std::atomic_thread_fence(std::memory_order_acquire);
        if (cell.seq.load(std::memory_order_relaxed) == before)
        {
            out = UnpackEndpoint(packed);
            return true;
        }
    }
    return false;
}

void PeerSlotTable::PublishEndpoint(std::uint32_t id, const transport::PeerEndpoint &endpoint)
{
    if (!InRange(id))
        return;
    if (state_[id].load(std::memory_order_acquire) != Encode(PeerSlotState::Occupied))
        return;

    auto &cell = endpoint_[id];
    const auto seq = cell.seq.load(std::memory_order_relaxed);
    cell.seq.store(seq + 1, std::memory_order_relaxed); // odd: write in progress
    std::atomic_thread_fence(std::memory_order_release);

    cell.value = PackEndpoint(endpoint);

    cell.seq.store(seq + 2, std::memory_order_release); // even: consistent again
}

PeerSlotState PeerSlotTable::StateOf(std::uint32_t id) const
{
    if (!InRange(id))
        return PeerSlotState::Free;
    return static_cast<PeerSlotState>(state_[id].load(std::memory_order_acquire));
}

} // namespace clv::vpn
