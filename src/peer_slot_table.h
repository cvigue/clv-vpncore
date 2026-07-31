// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_PEER_SLOT_TABLE_H
#define CLV_VPN_PEER_SLOT_TABLE_H

/**
 * @file peer_slot_table.h
 * @brief Immortal peer-id slot table: occupancy is the allocator.
 *
 * The 24-bit DATA_V2 / DCO peer-id is a lookup key (UDP RX demux, peer float,
 * kernel ovpn-dco peer index), so the structure that answers "who is peer N"
 * must also be the structure that answers "is N allocatable". A detached
 * free-list can hand out an id whose kernel peer or data-path reader still
 * exists.
 *
 * The table itself never shrinks or reallocates; only slot payloads change.
 * Data-path threads read slots directly and treat anything but @c Occupied as
 * a drop, so a slot is unreachable the moment the control plane retires it —
 * before any kernel teardown or QSBR grace period has to finish.
 */

#include "openvpn/protocol_constants.h"
#include "resource_lease.h"
#include "transport/transport.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>
#include <optional>
#include <thread>
#include <vector>

namespace clv::vpn {

/** @brief OpenVPN "undefined" peer-id; never allocated from the table. */
inline constexpr std::uint32_t kPeerIdUndef = openvpn::PEER_ID_MASK;

/**
 * @brief Lifecycle of one peer-id slot.
 *
 * Only @c Occupied slots are reachable from the data path. @c Reserved covers
 * the window between allocation and key publication; @c Retiring covers the
 * window between control-plane teardown and the id becoming allocatable again
 * (kernel DEL_PEER, QSBR grace).
 */
enum class PeerSlotState : std::uint8_t
{
    Free = 0,
    Reserved,
    Occupied,
    Retiring,
};

/**
 * @brief Trivially copyable peer address for lock-free slot publication.
 *
 * @c asio::ip::address is not safe to memcpy under a concurrent writer, so the
 * slot stores the wire form and converts at the boundary.
 */
struct PackedEndpoint
{
    std::array<std::uint8_t, 16> addr{};
    std::uint16_t port = 0;
    bool is_v6 = false;

    bool operator==(const PackedEndpoint &) const = default;
};

/** @brief Convert a transport endpoint to the packed slot form. */
[[nodiscard]] PackedEndpoint PackEndpoint(const transport::PeerEndpoint &ep);

/** @brief Convert a packed slot endpoint back to transport form. */
[[nodiscard]] transport::PeerEndpoint UnpackEndpoint(const PackedEndpoint &packed);

/**
 * @brief Immortal table of peer-id slots, indexed by wire peer-id.
 *
 * Allocator transitions (@ref Reserve, @ref Occupy, @ref Retire, @ref Free)
 * are single-writer: they must all run on the control plane's io_context.
 * The atomics exist so RX/TX threads see consistent slots, not to make the
 * allocator contention-safe.
 *
 * After a slot is @c Occupied, the endpoint may only be written by the RX
 * thread (peer float). Two concurrent endpoint writers would tear the address.
 */
class PeerSlotTable
{
  public:
    /** @brief Move-only lease; destruction frees the slot for reallocation. */
    using Lease = PoolLease<PeerSlotTable, std::uint32_t>;

    /**
     * @brief Build a table of @p capacity slots, all @c Free.
     * @param capacity Number of ids (`max_clients`); must be &lt; @c kPeerIdUndef
     * @throws std::invalid_argument if capacity is 0 or &gt;= @c kPeerIdUndef
     */
    explicit PeerSlotTable(std::size_t capacity);

    PeerSlotTable(const PeerSlotTable &) = delete;
    PeerSlotTable &operator=(const PeerSlotTable &) = delete;
    PeerSlotTable(PeerSlotTable &&) = delete;
    PeerSlotTable &operator=(PeerSlotTable &&) = delete;

    /**
     * @brief Claim a @c Free slot, advancing the allocation cursor.
     *
     * The cursor scan spreads reuse across the id space so a straggler
     * datagram carrying a stale id is unlikely to land on a live slot. Reuse
     * *correctness* comes from @c Retiring, not from the scan order.
     *
     * @return Lease owning the id, or nullopt when every slot is in use
     */
    [[nodiscard]] std::optional<Lease> Reserve();

    /**
     * @brief Publish a slot to the data path.
     *
     * Call only after the session's keys are in the QSBR snapshot: the
     * release-store of @c Occupied is what makes the id reachable from RX.
     *
     * @param id Reserved slot id
     * @param session_id TLS session this slot resolves to
     * @param endpoint Current remote endpoint
     */
    void Occupy(std::uint32_t id, std::uint64_t session_id,
                const transport::PeerEndpoint &endpoint);

    /**
     * @brief Make a slot unreachable from the data path without freeing it.
     *
     * Must run before kernel peer teardown and before QSBR grace, so no reader
     * can pick the slot up again while the id is still in flight.
     *
     * @param id Occupied or reserved slot id
     */
    void Retire(std::uint32_t id);

    /**
     * @brief Return a retired slot to the allocatable pool.
     * @param id Slot id whose kernel peer and data-path readers are both gone
     */
    void Free(std::uint32_t id);

    /** @brief @ref Free under the name @c PoolLease expects. */
    void Release(std::uint32_t id)
    {
        Free(id);
    }

    /**
     * @brief Resolve an id to its session, if the slot is live.
     * @param id Wire peer-id from a P_DATA_V2 header
     * @return Session id, or nullopt when the slot is not @c Occupied
     */
    [[nodiscard]] std::optional<std::uint64_t> LookupSession(std::uint32_t id) const;

    /**
     * @brief Read a live slot's endpoint (seqlock; retries on a torn read).
     * @param id Wire peer-id
     * @param out Receives the endpoint on success
     * @return false when the slot is not @c Occupied or the read kept tearing
     */
    [[nodiscard]] bool ReadEndpoint(std::uint32_t id, transport::PeerEndpoint &out) const;

    /**
     * @brief Publish a new endpoint for a live slot (peer float).
     *
     * RX-only after the slot is @c Occupied. Callers must have authenticated
     * the packet first: an unauthenticated write here redirects server egress.
     *
     * @param id Wire peer-id
     * @param endpoint Newly observed source endpoint
     */
    void PublishEndpoint(std::uint32_t id, const transport::PeerEndpoint &endpoint);

    /** @brief Current state of a slot, or @c Free for an out-of-range id. */
    [[nodiscard]] PeerSlotState StateOf(std::uint32_t id) const;

    /**
     * @brief Record whether a kernel ovpn-dco peer exists for this slot.
     *
     * Kernel peers are indexed by the same id, so their existence belongs in
     * the slot rather than a parallel map that can outlive the id. Survives
     * @ref Retire (teardown must still send DEL_PEER) and is cleared by
     * @ref Free. Control-plane only; never read from the data path.
     *
     * @param id Slot id
     * @param present True once NEW_PEER succeeded, false once the peer is gone
     */
    void SetKernelPeer(std::uint32_t id, bool present);

    /** @brief Whether a kernel peer is still believed to exist for this slot. */
    [[nodiscard]] bool HasKernelPeer(std::uint32_t id) const;

    /**
     * @brief Hand the single-writer role to the calling thread.
     *
     * Shutdown frees slots from whichever thread called Stop(), not from the
     * control io_context. Only legal once every data-path thread that reads
     * slots has been joined.
     */
    void RebindControlThread() noexcept;

    /** @brief Total slot count (`max_clients`). */
    [[nodiscard]] std::size_t TotalCount() const noexcept
    {
        return capacity_;
    }

    /** @brief Slots currently @c Free. Control-plane only. */
    [[nodiscard]] std::size_t AvailableCount() const noexcept
    {
        return free_count_;
    }

    /** @brief Slots not @c Free (reserved, occupied, or retiring). Control-plane only. */
    [[nodiscard]] std::size_t AllocatedCount() const noexcept
    {
        return capacity_ - free_count_;
    }

  private:
    /**
     * @brief Endpoint cell guarded by a seqlock.
     *
     * Padded because RX writes it on the float path while TX reads it; the
     * dense state/session arrays stay unpadded so a wrap scan does not evict
     * data-path cache lines.
     */
    struct alignas(std::hardware_destructive_interference_size) EndpointCell
    {
        std::atomic<std::uint32_t> seq{0};
        PackedEndpoint value{};
    };

    [[nodiscard]] bool InRange(std::uint32_t id) const noexcept
    {
        return id < capacity_;
    }

    const std::size_t capacity_;

    std::vector<std::atomic<std::uint8_t>> state_;
    std::vector<std::atomic<std::uint64_t>> session_id_;
    std::vector<EndpointCell> endpoint_;

    // Control-plane-only; plain bytes because no data-path thread reads it.
    std::vector<std::uint8_t> kernel_peer_;

    /// Debug-only single-writer check; latches on the first allocator call.
    void AssertControlThread() const noexcept;

    // Control-plane-only allocator state; no atomics by design (single writer).
    std::size_t cursor_ = 0;
    std::size_t free_count_ = 0;
    mutable std::atomic<std::thread::id> owner_{};
};

} // namespace clv::vpn

#endif // CLV_VPN_PEER_SLOT_TABLE_H
