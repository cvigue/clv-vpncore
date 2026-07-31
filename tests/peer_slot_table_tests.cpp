// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include "peer_slot_table.h"
#include "ip_pool_manager.h"
#include "resource_lease.h"

#include <gtest/gtest.h>

#include <asio/ip/address.hpp>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace clv::vpn;

namespace {

transport::PeerEndpoint Ep(const char *addr, std::uint16_t port)
{
    return transport::PeerEndpoint{.addr = asio::ip::make_address(addr), .port = port};
}

} // namespace

TEST(PeerSlotTable, ReservesUniqueIdsFromZero)
{
    PeerSlotTable table(4);
    EXPECT_EQ(table.TotalCount(), 4u);
    EXPECT_EQ(table.AvailableCount(), 4u);
    EXPECT_EQ(table.AllocatedCount(), 0u);

    auto a = table.Reserve();
    auto b = table.Reserve();
    ASSERT_TRUE(a);
    ASSERT_TRUE(b);
    EXPECT_EQ(a->value(), 0u);
    EXPECT_EQ(b->value(), 1u);
    EXPECT_EQ(table.StateOf(0), PeerSlotState::Reserved);
    EXPECT_EQ(table.AllocatedCount(), 2u);
    EXPECT_EQ(table.AvailableCount(), 2u);
}

TEST(PeerSlotTable, RejectsInvalidCapacity)
{
    EXPECT_THROW(PeerSlotTable{0}, std::invalid_argument);
    EXPECT_THROW(PeerSlotTable{kPeerIdUndef}, std::invalid_argument);
    EXPECT_THROW(PeerSlotTable{kPeerIdUndef + 1}, std::invalid_argument);
}

TEST(PeerSlotTable, NeverHandsOutUndef)
{
    PeerSlotTable table(16);
    std::unordered_set<std::uint32_t> seen;
    std::vector<PeerSlotTable::Lease> leases;
    for (std::size_t i = 0; i < 16; ++i)
    {
        auto lease = table.Reserve();
        ASSERT_TRUE(lease);
        EXPECT_LT(lease->value(), kPeerIdUndef);
        EXPECT_TRUE(seen.insert(lease->value()).second);
        leases.push_back(std::move(*lease));
    }
    EXPECT_FALSE(table.Reserve().has_value());
}

TEST(PeerSlotTable, ExhaustionReturnsNullopt)
{
    PeerSlotTable table(2);
    auto a = table.Reserve();
    auto b = table.Reserve();
    ASSERT_TRUE(a);
    ASSERT_TRUE(b);
    EXPECT_EQ(table.AvailableCount(), 0u);
    EXPECT_FALSE(table.Reserve().has_value());
    EXPECT_FALSE(table.Reserve().has_value());
}

TEST(PeerSlotTable, ReservedSlotIsNotReallocatable)
{
    PeerSlotTable table(1);
    auto a = table.Reserve();
    ASSERT_TRUE(a);
    EXPECT_EQ(table.StateOf(a->value()), PeerSlotState::Reserved);
    EXPECT_EQ(table.AvailableCount(), 0u);
    EXPECT_FALSE(table.Reserve().has_value());
}

TEST(PeerSlotTable, OccupiedSlotIsNotReallocatable)
{
    PeerSlotTable table(1);
    auto a = table.Reserve();
    ASSERT_TRUE(a);
    table.Occupy(a->value(), 1, Ep("192.0.2.1", 1194));
    EXPECT_EQ(table.StateOf(a->value()), PeerSlotState::Occupied);
    EXPECT_FALSE(table.Reserve().has_value());
}

TEST(PeerSlotTable, CursorDoesNotImmediatelyReuseFreedId)
{
    PeerSlotTable table(4);

    auto first = table.Reserve();
    ASSERT_TRUE(first);
    ASSERT_EQ(first->value(), 0u);
    first.reset(); // frees slot 0

    // Cursor sits past slot 0, so the next reservation walks forward.
    auto second = table.Reserve();
    ASSERT_TRUE(second);
    EXPECT_NE(second->value(), 0u);
    EXPECT_EQ(second->value(), 1u);
}

TEST(PeerSlotTable, CursorWrapsAndFindsHoles)
{
    PeerSlotTable table(3);
    auto a = table.Reserve();
    auto b = table.Reserve();
    auto c = table.Reserve();
    ASSERT_TRUE(a);
    ASSERT_TRUE(b);
    ASSERT_TRUE(c);
    EXPECT_FALSE(table.Reserve().has_value());

    // Free the lowest id; cursor has wrapped to 0 but must still find it.
    const auto freed = a->value();
    a.reset();
    auto d = table.Reserve();
    ASSERT_TRUE(d);
    EXPECT_EQ(d->value(), freed);
    EXPECT_FALSE(table.Reserve().has_value());
}

TEST(PeerSlotTable, RetiringSlotIsNotReallocatable)
{
    PeerSlotTable table(2);
    auto a = table.Reserve();
    auto b = table.Reserve();
    ASSERT_TRUE(a);
    ASSERT_TRUE(b);

    const auto id = a->value();
    table.Occupy(id, 0xAAAA, Ep("192.0.2.10", 1194));
    ASSERT_EQ(table.StateOf(id), PeerSlotState::Occupied);

    table.Retire(id);
    EXPECT_EQ(table.StateOf(id), PeerSlotState::Retiring);
    EXPECT_EQ(table.AvailableCount(), 0u);
    EXPECT_FALSE(table.Reserve().has_value());

    // Only the lease destructor (post kernel teardown + grace) frees the id.
    a.reset();
    EXPECT_EQ(table.StateOf(id), PeerSlotState::Free);
    auto reused = table.Reserve();
    ASSERT_TRUE(reused);
    EXPECT_EQ(reused->value(), id);
}

TEST(PeerSlotTable, OnlyOccupiedSlotsResolveOnTheDataPath)
{
    PeerSlotTable table(4);
    auto lease = table.Reserve();
    ASSERT_TRUE(lease);
    const auto id = lease->value();

    // Reserved: keys are not published yet.
    EXPECT_FALSE(table.LookupSession(id).has_value());
    transport::PeerEndpoint out;
    EXPECT_FALSE(table.ReadEndpoint(id, out));

    table.Occupy(id, 0x1234, Ep("192.0.2.7", 4444));
    auto sid = table.LookupSession(id);
    ASSERT_TRUE(sid);
    EXPECT_EQ(*sid, 0x1234u);
    ASSERT_TRUE(table.ReadEndpoint(id, out));
    EXPECT_EQ(out, Ep("192.0.2.7", 4444));

    table.Retire(id);
    EXPECT_FALSE(table.LookupSession(id).has_value());
    EXPECT_FALSE(table.ReadEndpoint(id, out));
}

TEST(PeerSlotTable, OutOfRangeAndUndefIdsResolveToNothing)
{
    PeerSlotTable table(2);
    auto lease = table.Reserve();
    ASSERT_TRUE(lease);
    table.Occupy(lease->value(), 7, Ep("192.0.2.1", 1194));

    EXPECT_FALSE(table.LookupSession(2).has_value());
    EXPECT_FALSE(table.LookupSession(kPeerIdUndef).has_value());
    EXPECT_EQ(table.StateOf(kPeerIdUndef), PeerSlotState::Free);

    transport::PeerEndpoint out;
    EXPECT_FALSE(table.ReadEndpoint(kPeerIdUndef, out));
}

TEST(PeerSlotTable, PublishEndpointUpdatesLiveSlotOnly)
{
    PeerSlotTable table(2);
    auto lease = table.Reserve();
    ASSERT_TRUE(lease);
    const auto id = lease->value();
    table.Occupy(id, 9, Ep("192.0.2.5", 1194));

    table.PublishEndpoint(id, Ep("198.51.100.9", 5555));
    transport::PeerEndpoint out;
    ASSERT_TRUE(table.ReadEndpoint(id, out));
    EXPECT_EQ(out, Ep("198.51.100.9", 5555));

    // Retired slots ignore float updates.
    table.Retire(id);
    table.PublishEndpoint(id, Ep("203.0.113.1", 6666));
    EXPECT_FALSE(table.ReadEndpoint(id, out));
}

TEST(PeerSlotTable, PackedEndpointRoundTripsIpv6)
{
    PeerSlotTable table(1);
    auto lease = table.Reserve();
    ASSERT_TRUE(lease);
    const auto v6 = Ep("2001:db8::1", 1194);
    table.Occupy(lease->value(), 1, v6);

    transport::PeerEndpoint out;
    ASSERT_TRUE(table.ReadEndpoint(lease->value(), out));
    EXPECT_EQ(out, v6);
}

TEST(PeerSlotTable, KernelPeerFlagSurvivesRetireAndClearsOnFree)
{
    PeerSlotTable table(2);
    auto lease = table.Reserve();
    ASSERT_TRUE(lease);
    const auto id = lease->value();

    EXPECT_FALSE(table.HasKernelPeer(id));
    table.Occupy(id, 5, Ep("192.0.2.4", 1194));
    table.SetKernelPeer(id, true);

    // Teardown retires the slot first, but DEL_PEER still has to be sent, so
    // the flag must outlive Retire.
    table.Retire(id);
    EXPECT_TRUE(table.HasKernelPeer(id));

    table.SetKernelPeer(id, false);
    lease.reset();

    // A reallocated slot never inherits a kernel peer.
    auto reused = table.Reserve();
    ASSERT_TRUE(reused);
    EXPECT_FALSE(table.HasKernelPeer(reused->value()));
}

TEST(PeerSlotTable, FreeClearsKernelPeerFlag)
{
    PeerSlotTable table(1);
    auto lease = table.Reserve();
    ASSERT_TRUE(lease);
    const auto id = lease->value();
    table.SetKernelPeer(id, true);

    lease.reset();
    EXPECT_FALSE(table.HasKernelPeer(id));
}

TEST(PeerSlotTable, TeardownOrderKeepsIdUnreachableUntilKernelPeerIsGone)
{
    PeerSlotTable table(2);
    auto lease = table.Reserve();
    ASSERT_TRUE(lease);
    const auto id = lease->value();
    table.Occupy(id, 0x1111, Ep("192.0.2.8", 1194));
    table.SetKernelPeer(id, true);

    // 1. Retire: the data path can no longer resolve the id...
    table.Retire(id);
    EXPECT_FALSE(table.LookupSession(id).has_value());
    // ...but teardown still knows a kernel peer must be deleted...
    EXPECT_TRUE(table.HasKernelPeer(id));
    // ...and the id is not allocatable in the meantime.
    auto other = table.Reserve();
    ASSERT_TRUE(other);
    EXPECT_NE(other->value(), id);

    // 2. DEL_PEER acknowledged, 3. grace period elapsed, 4. lease destroyed.
    table.SetKernelPeer(id, false);
    lease.reset();
    other.reset();

    auto reused = table.Reserve();
    ASSERT_TRUE(reused);
    EXPECT_FALSE(table.HasKernelPeer(reused->value()));
}

TEST(PeerSlotTable, RebindControlThreadAllowsShutdownFreeFromAnotherThread)
{
    PeerSlotTable table(2);
    auto lease = table.Reserve(); // latches this thread as the writer
    ASSERT_TRUE(lease);

    // Shutdown frees leases on whichever thread called Stop().
    std::thread shutdown([&]
    {
        table.RebindControlThread();
        lease.reset();
        EXPECT_EQ(table.AvailableCount(), 2u);
    });
    shutdown.join();

    EXPECT_EQ(table.AllocatedCount(), 0u);
}

TEST(PeerSlotTable, MoveLeaseTransfersOwnership)
{
    PeerSlotTable table(1);
    auto maybe = table.Reserve();
    ASSERT_TRUE(maybe);
    PeerSlotTable::Lease moved = std::move(*maybe);
    EXPECT_FALSE(maybe->has_value());
    EXPECT_TRUE(moved.has_value());
    EXPECT_EQ(table.AllocatedCount(), 1u);
    moved.Reset();
    EXPECT_EQ(table.AllocatedCount(), 0u);
    EXPECT_EQ(table.AvailableCount(), 1u);
}

TEST(IpPoolLease, DestroyReturnsAddressWithoutExplicitRelease)
{
    IpPoolManager pool("10.8.0.0/30", true, 0); // gateway .1, one usable .2
    ASSERT_EQ(pool.TotalCount(), 1u);

    auto ip = pool.AllocateIpv4(42);
    ASSERT_TRUE(ip.has_value());

    {
        PoolLease<IpPoolManager, std::uint32_t> lease{&pool, *ip};
        EXPECT_TRUE(pool.IsIpv4Allocated(*ip));
        EXPECT_EQ(pool.AvailableCount(), 0u);
    }

    EXPECT_FALSE(pool.IsIpv4Allocated(*ip));
    EXPECT_EQ(pool.AvailableCount(), 1u);
    EXPECT_FALSE(pool.GetAssignedIpv4(42).has_value());
}
