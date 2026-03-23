// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include "ip_pool_manager.h"
#include "util/ipv6_utils.h"
#include <cstdint>
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <vector>

using namespace clv::vpn;

namespace {

// Helper to convert IP from uint32_t to string
std::string IpToString(uint32_t ip)
{
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    return inet_ntoa(addr);
}

// Helper to convert IP from string to uint32_t
uint32_t StringToIp(const std::string &ip_str)
{
    struct in_addr addr;
    inet_pton(AF_INET, ip_str.c_str(), &addr);
    return ntohl(addr.s_addr);
}

} // namespace

class IpPoolManagerTest : public ::testing::Test
{
};

TEST_F(IpPoolManagerTest, ConstructorValidCidr)
{
    EXPECT_NO_THROW({
        IpPoolManager pool("10.8.0.0/24");
    });
}

TEST_F(IpPoolManagerTest, ConstructorInvalidCidr)
{
    EXPECT_THROW(IpPoolManager("invalid"), std::invalid_argument);
    EXPECT_THROW(IpPoolManager("10.8.0.0"), std::invalid_argument);
    EXPECT_THROW(IpPoolManager("10.8.0.0/33"), std::invalid_argument);
    EXPECT_THROW(IpPoolManager("10.8.0.256/24"), std::invalid_argument);
}

TEST_F(IpPoolManagerTest, PoolSize24Network)
{
    IpPoolManager pool("10.8.0.0/24", true);

    // /24 network: 256 addresses
    // - 1 network address (10.8.0.0)
    // - 1 broadcast (10.8.0.255)
    // - 1 gateway (10.8.0.1) reserved
    // = 253 usable IPs
    EXPECT_EQ(pool.TotalCount(), 253);
    EXPECT_EQ(pool.AvailableCount(), 253);
    EXPECT_EQ(pool.AllocatedCount(), 0);
}

TEST_F(IpPoolManagerTest, PoolSize24NetworkNoGatewayReserve)
{
    IpPoolManager pool("10.8.0.0/24", false);

    // Without gateway reservation: 254 usable IPs
    EXPECT_EQ(pool.TotalCount(), 254);
    EXPECT_EQ(pool.AvailableCount(), 254);
}

TEST_F(IpPoolManagerTest, PoolSize30Network)
{
    IpPoolManager pool("192.168.1.0/30", false);

    // /30 network: 4 addresses
    // - 1 network address
    // - 1 broadcast
    // = 2 usable IPs
    EXPECT_EQ(pool.TotalCount(), 2);
    EXPECT_EQ(pool.AvailableCount(), 2);
}

TEST_F(IpPoolManagerTest, AllocateIpBasic)
{
    IpPoolManager pool("10.8.0.0/24");

    auto ip1 = pool.AllocateIpv4(1001);
    ASSERT_TRUE(ip1.has_value());

    // Should be within 10.8.0.2 .. 10.8.0.254 (skip .0 network, .1 gateway, .255 broadcast)
    EXPECT_GE(*ip1, 0x0A080002u); // 10.8.0.2
    EXPECT_LE(*ip1, 0x0A0800FEu); // 10.8.0.254
    EXPECT_EQ(pool.AllocatedCount(), 1);
    EXPECT_EQ(pool.AvailableCount(), 252);
}

TEST_F(IpPoolManagerTest, AllocateMultipleIps)
{
    IpPoolManager pool("10.8.0.0/30", false);

    auto ip1 = pool.AllocateIpv4(1001);
    auto ip2 = pool.AllocateIpv4(1002);

    ASSERT_TRUE(ip1.has_value());
    ASSERT_TRUE(ip2.has_value());
    EXPECT_NE(*ip1, *ip2);

    EXPECT_EQ(pool.AllocatedCount(), 2);
    EXPECT_EQ(pool.AvailableCount(), 0);
}

TEST_F(IpPoolManagerTest, AllocateIpPoolExhaustion)
{
    IpPoolManager pool("192.168.1.0/30", false);

    // Allocate all 2 available IPs
    auto ip1 = pool.AllocateIpv4(1);
    auto ip2 = pool.AllocateIpv4(2);
    auto ip3 = pool.AllocateIpv4(3);

    EXPECT_TRUE(ip1.has_value());
    EXPECT_TRUE(ip2.has_value());
    EXPECT_FALSE(ip3.has_value()); // Pool exhausted

    EXPECT_EQ(pool.AllocatedCount(), 2);
    EXPECT_EQ(pool.AvailableCount(), 0);
}

TEST_F(IpPoolManagerTest, AllocateIpIdempotent)
{
    IpPoolManager pool("10.8.0.0/24");

    auto ip1 = pool.AllocateIpv4(1001);
    auto ip2 = pool.AllocateIpv4(1001); // Same session

    ASSERT_TRUE(ip1.has_value());
    ASSERT_TRUE(ip2.has_value());
    EXPECT_EQ(*ip1, *ip2); // Should get same IP

    // Only 1 IP allocated
    EXPECT_EQ(pool.AllocatedCount(), 1);
}

TEST_F(IpPoolManagerTest, ReleaseIpBasic)
{
    IpPoolManager pool("10.8.0.0/24");

    auto ip = pool.AllocateIpv4(1001);
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(pool.AllocatedCount(), 1);

    bool released = pool.ReleaseIpv4(1001);
    EXPECT_TRUE(released);
    EXPECT_EQ(pool.AllocatedCount(), 0);
    EXPECT_EQ(pool.AvailableCount(), 253);
}

TEST_F(IpPoolManagerTest, ReleaseIpNotAllocated)
{
    IpPoolManager pool("10.8.0.0/24");

    bool released = pool.ReleaseIpv4(9999);
    EXPECT_FALSE(released); // Session has no IP
}

TEST_F(IpPoolManagerTest, ReleaseAndReallocate)
{
    IpPoolManager pool("192.168.1.0/30", false);

    // Allocate all IPs
    auto ip1 = pool.AllocateIpv4(1);
    auto ip2 = pool.AllocateIpv4(2);
    EXPECT_TRUE(ip1.has_value());
    EXPECT_TRUE(ip2.has_value());

    // Try to allocate - should fail
    auto ip3 = pool.AllocateIpv4(3);
    EXPECT_FALSE(ip3.has_value());

    // Release one IP
    pool.ReleaseIpv4(1);

    // Now we can allocate again
    auto ip4 = pool.AllocateIpv4(4);
    EXPECT_TRUE(ip4.has_value());
}

TEST_F(IpPoolManagerTest, GetAssignedIp)
{
    IpPoolManager pool("10.8.0.0/24");

    EXPECT_FALSE(pool.GetAssignedIpv4(1001).has_value());

    auto ip = pool.AllocateIpv4(1001);
    ASSERT_TRUE(ip.has_value());

    auto assigned = pool.GetAssignedIpv4(1001);
    ASSERT_TRUE(assigned.has_value());
    EXPECT_EQ(*assigned, *ip);
}

TEST_F(IpPoolManagerTest, IsIpAllocated)
{
    IpPoolManager pool("10.8.0.0/24");

    auto ip = pool.AllocateIpv4(1001);
    ASSERT_TRUE(ip.has_value());

    EXPECT_TRUE(pool.IsIpv4Allocated(*ip));

    uint32_t unallocated_ip = StringToIp("10.8.0.100");
    EXPECT_FALSE(pool.IsIpv4Allocated(unallocated_ip));
}

TEST_F(IpPoolManagerTest, ThreadSafety)
{
    IpPoolManager pool("10.8.0.0/24");

    constexpr int num_threads = 10;
    constexpr int allocations_per_thread = 10;

    std::vector<std::thread> threads;
    std::vector<std::vector<std::optional<uint32_t>>> results(num_threads);

    // Allocate IPs concurrently
    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back([&, i]()
        {
            for (int j = 0; j < allocations_per_thread; ++j)
            {
                uint64_t session_id = i * allocations_per_thread + j + 1;
                results[i].push_back(pool.AllocateIpv4(session_id));
            }
        });
    }

    for (auto &t : threads)
    {
        t.join();
    }

    // Verify all allocations succeeded and are unique
    std::set<uint32_t> allocated_ips;
    for (const auto &thread_results : results)
    {
        for (const auto &ip_opt : thread_results)
        {
            ASSERT_TRUE(ip_opt.has_value());
            auto [_, inserted] = allocated_ips.insert(*ip_opt);
            EXPECT_TRUE(inserted) << "Duplicate IP allocated: " << IpToString(*ip_opt);
        }
    }

    EXPECT_EQ(pool.AllocatedCount(), num_threads * allocations_per_thread);
}

TEST_F(IpPoolManagerTest, DifferentNetworks)
{
    {
        IpPoolManager pool("192.168.1.0/24");
        auto ip = pool.AllocateIpv4(1);
        ASSERT_TRUE(ip.has_value());
        std::string ip_str = IpToString(*ip);
        EXPECT_TRUE(ip_str.starts_with("192.168.1."));
    }

    {
        IpPoolManager pool("172.16.0.0/16");
        auto ip = pool.AllocateIpv4(1);
        ASSERT_TRUE(ip.has_value());
        std::string ip_str = IpToString(*ip);
        EXPECT_TRUE(ip_str.starts_with("172.16."));
    }
}

// ---------------------------------------------------------------------------
// max_clients cap tests
// ---------------------------------------------------------------------------

TEST_F(IpPoolManagerTest, MaxClientsCapsPoolSize)
{
    // /24 normally yields 253 usable IPs; cap to 50
    IpPoolManager pool("10.8.0.0/24", true, 50);
    EXPECT_EQ(pool.TotalCount(), 50);
    EXPECT_EQ(pool.AvailableCount(), 50);
}

TEST_F(IpPoolManagerTest, MaxClientsZeroMeansNoCap)
{
    // max_clients=0 → use full CIDR range (253 for /24)
    IpPoolManager pool("10.8.0.0/24", true, 0);
    EXPECT_EQ(pool.TotalCount(), 253);
}

TEST_F(IpPoolManagerTest, MaxClientsLargerThanCidrNoCap)
{
    // max_clients=500 but /24 only has 253 → pool should be 253
    IpPoolManager pool("10.8.0.0/24", true, 500);
    EXPECT_EQ(pool.TotalCount(), 253);
}

TEST_F(IpPoolManagerTest, MaxClientsExhaustsCappedPool)
{
    IpPoolManager pool("10.8.0.0/24", true, 2);
    EXPECT_EQ(pool.TotalCount(), 2);

    auto ip1 = pool.AllocateIpv4(1);
    auto ip2 = pool.AllocateIpv4(2);
    auto ip3 = pool.AllocateIpv4(3);

    EXPECT_TRUE(ip1.has_value());
    EXPECT_TRUE(ip2.has_value());
    EXPECT_FALSE(ip3.has_value()); // Pool exhausted at max_clients=2
}

TEST_F(IpPoolManagerTest, MaxClientsIpv6CapsPool)
{
    // /112 normally yields 65533 addresses; cap to 10
    IpPoolManager pool("10.8.0.0/24", true, 10);
    pool.EnableIpv6Pool("fd00::/112", true, 10);

    EXPECT_EQ(pool.TotalCount(), 10);
    EXPECT_EQ(pool.Ipv6AvailableCount(), 10);
}

// ===========================================================================
// IPv6 IP pool tests
// ===========================================================================

using Ipv6Address = ipv6::Ipv6Address;

// Helper to build an expected IPv6 address from fd00:: prefix with a host byte
static Ipv6Address MakeIpv6(std::uint8_t host_hi, std::uint8_t host_lo)
{
    Ipv6Address addr{};
    addr[0] = 0xfd; // fd00::
    addr[14] = host_hi;
    addr[15] = host_lo;
    return addr;
}

TEST_F(IpPoolManagerTest, Ipv6EnablePoolValid)
{
    IpPoolManager pool("10.8.0.0/24");
    EXPECT_FALSE(pool.HasIpv6Pool());

    EXPECT_NO_THROW(pool.EnableIpv6Pool("fd00::/112", true));
    EXPECT_TRUE(pool.HasIpv6Pool());
}

TEST_F(IpPoolManagerTest, Ipv6EnablePoolInvalidCidr)
{
    IpPoolManager pool("10.8.0.0/24");

    EXPECT_THROW(pool.EnableIpv6Pool("invalid"), std::invalid_argument);
    EXPECT_THROW(pool.EnableIpv6Pool("fd00::/128"), std::invalid_argument); // no host bits
    EXPECT_THROW(pool.EnableIpv6Pool("fd00::/64"), std::invalid_argument);  // too wide (< /112)
}

TEST_F(IpPoolManagerTest, Ipv6PoolSize112Network)
{
    IpPoolManager pool("10.8.0.0/24");
    pool.EnableIpv6Pool("fd00::/112", true);

    // /112: 65536 addrs - network - all-ones - gateway = 65533
    EXPECT_EQ(pool.Ipv6AvailableCount(), 65533);
}

TEST_F(IpPoolManagerTest, Ipv6PoolSize112NoGateway)
{
    IpPoolManager pool("10.8.0.0/24");
    pool.EnableIpv6Pool("fd00::/112", false);

    // /112: 65536 addrs - network - all-ones = 65534, start from ::1
    EXPECT_EQ(pool.Ipv6AvailableCount(), 65534);
}

TEST_F(IpPoolManagerTest, Ipv6AllocateBasic)
{
    IpPoolManager pool("10.8.0.0/24");
    pool.EnableIpv6Pool("fd00::/120", true, 50);

    auto ip = pool.AllocateIpv6(1001);
    ASSERT_TRUE(ip.has_value());

    // Should be fd00::2 .. fd00::fe (skip ::0, ::1 gateway, ::ff broadcast)
    EXPECT_EQ((*ip)[0], 0xfd);
    EXPECT_GT((*ip)[15], 1);   // past gateway
    EXPECT_LT((*ip)[15], 255); // before broadcast
}

TEST_F(IpPoolManagerTest, Ipv6AllocateMultiple)
{
    IpPoolManager pool("10.8.0.0/24");
    pool.EnableIpv6Pool("fd00::/120", true, 50);

    auto ip1 = pool.AllocateIpv6(1001);
    auto ip2 = pool.AllocateIpv6(1002);

    ASSERT_TRUE(ip1.has_value());
    ASSERT_TRUE(ip2.has_value());
    EXPECT_NE(*ip1, *ip2);
}

TEST_F(IpPoolManagerTest, Ipv6AllocateIdempotent)
{
    IpPoolManager pool("10.8.0.0/24");
    pool.EnableIpv6Pool("fd00::/120", true);

    auto ip1 = pool.AllocateIpv6(1001);
    auto ip2 = pool.AllocateIpv6(1001); // Same session

    ASSERT_TRUE(ip1.has_value());
    ASSERT_TRUE(ip2.has_value());
    EXPECT_EQ(*ip1, *ip2);
}

TEST_F(IpPoolManagerTest, Ipv6AllocateExhaustion)
{
    IpPoolManager pool("10.8.0.0/24");
    pool.EnableIpv6Pool("fd00::/120", true, 2); // cap to 2

    auto ip1 = pool.AllocateIpv6(1);
    auto ip2 = pool.AllocateIpv6(2);
    auto ip3 = pool.AllocateIpv6(3);

    EXPECT_TRUE(ip1.has_value());
    EXPECT_TRUE(ip2.has_value());
    EXPECT_FALSE(ip3.has_value());
}

TEST_F(IpPoolManagerTest, Ipv6AllocateWithoutPool)
{
    IpPoolManager pool("10.8.0.0/24");
    // IPv6 pool not enabled
    auto ip = pool.AllocateIpv6(1001);
    EXPECT_FALSE(ip.has_value());
}

TEST_F(IpPoolManagerTest, Ipv6ReleaseBasic)
{
    IpPoolManager pool("10.8.0.0/24");
    pool.EnableIpv6Pool("fd00::/120", true);

    auto ip = pool.AllocateIpv6(1001);
    ASSERT_TRUE(ip.has_value());

    EXPECT_TRUE(pool.ReleaseIpv6(1001));
    EXPECT_FALSE(pool.GetAssignedIpv6(1001).has_value());
}

TEST_F(IpPoolManagerTest, Ipv6ReleaseNotAllocated)
{
    IpPoolManager pool("10.8.0.0/24");
    pool.EnableIpv6Pool("fd00::/120", true);

    EXPECT_FALSE(pool.ReleaseIpv6(9999));
}

TEST_F(IpPoolManagerTest, Ipv6ReleaseAndReallocate)
{
    IpPoolManager pool("10.8.0.0/24");
    pool.EnableIpv6Pool("fd00::/120", true, 2);

    auto ip1 = pool.AllocateIpv6(1);
    auto ip2 = pool.AllocateIpv6(2);
    EXPECT_FALSE(pool.AllocateIpv6(3).has_value()); // exhausted

    pool.ReleaseIpv6(1);
    auto ip3 = pool.AllocateIpv6(3);
    EXPECT_TRUE(ip3.has_value());
}

TEST_F(IpPoolManagerTest, Ipv6GetAssigned)
{
    IpPoolManager pool("10.8.0.0/24");
    pool.EnableIpv6Pool("fd00::/120", true);

    EXPECT_FALSE(pool.GetAssignedIpv6(1001).has_value());

    auto ip = pool.AllocateIpv6(1001);
    ASSERT_TRUE(ip.has_value());

    auto assigned = pool.GetAssignedIpv6(1001);
    ASSERT_TRUE(assigned.has_value());
    EXPECT_EQ(*assigned, *ip);
}

TEST_F(IpPoolManagerTest, Ipv6IsAllocated)
{
    IpPoolManager pool("10.8.0.0/24");
    pool.EnableIpv6Pool("fd00::/120", true);

    auto ip = pool.AllocateIpv6(1001);
    ASSERT_TRUE(ip.has_value());

    EXPECT_TRUE(pool.IsIpv6Allocated(*ip));
    EXPECT_FALSE(pool.IsIpv6Allocated(MakeIpv6(0, 0x99))); // unallocated
}

TEST_F(IpPoolManagerTest, Ipv6DualStackRoundTrip)
{
    IpPoolManager pool("10.8.0.0/24");
    pool.EnableIpv6Pool("fd00::/120", true);

    // Allocate both v4 and v6 for same session
    auto v4 = pool.AllocateIpv4(1001);
    auto v6 = pool.AllocateIpv6(1001);

    ASSERT_TRUE(v4.has_value());
    ASSERT_TRUE(v6.has_value());

    // Both assigned
    EXPECT_TRUE(pool.GetAssignedIpv4(1001).has_value());
    EXPECT_TRUE(pool.GetAssignedIpv6(1001).has_value());

    // Release both
    EXPECT_TRUE(pool.ReleaseIpv4(1001));
    EXPECT_TRUE(pool.ReleaseIpv6(1001));

    EXPECT_FALSE(pool.GetAssignedIpv4(1001).has_value());
    EXPECT_FALSE(pool.GetAssignedIpv6(1001).has_value());
}
