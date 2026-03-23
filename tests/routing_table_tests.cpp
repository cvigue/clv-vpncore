// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "routing_table.h"
#include "util/ipv6_utils.h"
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

using namespace clv::vpn;

// Helper to convert IP string to uint32
uint32_t IpToUint32(const char *ip_str)
{
    uint32_t addr;
    inet_pton(AF_INET, ip_str, &addr);
    return ntohl(addr); // Convert to host byte order
}

class RoutingTableTest : public ::testing::Test
{
  protected:
    RoutingTableIpv4 table;
};

TEST_F(RoutingTableTest, AddAndLookupExactMatch)
{
    // Add route: 192.168.1.0/24 -> session 1
    uint32_t network = IpToUint32("192.168.1.0");
    table.AddRoute(network, 24, 1);

    // Lookup should find it
    uint32_t dest_ip = IpToUint32("192.168.1.100");
    auto result = table.Lookup(dest_ip);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 1);
}

TEST_F(RoutingTableTest, LookupNoMatch)
{
    uint32_t network = IpToUint32("192.168.1.0");
    table.AddRoute(network, 24, 1);

    uint32_t dest_ip = IpToUint32("10.0.0.1");
    auto result = table.Lookup(dest_ip);
    EXPECT_FALSE(result.has_value());
}

TEST_F(RoutingTableTest, LongestPrefixMatch)
{
    // Add two overlapping routes with different session IDs
    uint32_t network1 = IpToUint32("192.168.0.0");
    uint32_t network2 = IpToUint32("192.168.1.0");

    table.AddRoute(network1, 16, 1); // 192.168.0.0/16
    table.AddRoute(network2, 24, 2); // 192.168.1.0/24 (more specific)

    // Lookup IP in second network should return session 2 (longest match)
    uint32_t dest_ip = IpToUint32("192.168.1.50");
    auto result = table.Lookup(dest_ip);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 2);

    // Lookup IP in first network but not second should return session 1
    dest_ip = IpToUint32("192.168.100.50");
    result = table.Lookup(dest_ip);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 1);
}

TEST_F(RoutingTableTest, MultipleRoutes)
{
    table.AddRoute(IpToUint32("10.0.0.0"), 8, 1);
    table.AddRoute(IpToUint32("172.16.0.0"), 12, 2);
    table.AddRoute(IpToUint32("192.168.0.0"), 16, 3);

    EXPECT_EQ(table.GetRouteCount(), 3);

    auto result1 = table.Lookup(IpToUint32("10.1.1.1"));
    EXPECT_EQ(*result1, 1);

    auto result2 = table.Lookup(IpToUint32("172.20.1.1"));
    EXPECT_EQ(*result2, 2);

    auto result3 = table.Lookup(IpToUint32("192.168.100.1"));
    EXPECT_EQ(*result3, 3);
}

TEST_F(RoutingTableTest, RemoveRoute)
{
    uint32_t network = IpToUint32("192.168.1.0");
    table.AddRoute(network, 24, 1);

    uint32_t dest_ip = IpToUint32("192.168.1.100");
    EXPECT_TRUE(table.Lookup(dest_ip).has_value());

    // Remove the route
    bool removed = table.RemoveRoute(network, 24);
    EXPECT_TRUE(removed);

    // Lookup should now fail
    EXPECT_FALSE(table.Lookup(dest_ip).has_value());
}

TEST_F(RoutingTableTest, RemoveNonexistentRoute)
{
    uint32_t network = IpToUint32("192.168.1.0");
    bool removed = table.RemoveRoute(network, 24);
    EXPECT_FALSE(removed);
}

TEST_F(RoutingTableTest, GetRoutesForSession)
{
    uint32_t net1 = IpToUint32("10.0.0.0");
    uint32_t net2 = IpToUint32("192.168.0.0");
    uint32_t net3 = IpToUint32("172.16.0.0");

    table.AddRoute(net1, 8, 1);  // Session 1
    table.AddRoute(net2, 16, 1); // Session 1
    table.AddRoute(net3, 12, 2); // Session 2

    auto routes1 = table.GetRoutesForSession(1);
    EXPECT_EQ(routes1.size(), 2);

    auto routes2 = table.GetRoutesForSession(2);
    EXPECT_EQ(routes2.size(), 1);

    auto routes3 = table.GetRoutesForSession(3);
    EXPECT_EQ(routes3.size(), 0);
}

TEST_F(RoutingTableTest, RemoveSessionRoutes)
{
    uint32_t net1 = IpToUint32("10.0.0.0");
    uint32_t net2 = IpToUint32("192.168.0.0");
    uint32_t net3 = IpToUint32("172.16.0.0");

    table.AddRoute(net1, 8, 1);
    table.AddRoute(net2, 16, 1);
    table.AddRoute(net3, 12, 2);

    size_t removed = table.RemoveSessionRoutes(1);
    EXPECT_EQ(removed, 2);
    EXPECT_EQ(table.GetRouteCount(), 1);

    // Session 2 route should still exist
    auto result = table.Lookup(IpToUint32("172.16.1.1"));
    EXPECT_TRUE(result.has_value());
}

TEST_F(RoutingTableTest, HostRoute)
{
    // /32 is a host route
    uint32_t host_ip = IpToUint32("192.168.1.1");
    table.AddRoute(host_ip, 32, 1);

    auto result = table.Lookup(host_ip);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 1);

    // Nearby IPs should not match
    auto other_result = table.Lookup(IpToUint32("192.168.1.2"));
    EXPECT_FALSE(other_result.has_value());
}

TEST_F(RoutingTableTest, DefaultRoute)
{
    // /0 is the default route
    uint32_t any_network = IpToUint32("0.0.0.0");
    table.AddRoute(any_network, 0, 1);

    // Any IP should match the default route
    auto result1 = table.Lookup(IpToUint32("1.2.3.4"));
    EXPECT_TRUE(result1.has_value());
    EXPECT_EQ(*result1, 1);

    auto result2 = table.Lookup(IpToUint32("192.168.1.1"));
    EXPECT_TRUE(result2.has_value());
    EXPECT_EQ(*result2, 1);
}

TEST_F(RoutingTableTest, ClearAllRoutes)
{
    table.AddRoute(IpToUint32("10.0.0.0"), 8, 1);
    table.AddRoute(IpToUint32("192.168.0.0"), 16, 2);

    EXPECT_EQ(table.GetRouteCount(), 2);

    table.Clear();
    EXPECT_EQ(table.GetRouteCount(), 0);

    auto result = table.Lookup(IpToUint32("10.1.1.1"));
    EXPECT_FALSE(result.has_value());
}

TEST_F(RoutingTableTest, InvalidPrefixLength)
{
    uint32_t network = IpToUint32("192.168.1.0");
    bool added = table.AddRoute(network, 33, 1);
    EXPECT_FALSE(added);
}

TEST_F(RoutingTableTest, NetworkNormalization)
{
    // Add route with host bits set (should be normalized)
    // 192.168.1.100/24 should be treated as 192.168.1.0/24
    uint32_t network_with_host_bits = IpToUint32("192.168.1.100");
    table.AddRoute(network_with_host_bits, 24, 1);

    // Should match IPs in 192.168.1.0/24
    auto result = table.Lookup(IpToUint32("192.168.1.50"));
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 1);
}

TEST_F(RoutingTableTest, UpdateRoute)
{
    uint32_t network = IpToUint32("192.168.1.0");
    table.AddRoute(network, 24, 1);

    auto result = table.Lookup(IpToUint32("192.168.1.1"));
    EXPECT_EQ(*result, 1);

    // Update route to different session
    table.AddRoute(network, 24, 2);

    result = table.Lookup(IpToUint32("192.168.1.1"));
    EXPECT_EQ(*result, 2);
}

// ===========================================================================
// IPv6 routing table tests
// ===========================================================================

using Ipv6Address = ipv6::Ipv6Address;

// Helper to convert IPv6 string to Ipv6Address (network byte order)
Ipv6Address Ipv6FromString(const char *ip_str)
{
    Ipv6Address addr{};
    inet_pton(AF_INET6, ip_str, addr.data());
    return addr;
}

class RoutingTableIpv6Test : public ::testing::Test
{
  protected:
    RoutingTableIpv6 table;
};

TEST_F(RoutingTableIpv6Test, AddAndLookupExactMatch)
{
    auto network = Ipv6FromString("2001:db8:1::");
    table.AddRoute(network, 48, 1);

    auto dest = Ipv6FromString("2001:db8:1::42");
    auto result = table.Lookup(dest);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 1);
}

TEST_F(RoutingTableIpv6Test, LookupNoMatch)
{
    auto network = Ipv6FromString("2001:db8:1::");
    table.AddRoute(network, 48, 1);

    auto dest = Ipv6FromString("fd00::1");
    auto result = table.Lookup(dest);
    EXPECT_FALSE(result.has_value());
}

TEST_F(RoutingTableIpv6Test, LongestPrefixMatch)
{
    auto network1 = Ipv6FromString("2001:db8::");
    auto network2 = Ipv6FromString("2001:db8:1::");

    table.AddRoute(network1, 32, 1); // 2001:db8::/32
    table.AddRoute(network2, 48, 2); // 2001:db8:1::/48 (more specific)

    // Should match the /48
    auto dest = Ipv6FromString("2001:db8:1::99");
    auto result = table.Lookup(dest);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 2);

    // Should fall back to /32
    dest = Ipv6FromString("2001:db8:ff::1");
    result = table.Lookup(dest);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 1);
}

TEST_F(RoutingTableIpv6Test, MultipleRoutes)
{
    table.AddRoute(Ipv6FromString("2001:db8:1::"), 48, 1);
    table.AddRoute(Ipv6FromString("fd00::"), 16, 2);
    table.AddRoute(Ipv6FromString("fe80::"), 10, 3);

    EXPECT_EQ(table.GetRouteCount(), 3);

    EXPECT_EQ(*table.Lookup(Ipv6FromString("2001:db8:1::abc")), 1);
    EXPECT_EQ(*table.Lookup(Ipv6FromString("fd00::5")), 2);
    EXPECT_EQ(*table.Lookup(Ipv6FromString("fe80::1")), 3);
}

TEST_F(RoutingTableIpv6Test, RemoveRoute)
{
    auto network = Ipv6FromString("2001:db8:1::");
    table.AddRoute(network, 48, 1);

    auto dest = Ipv6FromString("2001:db8:1::42");
    EXPECT_TRUE(table.Lookup(dest).has_value());

    EXPECT_TRUE(table.RemoveRoute(network, 48));
    EXPECT_FALSE(table.Lookup(dest).has_value());
}

TEST_F(RoutingTableIpv6Test, RemoveNonexistentRoute)
{
    auto network = Ipv6FromString("2001:db8:1::");
    EXPECT_FALSE(table.RemoveRoute(network, 48));
}

TEST_F(RoutingTableIpv6Test, GetRoutesForSession)
{
    table.AddRoute(Ipv6FromString("2001:db8:1::"), 48, 1);
    table.AddRoute(Ipv6FromString("2001:db8:2::"), 48, 1);
    table.AddRoute(Ipv6FromString("fd00::"), 16, 2);

    EXPECT_EQ(table.GetRoutesForSession(1).size(), 2);
    EXPECT_EQ(table.GetRoutesForSession(2).size(), 1);
    EXPECT_EQ(table.GetRoutesForSession(3).size(), 0);
}

TEST_F(RoutingTableIpv6Test, RemoveSessionRoutes)
{
    table.AddRoute(Ipv6FromString("2001:db8:1::"), 48, 1);
    table.AddRoute(Ipv6FromString("2001:db8:2::"), 48, 1);
    table.AddRoute(Ipv6FromString("fd00::"), 16, 2);

    size_t removed = table.RemoveSessionRoutes(1);
    EXPECT_EQ(removed, 2);
    EXPECT_EQ(table.GetRouteCount(), 1);

    EXPECT_TRUE(table.Lookup(Ipv6FromString("fd00::5")).has_value());
}

TEST_F(RoutingTableIpv6Test, HostRoute)
{
    auto host = Ipv6FromString("2001:db8::1");
    table.AddRoute(host, 128, 1);

    EXPECT_TRUE(table.Lookup(host).has_value());
    EXPECT_FALSE(table.Lookup(Ipv6FromString("2001:db8::2")).has_value());
}

TEST_F(RoutingTableIpv6Test, DefaultRoute)
{
    table.AddRoute(Ipv6FromString("::"), 0, 1);

    EXPECT_EQ(*table.Lookup(Ipv6FromString("2001:db8::1")), 1);
    EXPECT_EQ(*table.Lookup(Ipv6FromString("fe80::1")), 1);
}

TEST_F(RoutingTableIpv6Test, ClearAllRoutes)
{
    table.AddRoute(Ipv6FromString("2001:db8:1::"), 48, 1);
    table.AddRoute(Ipv6FromString("fd00::"), 16, 2);

    EXPECT_EQ(table.GetRouteCount(), 2);

    table.Clear();
    EXPECT_EQ(table.GetRouteCount(), 0);
    EXPECT_FALSE(table.Lookup(Ipv6FromString("2001:db8:1::1")).has_value());
}

TEST_F(RoutingTableIpv6Test, InvalidPrefixLength)
{
    auto network = Ipv6FromString("2001:db8::");
    EXPECT_FALSE(table.AddRoute(network, 129, 1));
}

TEST_F(RoutingTableIpv6Test, NetworkNormalization)
{
    // 2001:db8:1::ff/48 should normalize to 2001:db8:1::/48
    auto network_with_host = Ipv6FromString("2001:db8:1::ff");
    table.AddRoute(network_with_host, 48, 1);

    auto result = table.Lookup(Ipv6FromString("2001:db8:1::42"));
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 1);
}

TEST_F(RoutingTableIpv6Test, UpdateRoute)
{
    auto network = Ipv6FromString("2001:db8:1::");
    table.AddRoute(network, 48, 1);
    EXPECT_EQ(*table.Lookup(Ipv6FromString("2001:db8:1::1")), 1);

    table.AddRoute(network, 48, 2);
    EXPECT_EQ(*table.Lookup(Ipv6FromString("2001:db8:1::1")), 2);
}
