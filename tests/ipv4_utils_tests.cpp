// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include <util/ipv4_utils.h>
#include <cstdint>
#include <gtest/gtest.h>

using namespace clv::vpn;

TEST(Ipv4UtilsTest, ParseCidrValid)
{
    auto result = ipv4::ParseCidr("10.8.0.0/24");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 0x0A080000); // 10.8.0.0 in host byte order
    EXPECT_EQ(result->second, 24);
}

TEST(Ipv4UtilsTest, ParseCidrVariousPrefixes)
{
    auto r8 = ipv4::ParseCidr("192.168.0.0/8");
    ASSERT_TRUE(r8.has_value());
    EXPECT_EQ(r8->second, 8);

    auto r16 = ipv4::ParseCidr("172.16.0.0/16");
    ASSERT_TRUE(r16.has_value());
    EXPECT_EQ(r16->second, 16);

    auto r32 = ipv4::ParseCidr("10.0.0.1/32");
    ASSERT_TRUE(r32.has_value());
    EXPECT_EQ(r32->second, 32);
}

TEST(Ipv4UtilsTest, ParseCidrInvalidFormat)
{
    EXPECT_FALSE(ipv4::ParseCidr("10.8.0.0").has_value());
    EXPECT_FALSE(ipv4::ParseCidr("10.8.0.0/").has_value());
    EXPECT_FALSE(ipv4::ParseCidr("/24").has_value());
}

TEST(Ipv4UtilsTest, ParseCidrInvalidPrefix)
{
    EXPECT_FALSE(ipv4::ParseCidr("10.8.0.0/33").has_value());
    EXPECT_FALSE(ipv4::ParseCidr("10.8.0.0/-1").has_value());
}

TEST(Ipv4UtilsTest, ParseCidrInvalidIp)
{
    EXPECT_FALSE(ipv4::ParseCidr("256.0.0.1/24").has_value());
    EXPECT_FALSE(ipv4::ParseCidr("10.8.0/24").has_value());
}

TEST(Ipv4UtilsTest, CreateMask)
{
    EXPECT_EQ(ipv4::CreateMask(0), 0x00000000);
    EXPECT_EQ(ipv4::CreateMask(8), 0xFF000000);
    EXPECT_EQ(ipv4::CreateMask(16), 0xFFFF0000);
    EXPECT_EQ(ipv4::CreateMask(24), 0xFFFFFF00);
    EXPECT_EQ(ipv4::CreateMask(32), 0xFFFFFFFF);
}

TEST(Ipv4UtilsTest, IpMatchesNetwork)
{
    // 10.8.0.0/24 contains 10.8.0.1 through 10.8.0.254
    uint32_t network = 0x0A080000;                                 // 10.8.0.0
    EXPECT_TRUE(ipv4::IpMatchesNetwork(0x0A080001, network, 24));  // 10.8.0.1
    EXPECT_TRUE(ipv4::IpMatchesNetwork(0x0A0800FE, network, 24));  // 10.8.0.254
    EXPECT_FALSE(ipv4::IpMatchesNetwork(0x0A080100, network, 24)); // 10.8.1.0
}

TEST(Ipv4UtilsTest, IpMatchesNetworkHostRoute)
{
    uint32_t ip = 0x0A080001; // 10.8.0.1
    EXPECT_TRUE(ipv4::IpMatchesNetwork(ip, ip, 32));
    EXPECT_FALSE(ipv4::IpMatchesNetwork(ip + 1, ip, 32));
}

TEST(Ipv4UtilsTest, IpMatchesNetworkDefaultRoute)
{
    uint32_t network = 0;
    EXPECT_TRUE(ipv4::IpMatchesNetwork(0x08080808, network, 0)); // 8.8.8.8
    EXPECT_TRUE(ipv4::IpMatchesNetwork(0xFFFFFFFF, network, 0)); // Any IP
}

TEST(Ipv4UtilsTest, NormalizeNetwork)
{
    // Host bits should be zeroed
    uint32_t addr_with_host_bits = 0x0A0800FF; // 10.8.0.255
    uint32_t normalized = ipv4::NormalizeNetwork(addr_with_host_bits, 24);
    EXPECT_EQ(normalized, 0x0A080000); // 10.8.0.0
}

TEST(Ipv4UtilsTest, Ipv4ToString)
{
    EXPECT_EQ(ipv4::Ipv4ToString(0x0A080001), "10.8.0.1");
    EXPECT_EQ(ipv4::Ipv4ToString(0xC0A80001), "192.168.0.1");
    EXPECT_EQ(ipv4::Ipv4ToString(0x08080808), "8.8.8.8");
}

TEST(Ipv4UtilsTest, CalculateUsableHosts)
{
    EXPECT_EQ(ipv4::CalculateUsableHosts(24), 254);     // /24 = 256 - 2
    EXPECT_EQ(ipv4::CalculateUsableHosts(30), 2);       // /30 = 4 - 2
    EXPECT_EQ(ipv4::CalculateUsableHosts(31), 0);       // /31 point-to-point
    EXPECT_EQ(ipv4::CalculateUsableHosts(32), 0);       // /32 host route
    EXPECT_EQ(ipv4::CalculateUsableHosts(8), 16777214); // /8 = 16M - 2
}

TEST(Ipv4UtilsTest, RoundTripParseCidrAndNormalize)
{
    // Parse CIDR, normalize, verify round trip
    auto parsed = ipv4::ParseCidr("10.8.0.100/24");
    ASSERT_TRUE(parsed.has_value());
    auto [addr, prefix] = *parsed;

    uint32_t normalized = ipv4::NormalizeNetwork(addr, prefix);
    EXPECT_EQ(normalized, 0x0A080000);

    // Verify the IP was in the network
    EXPECT_TRUE(ipv4::IpMatchesNetwork(addr, normalized, prefix));
}
