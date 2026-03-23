// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include "scoped_masquerade.h"

#include <cstdint>
#include <util/nftables_client.h>

#include <arpa/inet.h>
#include <cstring>
#include <gtest/gtest.h>

using namespace clv::vpn;

// ---------------------------------------------------------------------------
// ParseMasqueradeCidr — auto-detection unit tests
// ---------------------------------------------------------------------------

TEST(ParseMasqueradeCidrTest, Ipv4Standard)
{
    auto r = ParseMasqueradeCidr("10.8.0.0/24");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->family, NfTablesClient::kIPv4);
    EXPECT_EQ(r->prefix_len, 24);

    // Verify network bytes are big-endian 10.8.0.0
    std::uint8_t expected[] = {10, 8, 0, 0};
    EXPECT_EQ(std::memcmp(r->network.data(), expected, 4), 0);
}

TEST(ParseMasqueradeCidrTest, Ipv4PrivateRanges)
{
    auto r1 = ParseMasqueradeCidr("192.168.1.0/24");
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(r1->family, NfTablesClient::kIPv4);
    EXPECT_EQ(r1->prefix_len, 24);
    std::uint8_t e1[] = {192, 168, 1, 0};
    EXPECT_EQ(std::memcmp(r1->network.data(), e1, 4), 0);

    auto r2 = ParseMasqueradeCidr("172.16.0.0/12");
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(r2->family, NfTablesClient::kIPv4);
    EXPECT_EQ(r2->prefix_len, 12);
}

TEST(ParseMasqueradeCidrTest, Ipv4EdgePrefixes)
{
    auto r0 = ParseMasqueradeCidr("0.0.0.0/0");
    ASSERT_TRUE(r0.has_value());
    EXPECT_EQ(r0->family, NfTablesClient::kIPv4);
    EXPECT_EQ(r0->prefix_len, 0);

    auto r32 = ParseMasqueradeCidr("10.0.0.1/32");
    ASSERT_TRUE(r32.has_value());
    EXPECT_EQ(r32->family, NfTablesClient::kIPv4);
    EXPECT_EQ(r32->prefix_len, 32);
}

TEST(ParseMasqueradeCidrTest, Ipv6Standard)
{
    auto r = ParseMasqueradeCidr("fd00::/112");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->family, NfTablesClient::kIPv6);
    EXPECT_EQ(r->prefix_len, 112);

    // fd00:: = fd00 followed by 14 zero bytes
    std::uint8_t expected[16] = {};
    expected[0] = 0xfd;
    expected[1] = 0x00;
    EXPECT_EQ(std::memcmp(r->network.data(), expected, 16), 0);
}

TEST(ParseMasqueradeCidrTest, Ipv6FullAddress)
{
    auto r = ParseMasqueradeCidr("2001:db8:1::1/64");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->family, NfTablesClient::kIPv6);
    EXPECT_EQ(r->prefix_len, 64);

    // Verify first 4 bytes: 2001:0db8
    EXPECT_EQ(r->network[0], 0x20);
    EXPECT_EQ(r->network[1], 0x01);
    EXPECT_EQ(r->network[2], 0x0d);
    EXPECT_EQ(r->network[3], 0xb8);
}

TEST(ParseMasqueradeCidrTest, Ipv6EdgePrefixes)
{
    auto r0 = ParseMasqueradeCidr("::/0");
    ASSERT_TRUE(r0.has_value());
    EXPECT_EQ(r0->family, NfTablesClient::kIPv6);
    EXPECT_EQ(r0->prefix_len, 0);

    auto r128 = ParseMasqueradeCidr("::1/128");
    ASSERT_TRUE(r128.has_value());
    EXPECT_EQ(r128->family, NfTablesClient::kIPv6);
    EXPECT_EQ(r128->prefix_len, 128);
}

TEST(ParseMasqueradeCidrTest, DottedQuadStaysIpv4)
{
    // Plain dotted-quad must be detected as IPv4, not as IPv6-mapped
    auto r = ParseMasqueradeCidr("10.8.0.0/24");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->family, NfTablesClient::kIPv4);
}

TEST(ParseMasqueradeCidrTest, Ipv4MappedIpv6)
{
    // Explicit IPv4-mapped IPv6 notation should be detected as IPv6
    auto r = ParseMasqueradeCidr("::ffff:10.8.0.0/96");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->family, NfTablesClient::kIPv6);
    EXPECT_EQ(r->prefix_len, 96);
}

TEST(ParseMasqueradeCidrTest, InvalidInputsReturnNullopt)
{
    EXPECT_FALSE(ParseMasqueradeCidr("").has_value());
    EXPECT_FALSE(ParseMasqueradeCidr("garbage").has_value());
    EXPECT_FALSE(ParseMasqueradeCidr("10.8.0.0").has_value());    // no prefix
    EXPECT_FALSE(ParseMasqueradeCidr("fd00::").has_value());      // no prefix
    EXPECT_FALSE(ParseMasqueradeCidr("10.8.0.0/33").has_value()); // prefix > 32
    EXPECT_FALSE(ParseMasqueradeCidr("fd00::/129").has_value());  // prefix > 128
    EXPECT_FALSE(ParseMasqueradeCidr("/24").has_value());         // no address
    EXPECT_FALSE(ParseMasqueradeCidr("10.8.0.0/-1").has_value()); // negative prefix
}
