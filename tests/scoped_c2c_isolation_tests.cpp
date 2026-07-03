// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include "scoped_c2c_isolation.h"
#include "test_log_util.h"

#include <net/ipv6_utils.h>
#include <cstring>
#include <gtest/gtest.h>
#include "platform/linux/nftables/nftables_client.h"

using namespace clv::vpn;

TEST(ParseIntraPoolDropTargetTest, Ipv4PoolAndBridge)
{
    auto target = ParseIntraPoolDropTarget("10.8.0.0/24", "10.8.0.1");
    ASSERT_TRUE(target.has_value());
    EXPECT_EQ(target->family, NfTablesClient::kIPv4);
    EXPECT_EQ(target->prefix_len, 24);

    std::uint8_t expected_net[] = {10, 8, 0, 0};
    EXPECT_EQ(std::memcmp(target->network.data(), expected_net, 4), 0);

    std::uint8_t expected_bridge[] = {10, 8, 0, 1};
    EXPECT_EQ(std::memcmp(target->bridge_ip.data(), expected_bridge, 4), 0);
}

TEST(ParseIntraPoolDropTargetTest, Ipv6PoolAndBridge)
{
    auto target = ParseIntraPoolDropTarget("fd00::/64", "fd00::1");
    ASSERT_TRUE(target.has_value());
    EXPECT_EQ(target->family, NfTablesClient::kIPv6);
    EXPECT_EQ(target->prefix_len, 64);

    auto expected_bridge = clv::net::ipv6::ParseIpv6("fd00::1");
    ASSERT_TRUE(expected_bridge.has_value());
    EXPECT_EQ(std::memcmp(target->bridge_ip.data(), expected_bridge->data(), 16), 0);
}

TEST(ParseIntraPoolDropTargetTest, RejectsInvalidPoolCidr)
{
    EXPECT_FALSE(ParseIntraPoolDropTarget("not-a-cidr", "10.8.0.1").has_value());
}

TEST(ParseIntraPoolDropTargetTest, RejectsInvalidBridgeIp)
{
    EXPECT_FALSE(ParseIntraPoolDropTarget("10.8.0.0/24", "not-an-ip").has_value());
}

TEST(ParseIntraPoolDropTargetTest, RejectsIpv4BridgeForIpv6Pool)
{
    EXPECT_FALSE(ParseIntraPoolDropTarget("fd00::/64", "10.8.0.1").has_value());
}

TEST(ScopedNftIntraPoolDropTest, EmptyIfnameThrows)
{
    EXPECT_THROW((ScopedNftIntraPoolDrop{"", "10.8.0.0/24", "10.8.0.1", test::NullLogger()}),
                 std::invalid_argument);
}

TEST(ScopedNftIntraPoolDropTest, InvalidPoolThrows)
{
    EXPECT_THROW((ScopedNftIntraPoolDrop{"tun0", "bad", "10.8.0.1", test::NullLogger()}),
                 std::invalid_argument);
}
