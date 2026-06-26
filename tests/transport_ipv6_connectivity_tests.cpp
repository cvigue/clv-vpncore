// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "transport/connector.h"
#include "transport/listener.h"

#include <gtest/gtest.h>

#include <asio/ip/v6_only.hpp>

using namespace clv::vpn::transport;

namespace {

TEST(TransportIPv6ConnectivityTest, UdpListenerUsesDualStackIpv6Socket)
{
    asio::io_context ctx;
    UdpListener listener(ctx, "", 0);

    auto &sock = listener.RawSocket();
    EXPECT_TRUE(sock.local_endpoint().address().is_v6());

    asio::ip::v6_only v6_only_opt;
    sock.get_option(v6_only_opt);
    EXPECT_FALSE(v6_only_opt.value());
}

TEST(TransportIPv6ConnectivityTest, UdpConnectorWithIpv6HostKeepsPureIpv6Endpoint)
{
    asio::io_context ctx;
    UdpConnector connector(ctx);

    auto transport = connector.Connect("2001:db8::1", 1194, false);
    const auto &resolved = connector.ResolvedEndpoint();

    ASSERT_TRUE(resolved.address().is_v6());
    EXPECT_FALSE(resolved.address().to_v6().is_v4_mapped());

    const auto peer = transport.GetPeer();
    ASSERT_TRUE(peer.addr.is_v6());
    EXPECT_FALSE(peer.addr.to_v6().is_v4_mapped());
}

TEST(TransportIPv6ConnectivityTest, UdpConnectorWithIpv4HostUsesMappedV6WhenNotInDco)
{
    asio::io_context ctx;
    UdpConnector connector(ctx);

    auto transport = connector.Connect("127.0.0.1", 1194, false);
    const auto &resolved = connector.ResolvedEndpoint();

    ASSERT_TRUE(resolved.address().is_v6());
    EXPECT_TRUE(resolved.address().to_v6().is_v4_mapped());

    const auto peer = transport.GetPeer();
    ASSERT_TRUE(peer.addr.is_v4());
    EXPECT_EQ(peer.addr.to_v4().to_string(), "127.0.0.1");
}

TEST(TransportIPv6ConnectivityTest, UdpConnectorWithIpv4HostKeepsIpv4InDcoMode)
{
    asio::io_context ctx;
    UdpConnector connector(ctx);

    auto transport = connector.Connect("127.0.0.1", 1194, true);
    const auto &resolved = connector.ResolvedEndpoint();

    ASSERT_TRUE(resolved.address().is_v4());
    EXPECT_EQ(resolved.address().to_v4().to_string(), "127.0.0.1");

    const auto peer = transport.GetPeer();
    ASSERT_TRUE(peer.addr.is_v4());
    EXPECT_EQ(peer.addr.to_v4().to_string(), "127.0.0.1");
}

} // namespace