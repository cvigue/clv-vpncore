// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "transport/transport.h"

#include <gtest/gtest.h>

#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>

using namespace clv::vpn::transport;

namespace {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

asio::ip::address_v4 Addr4(const char *s)
{
    return asio::ip::make_address_v4(s);
}

asio::ip::address_v6 Addr6(const char *s)
{
    return asio::ip::make_address_v6(s);
}

// Build a v4-mapped IPv6 address from a dotted-decimal string
asio::ip::address_v6 V4Mapped(const char *s)
{
    return asio::ip::make_address_v6(asio::ip::v4_mapped, Addr4(s));
}

// ---------------------------------------------------------------------------
// FromAsioEndpoint (UDP)
// ---------------------------------------------------------------------------

TEST(TransportEndpointTest, FromUdpEndpoint_Ipv4_ReturnsV4)
{
    asio::ip::udp::endpoint ep{Addr4("192.168.1.1"), 1194};
    auto peer = FromAsioEndpoint(ep);

    EXPECT_TRUE(peer.addr.is_v4());
    EXPECT_EQ(peer.addr.to_v4(), Addr4("192.168.1.1"));
    EXPECT_EQ(peer.port, 1194);
}

TEST(TransportEndpointTest, FromUdpEndpoint_V4MappedV6_NormalizesToV4)
{
    // Dual-stack sockets return v4-mapped v6 for IPv4 peers; normalise back.
    asio::ip::udp::endpoint ep{V4Mapped("10.0.0.5"), 4444};
    auto peer = FromAsioEndpoint(ep);

    EXPECT_TRUE(peer.addr.is_v4());
    EXPECT_EQ(peer.addr.to_v4(), Addr4("10.0.0.5"));
    EXPECT_EQ(peer.port, 4444);
}

TEST(TransportEndpointTest, FromUdpEndpoint_PureV6_Preserved)
{
    asio::ip::udp::endpoint ep{Addr6("2001:db8::1"), 5000};
    auto peer = FromAsioEndpoint(ep);

    EXPECT_TRUE(peer.addr.is_v6());
    EXPECT_EQ(peer.addr.to_v6(), Addr6("2001:db8::1"));
    EXPECT_EQ(peer.port, 5000);
}

// ---------------------------------------------------------------------------
// FromAsioEndpoint (TCP)
// ---------------------------------------------------------------------------

TEST(TransportEndpointTest, FromTcpEndpoint_Ipv4)
{
    asio::ip::tcp::endpoint ep{Addr4("172.16.0.1"), 443};
    auto peer = FromAsioEndpoint(ep);

    EXPECT_TRUE(peer.addr.is_v4());
    EXPECT_EQ(peer.addr.to_v4(), Addr4("172.16.0.1"));
    EXPECT_EQ(peer.port, 443);
}

TEST(TransportEndpointTest, FromTcpEndpoint_Ipv6)
{
    asio::ip::tcp::endpoint ep{Addr6("::1"), 8080};
    auto peer = FromAsioEndpoint(ep);

    EXPECT_TRUE(peer.addr.is_v6());
    EXPECT_EQ(peer.port, 8080);
}

// ---------------------------------------------------------------------------
// ToUdpEndpoint
// ---------------------------------------------------------------------------

TEST(TransportEndpointTest, ToUdpEndpoint_Ipv4_ConvertsToMappedV6)
{
    // On dual-stack sockets, IPv4 destinations are sent as v4-mapped.
    PeerEndpoint peer{asio::ip::address{Addr4("203.0.113.7")}, 1194};
    auto ep = ToUdpEndpoint(peer);

    EXPECT_TRUE(ep.address().is_v6());
    EXPECT_TRUE(ep.address().to_v6().is_v4_mapped());
    EXPECT_EQ(ep.port(), 1194);
}

TEST(TransportEndpointTest, ToUdpEndpoint_PureV6_Preserved)
{
    PeerEndpoint peer{asio::ip::address{Addr6("2001:db8::2")}, 2000};
    auto ep = ToUdpEndpoint(peer);

    EXPECT_TRUE(ep.address().is_v6());
    EXPECT_FALSE(ep.address().to_v6().is_v4_mapped());
    EXPECT_EQ(ep.port(), 2000);
}

// ---------------------------------------------------------------------------
// ToTcpEndpoint
// ---------------------------------------------------------------------------

TEST(TransportEndpointTest, ToTcpEndpoint_Ipv4)
{
    PeerEndpoint peer{asio::ip::address{Addr4("192.0.2.1")}, 443};
    auto ep = ToTcpEndpoint(peer);

    EXPECT_TRUE(ep.address().is_v4());
    EXPECT_EQ(ep.address().to_v4(), Addr4("192.0.2.1"));
    EXPECT_EQ(ep.port(), 443);
}

TEST(TransportEndpointTest, ToTcpEndpoint_Ipv6)
{
    PeerEndpoint peer{asio::ip::address{Addr6("fe80::1")}, 9000};
    auto ep = ToTcpEndpoint(peer);

    EXPECT_TRUE(ep.address().is_v6());
    EXPECT_EQ(ep.port(), 9000);
}

// ---------------------------------------------------------------------------
// Round-trip: PeerEndpoint → ToUdpEndpoint → v4-mapped → FromAsioEndpoint
// ---------------------------------------------------------------------------

TEST(TransportEndpointTest, RoundTrip_Ipv4_UdpMapped_BackToV4)
{
    PeerEndpoint original{asio::ip::address{Addr4("1.2.3.4")}, 1194};

    // ToUdpEndpoint converts v4 → v4-mapped (for dual-stack sendto)
    auto udp_ep = ToUdpEndpoint(original);
    ASSERT_TRUE(udp_ep.address().to_v6().is_v4_mapped());

    // FromAsioEndpoint normalises back to plain v4
    auto roundtripped = FromAsioEndpoint(udp_ep);
    EXPECT_TRUE(roundtripped.addr.is_v4());
    EXPECT_EQ(roundtripped.addr.to_v4(), Addr4("1.2.3.4"));
    EXPECT_EQ(roundtripped.port, 1194);
}

TEST(TransportEndpointTest, PeerEndpointEquality)
{
    PeerEndpoint a{asio::ip::address{Addr4("10.0.0.1")}, 1194};
    PeerEndpoint b{asio::ip::address{Addr4("10.0.0.1")}, 1194};
    PeerEndpoint c{asio::ip::address{Addr4("10.0.0.2")}, 1194};

    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

} // namespace
