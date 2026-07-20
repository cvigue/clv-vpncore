// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include "openvpn/psid_cookie.h"

#include <gtest/gtest.h>

#include <asio/ip/address.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using clv::vpn::openvpn::BuildCookieHardResetResponse;
using clv::vpn::openvpn::BuildEarlyNegFlagsTlv;
using clv::vpn::openvpn::CalculateSessionIdHmac;
using clv::vpn::openvpn::CheckSessionIdHmac;
using clv::vpn::openvpn::EARLY_NEG_FLAG_RESEND_WKC;
using clv::vpn::openvpn::EARLY_NEG_START;
using clv::vpn::openvpn::IsEarlyHandshakeCookieEcho;
using clv::vpn::openvpn::Opcode;
using clv::vpn::openvpn::OpenVpnPacket;
using clv::vpn::openvpn::ParseEarlyNegFlagsTlv;
using clv::vpn::openvpn::PsidCookieEndpoint;
using clv::vpn::openvpn::PsidCookieKey;
using clv::vpn::openvpn::SessionId;
using clv::vpn::openvpn::SupportsEarlyNegotiation;

namespace {

PsidCookieKey TestKey()
{
    std::array<std::uint8_t, 32> k{};
    for (std::size_t i = 0; i < k.size(); ++i)
        k[i] = static_cast<std::uint8_t>(i + 1);
    return *PsidCookieKey::FromBytes(k);
}

PsidCookieEndpoint V4Endpoint(const char *ip, std::uint16_t port)
{
    return PsidCookieEndpoint{.addr = asio::ip::make_address(ip), .port = port};
}

} // namespace

TEST(PsidCookie, DeterministicForSameInputs)
{
    const auto key = TestKey();
    const SessionId client{0x0123456789abcdefull};
    const auto ep = V4Endpoint("10.99.0.2", 1194);
    const std::uint32_t now = 1'700'000'000u;
    const int hw = 60;

    const auto a = CalculateSessionIdHmac(key, client, ep, hw, 0, now);
    const auto b = CalculateSessionIdHmac(key, client, ep, hw, 0, now);
    EXPECT_EQ(a.value, b.value);
    EXPECT_NE(a.value, 0u);
}

TEST(PsidCookie, ChangesWithClientSidAddrPortTime)
{
    const auto key = TestKey();
    const SessionId client{0x1111111111111111ull};
    const auto ep = V4Endpoint("10.99.0.2", 1194);
    const std::uint32_t now = 1'700'000'000u;
    const int hw = 60;

    const auto base = CalculateSessionIdHmac(key, client, ep, hw, 0, now);

    EXPECT_NE(base.value,
              CalculateSessionIdHmac(key, SessionId{client.value + 1}, ep, hw, 0, now).value);
    EXPECT_NE(base.value,
              CalculateSessionIdHmac(key, client, V4Endpoint("10.99.0.3", 1194), hw, 0, now).value);
    EXPECT_NE(base.value,
              CalculateSessionIdHmac(key, client, V4Endpoint("10.99.0.2", 1195), hw, 0, now).value);

    // Move far enough to leave the current bucket (interval = 30 for hw=60).
    EXPECT_NE(base.value,
              CalculateSessionIdHmac(key, client, ep, hw, 0, now + 60).value);
}

TEST(PsidCookie, CheckAcceptsAdjacentBuckets)
{
    const auto key = TestKey();
    const SessionId client{0xaaaaaaaaaaaaaaaaull};
    const auto ep = V4Endpoint("192.0.2.10", 4500);
    const int hw = 60;
    const std::uint32_t now = 1'700'000'100u;

    // Issue cookie at offset 0 relative to an older "then".
    const std::uint32_t then = now - 20;
    const auto cookie = CalculateSessionIdHmac(key, client, ep, hw, 0, then);

    EXPECT_TRUE(CheckSessionIdHmac(key, cookie, client, ep, hw, now));
}

TEST(PsidCookie, CheckRejectsWrongAddr)
{
    const auto key = TestKey();
    const SessionId client{0xbbbbbbbbbbbbbbbbull};
    const auto ep = V4Endpoint("192.0.2.10", 4500);
    const std::uint32_t now = 1'700'000'000u;
    const auto cookie = CalculateSessionIdHmac(key, client, ep, 60, 0, now);

    EXPECT_FALSE(CheckSessionIdHmac(key, cookie, client, V4Endpoint("192.0.2.11", 4500), 60, now));
}

TEST(PsidCookie, Ipv6EndpointSupported)
{
    const auto key = TestKey();
    const SessionId client{0xccccccccccccccccull};
    PsidCookieEndpoint ep{.addr = asio::ip::make_address("fd99::2"), .port = 1194};
    const std::uint32_t now = 1'700'000'000u;
    const auto cookie = CalculateSessionIdHmac(key, client, ep, 60, 0, now);
    EXPECT_TRUE(CheckSessionIdHmac(key, cookie, client, ep, 60, now));
    EXPECT_FALSE(CheckSessionIdHmac(
        key, cookie, client, PsidCookieEndpoint{.addr = asio::ip::make_address("fd99::3"), .port = 1194}, 60, now));
}

TEST(PsidCookie, EarlyNegHelpers)
{
    EXPECT_TRUE(SupportsEarlyNegotiation(EARLY_NEG_START));
    EXPECT_TRUE(SupportsEarlyNegotiation(EARLY_NEG_START | 0x1u));
    EXPECT_FALSE(SupportsEarlyNegotiation(1u));

    auto tlv = BuildEarlyNegFlagsTlv(EARLY_NEG_FLAG_RESEND_WKC);
    ASSERT_EQ(tlv.size(), 6u);
    auto parsed = ParseEarlyNegFlagsTlv(tlv);
    ASSERT_TRUE(parsed);
    EXPECT_EQ(*parsed, EARLY_NEG_FLAG_RESEND_WKC);
}

TEST(PsidCookie, BuildCookieHardResetResponse)
{
    auto pkt = BuildCookieHardResetResponse(Opcode::P_CONTROL_HARD_RESET_CLIENT_V2,
                                            /*server_sid=*/0x1111,
                                            /*client_sid=*/0x2222,
                                            /*ack=*/0,
                                            /*key_id=*/0);
    EXPECT_EQ(pkt.opcode_, Opcode::P_CONTROL_HARD_RESET_SERVER_V2);
    EXPECT_EQ(pkt.session_id_, 0x1111u);
    ASSERT_EQ(pkt.packet_id_array_.size(), 1u);
    EXPECT_EQ(pkt.packet_id_array_[0], 0u);
    EXPECT_EQ(pkt.remote_session_id_, 0x2222u);

    auto v2 = BuildCookieHardResetResponse(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3,
                                           0x1111,
                                           0x2222,
                                           0,
                                           0,
                                           BuildEarlyNegFlagsTlv(),
                                           0,
                                           /*force_server_v2=*/true);
    EXPECT_EQ(v2.opcode_, Opcode::P_CONTROL_HARD_RESET_SERVER_V2);
    EXPECT_FALSE(v2.payload_.empty());
}

TEST(PsidCookie, IsEarlyHandshakeCookieEcho)
{
    OpenVpnPacket ack;
    ack.opcode_ = Opcode::P_ACK_V1;
    ack.session_id_ = 1;
    ack.remote_session_id_ = 2;
    ack.packet_id_array_ = {0};
    EXPECT_TRUE(IsEarlyHandshakeCookieEcho(ack, /*has_own_packet_id=*/false));

    OpenVpnPacket ctrl;
    ctrl.opcode_ = Opcode::P_CONTROL_V1;
    ctrl.session_id_ = 1;
    ctrl.remote_session_id_ = 2;
    ctrl.packet_id_ = 0;
    ctrl.packet_id_array_ = {0};
    EXPECT_TRUE(IsEarlyHandshakeCookieEcho(ctrl, true));

    ctrl.packet_id_ = 5;
    EXPECT_FALSE(IsEarlyHandshakeCookieEcho(ctrl, true));
}
