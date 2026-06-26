// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "transport_mode.h"
#include "dco_utils.h"
#include "openvpn/vpn_config.h"

#include <gtest/gtest.h>

using namespace clv::vpn;

// ============================================================================
// ResolveTransportMode — protocol selection logic
// ============================================================================

// Helper: config with only a client role
static VpnConfig MakeClientConfig(const std::string &proto, bool enable_dco = false)
{
    VpnConfig cfg;
    cfg.client.emplace();
    cfg.client->proto = proto;
    cfg.performance.enable_dco = enable_dco;
    return cfg;
}

// Helper: config with only a server role
static VpnConfig MakeServerConfig(const std::string &proto, bool enable_dco = false)
{
    VpnConfig cfg;
    cfg.server.emplace();
    cfg.server->proto = proto;
    cfg.performance.enable_dco = enable_dco;
    return cfg;
}

// --- TCP paths ---

TEST(ResolveTransportMode, ClientTcpProto_ReturnsTcp)
{
    auto cfg = MakeClientConfig("tcp");
    EXPECT_EQ(ResolveTransportMode(cfg), TransportMode::Tcp);
}

TEST(ResolveTransportMode, ServerTcpProto_ReturnsTcp)
{
    auto cfg = MakeServerConfig("tcp");
    EXPECT_EQ(ResolveTransportMode(cfg), TransportMode::Tcp);
}

// TCP takes priority over DCO flag when both are set
TEST(ResolveTransportMode, TcpTakesPriorityOverDco)
{
    auto cfg = MakeClientConfig("tcp", /*enable_dco=*/true);
    EXPECT_EQ(ResolveTransportMode(cfg), TransportMode::Tcp);
}

// --- Explicit DCO-disabled paths (deterministic regardless of kernel module) ---

TEST(ResolveTransportMode, ClientUdpDcoDisabled_ReturnsUdp)
{
    auto cfg = MakeClientConfig("udp", /*enable_dco=*/false);
    EXPECT_EQ(ResolveTransportMode(cfg), TransportMode::Udp);
}

TEST(ResolveTransportMode, ServerUdpDcoDisabled_ReturnsUdp)
{
    auto cfg = MakeServerConfig("udp", /*enable_dco=*/false);
    EXPECT_EQ(ResolveTransportMode(cfg), TransportMode::Udp);
}

TEST(ResolveTransportMode, NoRole_DcoDisabled_ReturnsUdp)
{
    // Neither client nor server set; proto defaults to "" — not "tcp".
    VpnConfig cfg;
    cfg.performance.enable_dco = false;
    EXPECT_EQ(ResolveTransportMode(cfg), TransportMode::Udp);
}

// --- DCO-enabled path (result depends on actual kernel module availability) ---

TEST(ResolveTransportMode, DcoEnabled_ReturnsBasedOnKernelModule)
{
    // Result is deterministic given the runtime state: if ovpn-dco-v2 is
    // available the function must return Dco; otherwise it falls back to Udp.
    auto cfg = MakeClientConfig("udp", /*enable_dco=*/true);
    bool dco_available = dco::IsAvailable();
    TransportMode expected = dco_available ? TransportMode::Dco : TransportMode::Udp;
    EXPECT_EQ(ResolveTransportMode(cfg), expected);
}

// Server role gets the same DCO logic
TEST(ResolveTransportMode, Server_DcoEnabled_ReturnsBasedOnKernelModule)
{
    auto cfg = MakeServerConfig("udp", /*enable_dco=*/true);
    bool dco_available = dco::IsAvailable();
    TransportMode expected = dco_available ? TransportMode::Dco : TransportMode::Udp;
    EXPECT_EQ(ResolveTransportMode(cfg), expected);
}

// ============================================================================
// TransportModeString — human-readable labels
// ============================================================================

TEST(TransportModeString, ReturnsCorrectLabelForEachMode)
{
    EXPECT_STREQ(TransportModeString(TransportMode::Udp), "UDP (TUN-based)");
    EXPECT_STREQ(TransportModeString(TransportMode::Tcp), "TCP (TUN-based)");
    EXPECT_STREQ(TransportModeString(TransportMode::Dco), "DCO (kernel offload)");
}

TEST(TransportModeString, ReturnsUnknownForInvalidCast)
{
    auto bad = static_cast<TransportMode>(99);
    EXPECT_STREQ(TransportModeString(bad), "Unknown");
}
