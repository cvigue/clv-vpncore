// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include "tunnel_zone.h"
#include "tunnel_zone_attachment_guard.h"
#include "traffic_policy.h"
#include "test_log_util.h"
#include "platform/linux/nftables/nftables_client.h"

#include <gtest/gtest.h>

using namespace clv::vpn;

namespace {

VpnConfig::ServerConfig MakeServerConfig()
{
    VpnConfig::ServerConfig srv;
    srv.network = "10.8.0.0/24";
    srv.network_v6 = "fd00::/64";
    srv.bridge_ip = "10.8.0.1";
    srv.client_to_client = false;
    return srv;
}

HubAttachmentSpec MakeHubSpec(std::string data_dev)
{
    return BuildHubAttachmentSpec(MakeServerConfig(), std::move(data_dev));
}

} // namespace

TEST(TunnelZoneTest, RegisterAndUnregisterHubAttachment)
{
    TunnelZone zone(ZonePolicy{}, test::NullLogger(), /*install_kernel_policy=*/false);

    auto spec = MakeHubSpec("tun0");
    zone.RegisterHubAttachment(spec);

    EXPECT_EQ(zone.HubAttachmentCount(), 1u);
    EXPECT_TRUE(zone.HasHubAttachment("tun0"));

    const auto found = zone.FindHubAttachment("tun0");
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->data_dev, "tun0");
    EXPECT_EQ(found->pool_v4.cidr, "10.8.0.0/24");
    EXPECT_EQ(found->pool_v4.bridge_ip, "10.8.0.1");
    ASSERT_TRUE(found->pool_v6.has_value());
    EXPECT_EQ(found->pool_v6->cidr, "fd00::/64");
    EXPECT_TRUE(found->masquerade);
    EXPECT_FALSE(found->client_to_client);

    zone.UnregisterHubAttachment("tun0");
    EXPECT_EQ(zone.HubAttachmentCount(), 0u);
    EXPECT_FALSE(zone.HasHubAttachment("tun0"));
}

TEST(TunnelZoneTest, DuplicateRegistrationThrows)
{
    TunnelZone zone(ZonePolicy{}, test::NullLogger(), /*install_kernel_policy=*/false);
    zone.RegisterHubAttachment(MakeHubSpec("ovpn-dco0"));

    EXPECT_THROW(zone.RegisterHubAttachment(MakeHubSpec("ovpn-dco0")),
                 std::invalid_argument);
}

TEST(TunnelZoneTest, EmptyDataDevThrows)
{
    TunnelZone zone(ZonePolicy{}, test::NullLogger(), /*install_kernel_policy=*/false);
    HubAttachmentSpec spec;
    EXPECT_THROW(zone.RegisterHubAttachment(std::move(spec)), std::invalid_argument);
}

TEST(TunnelZoneTest, UnregisterMissingIsNoop)
{
    TunnelZone zone(ZonePolicy{}, test::NullLogger(), /*install_kernel_policy=*/false);
    EXPECT_NO_THROW(zone.UnregisterHubAttachment("missing"));
    EXPECT_EQ(zone.HubAttachmentCount(), 0u);
}

TEST(TunnelZoneAttachmentGuardTest, ResetRegistersAndReleaseUnregisters)
{
    TunnelZone zone(ZonePolicy{}, test::NullLogger(), /*install_kernel_policy=*/false);
    TunnelZoneAttachmentGuard guard;

    EXPECT_FALSE(guard.attached());
    guard.Reset(&zone, MakeHubSpec("tun0"));
    EXPECT_TRUE(guard.attached());
    EXPECT_EQ(guard.data_dev(), "tun0");
    EXPECT_EQ(zone.HubAttachmentCount(), 1u);
    EXPECT_TRUE(zone.HasHubAttachment("tun0"));

    guard.Release();
    EXPECT_FALSE(guard.attached());
    EXPECT_EQ(zone.HubAttachmentCount(), 0u);
    EXPECT_FALSE(zone.HasHubAttachment("tun0"));
}

TEST(TunnelZoneAttachmentGuardTest, DestructorReleases)
{
    TunnelZone zone(ZonePolicy{}, test::NullLogger(), /*install_kernel_policy=*/false);
    {
        TunnelZoneAttachmentGuard guard;
        guard.Reset(&zone, MakeHubSpec("tun1"));
        EXPECT_EQ(zone.HubAttachmentCount(), 1u);
    }
    EXPECT_EQ(zone.HubAttachmentCount(), 0u);
}

TEST(TunnelZoneAttachmentGuardTest, NullZoneIsNoop)
{
    TunnelZoneAttachmentGuard guard;
    EXPECT_NO_THROW(guard.Reset(nullptr, MakeHubSpec("tun0")));
    EXPECT_FALSE(guard.attached());
}

TEST(TunnelZoneAttachmentGuardTest, ResetReplacesPriorAttachment)
{
    TunnelZone zone(ZonePolicy{}, test::NullLogger(), /*install_kernel_policy=*/false);
    TunnelZoneAttachmentGuard guard;
    guard.Reset(&zone, MakeHubSpec("tun0"));
    guard.Reset(&zone, MakeHubSpec("tun1"));
    EXPECT_TRUE(guard.attached());
    EXPECT_EQ(guard.data_dev(), "tun1");
    EXPECT_FALSE(zone.HasHubAttachment("tun0"));
    EXPECT_TRUE(zone.HasHubAttachment("tun1"));
    EXPECT_EQ(zone.HubAttachmentCount(), 1u);
}

TEST(TunnelZoneTest, HubSpecPreservesClientToClientWhenEnabled)
{
    TunnelZone zone(ZonePolicy{}, test::NullLogger(), /*install_kernel_policy=*/false);

    auto spec = MakeHubSpec("tun0");
    spec.client_to_client = true;
    zone.RegisterHubAttachment(spec);

    const auto found = zone.FindHubAttachment("tun0");
    ASSERT_TRUE(found.has_value());
    EXPECT_TRUE(found->client_to_client);
}

TEST(TunnelZoneTest, HubSpecPreservesClientToClientWhenDisabled)
{
    TunnelZone zone(ZonePolicy{}, test::NullLogger(), /*install_kernel_policy=*/false);

    auto spec = MakeHubSpec("tun0");
    spec.client_to_client = false;
    zone.RegisterHubAttachment(spec);

    const auto found = zone.FindHubAttachment("tun0");
    ASSERT_TRUE(found.has_value());
    EXPECT_FALSE(found->client_to_client);
}

TEST(TunnelZoneTest, TwoHubsRegisterIndependently)
{
    TunnelZone zone(ZonePolicy{}, test::NullLogger(), /*install_kernel_policy=*/false);

    zone.RegisterHubAttachment(MakeHubSpec("tun0"));
    zone.RegisterHubAttachment(MakeHubSpec("tun1"));

    EXPECT_EQ(zone.HubAttachmentCount(), 2u);
    EXPECT_TRUE(zone.HasHubAttachment("tun0"));
    EXPECT_TRUE(zone.HasHubAttachment("tun1"));

    zone.UnregisterHubAttachment("tun1");
    EXPECT_EQ(zone.HubAttachmentCount(), 1u);
    EXPECT_TRUE(zone.HasHubAttachment("tun0"));
    EXPECT_FALSE(zone.HasHubAttachment("tun1"));

    zone.UnregisterHubAttachment("tun0");
    EXPECT_EQ(zone.HubAttachmentCount(), 0u);
}

TEST(NfTablesClientTableNameTest, PerIfnameNatAndFilterNames)
{
    EXPECT_EQ(NfTablesClient::TableName(NfTablesClient::kIPv4, false, "tun0"), "clv_vpn_nat_tun0");
    EXPECT_EQ(NfTablesClient::TableName(NfTablesClient::kIPv4, true, "tun0"), "clv_vpn_filter_tun0");
    EXPECT_EQ(NfTablesClient::TableName(NfTablesClient::kIPv6, false, "tun0"), "clv_vpn_nat6_tun0");
    EXPECT_EQ(NfTablesClient::TableName(NfTablesClient::kIPv6, true, "tun1"), "clv_vpn_filter6_tun1");
}

TEST(NfTablesClientTableNameTest, SanitizesAndIsolatesHubs)
{
    EXPECT_EQ(NfTablesClient::TableName(NfTablesClient::kIPv4, true, "ovpn-dco0"),
              "clv_vpn_filter_ovpn_dco0");
    EXPECT_NE(NfTablesClient::TableName(NfTablesClient::kIPv4, true, "tun0"),
              NfTablesClient::TableName(NfTablesClient::kIPv4, true, "tun1"));
    EXPECT_EQ(NfTablesClient::TableName(NfTablesClient::kIPv4, false, ""), "clv_vpn_nat_dev");
}

TEST(TunnelZoneTest, EnsureTransitRoutingNoopWithoutKernelPolicy)
{
    ZonePolicy policy;
    policy.ip_forward = true;
    TunnelZone zone(policy, test::NullLogger(), /*install_kernel_policy=*/false);
    EXPECT_NO_THROW(zone.EnsureTransitRouting());
    EXPECT_NO_THROW(zone.EnsureTransitRouting());
}

TEST(TunnelZoneTest, EnsureTransitRoutingNoopWhenPolicyDisabled)
{
    TunnelZone zone(ZonePolicy{}, test::NullLogger(), /*install_kernel_policy=*/true);
    EXPECT_NO_THROW(zone.EnsureTransitRouting());
}

TEST(BuildZonePolicyTest, ServerRoleDefaultsIpForward)
{
    VpnConfig config;
    config.server = VpnConfig::ServerConfig{};
    EXPECT_TRUE(BuildZonePolicy(config).ip_forward);
}

TEST(BuildZonePolicyTest, ExplicitTransitRoutingOverrides)
{
    VpnConfig config;
    config.server = VpnConfig::ServerConfig{};
    config.process.transit_routing = false;
    EXPECT_FALSE(BuildZonePolicy(config).ip_forward);
}
