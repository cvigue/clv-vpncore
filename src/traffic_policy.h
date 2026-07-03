// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRAFFIC_POLICY_H
#define CLV_VPN_TRAFFIC_POLICY_H

#include "openvpn/push_exchange_helpers.h"
#include "openvpn/vpn_config.h"

#include <optional>
#include <string>

namespace clv::vpn {

struct TunnelPool
{
    std::string cidr;
    std::string bridge_ip;
};

struct HubAttachmentSpec
{
    std::string data_dev;
    bool client_to_client = false;
    TunnelPool pool_v4{};
    std::optional<TunnelPool> pool_v6;
    bool masquerade = false;
};

struct ZonePolicy
{
    bool ip_forward = false;
};

inline ZonePolicy BuildZonePolicy(const VpnConfig &config)
{
    ZonePolicy policy;
    if (config.process.transit_routing.has_value())
        policy.ip_forward = *config.process.transit_routing;
    else if (config.HasServerRole())
        policy.ip_forward = true;
    return policy;
}

inline HubAttachmentSpec BuildHubAttachmentSpec(const VpnConfig::ServerConfig &srv,
                                                std::string data_dev)
{
    HubAttachmentSpec spec;
    spec.data_dev = std::move(data_dev);
    spec.client_to_client = srv.client_to_client;
    spec.pool_v4.cidr = srv.network;
    spec.pool_v4.bridge_ip = DeriveServerIp(srv);
    // Unconditional for now — matches pre-TunnelZone VpnServer behavior; no server.masquerade
    // config field exists yet.
    spec.masquerade = true;
    if (!srv.network_v6.empty())
        spec.pool_v6 = TunnelPool{srv.network_v6, DeriveServerIpv6(srv)};
    return spec;
}

} // namespace clv::vpn

#endif // CLV_VPN_TRAFFIC_POLICY_H
