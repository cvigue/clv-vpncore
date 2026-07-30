// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRAFFIC_POLICY_H
#define CLV_VPN_TRAFFIC_POLICY_H

#include "openvpn/push_exchange_helpers.h"
#include "openvpn/vpn_config.h"

#include <optional>
#include <string>

namespace clv::vpn {

/** @brief IPv4 or IPv6 tunnel address pool for hub policy. */
struct TunnelPool
{
    std::string cidr;      ///< Pool CIDR (e.g. "10.8.0.0/24")
    std::string bridge_ip; ///< Server/gateway address within the pool
};

/** @brief Specification for registering a hub TUN attachment with TunnelZone. */
struct HubAttachmentSpec
{
    std::string data_dev;
    bool client_to_client = false;
    TunnelPool pool_v4{};
    std::optional<TunnelPool> pool_v6;
    bool masquerade = false;
};

/** @brief Process-wide traffic policy applied by TunnelZone. */
struct ZonePolicy
{
    bool ip_forward = false; ///< Enable IPv4/IPv6 forwarding when true
};

/**
 * @brief Build zone policy from VpnConfig process settings.
 * @param config Full VPN configuration
 * @return ZonePolicy with ip_forward from explicit setting or server default
 */
inline ZonePolicy BuildZonePolicy(const VpnConfig &config)
{
    ZonePolicy policy;
    if (config.process.transit_routing.has_value())
        policy.ip_forward = *config.process.transit_routing;
    else if (config.HasServerRole())
        policy.ip_forward = true;
    return policy;
}

/**
 * @brief Build a hub attachment spec from server config and netdev name.
 * @param srv Server configuration (network pools, C2C, masquerade)
 * @param data_dev Hub TUN or DCO device name
 * @return HubAttachmentSpec ready for TunnelZone::RegisterHubAttachment
 */
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
