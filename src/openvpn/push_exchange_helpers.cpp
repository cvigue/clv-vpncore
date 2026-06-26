// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/push_exchange_helpers.h"

#include "openvpn/config_exchange.h"
#include "openvpn/connection.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/vpn_config.h"

#include <net/ipv4_utils.h>
#include <net/ipv6_utils.h>

#include <spdlog/spdlog.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace clv::vpn {

namespace ipv4 = clv::net::ipv4;
namespace ipv6 = clv::net::ipv6;

// ---------------------------------------------------------------------------
// Server IP / renegotiation helpers
// ---------------------------------------------------------------------------

std::string DeriveServerIp(const VpnConfig::ServerConfig &srv)
{
    if (!srv.bridge_ip.empty())
        return srv.bridge_ip;
    auto parsed = ipv4::ParseCidr(srv.network);
    if (!parsed)
        throw std::invalid_argument("Invalid server network CIDR: " + srv.network);
    auto [network_addr, prefix_length] = *parsed;
    std::uint32_t gateway_ip = network_addr + 1;
    return ipv4::Ipv4ToString(gateway_ip);
}

std::string DeriveServerIpv6(const VpnConfig::ServerConfig &srv)
{
    auto parsed = ipv6::ParseCidr6(srv.network_v6);
    if (!parsed)
        throw std::invalid_argument("Invalid server IPv6 network CIDR: " + srv.network_v6);
    auto [net_v6, prefix_v6] = *parsed;
    ipv6::Ipv6Address server_v6 = net_v6;
    server_v6[15] += 1;
    return ipv6::Ipv6ToString(server_v6);
}

std::uint32_t EffectiveRenegotiateSeconds(const VpnConfig::ServerConfig &srv)
{
    if (srv.renegotiate_seconds <= 0)
        return 0;
    if (srv.renegotiate_seconds < VpnConfig::ServerConfig::kMinRenegotiateSeconds)
        return static_cast<std::uint32_t>(VpnConfig::ServerConfig::kMinRenegotiateSeconds);
    return static_cast<std::uint32_t>(srv.renegotiate_seconds);
}

// ---------------------------------------------------------------------------
// BuildServerPushReplyConfig
// ---------------------------------------------------------------------------

openvpn::NegotiatedConfig BuildServerPushReplyConfig(const VpnConfig::ServerConfig &srv,
                                                     const Connection &session)
{
    if (!session.GetAssignedIpv4())
        throw std::runtime_error("Failed to allocate IP for client session");

    auto parsed_net = ipv4::ParseCidr(srv.network);
    if (!parsed_net)
        throw std::runtime_error("Failed to parse server network CIDR: " + srv.network);
    auto [net_addr, prefix_len] = *parsed_net;
    std::string netmask = ipv4::Ipv4ToString(ipv4::CreateMask(prefix_len));
    std::string server_ip = DeriveServerIp(srv);

    openvpn::NegotiatedConfig cfg;
    cfg.ifconfig = {ipv4::Ipv4ToString(*session.GetAssignedIpv4()), netmask};

    if (session.GetAssignedIpv6())
    {
        auto parsed_v6 = ipv6::ParseCidr6(srv.network_v6);
        if (parsed_v6)
        {
            auto prefix_v6 = parsed_v6->second;
            std::string ipv6_str = ipv6::Ipv6ToString(*session.GetAssignedIpv6());
            std::string server_v6_str = DeriveServerIpv6(srv);
            cfg.ifconfig_ipv6 = {
                ipv6_str + "/" + std::to_string(prefix_v6) + " " + server_v6_str, 0};
        }
    }

    cfg.topology = "subnet";
    cfg.route_gateway = server_ip;

    if (srv.client_to_client && srv.push_routes)
        cfg.routes.push_back({ipv4::Ipv4ToString(net_addr), netmask, 0});

    if (srv.push_routes)
    {
        for (const auto &route_cidr : srv.routes)
        {
            auto parsed_route = ipv4::ParseCidr(route_cidr);
            if (parsed_route)
            {
                auto [rnet, rpfx] = *parsed_route;
                cfg.routes.push_back(
                    {ipv4::Ipv4ToString(rnet), ipv4::Ipv4ToString(ipv4::CreateMask(rpfx)), 0});
            }
        }
        for (const auto &route_v6 : srv.routes_v6)
        {
            if (ipv6::ParseCidr6(route_v6))
                cfg.routes_ipv6.push_back({route_v6, "", 0});
        }
    }

    // DNS — prefer structured IV_PROTO_DNS_OPTION_V2 format when the client
    // supports it; fall back to legacy dhcp-option DNS otherwise.
    if (session.GetClientIvProto() & openvpn::IV_PROTO_DNS_OPTION_V2)
    {
        for (std::size_t i = 0; i < srv.client_dns.size(); ++i)
        {
            openvpn::DnsServerEntry entry;
            entry.priority = static_cast<int>(i);
            entry.addresses.push_back(srv.client_dns[i]);
            cfg.dns_servers.push_back(std::move(entry));
        }
        for (const auto &d : srv.client_dns_search_domains)
            cfg.dns_search_domains.push_back(d);
    }
    else
    {
        for (const auto &dns : srv.client_dns)
            cfg.dhcp_options.push_back({"DNS", dns});
    }

    cfg.cipher = srv.cipher;
    cfg.tun_mtu = static_cast<std::uint16_t>(srv.tun_mtu);
    cfg.ping_interval = static_cast<std::uint32_t>(srv.keepalive.first);
    cfg.ping_restart = static_cast<std::uint32_t>(srv.keepalive.second);
    cfg.peer_id = static_cast<std::int32_t>(session.GetSessionId().value & openvpn::PEER_ID_MASK);

    const auto reneg = EffectiveRenegotiateSeconds(srv);
    if (reneg > 0)
        cfg.reneg_sec = reneg;

    return cfg;
}

} // namespace clv::vpn
