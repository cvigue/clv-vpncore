// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "client_network_setup.h"

#include "iface_utils.h"
#include "openvpn/config_exchange.h"
#include "platform/linux/tun/tun_device.h"
#include "route_utils.h"

#include <cstdint>
#include <net/ipv4_utils.h>
#include <spdlog/spdlog.h>

#include <stdexcept>
#include <string>

namespace clv::vpn {
namespace {

namespace ipv4 = clv::net::ipv4;

} // namespace

std::string NormalizeNegotiatedRoute4(const std::string &network, const std::string &gw)
{
    if (network.find('/') != std::string::npos)
        return network;
    if (!gw.empty())
    {
        if (auto mask = ipv4::ParseIpv4(gw))
            return network + "/" + std::to_string(ipv4::MaskToPrefix(*mask));
    }
    return network + "/32";
}

std::string ConnectedCidrFromIfconfig(const openvpn::NegotiatedConfig &negotiated)
{
    // Only subnet topology uses ifconfig.second as a netmask; p2p/net30 store a peer IP.
    if (negotiated.topology != "subnet")
        return {};
    if (negotiated.ifconfig.first.empty() || negotiated.ifconfig.second.empty())
        return {};

    auto host = ipv4::ParseIpv4(negotiated.ifconfig.first);
    auto mask = ipv4::ParseIpv4(negotiated.ifconfig.second);
    if (!host || !mask)
        throw std::runtime_error("Invalid ifconfig for connected subnet CIDR");

    auto prefix = ipv4::MaskToPrefix(*mask);
    auto net = *host & ipv4::CreateMask(prefix);
    return ipv4::Ipv4ToString(net) + "/" + std::to_string(prefix);
}

void ConfigureClientTun(tun::TunDevice &tun,
                        const openvpn::NegotiatedConfig &negotiated,
                        const std::string &dev_name,
                        spdlog::logger &logger)
{
    std::string name = tun.Create(dev_name);
    logger.info("Created TUN: {}", name);

    const auto &assigned_ip = negotiated.ifconfig.first;
    const auto &assigned_netmask = negotiated.ifconfig.second;

    if (negotiated.topology == "subnet" && !assigned_netmask.empty())
    {
        auto mask = ipv4::ParseIpv4(assigned_netmask);
        if (!mask)
            throw std::runtime_error("Invalid ifconfig netmask: " + assigned_netmask);
        tun.SetAddress(assigned_ip, ipv4::MaskToPrefix(*mask));
    }
    else
    {
        std::string remote_ip = assigned_netmask.empty() ? "255.255.255.255" : assigned_netmask;
        iface::SetPointToPoint(tun.GetName().c_str(), assigned_ip, remote_ip);
    }

    tun.SetMtu(kClientDefaultTunMtu);
    tun.BringUp();

    if (!negotiated.ifconfig_ipv6.first.empty())
    {
        auto prefix6 = static_cast<std::uint8_t>(negotiated.ifconfig_ipv6.second);
        tun.AddIpv6Address(negotiated.ifconfig_ipv6.first, prefix6);
    }
}

void InstallClientNegotiatedRoutes(tun::TunDevice &tun,
                                   const openvpn::NegotiatedConfig &negotiated,
                                   spdlog::logger &logger)
{
    std::string dev = tun.GetName();
    if (dev.empty())
        return;

    const std::string connected_cidr = ConnectedCidrFromIfconfig(negotiated);

    for (const auto &[network, gw, metric] : negotiated.routes)
    {
        (void)metric;
        const std::string cidr = NormalizeNegotiatedRoute4(network, gw);

        if (!connected_cidr.empty() && cidr == connected_cidr)
        {
            logger.debug("Route: {} skipped (connected subnet, kernel-managed)", cidr);
            continue;
        }

        std::string via;
        if (!negotiated.route_gateway.empty())
            via = negotiated.route_gateway;
        logger.info("Route: {} dev {}{}", cidr, dev, via.empty() ? "" : " via " + via);
        route::ReplaceRoute4(dev, cidr, via);
    }

    for (const auto &[network, gw, metric] : negotiated.routes_ipv6)
    {
        (void)gw;
        (void)metric;
        logger.info("IPv6 route: {} dev {}", network, dev);
        route::ReplaceRoute6(dev, network);
    }
}

} // namespace clv::vpn
