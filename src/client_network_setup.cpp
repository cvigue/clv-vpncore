// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "client_network_setup.h"

#include "iface_utils.h"
#include "route_utils.h"

#include <asio/ip/address_v4.hpp>
#include <net/ipv4_utils.h>
#include <spdlog/spdlog.h>

#include <exception>
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
        try
        {
            auto prefix = ipv4::MaskToPrefix(asio::ip::make_address_v4(gw).to_uint());
            return network + "/" + std::to_string(prefix);
        }
        catch (...)
        {
            return network + "/32";
        }
    }
    return network + "/32";
}

std::string ConnectedCidrFromIfconfig(const openvpn::NegotiatedConfig &negotiated)
{
    if (negotiated.ifconfig.first.empty() || negotiated.ifconfig.second.empty())
        return {};
    try
    {
        auto host = asio::ip::make_address_v4(negotiated.ifconfig.first).to_uint();
        auto prefix = ipv4::MaskToPrefix(asio::ip::make_address_v4(negotiated.ifconfig.second).to_uint());
        auto net = host & ipv4::CreateMask(prefix);
        return ipv4::Ipv4ToString(net) + "/" + std::to_string(prefix);
    }
    catch (...)
    {
        return {};
    }
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
        auto prefix = ipv4::MaskToPrefix(asio::ip::make_address_v4(assigned_netmask).to_uint());
        tun.SetAddress(assigned_ip, prefix);
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
        try
        {
            route::ReplaceRoute4(dev, cidr, via);
        }
        catch (const std::exception &e)
        {
            logger.error("Route failed: {}", e.what());
        }
    }

    for (const auto &[network, gw, metric] : negotiated.routes_ipv6)
    {
        (void)gw;
        (void)metric;
        logger.info("IPv6 route: {} dev {}", network, dev);
        try
        {
            route::ReplaceRoute6(dev, network);
        }
        catch (const std::exception &e)
        {
            logger.error("IPv6 route failed: {}", e.what());
        }
    }
}

} // namespace clv::vpn
