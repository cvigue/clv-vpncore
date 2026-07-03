// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TUN_TUN_SETUP_H
#define CLV_VPN_TUN_TUN_SETUP_H

#include "platform/linux/tun/tun_device.h"

#include "openvpn/push_exchange_helpers.h"
#include "openvpn/vpn_config.h"

#include <net/ipv4_utils.h>
#include <net/ipv6_utils.h>

#include <spdlog/logger.h>

#include <stdexcept>
#include <string>

namespace clv::vpn::tun {

/**
 * @brief Create and configure a server-side TUN device from @p srv.
 * @return Actual netdev name (from kernel).
 */
inline std::string SetupServerTun(TunDevice &tun,
                                  const VpnConfig::ServerConfig &srv,
                                  spdlog::logger &logger)
{
    std::string dev_name = srv.dev;
    if (dev_name == "tun")
        dev_name = "";

    std::string actual_name = tun.Create(dev_name);
    logger.info("Created TUN device: {}", actual_name);

    auto parsed = clv::net::ipv4::ParseCidr(srv.network);
    if (!parsed)
        throw std::invalid_argument("Invalid server network CIDR: " + srv.network);
    auto [network_addr, prefix_len] = *parsed;
    (void)network_addr;

    const std::string server_ip = DeriveServerIp(srv);
    tun.SetAddress(server_ip, prefix_len);
    logger.info("Set TUN address: {}/{}", server_ip, static_cast<int>(prefix_len));
    tun.SetMtu(srv.tun_mtu);

    if (srv.tun_txqueuelen > 0)
    {
        tun.SetTxQueueLen(srv.tun_txqueuelen);
        logger.info("Set TUN txqueuelen: {}", srv.tun_txqueuelen);
    }

    tun.BringUp();
    logger.info("TUN device is up");

    if (!srv.network_v6.empty())
    {
        auto parsed_v6 = clv::net::ipv6::ParseCidr6(srv.network_v6);
        if (parsed_v6)
        {
            const auto [net_v6, prefix_v6] = *parsed_v6;
            (void)net_v6;
            const std::string server_v6_str = DeriveServerIpv6(srv);
            tun.AddIpv6Address(server_v6_str, prefix_v6);
            logger.info("Set TUN IPv6 address: {}/{}", server_v6_str, prefix_v6);
        }
    }

    return actual_name;
}

} // namespace clv::vpn::tun

#endif // CLV_VPN_TUN_TUN_SETUP_H
