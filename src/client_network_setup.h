// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CLIENT_NETWORK_SETUP_H
#define CLV_VPN_CLIENT_NETWORK_SETUP_H

/**
 * @file client_network_setup.h
 * @brief Shared client TUN addressing and negotiated-route install.
 *
 * Userspace UDP/TCP channels call ConfigureClientTun + InstallClientNegotiatedRoutes.
 * DCO keeps its install backend but reuses NormalizeNegotiatedRoute4.
 */

#include "openvpn/config_exchange.h"
#include "platform/linux/tun/tun_device.h"

#include <cstdint>
#include <string>

namespace spdlog {
class logger;
}

namespace clv::vpn {

/** Default userspace TUN MTU when the peer did not push tun-mtu. */
inline constexpr std::uint16_t kClientDefaultTunMtu = 1400;

/**
 * Normalize a pushed IPv4 route (network[, netmask-as-gw]) to CIDR.
 * Already-CIDR networks are returned unchanged; bare hosts become /32.
 */
[[nodiscard]] std::string NormalizeNegotiatedRoute4(const std::string &network,
                                                    const std::string &gw);

/**
 * Connected IPv4 CIDR from ifconfig when topology is subnet; empty otherwise.
 * Invalid host/mask throws (aborts connect via ConnectionLoop).
 */
[[nodiscard]] std::string ConnectedCidrFromIfconfig(const openvpn::NegotiatedConfig &negotiated);

/**
 * Create + address + MTU + bring-up (+ optional IPv6) for a userspace TunDevice.
 * @param tun       Device (not yet created).
 * @param negotiated  Push/ifconfig result.
 * @param dev_name  Preferred TUN name (may be empty for kernel pick).
 * @param logger    Diagnostics.
 */
void ConfigureClientTun(tun::TunDevice &tun,
                        const openvpn::NegotiatedConfig &negotiated,
                        const std::string &dev_name,
                        spdlog::logger &logger);

/**
 * Install negotiated IPv4/IPv6 routes on a userspace TunDevice (skips connected CIDR).
 */
void InstallClientNegotiatedRoutes(tun::TunDevice &tun,
                                   const openvpn::NegotiatedConfig &negotiated,
                                   spdlog::logger &logger);

} // namespace clv::vpn

#endif // CLV_VPN_CLIENT_NETWORK_SETUP_H
