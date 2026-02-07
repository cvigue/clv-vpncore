// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_IFACE_UTILS_H
#define CLV_VPN_IFACE_UTILS_H

/**
 * @file iface_utils.h
 * @brief Shared network-interface ioctl helpers.
 *
 * Free functions for setting an interface's IPv4/IPv6 address, netmask, flags,
 * and point-to-point destination via ioctl.  Used by both the DCO server
 * (`DcoDataChannel::ConfigureDcoInterface`) and DCO client
 * (`VpnClient::ConfigureDcoInterface`).
 *
 * Covers factoring items F8 and F18 from goals-plan.md §6.
 */

#include "unique_fd.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <linux/if.h>
#include <linux/ipv6.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <system_error>

#include <scope_guard.h>

namespace clv::vpn::iface {

/**
 * @brief Set an interface's IPv4 address via SIOCSIFADDR.
 * @param sock   AF_INET/SOCK_DGRAM socket fd
 * @param ifname Interface name
 * @param ip_str Dotted-decimal IPv4 address
 * @throws std::invalid_argument if @p ip_str is unparseable
 * @throws std::system_error on ioctl failure
 */
inline void SetIpAddress(int sock, const char *ifname, const std::string &ip_str)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1)
        throw std::invalid_argument("Invalid IP address: " + ip_str);

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    auto *sa = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
    sa->sin_family = AF_INET;
    sa->sin_addr = addr;

    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0)
        throw std::system_error(errno, std::system_category(), "Failed to set IP address " + ip_str);
}

/**
 * @brief Set an interface's IPv4 netmask via SIOCSIFNETMASK.
 * @param sock         AF_INET/SOCK_DGRAM socket fd
 * @param ifname       Interface name
 * @param mask_host    Netmask in **host** byte order (e.g. 0xFFFFFF00 for /24)
 * @throws std::system_error on ioctl failure
 */
inline void SetNetmask(int sock, const char *ifname, uint32_t mask_host)
{
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    auto *sa = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = htonl(mask_host);

    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0)
        throw std::system_error(errno, std::system_category(), "Failed to set netmask");
}

/**
 * @brief Bring an interface up (set IFF_UP | IFF_RUNNING).
 * @param sock   AF_INET/SOCK_DGRAM socket fd
 * @param ifname Interface name
 * @throws std::system_error on ioctl failure
 */
inline void BringUp(int sock, const char *ifname)
{
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
        throw std::system_error(errno, std::system_category(), "Failed to get interface flags");

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
        throw std::system_error(errno, std::system_category(), "Failed to bring interface up");
}

/**
 * @brief Set an interface's point-to-point destination address via SIOCSIFDSTADDR.
 *
 * Configures a point-to-point (net30/P2P) interface by setting the local IP,
 * the peer (destination) IP, a /32 netmask, and bringing the interface up.
 *
 * @param ifname       Interface name
 * @param local_ip     Local dotted-decimal IPv4 address
 * @param peer_ip      Remote dotted-decimal IPv4 address
 * @throws std::invalid_argument if an address is unparseable
 * @throws std::system_error on ioctl failure
 */
inline void SetPointToPoint(const char *ifname,
                            const std::string &local_ip,
                            const std::string &peer_ip)
{
    clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));

    // 1. Set the local address
    SetIpAddress(sock.get(), ifname, local_ip);

    // 2. Set the point-to-point destination address
    struct in_addr dst;
    if (inet_pton(AF_INET, peer_ip.c_str(), &dst) != 1)
        throw std::invalid_argument("Invalid peer IP address: " + peer_ip);

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    auto *sa = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_dstaddr);
    sa->sin_family = AF_INET;
    sa->sin_addr = dst;

    if (ioctl(sock.get(), SIOCSIFDSTADDR, &ifr) < 0)
        throw std::system_error(errno, std::system_category(), "Failed to set P2P destination " + peer_ip);

    // 3. Netmask /32 for a host route to the peer
    SetNetmask(sock.get(), ifname, 0xFFFFFFFFu);

    // 4. Bring up with IFF_POINTOPOINT flag
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock.get(), SIOCGIFFLAGS, &ifr) < 0)
        throw std::system_error(errno, std::system_category(), "Failed to get interface flags");

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING | IFF_POINTOPOINT;
    if (ioctl(sock.get(), SIOCSIFFLAGS, &ifr) < 0)
        throw std::system_error(errno, std::system_category(), "Failed to bring P2P interface up");
}

/**
 * @brief Add an IPv6 address to an interface via SIOCSIFADDR (AF_INET6).
 *
 * Uses the `in6_ifreq` ioctl rather than shelling out to `ip -6 addr add`.
 *
 * @param ifname       Interface name
 * @param addr_str     IPv6 address string (e.g. "fd00::2")
 * @param prefix_len   Prefix length (0–128)
 * @throws std::invalid_argument if @p addr_str is unparseable or prefix is out of range
 * @throws std::system_error on ioctl / if_nametoindex failure
 */
inline void AddIpv6Address(const char *ifname,
                           const std::string &addr_str,
                           std::uint8_t prefix_len)
{
    if (prefix_len > 128)
        throw std::invalid_argument("Invalid IPv6 prefix length: " + std::to_string(prefix_len));

    struct in6_addr addr6{};
    if (inet_pton(AF_INET6, addr_str.c_str(), &addr6) != 1)
        throw std::invalid_argument("Invalid IPv6 address: " + addr_str);

    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
        throw std::system_error(errno, std::system_category(), std::string("if_nametoindex failed for ") + ifname);

    struct in6_ifreq ifr6{};
    ifr6.ifr6_addr = addr6;
    ifr6.ifr6_prefixlen = prefix_len;
    ifr6.ifr6_ifindex = static_cast<int>(ifindex);

    clv::UniqueFd sock6(::socket(AF_INET6, SOCK_DGRAM, 0));
    if (ioctl(sock6.get(), SIOCSIFADDR, &ifr6) < 0)
        throw std::system_error(errno, std::system_category(), "Failed to set IPv6 address " + addr_str);
}

} // namespace clv::vpn::iface

#endif // CLV_VPN_IFACE_UTILS_H
