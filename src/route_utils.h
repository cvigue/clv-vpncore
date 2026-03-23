// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_ROUTE_UTILS_H
#define CLV_VPN_ROUTE_UTILS_H

/**
 * @file route_utils.h
 * @brief Programmatic route installation via rtnetlink (RTM_NEWROUTE).
 *
 * Replaces `system("ip route replace ...")` and `system("ip -6 route replace ...")`
 * with proper netlink messages.  Uses the existing NetlinkHelper utilities for
 * socket creation, send, and ACK handling.
 */

#include <arpa/inet.h>

#include <cerrno>
#include <cstring>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <util/netlink_helper.h>

namespace clv::vpn::route {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

namespace detail {

/**
 * @brief Append an rtattr to a netlink message buffer.
 *
 * Writes an `rtattr` header + payload at `buf + *offset`, advancing
 * `*offset` by the RTA_ALIGN-ed size.
 *
 * @param buf      Message buffer start
 * @param offset   Current write offset (updated)
 * @param capacity Buffer capacity
 * @param type     rtattr type
 * @param data     Payload pointer
 * @param len      Payload length
 * @throws std::runtime_error if the attribute would overflow the buffer
 */
inline void RtaPut(char *buf, std::size_t &offset, std::size_t capacity,
                   unsigned short type, const void *data, std::size_t len)
{
    std::size_t attr_len = RTA_LENGTH(len);
    std::size_t aligned = RTA_ALIGN(attr_len);
    if (offset + aligned > capacity)
        throw std::runtime_error("route_utils: buffer overflow");

    auto *rta = reinterpret_cast<struct rtattr *>(buf + offset);
    rta->rta_type = type;
    rta->rta_len = static_cast<unsigned short>(attr_len);
    std::memcpy(RTA_DATA(rta), data, len);
    // Zero padding bytes for deterministic messages
    if (aligned > attr_len)
        std::memset(buf + offset + attr_len, 0, aligned - attr_len);
    offset += aligned;
}

} // namespace detail

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * @brief Install (replace) an IPv4 route via RTM_NEWROUTE.
 *
 * Equivalent to `ip route replace <dst_cidr> dev <ifname> [via <gateway>]`.
 *
 * @param ifname     Device name (e.g. "tun0" or "ovpn0")
 * @param dst_cidr   Destination in CIDR notation (e.g. "192.168.50.0/24")
 * @param gateway    Optional gateway in dotted-decimal (empty string = none)
 * @throws std::invalid_argument on parse failure
 * @throws std::system_error on netlink failure
 */
inline void ReplaceRoute4(const std::string &ifname,
                          const std::string &dst_cidr,
                          const std::string &gateway = {})
{
    // Parse CIDR
    auto slash = dst_cidr.find('/');
    if (slash == std::string::npos)
        throw std::invalid_argument("route_utils: missing '/' in CIDR: " + dst_cidr);

    std::string dst_ip = dst_cidr.substr(0, slash);
    int prefix = std::stoi(dst_cidr.substr(slash + 1));
    if (prefix < 0 || prefix > 32)
        throw std::invalid_argument("route_utils: invalid prefix length: " + dst_cidr);

    struct in_addr dst{};
    if (inet_pton(AF_INET, dst_ip.c_str(), &dst) != 1)
        throw std::invalid_argument("route_utils: invalid IPv4 address: " + dst_ip);

    unsigned int ifindex = if_nametoindex(ifname.c_str());
    if (ifindex == 0)
        throw std::system_error(errno, std::system_category(), "route_utils: if_nametoindex failed for " + ifname);

    // Build the RTM_NEWROUTE request
    struct
    {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char attrs[256];
    } req{};

    req.nlh.nlmsg_type = RTM_NEWROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    req.nlh.nlmsg_seq = 1;

    req.rtm.rtm_family = AF_INET;
    req.rtm.rtm_dst_len = static_cast<unsigned char>(prefix);
    req.rtm.rtm_table = RT_TABLE_MAIN;
    req.rtm.rtm_protocol = RTPROT_BOOT;
    req.rtm.rtm_scope = RT_SCOPE_LINK;
    req.rtm.rtm_type = RTN_UNICAST;

    // If a gateway is specified, route scope should be "universe" (not link)
    if (!gateway.empty())
        req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;

    std::size_t offset = 0;
    constexpr std::size_t cap = sizeof(req.attrs);

    // RTA_DST
    detail::RtaPut(req.attrs, offset, cap, RTA_DST, &dst, sizeof(dst));

    // RTA_OIF (output interface)
    detail::RtaPut(req.attrs, offset, cap, RTA_OIF, &ifindex, sizeof(ifindex));

    // RTA_GATEWAY (optional)
    if (!gateway.empty())
    {
        struct in_addr gw{};
        if (inet_pton(AF_INET, gateway.c_str(), &gw) != 1)
            throw std::invalid_argument("route_utils: invalid gateway: " + gateway);

        detail::RtaPut(req.attrs, offset, cap, RTA_GATEWAY, &gw, sizeof(gw));
    }

    req.nlh.nlmsg_len = static_cast<__u32>(
        NLMSG_LENGTH(sizeof(struct rtmsg)) + offset);

    auto sock = NetlinkHelper::CreateRtnetlinkSocket();
    NetlinkHelper::SendNetlinkMessage(sock.get(), &req, req.nlh.nlmsg_len, "RTM_NEWROUTE (IPv4)");
    NetlinkHelper::ReceiveNetlinkAck(sock.get(), "RTM_NEWROUTE (IPv4)");
}

/**
 * @brief Install (replace) an IPv6 route via RTM_NEWROUTE.
 *
 * Equivalent to `ip -6 route replace <dst_cidr> dev <ifname>`.
 *
 * @param ifname     Device name (e.g. "tun0" or "ovpn0")
 * @param dst_cidr   Destination in CIDR notation (e.g. "fd00::/64")
 * @throws std::invalid_argument on parse failure
 * @throws std::system_error on netlink failure
 */
inline void ReplaceRoute6(const std::string &ifname,
                          const std::string &dst_cidr)
{
    // Parse CIDR
    auto slash = dst_cidr.find('/');
    if (slash == std::string::npos)
        throw std::invalid_argument("route_utils: missing '/' in IPv6 CIDR: " + dst_cidr);

    std::string dst_ip = dst_cidr.substr(0, slash);
    int prefix = std::stoi(dst_cidr.substr(slash + 1));
    if (prefix < 0 || prefix > 128)
        throw std::invalid_argument("route_utils: invalid IPv6 prefix length: " + dst_cidr);

    struct in6_addr dst{};
    if (inet_pton(AF_INET6, dst_ip.c_str(), &dst) != 1)
        throw std::invalid_argument("route_utils: invalid IPv6 address: " + dst_ip);

    unsigned int ifindex = if_nametoindex(ifname.c_str());
    if (ifindex == 0)
        throw std::system_error(errno, std::system_category(), "route_utils: if_nametoindex failed for " + ifname);

    // Build the RTM_NEWROUTE request
    struct
    {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char attrs[256];
    } req{};

    req.nlh.nlmsg_type = RTM_NEWROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    req.nlh.nlmsg_seq = 1;

    req.rtm.rtm_family = AF_INET6;
    req.rtm.rtm_dst_len = static_cast<unsigned char>(prefix);
    req.rtm.rtm_table = RT_TABLE_MAIN;
    req.rtm.rtm_protocol = RTPROT_BOOT;
    req.rtm.rtm_scope = RT_SCOPE_UNIVERSE; // IPv6 routes are always universe scope
    req.rtm.rtm_type = RTN_UNICAST;

    std::size_t offset = 0;
    constexpr std::size_t cap = sizeof(req.attrs);

    // RTA_DST
    detail::RtaPut(req.attrs, offset, cap, RTA_DST, &dst, sizeof(dst));

    // RTA_OIF (output interface)
    detail::RtaPut(req.attrs, offset, cap, RTA_OIF, &ifindex, sizeof(ifindex));

    req.nlh.nlmsg_len = static_cast<__u32>(
        NLMSG_LENGTH(sizeof(struct rtmsg)) + offset);

    auto sock = NetlinkHelper::CreateRtnetlinkSocket();
    NetlinkHelper::SendNetlinkMessage(sock.get(), &req, req.nlh.nlmsg_len, "RTM_NEWROUTE (IPv6)");
    NetlinkHelper::ReceiveNetlinkAck(sock.get(), "RTM_NEWROUTE (IPv6)");
}

/**
 * @brief Query the main routing table via RTM_GETROUTE dump.
 *
 * @details Sends a netlink dump request for the specified address family and
 * formats each route as a human-readable string, suitable for diagnostic
 * logging.
 *
 * @param family AF_INET for IPv4 routes, AF_INET6 for IPv6 routes
 * @return Vector of formatted route strings (e.g. "10.8.0.0/24 dev tun0",
 *         "default dev eth0 via 10.0.0.1").  Empty on failure.
 */
inline std::vector<std::string> QueryRoutes(int family)
{
    struct
    {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req{};

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.rtm.rtm_family = static_cast<unsigned char>(family);

    auto sock = NetlinkHelper::CreateRtnetlinkSocket();
    NetlinkHelper::SendNetlinkMessage(sock.get(), &req, req.nlh.nlmsg_len, family == AF_INET ? "RTM_GETROUTE (IPv4 dump)" : "RTM_GETROUTE (IPv6 dump)");

    std::vector<std::string> results;
    char buf[16384];

    for (;;)
    {
        ssize_t nbytes = ::recv(sock.get(), buf, sizeof(buf), 0);
        if (nbytes <= 0)
            break;

        int remaining = static_cast<int>(nbytes);
        bool done = false;

        for (auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
             NLMSG_OK(nlh, remaining);
             nlh = NLMSG_NEXT(nlh, remaining))
        {
            if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR)
            {
                done = true;
                break;
            }
            if (nlh->nlmsg_type != RTM_NEWROUTE)
                continue;

            auto *rtm = reinterpret_cast<struct rtmsg *>(NLMSG_DATA(nlh));
            if (rtm->rtm_table != RT_TABLE_MAIN)
                continue;

            // Parse route attributes
            char dst_buf[sizeof(struct in6_addr)]{};
            char gw_buf[sizeof(struct in6_addr)]{};
            bool has_dst = false;
            bool has_gw = false;
            unsigned int oif = 0;

            auto *rta = reinterpret_cast<struct rtattr *>(RTM_RTA(rtm));
            int rta_len = static_cast<int>(RTM_PAYLOAD(nlh));

            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len))
            {
                auto plen = RTA_PAYLOAD(rta);
                switch (rta->rta_type)
                {
                case RTA_DST:
                    if (plen > 0 && static_cast<std::size_t>(plen) <= sizeof(dst_buf))
                        std::memcpy(dst_buf, RTA_DATA(rta), static_cast<std::size_t>(plen));
                    has_dst = true;
                    break;
                case RTA_GATEWAY:
                    if (plen > 0 && static_cast<std::size_t>(plen) <= sizeof(gw_buf))
                        std::memcpy(gw_buf, RTA_DATA(rta), static_cast<std::size_t>(plen));
                    has_gw = true;
                    break;
                case RTA_OIF:
                    if (plen == sizeof(oif))
                        std::memcpy(&oif, RTA_DATA(rta), sizeof(oif));
                    break;
                }
            }

            // Format: "<dst>/<prefix> dev <ifname> [via <gw>]"
            char addr_str[INET6_ADDRSTRLEN];
            std::string line;

            if (has_dst && rtm->rtm_dst_len > 0)
            {
                inet_ntop(family, dst_buf, addr_str, sizeof(addr_str));
                line = std::string(addr_str) + "/" + std::to_string(rtm->rtm_dst_len);
            }
            else
            {
                line = "default";
            }

            if (oif != 0)
            {
                char ifname[IF_NAMESIZE];
                if (if_indextoname(oif, ifname))
                    line += " dev " + std::string(ifname);
            }

            if (has_gw)
            {
                inet_ntop(family, gw_buf, addr_str, sizeof(addr_str));
                line += " via " + std::string(addr_str);
            }

            results.push_back(std::move(line));
        }

        if (done)
            break;
    }

    return results;
}

} // namespace clv::vpn::route

#endif // CLV_VPN_ROUTE_UTILS_H
