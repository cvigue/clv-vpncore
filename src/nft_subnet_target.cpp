// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include "nft_subnet_target.h"

#include <net/ipv4_utils.h>
#include <net/ipv6_utils.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstring>

namespace clv::vpn {

namespace ipv4 = clv::net::ipv4;
namespace ipv6 = clv::net::ipv6;

std::optional<MasqueradeTarget> ParseMasqueradeCidr(const std::string &cidr)
{
    if (auto v4 = ipv4::ParseCidr(cidr))
    {
        MasqueradeTarget t{};
        t.family = NfTablesClient::kIPv4;
        t.prefix_len = v4->second;
        std::uint32_t net_order = htonl(v4->first);
        std::memcpy(t.network.data(), &net_order, 4);
        return t;
    }

    if (auto v6 = ipv6::ParseCidr6(cidr))
    {
        MasqueradeTarget t{};
        t.family = NfTablesClient::kIPv6;
        t.prefix_len = v6->second;
        std::memcpy(t.network.data(), v6->first.data(), 16);
        return t;
    }

    return std::nullopt;
}

std::optional<std::array<std::uint8_t, 16>>
ParseHostAddress(std::uint8_t family, const std::string &host_ip)
{
    std::array<std::uint8_t, 16> out{};

    if (family == NfTablesClient::kIPv4)
    {
        auto addr = ipv4::ParseIpv4(host_ip);
        if (!addr)
            return std::nullopt;
        std::uint32_t net_order = htonl(*addr);
        std::memcpy(out.data(), &net_order, 4);
        return out;
    }

    auto addr6 = ipv6::ParseIpv6(host_ip);
    if (!addr6)
        return std::nullopt;
    std::memcpy(out.data(), addr6->data(), 16);
    return out;
}

std::optional<IntraPoolDropTarget>
ParseIntraPoolDropTarget(const std::string &pool_cidr, const std::string &bridge_ip)
{
    auto pool = ParseMasqueradeCidr(pool_cidr);
    if (!pool)
        return std::nullopt;

    auto bridge = ParseHostAddress(pool->family, bridge_ip);
    if (!bridge)
        return std::nullopt;

    IntraPoolDropTarget target{};
    static_cast<NftSubnetTarget &>(target) = *pool;
    target.bridge_ip = *bridge;
    return target;
}

} // namespace clv::vpn
