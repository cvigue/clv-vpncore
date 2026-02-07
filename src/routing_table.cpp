// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "routing_table.h"

#include <util/ipv4_utils.h>
#include <util/ipv6_utils.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace clv::vpn {

bool RoutingTableIpv4::AddRoute(uint32_t network, uint8_t prefix_length, uint64_t session_id)
{
    // Validate prefix length
    if (prefix_length > 32)
        return false;

    // Normalize network address to remove host bits
    uint32_t normalized_network = ipv4::NormalizeNetwork(network, prefix_length);

    RouteKey key{normalized_network, prefix_length};
    routes_[key] = session_id;
    return true;
}

bool RoutingTableIpv4::RemoveRoute(uint32_t network, uint8_t prefix_length)
{
    if (prefix_length > 32)
        return false;

    uint32_t normalized_network = ipv4::NormalizeNetwork(network, prefix_length);

    RouteKey key{normalized_network, prefix_length};
    return routes_.erase(key) > 0;
}

std::optional<uint64_t> RoutingTableIpv4::Lookup(uint32_t dest_ipv4) const
{
    auto it = std::ranges::find_if(routes_, [dest_ipv4](const auto &pair)
    {
        return ipv4::IpMatchesNetwork(dest_ipv4, pair.first.network, pair.first.prefix_length);
    });

    if (it != routes_.end())
        return it->second;

    return std::nullopt;
}

std::vector<RoutingTableIpv4::Route> RoutingTableIpv4::GetRoutesForSession(uint64_t session_id) const
{
    std::vector<Route> result;
    std::ranges::for_each(routes_, [&](const auto &pair)
    {
        if (pair.second == session_id)
            result.push_back({pair.first.network, pair.first.prefix_length, pair.second});
    });
    return result;
}

size_t RoutingTableIpv4::RemoveSessionRoutes(uint64_t session_id)
{
    return std::erase_if(routes_, [session_id](const auto &pair)
    {
        return pair.second == session_id;
    });
}

// ---------------------------------------------------------------------------
// RoutingTableIpv6
// ---------------------------------------------------------------------------

bool RoutingTableIpv6::AddRoute(const Ipv6Address &network, uint8_t prefix_length, uint64_t session_id)
{
    if (prefix_length > 128)
        return false;

    auto normalized = ipv6::NormalizeNetwork(network, prefix_length);
    RouteKey key{normalized, prefix_length};
    routes_[key] = session_id;
    return true;
}

bool RoutingTableIpv6::RemoveRoute(const Ipv6Address &network, uint8_t prefix_length)
{
    if (prefix_length > 128)
        return false;

    auto normalized = ipv6::NormalizeNetwork(network, prefix_length);
    RouteKey key{normalized, prefix_length};
    return routes_.erase(key) > 0;
}

std::optional<uint64_t> RoutingTableIpv6::Lookup(const Ipv6Address &dest_ipv6) const
{
    auto it = std::ranges::find_if(routes_, [&dest_ipv6](const auto &pair)
    {
        return ipv6::Ipv6MatchesPrefix(dest_ipv6, pair.first.network, pair.first.prefix_length);
    });

    if (it != routes_.end())
        return it->second;

    return std::nullopt;
}

std::vector<RoutingTableIpv6::Route> RoutingTableIpv6::GetRoutesForSession(uint64_t session_id) const
{
    std::vector<Route> result;
    std::ranges::for_each(routes_, [&](const auto &pair)
    {
        if (pair.second == session_id)
            result.push_back({pair.first.network, pair.first.prefix_length, pair.second});
    });
    return result;
}

size_t RoutingTableIpv6::RemoveSessionRoutes(uint64_t session_id)
{
    return std::erase_if(routes_, [session_id](const auto &pair)
    {
        return pair.second == session_id;
    });
}

} // namespace clv::vpn
