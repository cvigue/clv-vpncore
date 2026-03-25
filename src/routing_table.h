// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_ROUTING_TABLE_H
#define CLV_VPN_ROUTING_TABLE_H

#include <util/ipv4_utils.h>
#include <util/ipv6_utils.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace clv::vpn {

// ---------------------------------------------------------------------------
// Address-family traits — provide NormalizeNetwork, Matches, and MaxPrefix
// ---------------------------------------------------------------------------

struct Ipv4RoutingTraits
{
    using Address = std::uint32_t;
    static constexpr std::uint8_t kMaxPrefix = 32;

    static Address Normalize(const Address &addr, std::uint8_t prefix)
    {
        return ipv4::NormalizeNetwork(addr, prefix);
    }

    static bool Matches(const Address &addr, const Address &network, std::uint8_t prefix)
    {
        return ipv4::IpMatchesNetwork(addr, network, prefix);
    }
};

struct Ipv6RoutingTraits
{
    using Address = ipv6::Ipv6Address;
    static constexpr std::uint8_t kMaxPrefix = 128;

    static Address Normalize(const Address &addr, std::uint8_t prefix)
    {
        return ipv6::NormalizeNetwork(addr, prefix);
    }

    static bool Matches(const Address &addr, const Address &network, std::uint8_t prefix)
    {
        return ipv6::Ipv6MatchesPrefix(addr, network, prefix);
    }
};

// ---------------------------------------------------------------------------
// RoutingTable<Traits> — longest-prefix-match routing table
// ---------------------------------------------------------------------------

/**
 * @brief Longest-prefix-match routing table for VPN traffic.
 *
 * Maintains a mapping of CIDR blocks to client session IDs.
 * Supports efficient longest-prefix-match lookups for routing decisions.
 *
 * @tparam Traits  Address-family traits providing @c Address type,
 *                 @c kMaxPrefix, @c Normalize(), and @c Matches().
 */
template <typename Traits>
class RoutingTable
{
  public:
    using Address = typename Traits::Address;

    struct Route
    {
        Address network;
        std::uint8_t prefix_length;
        std::uint64_t session_id;
    };

    bool AddRoute(const Address &network, std::uint8_t prefix_length, std::uint64_t session_id)
    {
        if (prefix_length > Traits::kMaxPrefix)
            return false;

        auto normalized = Traits::Normalize(network, prefix_length);
        RouteKey key{normalized, prefix_length};
        routes_[key] = session_id;
        return true;
    }

    bool RemoveRoute(const Address &network, std::uint8_t prefix_length)
    {
        if (prefix_length > Traits::kMaxPrefix)
            return false;

        auto normalized = Traits::Normalize(network, prefix_length);
        RouteKey key{normalized, prefix_length};
        return routes_.erase(key) > 0;
    }

    std::optional<std::uint64_t> Lookup(const Address &dest) const
    {
        auto it = std::ranges::find_if(routes_, [&dest](const auto &pair)
        {
            return Traits::Matches(dest, pair.first.network, pair.first.prefix_length);
        });

        if (it != routes_.end())
            return it->second;

        return std::nullopt;
    }

    std::vector<Route> GetRoutesForSession(std::uint64_t session_id) const
    {
        std::vector<Route> result;
        std::ranges::for_each(routes_, [&](const auto &pair)
        {
            if (pair.second == session_id)
                result.push_back({pair.first.network, pair.first.prefix_length, pair.second});
        });
        return result;
    }

    std::size_t RemoveSessionRoutes(std::uint64_t session_id)
    {
        return std::erase_if(routes_, [session_id](const auto &pair)
        {
            return pair.second == session_id;
        });
    }

    std::size_t GetRouteCount() const
    {
        return routes_.size();
    }

    void Clear()
    {
        routes_.clear();
    }

  private:
    struct RouteKey
    {
        Address network;
        std::uint8_t prefix_length;

        bool operator<(const RouteKey &other) const
        {
            if (prefix_length != other.prefix_length)
                return prefix_length > other.prefix_length;
            return network < other.network;
        }
    };

    std::map<RouteKey, std::uint64_t> routes_;
};

/** IPv4 routing table (host-byte-order uint32_t addresses, /0–/32) */
using RoutingTableIpv4 = RoutingTable<Ipv4RoutingTraits>;

/** IPv6 routing table (network-byte-order 16-byte addresses, /0–/128) */
using RoutingTableIpv6 = RoutingTable<Ipv6RoutingTraits>;

} // namespace clv::vpn

#endif // CLV_VPN_ROUTING_TABLE_H
