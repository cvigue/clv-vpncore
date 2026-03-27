// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_ROUTING_TABLE_H
#define CLV_VPN_ROUTING_TABLE_H

#include <util/ipv4_utils.h>
#include <util/ipv6_utils.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <unordered_map>
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
// Hash support for address types used as unordered_map keys
// ---------------------------------------------------------------------------

struct Ipv6AddressHash
{
    std::size_t operator()(const ipv6::Ipv6Address &addr) const noexcept
    {
        std::uint64_t lo, hi;
        std::memcpy(&lo, addr.data(), 8);
        std::memcpy(&hi, addr.data() + 8, 8);
        // boost-style hash combine
        std::size_t h = std::hash<std::uint64_t>{}(lo);
        h ^= std::hash<std::uint64_t>{}(hi) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

struct Ipv6AddressEqual
{
    bool operator()(const ipv6::Ipv6Address &a, const ipv6::Ipv6Address &b) const noexcept
    {
        return a == b;
    }
};

// ---------------------------------------------------------------------------
// AddressMapTraits — select hash/equal for each address family
// ---------------------------------------------------------------------------

template <typename Address>
struct AddressMapTraits
{
    using Hasher = std::hash<Address>;
    using Equal = std::equal_to<Address>;
};

template <>
struct AddressMapTraits<ipv6::Ipv6Address>
{
    using Hasher = Ipv6AddressHash;
    using Equal = Ipv6AddressEqual;
};

// ---------------------------------------------------------------------------
// RoutingTable<Traits> — longest-prefix-match routing table
//
// Stores one unordered_map per prefix length (0..kMaxPrefix).  Lookup
// iterates from the longest prefix to the shortest, masking the
// destination and probing the corresponding map.  For the common
// case of /32-only (IPv4) or /128-only (IPv6) host routes this
// collapses to a single O(1) hash probe.
// ---------------------------------------------------------------------------

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
        levels_[prefix_length][normalized] = session_id;
        return true;
    }

    bool RemoveRoute(const Address &network, std::uint8_t prefix_length)
    {
        if (prefix_length > Traits::kMaxPrefix)
            return false;

        auto normalized = Traits::Normalize(network, prefix_length);
        return levels_[prefix_length].erase(normalized) > 0;
    }

    std::optional<std::uint64_t> Lookup(const Address &dest) const
    {
        for (int p = Traits::kMaxPrefix; p >= 0; --p)
        {
            const auto &level = levels_[p];
            if (level.empty())
                continue;
            auto masked = Traits::Normalize(dest, static_cast<std::uint8_t>(p));
            if (auto it = level.find(masked); it != level.end())
                return it->second;
        }
        return std::nullopt;
    }

    std::vector<Route> GetRoutesForSession(std::uint64_t session_id) const
    {
        std::vector<Route> result;
        for (std::uint8_t p = 0; p <= Traits::kMaxPrefix; ++p)
        {
            for (const auto &[network, sid] : levels_[p])
            {
                if (sid == session_id)
                    result.push_back({network, p, sid});
            }
        }
        return result;
    }

    std::size_t RemoveSessionRoutes(std::uint64_t session_id)
    {
        std::size_t total = 0;
        for (auto &level : levels_)
        {
            total += std::erase_if(level, [session_id](const auto &pair)
            {
                return pair.second == session_id;
            });
        }
        return total;
    }

    std::size_t GetRouteCount() const
    {
        std::size_t total = 0;
        for (const auto &level : levels_)
            total += level.size();
        return total;
    }

    void Clear()
    {
        for (auto &level : levels_)
            level.clear();
    }

  private:
    using Map = std::unordered_map<
        Address,
        std::uint64_t,
        typename AddressMapTraits<Address>::Hasher,
        typename AddressMapTraits<Address>::Equal>;

    std::array<Map, Traits::kMaxPrefix + 1> levels_;
};

/** IPv4 routing table (host-byte-order uint32_t addresses, /0–/32) */
using RoutingTableIpv4 = RoutingTable<Ipv4RoutingTraits>;

/** IPv6 routing table (network-byte-order 16-byte addresses, /0–/128) */
using RoutingTableIpv6 = RoutingTable<Ipv6RoutingTraits>;

} // namespace clv::vpn

#endif // CLV_VPN_ROUTING_TABLE_H
