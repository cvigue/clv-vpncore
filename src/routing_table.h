// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_ROUTING_TABLE_H
#define CLV_VPN_ROUTING_TABLE_H

#include <net/ipv4_utils.h>
#include <net/ipv6_utils.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <unordered_map>
#include <vector>

namespace clv::vpn {

namespace ipv4 = clv::net::ipv4;
namespace ipv6 = clv::net::ipv6;

// ---------------------------------------------------------------------------
// Address-family traits — provide NormalizeNetwork, Matches, and MaxPrefix
// ---------------------------------------------------------------------------

/** @brief IPv4 address-family traits for RoutingTable. */
struct Ipv4RoutingTraits
{
    using Address = std::uint32_t;
    static constexpr std::uint8_t kMaxPrefix = 32;

    /**
     * @brief Mask an IPv4 address to its network prefix.
     * @param addr Host-byte-order IPv4 address
     * @param prefix Prefix length (0–32)
     * @return Network address with host bits cleared
     */
    static Address Normalize(const Address &addr, std::uint8_t prefix)
    {
        return ipv4::NormalizeNetwork(addr, prefix);
    }

    /**
     * @brief Test whether an address falls within a prefix.
     * @param addr Host-byte-order destination
     * @param network Network address (already normalized)
     * @param prefix Prefix length
     * @return true if addr matches network/prefix
     */
    static bool Matches(const Address &addr, const Address &network, std::uint8_t prefix)
    {
        return ipv4::IpMatchesNetwork(addr, network, prefix);
    }
};

/** @brief IPv6 address-family traits for RoutingTable. */
struct Ipv6RoutingTraits
{
    using Address = ipv6::Ipv6Address;
    static constexpr std::uint8_t kMaxPrefix = 128;

    /**
     * @brief Mask an IPv6 address to its network prefix.
     * @param addr 128-bit address
     * @param prefix Prefix length (0–128)
     * @return Network address with host bits cleared
     */
    static Address Normalize(const Address &addr, std::uint8_t prefix)
    {
        return ipv6::NormalizeNetwork(addr, prefix);
    }

    /**
     * @brief Test whether an address falls within a prefix.
     * @param addr Destination address
     * @param network Network address (already normalized)
     * @param prefix Prefix length
     * @return true if addr matches network/prefix
     */
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
    /**
     * @brief Hash an IPv6 address for unordered_map storage.
     * @param addr 128-bit address
     * @return Combined hash of both 64-bit halves
     */
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
    /** @brief Byte-wise equality for IPv6 addresses. */
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

/**
 * @brief Longest-prefix-match routing table.
 * @tparam Traits Address-family traits (Ipv4RoutingTraits or Ipv6RoutingTraits)
 */
template <typename Traits>
class RoutingTable
{
  public:
    using Address = typename Traits::Address;

    /** @brief A stored prefix route bound to a session. */
    struct Route
    {
        Address network;            ///< Network address (normalized)
        std::uint8_t prefix_length; ///< Prefix length
        std::uint64_t session_id;   ///< Owning session
    };

    /**
     * @brief Insert or replace a route.
     * @param network Network address (normalized by this call)
     * @param prefix_length Prefix length (must be <= Traits::kMaxPrefix)
     * @param session_id Session that owns this prefix
     * @return false if prefix_length is out of range
     */
    bool AddRoute(const Address &network, std::uint8_t prefix_length, std::uint64_t session_id)
    {
        if (prefix_length > Traits::kMaxPrefix)
            return false;

        auto normalized = Traits::Normalize(network, prefix_length);
        levels_[prefix_length][normalized] = session_id;
        return true;
    }

    /**
     * @brief Remove a specific prefix route.
     * @param network Network address (normalized by this call)
     * @param prefix_length Prefix length
     * @return true if a route was removed
     */
    bool RemoveRoute(const Address &network, std::uint8_t prefix_length)
    {
        if (prefix_length > Traits::kMaxPrefix)
            return false;

        auto normalized = Traits::Normalize(network, prefix_length);
        return levels_[prefix_length].erase(normalized) > 0;
    }

    /**
     * @brief Longest-prefix-match lookup for a destination.
     * @param dest Destination address
     * @return Session ID of the best matching route, or nullopt
     */
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

    /**
     * @brief List all routes owned by a session.
     * @param session_id Session to query
     * @return All matching Route entries
     */
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

    /**
     * @brief Remove every route owned by a session.
     * @param session_id Session whose routes should be dropped
     * @return Number of routes removed
     */
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

    /**
     * @brief Total number of stored routes across all prefix lengths.
     * @return Route count
     */
    std::size_t GetRouteCount() const
    {
        std::size_t total = 0;
        for (const auto &level : levels_)
            total += level.size();
        return total;
    }

    /** @brief Remove all routes from the table. */
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
