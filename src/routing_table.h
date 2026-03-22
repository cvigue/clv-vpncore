// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_ROUTING_TABLE_H
#define CLV_VPN_ROUTING_TABLE_H

#include <util/ipv6_utils.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace clv::vpn {

/**
 * @brief Longest-prefix-match routing table for VPN traffic
 *
 * Maintains a mapping of IPv4 CIDR blocks to client session IDs.
 * Supports efficient longest-prefix-match lookups for routing decisions.
 */
class RoutingTableIpv4
{
  public:
    struct Route
    {
        uint32_t network;      // Network address (host-byte order)
        uint8_t prefix_length; // CIDR prefix length (0-32)
        uint64_t session_id;   // Associated session ID
    };

    /**
     * @brief Add a route to the routing table
     * @param network Network address
     * @param prefix_length Prefix length in bits (0-32)
     * @param session_id Session ID to route to
     * @return True if added, false if invalid parameters
     */
    bool AddRoute(uint32_t network, uint8_t prefix_length, uint64_t session_id);

    /**
     * @brief Remove a route from the table
     * @param network Network address
     * @param prefix_length Prefix length
     * @return True if removed, false if not found
     */
    bool RemoveRoute(uint32_t network, uint8_t prefix_length);

    /**
     * @brief Find the session ID for a destination IPv4 address
     * Performs longest-prefix-match lookup
     * @param dest_ipv4 Destination IPv4 address
     * @return Session ID or nullopt if no match
     */
    std::optional<uint64_t> Lookup(uint32_t dest_ipv4) const;

    /**
     * @brief Get all routes for a given session
     * @param session_id Session ID
     * @return Vector of routes belonging to this session
     */
    std::vector<Route> GetRoutesForSession(uint64_t session_id) const;

    /**
     * @brief Remove all routes for a session
     * @param session_id Session ID
     * @return Number of routes removed
     */
    size_t RemoveSessionRoutes(uint64_t session_id);

    /**
     * @brief Get the total number of routes
     */
    size_t GetRouteCount() const
    {
        return routes_.size();
    }

    /**
     * @brief Clear all routes
     */
    void Clear()
    {
        routes_.clear();
    }

  private:
    // Internal representation: key is (network, prefix_length) pair, sorted by prefix_length descending
    // This allows efficient longest-prefix-match iteration
    // Using map with custom comparator to sort by prefix length (longest first)
    struct RouteKey
    {
        uint32_t network;
        uint8_t prefix_length;

        bool operator<(const RouteKey &other) const
        {
            // Sort by prefix length descending (longer prefixes first)
            if (prefix_length != other.prefix_length)
                return prefix_length > other.prefix_length;
            // Then by network address for deterministic ordering
            return network < other.network;
        }
    };

    std::map<RouteKey, uint64_t> routes_; // Maps route to session ID
};

// ---------------------------------------------------------------------------
// RoutingTableIpv6 — longest-prefix-match routing for IPv6 tunnel traffic
// ---------------------------------------------------------------------------

/**
 * @brief Longest-prefix-match routing table for IPv6 VPN traffic
 *
 * Mirrors RoutingTableIpv4 but operates on 128-bit addresses stored as
 * std::array<uint8_t, 16> in network byte order.
 */
class RoutingTableIpv6
{
  public:
    using Ipv6Address = ipv6::Ipv6Address;

    struct Route
    {
        Ipv6Address network;   ///< Network address (network byte order)
        uint8_t prefix_length; ///< CIDR prefix length (0-128)
        uint64_t session_id;   ///< Associated session ID
    };

    /**
     * @brief Add an IPv6 route to the routing table
     * @param network Network address (network byte order)
     * @param prefix_length Prefix length in bits (0-128)
     * @param session_id Session ID to route to
     * @return True if added, false if invalid parameters
     */
    bool AddRoute(const Ipv6Address &network, uint8_t prefix_length, uint64_t session_id);

    /**
     * @brief Remove an IPv6 route from the table
     * @param network Network address (network byte order)
     * @param prefix_length Prefix length
     * @return True if removed, false if not found
     */
    bool RemoveRoute(const Ipv6Address &network, uint8_t prefix_length);

    /**
     * @brief Find the session ID for a destination IPv6 address
     * Performs longest-prefix-match lookup
     * @param dest_ipv6 Destination IPv6 address (network byte order)
     * @return Session ID or nullopt if no match
     */
    std::optional<uint64_t> Lookup(const Ipv6Address &dest_ipv6) const;

    /**
     * @brief Get all routes for a given session
     * @param session_id Session ID
     * @return Vector of routes belonging to this session
     */
    std::vector<Route> GetRoutesForSession(uint64_t session_id) const;

    /**
     * @brief Remove all routes for a session
     * @param session_id Session ID
     * @return Number of routes removed
     */
    size_t RemoveSessionRoutes(uint64_t session_id);

    /**
     * @brief Get the total number of routes
     */
    size_t GetRouteCount() const
    {
        return routes_.size();
    }

    /**
     * @brief Clear all routes
     */
    void Clear()
    {
        routes_.clear();
    }

  private:
    struct RouteKey
    {
        Ipv6Address network;
        uint8_t prefix_length;

        bool operator<(const RouteKey &other) const
        {
            // Sort by prefix length descending (longer prefixes first)
            if (prefix_length != other.prefix_length)
                return prefix_length > other.prefix_length;
            // Then by network address for deterministic ordering
            return network < other.network;
        }
    };

    std::map<RouteKey, uint64_t> routes_;
};

} // namespace clv::vpn

#endif // CLV_VPN_ROUTING_TABLE_H
