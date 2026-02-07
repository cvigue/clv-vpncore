// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_IP_POOL_MANAGER_H
#define CLV_VPN_IP_POOL_MANAGER_H

#include "mutex_type.h"

#include <util/ipv6_utils.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace clv::vpn {

/**
 * @brief Manages IP address allocation from a pool
 *
 * Thread-safe IP address pool manager that:
 * - Allocates unique IPs to sessions from a network range
 * - Tracks assignments per session ID
 * - Reclaims IPs when sessions disconnect
 * - Supports CIDR notation (e.g., "10.8.0.0/24", "fd00::/112")
 * - Manages independent IPv4 and IPv6 address pools
 */
class IpPoolManager
{
  public:
    /**
     * @brief Initialize IP pool from CIDR network
     * @param network_cidr IPv4 network in CIDR notation (e.g., "10.8.0.0/24")
     * @param reserve_gateway If true, reserve .1 address for gateway
     * @param max_clients Maximum pool size (0 = use full CIDR range)
     * @throws std::invalid_argument if CIDR is invalid
     */
    explicit IpPoolManager(const std::string &network_cidr, bool reserve_gateway = true,
                           std::size_t max_clients = 0);

    /**
     * @brief Enable IPv6 pool from CIDR network
     *
     * May be called after construction to add an IPv6 address pool.
     * Typically uses a ULA prefix with a /112 or similar length.
     *
     * @param network_cidr6 IPv6 network in CIDR notation (e.g., "fd00::/112")
     * @param reserve_gateway If true, reserve ::1 address for gateway
     * @param max_clients Maximum pool size (0 = use full CIDR range)
     * @throws std::invalid_argument if CIDR is invalid
     */
    void EnableIpv6Pool(const std::string &network_cidr6, bool reserve_gateway = true,
                        std::size_t max_clients = 0);

    /**
     * @brief Allocate an IPv4 address for a session
     * @param session_id Session requesting an IPv4 address
     * @return Allocated IPv4 address, or nullopt if pool exhausted
     */
    std::optional<uint32_t> AllocateIpv4(uint64_t session_id);

    /**
     * @brief Release IPv4 address for a session
     * @param session_id Session releasing its IPv4 address
     * @return true if IPv4 was released, false if session had no IPv4
     */
    bool ReleaseIpv4(uint64_t session_id);

    /**
     * @brief Get IPv4 address assigned to a session
     * @param session_id Session to query
     * @return Assigned IPv4, or nullopt if none
     */
    std::optional<uint32_t> GetAssignedIpv4(uint64_t session_id) const;

    /**
     * @brief Check if an IPv4 address is currently allocated
     * @param ipv4 IPv4 address to check
     * @return true if IPv4 is allocated
     */
    bool IsIpv4Allocated(uint32_t ipv4) const;

    // ----- IPv6 pool methods -----

    using Ipv6Address = ipv6::Ipv6Address;

    /**
     * @brief Allocate an IPv6 address for a session
     * @param session_id Session requesting an IPv6 address
     * @return Allocated IPv6 address, or nullopt if pool exhausted or not enabled
     */
    std::optional<Ipv6Address> AllocateIpv6(uint64_t session_id);

    /**
     * @brief Release IPv6 address for a session
     * @param session_id Session releasing its IPv6 address
     * @return true if IPv6 was released, false if session had no IPv6
     */
    bool ReleaseIpv6(uint64_t session_id);

    /**
     * @brief Get IPv6 address assigned to a session
     * @param session_id Session to query
     * @return Assigned IPv6, or nullopt if none
     */
    std::optional<Ipv6Address> GetAssignedIpv6(uint64_t session_id) const;

    /**
     * @brief Check if an IPv6 address is currently allocated
     */
    bool IsIpv6Allocated(const Ipv6Address &ipv6) const;

    /**
     * @brief Check if the IPv6 pool is enabled
     */
    bool HasIpv6Pool() const;

    /**
     * @brief Get number of available IPv6 addresses
     */
    size_t Ipv6AvailableCount() const;

    /**
     * @brief Get number of available IPs in pool
     */
    size_t AvailableCount() const;

    /**
     * @brief Get number of allocated IPs
     */
    size_t AllocatedCount() const;

    /**
     * @brief Get total pool size
     */
    size_t TotalCount() const;

  private:
    /**
     * @brief Generate IPv4 addresses for the pool
     * @param network_cidr Network in CIDR notation (e.g., "10.8.0.0/24")
     * @param reserve_gateway If true, reserve .1 address for gateway
     * @param max_clients Maximum pool size (0 = use full CIDR range)
     * @return Number of IPs added to the pool
     */
    std::size_t PopulatePool(std::string network_cidr, bool reserve_gateway,
                             std::size_t max_clients);

    /**
     * @brief Generate IPv6 addresses for the v6 pool
     * @param network_cidr6 IPv6 CIDR (e.g., "fd00::/112")
     * @param reserve_gateway If true, reserve ::1 for gateway
     * @param max_clients Maximum pool size (0 = use full CIDR range)
     * @return Number of addresses added
     */
    std::size_t PopulateIpv6Pool(const std::string &network_cidr6, bool reserve_gateway,
                                 std::size_t max_clients);

    /// Protected data structure for thread-safe access
    struct PoolData
    {
        // ----- IPv4 -----
        std::vector<uint32_t> available_ipv4s;        // Free IPv4 address stack
        std::map<uint64_t, uint32_t> session_to_ipv4; // session_id -> IPv4
        std::map<uint32_t, uint64_t> ipv4_to_session; // IPv4 -> session_id

        // ----- IPv6 -----
        bool ipv6_enabled = false;
        std::vector<Ipv6Address> available_ipv6s; // Free IPv6 address stack
        std::map<uint64_t, Ipv6Address> session_to_ipv6;
        std::map<Ipv6Address, uint64_t> ipv6_to_session;
    };

    UniqueMutexType<PoolData> pool_data_;
    const size_t total_size_; // Total pool size (immutable after construction)
};

} // namespace clv::vpn

#endif // CLV_VPN_IP_POOL_MANAGER_H
