// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include "ip_pool_manager.h"

#include <cstddef>
#include <util/ipv4_utils.h>
#include <util/ipv6_utils.h>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace clv::vpn {

// Lambda to calculate total size during initialization, allowing const total_size_
IpPoolManager::IpPoolManager(const std::string &network_cidr, bool reserve_gateway,
                             std::size_t max_clients)
    : total_size_(PopulatePool(network_cidr, reserve_gateway, max_clients))
{
}

std::optional<uint32_t> IpPoolManager::AllocateIpv4(uint64_t session_id)
{
    auto pool = pool_data_.Lock();

    // Check if session already has an IPv4
    if (auto it = pool->session_to_ipv4.find(session_id); it != pool->session_to_ipv4.end())
        return it->second;

    // Allocate a new IPv4
    if (pool->available_ipv4s.empty())
        return std::nullopt;

    uint32_t ipv4 = pool->available_ipv4s.back();
    pool->available_ipv4s.pop_back();

    pool->session_to_ipv4[session_id] = ipv4;
    pool->ipv4_to_session[ipv4] = session_id;

    return ipv4;
}

bool IpPoolManager::ReleaseIpv4(uint64_t session_id)
{
    auto pool = pool_data_.Lock();

    if (auto it = pool->session_to_ipv4.find(session_id); it != pool->session_to_ipv4.end())
    {
        uint32_t ipv4 = it->second;
        pool->session_to_ipv4.erase(it);
        pool->ipv4_to_session.erase(ipv4);
        pool->available_ipv4s.push_back(ipv4);
        return true;
    }
    return false;
}

std::optional<uint32_t> IpPoolManager::GetAssignedIpv4(uint64_t session_id) const
{
    auto pool = pool_data_.Lock();

    auto it = pool->session_to_ipv4.find(session_id);
    if (it == pool->session_to_ipv4.end())
        return std::nullopt;

    return it->second;
}

bool IpPoolManager::IsIpv4Allocated(uint32_t ipv4) const
{
    auto pool = pool_data_.Lock();
    return pool->ipv4_to_session.find(ipv4) != pool->ipv4_to_session.end();
}

size_t IpPoolManager::AvailableCount() const
{
    auto pool = pool_data_.Lock();
    return pool->available_ipv4s.size();
}

size_t IpPoolManager::AllocatedCount() const
{
    auto pool = pool_data_.Lock();
    return pool->session_to_ipv4.size();
}

size_t IpPoolManager::TotalCount() const
{
    return total_size_;
}

std::size_t IpPoolManager::PopulatePool(std::string network_cidr, bool reserve_gateway,
                                        std::size_t max_clients)
{
    auto parsed = ipv4::ParseCidr(network_cidr);
    if (!parsed)
        throw std::invalid_argument("Invalid CIDR notation: " + network_cidr);

    auto [network_addr, prefix_length] = *parsed;

    if (prefix_length >= 32)
        throw std::invalid_argument("Prefix length must be less than 32");

    // Normalize network address to mask off host bits
    network_addr = ipv4::NormalizeNetwork(network_addr, prefix_length);

    // Calculate number of usable hosts
    uint32_t num_hosts = ipv4::CalculateUsableHosts(prefix_length);
    if (num_hosts == 0)
        throw std::invalid_argument("Network too small for host allocation");

    // Add usable host addresses
    uint32_t host_bits = 32 - prefix_length;
    uint32_t start = network_addr + 1; // Skip network address
    if (reserve_gateway)
        start++; // Skip .1 for gateway

    uint32_t end = network_addr + (1u << host_bits) - 1; // Exclude broadcast

    // Cap at max_clients if set
    if (max_clients > 0)
    {
        uint32_t range = end - start;
        if (range > static_cast<uint32_t>(max_clients))
            end = start + static_cast<uint32_t>(max_clients);
    }

    auto pool = pool_data_.Lock();
    for (uint32_t ip = start; ip < end; ++ip)
    {
        pool->available_ipv4s.push_back(ip);
    }

    return pool->available_ipv4s.size();
}

// ---------------------------------------------------------------------------
// IPv6 pool
// ---------------------------------------------------------------------------

void IpPoolManager::EnableIpv6Pool(const std::string &network_cidr6, bool reserve_gateway,
                                   std::size_t max_clients)
{
    auto count = PopulateIpv6Pool(network_cidr6, reserve_gateway, max_clients);
    if (count == 0)
        throw std::invalid_argument("IPv6 pool produced zero addresses: " + network_cidr6);
}

std::size_t IpPoolManager::PopulateIpv6Pool(const std::string &network_cidr6, bool reserve_gateway,
                                            std::size_t max_clients)
{
    auto parsed = ipv6::ParseCidr6(network_cidr6);
    if (!parsed)
        throw std::invalid_argument("Invalid IPv6 CIDR notation: " + network_cidr6);

    auto [network, prefix_length] = *parsed;

    if (prefix_length >= 128)
        throw std::invalid_argument("IPv6 prefix length must be < 128");

    // For safety, limit pool to /112 (65534 addresses) or wider.
    // Narrower prefixes would produce enormous pools.
    if (prefix_length < 112)
        throw std::invalid_argument("IPv6 prefix must be /112 or narrower for pool allocation");

    auto normalized = ipv6::NormalizeNetwork(network, prefix_length);

    uint32_t host_bits = 128 - prefix_length;
    uint32_t num_addrs = (1u << host_bits) - 2; // exclude network and all-ones
    if (num_addrs == 0)
        throw std::invalid_argument("IPv6 network too small for host allocation");

    auto pool = pool_data_.Lock();
    pool->ipv6_enabled = true;

    // Iterate host IDs from 1 (or 2 if reserving gateway) to (2^host_bits - 2)
    uint32_t start_host = reserve_gateway ? 2 : 1;
    uint32_t end_host = (1u << host_bits) - 1; // exclusive (skip all-ones)

    // Cap at max_clients if set
    if (max_clients > 0)
    {
        uint32_t range = end_host - start_host;
        if (range > static_cast<uint32_t>(max_clients))
            end_host = start_host + static_cast<uint32_t>(max_clients);
    }

    for (uint32_t h = start_host; h < end_host; ++h)
    {
        Ipv6Address addr = normalized;
        // Set the host bits (from the least significant bytes)
        // host_bits <= 16 since prefix >= 112
        addr[15] = static_cast<uint8_t>(h & 0xFF);
        if (host_bits > 8)
            addr[14] = static_cast<uint8_t>((h >> 8) & 0xFF);

        pool->available_ipv6s.push_back(addr);
    }

    return pool->available_ipv6s.size();
}

std::optional<IpPoolManager::Ipv6Address> IpPoolManager::AllocateIpv6(uint64_t session_id)
{
    auto pool = pool_data_.Lock();

    if (!pool->ipv6_enabled)
        return std::nullopt;

    // Check if session already has an IPv6
    if (auto it = pool->session_to_ipv6.find(session_id); it != pool->session_to_ipv6.end())
        return it->second;

    if (pool->available_ipv6s.empty())
        return std::nullopt;

    Ipv6Address ipv6 = pool->available_ipv6s.back();
    pool->available_ipv6s.pop_back();

    pool->session_to_ipv6[session_id] = ipv6;
    pool->ipv6_to_session[ipv6] = session_id;

    return ipv6;
}

bool IpPoolManager::ReleaseIpv6(uint64_t session_id)
{
    auto pool = pool_data_.Lock();

    if (auto it = pool->session_to_ipv6.find(session_id); it != pool->session_to_ipv6.end())
    {
        Ipv6Address ipv6 = it->second;
        pool->session_to_ipv6.erase(it);
        pool->ipv6_to_session.erase(ipv6);
        pool->available_ipv6s.push_back(ipv6);
        return true;
    }
    return false;
}

std::optional<IpPoolManager::Ipv6Address> IpPoolManager::GetAssignedIpv6(uint64_t session_id) const
{
    auto pool = pool_data_.Lock();
    auto it = pool->session_to_ipv6.find(session_id);
    if (it == pool->session_to_ipv6.end())
        return std::nullopt;
    return it->second;
}

bool IpPoolManager::IsIpv6Allocated(const Ipv6Address &ipv6) const
{
    auto pool = pool_data_.Lock();
    return pool->ipv6_to_session.find(ipv6) != pool->ipv6_to_session.end();
}

bool IpPoolManager::HasIpv6Pool() const
{
    auto pool = pool_data_.Lock();
    return pool->ipv6_enabled;
}

size_t IpPoolManager::Ipv6AvailableCount() const
{
    auto pool = pool_data_.Lock();
    return pool->available_ipv6s.size();
}

} // namespace clv::vpn
