// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "scoped_ipv6_masquerade.h"

#include <util/ipv6_utils.h>

#include <stdexcept>
#include <string>
#include <utility>

namespace clv::vpn {

ScopedIpv6Masquerade::ScopedIpv6Masquerade(const std::string &source_cidr6, spdlog::logger &logger)
    : logger_(&logger),
      source_cidr6_(source_cidr6)
{
    // Validate and parse IPv6 CIDR
    auto parsed = ipv6::ParseCidr6(source_cidr6_);
    if (!parsed)
    {
        throw std::invalid_argument("ScopedIpv6Masquerade: invalid IPv6 CIDR notation: " + source_cidr6_);
    }
    const auto &[network, prefix_len] = *parsed;

    // Open netlink socket to kernel nf_tables subsystem
    nft_.Open();

    // If our table already exists, someone else (or a previous run) created it.
    // Don't take ownership — we didn't create it.
    if (nft_.Ipv6TableExists())
    {
        logger_->info("IPv6 masquerade table for {} already exists", source_cidr6_);
        owns_ = false;
        return;
    }

    // Create table + chain + rule via netlink batch
    if (!nft_.EnsureIpv6Masquerade(network.data(), prefix_len))
    {
        throw std::runtime_error("ScopedIpv6Masquerade: nftables transaction failed for " + source_cidr6_);
    }

    owns_ = true;
    logger_->info("Added nftables IPv6 masquerade for {} (will remove on shutdown)", source_cidr6_);
}

ScopedIpv6Masquerade::~ScopedIpv6Masquerade() noexcept
{
    if (!owns_)
    {
        return;
    }

    try
    {
        if (nft_.RemoveIpv6Masquerade())
        {
            logger_->info("Removed nftables IPv6 masquerade for {}", source_cidr6_);
        }
        else
        {
            logger_->warn("Failed to remove nftables IPv6 masquerade for {}", source_cidr6_);
        }
    }
    catch (...)
    {
        // Destructor must not throw
    }
}

ScopedIpv6Masquerade::ScopedIpv6Masquerade(ScopedIpv6Masquerade &&other) noexcept
    : logger_(other.logger_),
      nft_(std::move(other.nft_)),
      source_cidr6_(std::move(other.source_cidr6_)),
      owns_(other.owns_)
{
    other.owns_ = false;
}

ScopedIpv6Masquerade &ScopedIpv6Masquerade::operator=(ScopedIpv6Masquerade &&other) noexcept
{
    if (this != &other)
    {
        // Remove our current rule if we own it
        if (owns_)
        {
            try
            {
                nft_.RemoveIpv6Masquerade();
            }
            catch (...)
            {
            }
        }

        logger_ = other.logger_;
        nft_ = std::move(other.nft_);
        source_cidr6_ = std::move(other.source_cidr6_);
        owns_ = other.owns_;
        other.owns_ = false;
    }
    return *this;
}

} // namespace clv::vpn
