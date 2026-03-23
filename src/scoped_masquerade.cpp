// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "scoped_masquerade.h"

#include <util/ipv4_utils.h>

#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

namespace clv::vpn {

ScopedMasquerade::ScopedMasquerade(const std::string &source_cidr, spdlog::logger &logger)
    : logger_(&logger),
      source_cidr_(source_cidr)
{
    // Validate and parse CIDR
    auto parsed = ipv4::ParseCidr(source_cidr_);
    if (!parsed)
    {
        throw std::invalid_argument("ScopedMasquerade: invalid CIDR notation: " + source_cidr_);
    }
    network_ = parsed->first;
    prefix_len_ = parsed->second;

    // Open netlink socket to kernel nf_tables subsystem
    nft_.Open();

    // If our table already exists, someone else (or a previous run) created it.
    // Don't take ownership — we didn't create it.
    if (nft_.TableExists(NfTablesClient::kIPv4))
    {
        logger_->info("Masquerade table for {} already exists", source_cidr_);
        owns_ = false;
        return;
    }

    // Convert host-order uint32_t to network-order bytes for the unified API
    std::uint32_t net_order = htonl(network_);
    std::uint8_t addr[4];
    std::memcpy(addr, &net_order, 4);

    // Create table + chain + rule via netlink batch
    if (!nft_.EnsureMasquerade(NfTablesClient::kIPv4, addr, prefix_len_))
    {
        throw std::runtime_error("ScopedMasquerade: nftables transaction failed for " + source_cidr_);
    }

    owns_ = true;
    logger_->info("Added nftables masquerade for {} (will remove on shutdown)", source_cidr_);
}

ScopedMasquerade::~ScopedMasquerade() noexcept
{
    if (!owns_)
    {
        return;
    }

    try
    {
        if (nft_.RemoveMasquerade(NfTablesClient::kIPv4))
        {
            logger_->info("Removed nftables masquerade for {}", source_cidr_);
        }
        else
        {
            logger_->warn("Failed to remove nftables masquerade for {}", source_cidr_);
        }
    }
    catch (...)
    {
        // Destructor must not throw
    }
}

ScopedMasquerade::ScopedMasquerade(ScopedMasquerade &&other) noexcept
    : logger_(other.logger_),
      nft_(std::move(other.nft_)),
      source_cidr_(std::move(other.source_cidr_)),
      network_(other.network_),
      prefix_len_(other.prefix_len_),
      owns_(other.owns_)
{
    other.owns_ = false;
}

ScopedMasquerade &ScopedMasquerade::operator=(ScopedMasquerade &&other) noexcept
{
    if (this != &other)
    {
        // Remove our current rule if we own it
        if (owns_)
        {
            try
            {
                nft_.RemoveMasquerade(NfTablesClient::kIPv4);
            }
            catch (...)
            {
            }
        }

        logger_ = other.logger_;
        nft_ = std::move(other.nft_);
        source_cidr_ = std::move(other.source_cidr_);
        network_ = other.network_;
        prefix_len_ = other.prefix_len_;
        owns_ = other.owns_;
        other.owns_ = false;
    }
    return *this;
}

} // namespace clv::vpn
