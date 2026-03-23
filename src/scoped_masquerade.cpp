// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "scoped_masquerade.h"
#include "util/nftables_client.h"

#include <cstdint>
#include <netinet/in.h>
#include <optional>
#include <util/ipv4_utils.h>
#include <util/ipv6_utils.h>

#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

namespace clv::vpn {

std::optional<MasqueradeTarget> ParseMasqueradeCidr(const std::string &cidr)
{
    // Try IPv4 first — ParseCidr cleanly rejects IPv6 strings, while
    // ParseCidr6 may accept IPv4-mapped forms (::ffff:x.x.x.x).
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

ScopedMasquerade::ScopedMasquerade(const std::string &source_cidr, spdlog::logger &logger)
    : logger_(&logger),
      cidr_(source_cidr)
{
    auto target = ParseMasqueradeCidr(cidr_);
    if (!target)
    {
        throw std::invalid_argument("ScopedMasquerade: invalid CIDR notation: " + cidr_);
    }
    family_ = target->family;

    nft_.Open();

    if (nft_.TableExists(family_))
    {
        logger_->info("Masquerade table for {} already exists", cidr_);
        owns_ = false;
        return;
    }

    if (!nft_.EnsureMasquerade(family_, target->network.data(), target->prefix_len))
    {
        throw std::runtime_error("ScopedMasquerade: nftables transaction failed for " + cidr_);
    }

    owns_ = true;
    logger_->info("Added nftables masquerade for {} (will remove on shutdown)", cidr_);
}

ScopedMasquerade::~ScopedMasquerade() noexcept
{
    if (!owns_)
        return;

    try
    {
        if (nft_.RemoveMasquerade(family_))
        {
            logger_->info("Removed nftables masquerade for {}", cidr_);
        }
        else
        {
            logger_->warn("Failed to remove nftables masquerade for {}", cidr_);
        }
    }
    catch (...)
    {
    }
}

ScopedMasquerade::ScopedMasquerade(ScopedMasquerade &&other) noexcept
    : logger_(other.logger_),
      nft_(std::move(other.nft_)),
      cidr_(std::move(other.cidr_)),
      family_(other.family_),
      owns_(other.owns_)
{
    other.owns_ = false;
}

ScopedMasquerade &ScopedMasquerade::operator=(ScopedMasquerade &&other) noexcept
{
    if (this != &other)
    {
        if (owns_)
        {
            try
            {
                nft_.RemoveMasquerade(family_);
            }
            catch (...)
            {
            }
        }

        logger_ = other.logger_;
        nft_ = std::move(other.nft_);
        cidr_ = std::move(other.cidr_);
        family_ = other.family_;
        owns_ = other.owns_;
        other.owns_ = false;
    }
    return *this;
}

} // namespace clv::vpn
