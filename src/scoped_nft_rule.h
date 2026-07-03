// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SCOPED_NFT_RULE_H
#define CLV_VPN_SCOPED_NFT_RULE_H

#include "nft_subnet_target.h"
#include "platform/linux/nftables/nftables_client.h"

#include <not_null.h>
#include <spdlog/logger.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

namespace clv::vpn {

// ---------------------------------------------------------------------------
// Policy: MASQUERADE (clv_vpn_nat / clv_vpn_nat6)
// ---------------------------------------------------------------------------

struct MasqueradeNftPolicy
{
    static void Install(NfTablesClient &nft,
                        not_null<spdlog::logger *> logger,
                        bool &owns,
                        std::uint8_t &family,
                        const std::string &cidr)
    {
        auto target = ParseMasqueradeCidr(cidr);
        if (!target)
            throw std::invalid_argument("ScopedMasquerade: invalid CIDR notation: " + cidr);

        family = target->family;
        nft.Open();

        if (nft.TableExists(family))
        {
            logger->info("Masquerade table for {} already exists", cidr);
            owns = false;
            return;
        }

        if (!nft.EnsureMasquerade(family, target->network.data(), target->prefix_len))
            throw std::runtime_error("ScopedMasquerade: nftables transaction failed for " + cidr);

        owns = true;
        logger->info("Added nftables masquerade for {} (will remove on shutdown)", cidr);
    }

    static void Remove(NfTablesClient &nft,
                       not_null<spdlog::logger *> logger,
                       std::uint8_t family,
                       const std::string &log_context) noexcept
    {
        try
        {
            if (nft.RemoveMasquerade(family))
                logger->info("Removed nftables masquerade for {}", log_context);
            else
                logger->warn("Failed to remove nftables masquerade for {}", log_context);
        }
        catch (...)
        {
        }
    }
};

// ---------------------------------------------------------------------------
// Policy: intra-pool forward DROP (clv_vpn_filter / clv_vpn_filter6)
// ---------------------------------------------------------------------------

struct IntraPoolDropNftPolicy
{
    static void Install(NfTablesClient &nft,
                        not_null<spdlog::logger *> logger,
                        bool &owns,
                        std::uint8_t &family,
                        const std::string &ifname,
                        const std::string &pool_cidr,
                        const std::string &bridge_ip)
    {
        if (ifname.empty())
            throw std::invalid_argument("ScopedNftIntraPoolDrop: ifname is required");

        auto target = ParseIntraPoolDropTarget(pool_cidr, bridge_ip);
        if (!target)
        {
            throw std::invalid_argument("ScopedNftIntraPoolDrop: invalid pool CIDR or bridge IP: "
                                        + pool_cidr + " / " + bridge_ip);
        }

        family = target->family;
        nft.Open();

        if (!nft.EnsureIntraPoolDrop(family, ifname.c_str(), target->network.data(),
                                     target->prefix_len, target->bridge_ip.data()))
        {
            throw std::runtime_error("ScopedNftIntraPoolDrop: nftables transaction failed for "
                                     + ifname + " " + pool_cidr);
        }

        owns = true;
        logger->info("Added nftables intra-pool drop on {} for {} (will remove on shutdown)",
                     ifname,
                     pool_cidr);
    }

    static void Remove(NfTablesClient &nft,
                       not_null<spdlog::logger *> logger,
                       std::uint8_t family,
                       const std::string &log_context) noexcept
    {
        try
        {
            if (nft.RemoveIntraPoolDrop(family))
                logger->info("Removed nftables intra-pool drop for {}", log_context);
            else
                logger->warn("Failed to remove nftables intra-pool drop for {}", log_context);
        }
        catch (...)
        {
        }
    }
};

// ---------------------------------------------------------------------------
// ScopedNftRule<Policy>
// ---------------------------------------------------------------------------

/**
 * @brief RAII guard for nftables rules installed via @p Policy.
 */
template <typename Policy>
class ScopedNftRule
{
  public:
    ScopedNftRule(const ScopedNftRule &) = delete;
    ScopedNftRule &operator=(const ScopedNftRule &) = delete;

    ~ScopedNftRule() noexcept
    {
        if (owns_)
            Policy::Remove(nft_, logger_, family_, log_context_);
    }

    ScopedNftRule(ScopedNftRule &&other) noexcept
        : logger_(other.logger_),
          nft_(std::move(other.nft_)),
          log_context_(std::move(other.log_context_)),
          family_(other.family_),
          owns_(other.owns_)
    {
        other.owns_ = false;
    }

    ScopedNftRule &operator=(ScopedNftRule &&other) noexcept
    {
        if (this != &other)
        {
            if (owns_)
                Policy::Remove(nft_, logger_, family_, log_context_);

            logger_ = other.logger_;
            nft_ = std::move(other.nft_);
            log_context_ = std::move(other.log_context_);
            family_ = other.family_;
            owns_ = other.owns_;
            other.owns_ = false;
        }
        return *this;
    }

  protected:
    not_null<spdlog::logger *> logger_;
    NfTablesClient nft_;
    std::string log_context_;
    std::uint8_t family_ = 0;
    bool owns_ = false;

    ScopedNftRule(not_null<spdlog::logger *> logger, std::string log_context)
        : logger_(logger),
          log_context_(std::move(log_context))
    {
    }
};

class ScopedMasquerade : public ScopedNftRule<MasqueradeNftPolicy>
{
  public:
    ScopedMasquerade(const std::string &source_cidr, spdlog::logger &logger)
        : ScopedNftRule<MasqueradeNftPolicy>(not_null{&logger}, source_cidr)
    {
        MasqueradeNftPolicy::Install(nft_, logger_, owns_, family_, source_cidr);
    }
};

class ScopedNftIntraPoolDrop : public ScopedNftRule<IntraPoolDropNftPolicy>
{
  public:
    ScopedNftIntraPoolDrop(const std::string &ifname,
                           const std::string &pool_cidr,
                           const std::string &bridge_ip,
                           spdlog::logger &logger)
        : ScopedNftRule<IntraPoolDropNftPolicy>(not_null{&logger}, pool_cidr + " on " + ifname)
    {
        IntraPoolDropNftPolicy::Install(nft_, logger_, owns_, family_, ifname, pool_cidr, bridge_ip);
    }
};

} // namespace clv::vpn

#endif // CLV_VPN_SCOPED_NFT_RULE_H
