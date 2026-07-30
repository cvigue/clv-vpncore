// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SCOPED_NFT_RULE_H
#define CLV_VPN_SCOPED_NFT_RULE_H

#include "nft_subnet_target.h"
#include "platform/linux/nftables/nftables_client.h"

#include <not_null.h>
#include <scoped_ownership.h>
#include <spdlog/logger.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

namespace clv::vpn {

/**
 * Contract for policies used with @ref ScopedNftRule.
 *
 * - @c Remove — fixed signature; called from the RAII base on teardown.
 * - @c Install — any static member named Install (arity is policy-specific);
 *   invoked by the concrete leaf ctor, not by ScopedNftRule itself.
 */
template <typename P>
concept NftRulePolicy = requires(NfTablesClient &nft,
                                 not_null<spdlog::logger *> logger,
                                 std::uint8_t family,
                                 const std::string &ifname,
                                 const std::string &log_context) {
    { P::Remove(nft, logger, family, ifname, log_context) } noexcept;
} && requires {
    &P::Install;
};

// ---------------------------------------------------------------------------
// Policy: MASQUERADE (per-ifname clv_vpn_nat[_6]_<if>)
// ---------------------------------------------------------------------------

struct MasqueradeNftPolicy
{
    static void Install(NfTablesClient &nft,
                        not_null<spdlog::logger *> logger,
                        bool &owns,
                        std::uint8_t &family,
                        const std::string &ifname,
                        const std::string &cidr)
    {
        if (ifname.empty())
            throw std::invalid_argument("ScopedMasquerade: ifname is required");

        auto target = ParseMasqueradeCidr(cidr);
        if (!target)
            throw std::invalid_argument("ScopedMasquerade: invalid CIDR notation: " + cidr);

        family = target->family;
        nft.Open();

        if (!nft.EnsureMasquerade(family, ifname.c_str(), target->network.data(), target->prefix_len))
            throw std::runtime_error("ScopedMasquerade: nftables transaction failed for " + cidr
                                     + " on " + ifname);

        owns = true;
        logger->info("Added nftables masquerade for {} on {} (will remove on shutdown)",
                     cidr,
                     ifname);
    }

    static void Remove(NfTablesClient &nft,
                       not_null<spdlog::logger *> logger,
                       std::uint8_t family,
                       const std::string &ifname,
                       const std::string &log_context) noexcept
    {
        try
        {
            if (nft.RemoveMasquerade(family, ifname.c_str()))
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
// Policy: intra-pool forward DROP (per-ifname clv_vpn_filter[_6]_<if>)
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

        if (!nft.EnsureIntraPoolDrop(family,
                                     ifname.c_str(),
                                     target->network.data(),
                                     target->prefix_len,
                                     target->bridge_ip.data()))
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
                       const std::string &ifname,
                       const std::string &log_context) noexcept
    {
        try
        {
            if (nft.RemoveIntraPoolDrop(family, ifname.c_str()))
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
 *
 * @tparam Policy  Must satisfy @ref NftRulePolicy.
 */
template <NftRulePolicy Policy>
class ScopedNftRule
{
  public:
    ScopedNftRule(const ScopedNftRule &) = delete;
    ScopedNftRule &operator=(const ScopedNftRule &) = delete;

    ~ScopedNftRule() noexcept
    {
        if (ownership_.owns())
            Policy::Remove(nft_, logger_, family_, ifname_, log_context_);
    }

    ScopedNftRule(ScopedNftRule &&other) noexcept
        : logger_(other.logger_),
          nft_(std::move(other.nft_)),
          ifname_(std::move(other.ifname_)),
          log_context_(std::move(other.log_context_)),
          family_(other.family_),
          ownership_(std::move(other.ownership_))
    {
    }

    ScopedNftRule &operator=(ScopedNftRule &&other) noexcept
    {
        if (this != &other)
        {
            if (ownership_.owns())
                Policy::Remove(nft_, logger_, family_, ifname_, log_context_);

            logger_ = other.logger_;
            nft_ = std::move(other.nft_);
            ifname_ = std::move(other.ifname_);
            log_context_ = std::move(other.log_context_);
            family_ = other.family_;
            ownership_ = std::move(other.ownership_);
        }
        return *this;
    }

  protected:
    not_null<spdlog::logger *> logger_;
    NfTablesClient nft_;
    std::string ifname_;
    std::string log_context_;
    std::uint8_t family_ = 0;
    clv::ScopedOwnership ownership_;

    ScopedNftRule(not_null<spdlog::logger *> logger, std::string ifname, std::string log_context)
        : logger_(logger),
          ifname_(std::move(ifname)),
          log_context_(std::move(log_context))
    {
    }
};

static_assert(NftRulePolicy<MasqueradeNftPolicy>);
static_assert(NftRulePolicy<IntraPoolDropNftPolicy>);

} // namespace clv::vpn

#endif // CLV_VPN_SCOPED_NFT_RULE_H
