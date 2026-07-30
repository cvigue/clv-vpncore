// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SCOPED_MASQUERADE_H
#define CLV_VPN_SCOPED_MASQUERADE_H

/**
 * @file scoped_masquerade.h
 * @brief RAII guard for tunnel NAT masquerade (product-facing).
 *
 * Owns @ref ScopedMasquerade; shared ScopedNftRule / policy machinery stays in
 * scoped_nft_rule.h. Tables are per hub ifname.
 */

#include "scoped_nft_rule.h"

#include <string>

namespace clv::vpn {

/**
 * @brief RAII nftables masquerade rule for a hub tunnel pool.
 */
class ScopedMasquerade : public ScopedNftRule<MasqueradeNftPolicy>
{
  public:
    /**
     * @brief Install masquerade for traffic sourced from @p source_cidr on @p ifname.
     * @param ifname Hub netdev name
     * @param source_cidr Tunnel pool CIDR to masquerade
     * @param logger Logger for nft installation events
     */
    ScopedMasquerade(const std::string &ifname,
                     const std::string &source_cidr,
                     spdlog::logger &logger)
        : ScopedNftRule<MasqueradeNftPolicy>(not_null{&logger}, ifname, source_cidr + " on " + ifname)
    {
        bool owns = ownership_.owns();
        MasqueradeNftPolicy::Install(nft_, logger_, owns, family_, ifname_, source_cidr);
        ownership_.set_owns(owns);
    }
};

} // namespace clv::vpn

#endif // CLV_VPN_SCOPED_MASQUERADE_H
