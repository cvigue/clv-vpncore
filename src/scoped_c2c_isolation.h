// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SCOPED_C2C_ISOLATION_H
#define CLV_VPN_SCOPED_C2C_ISOLATION_H

/**
 * @file scoped_c2c_isolation.h
 * @brief RAII guard for client-to-client isolation (product-facing).
 *
 * Owns @ref ScopedNftIntraPoolDrop (nft intra-pool DROP). Used when
 * HubAttachmentSpec::client_to_client is false. Shared ScopedNftRule /
 * policy machinery stays in scoped_nft_rule.h. Tables are per hub ifname.
 */

#include "not_null.h"
#include "scoped_nft_rule.h"

#include <string>

namespace clv::vpn {

/**
 * @brief RAII nftables intra-pool DROP rule (client-to-client isolation).
 */
class ScopedNftIntraPoolDrop : public ScopedNftRule<IntraPoolDropNftPolicy>
{
  public:
    /**
     * @brief Drop traffic between clients in the same tunnel pool.
     * @param ifname Hub netdev name
     * @param pool_cidr Tunnel pool CIDR
     * @param bridge_ip Server/gateway IP (exempt from drop)
     * @param logger Logger for nft installation events
     */
    ScopedNftIntraPoolDrop(const std::string &ifname,
                           const std::string &pool_cidr,
                           const std::string &bridge_ip,
                           spdlog::logger &logger)
        : ScopedNftRule<IntraPoolDropNftPolicy>(not_null{&logger},
                                                ifname,
                                                pool_cidr + " on " + ifname)
    {
        bool owns = ownership_.owns();
        IntraPoolDropNftPolicy::Install(nft_, logger_, owns, family_, ifname_, pool_cidr, bridge_ip);
        ownership_.set_owns(owns);
    }
};

} // namespace clv::vpn

#endif // CLV_VPN_SCOPED_C2C_ISOLATION_H
