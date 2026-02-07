// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SCOPED_IPV6_MASQUERADE_H
#define CLV_VPN_SCOPED_IPV6_MASQUERADE_H

#include <util/nftables_client.h>

#include <not_null.h>
#include <spdlog/logger.h>

#include <string>

namespace clv::vpn {

/**
 * @brief RAII guard that adds an nftables IPv6 MASQUERADE rule on construction
 *        and removes it on destruction.
 *
 * Creates a dedicated nftables table (@c clv_vpn_nat6) in the @c ip6 family
 * containing a @c postrouting chain with a rule equivalent to:
 * @code
 *   nft add rule ip6 clv_vpn_nat6 postrouting \
 *       ip6 saddr & <mask> == <network> \
 *       ip6 daddr & <mask> != <network> \
 *       masquerade
 * @endcode
 *
 * This NATs VPN client IPv6 traffic destined for external networks while
 * leaving client-to-client traffic untouched.  On destruction the entire
 * table is deleted, which removes all chains and rules atomically.
 *
 * Uses the kernel nf_tables netlink API directly — no shell commands.
 *
 * @note Requires root / CAP_NET_ADMIN.
 */
class ScopedIpv6Masquerade
{
  public:
    /**
     * @brief Add IPv6 masquerade rule via nftables netlink
     * @param source_cidr6 VPN IPv6 subnet in CIDR notation (e.g., "fd00::/112")
     * @param logger Logger for diagnostics
     * @throws std::invalid_argument if @p source_cidr6 is not valid IPv6 CIDR
     * @throws std::runtime_error if the netlink transaction fails
     */
    ScopedIpv6Masquerade(const std::string &source_cidr6, spdlog::logger &logger);

    /**
     * @brief Remove the masquerade table/rule
     */
    ~ScopedIpv6Masquerade() noexcept;

    // Non-copyable
    ScopedIpv6Masquerade(const ScopedIpv6Masquerade &) = delete;
    ScopedIpv6Masquerade &operator=(const ScopedIpv6Masquerade &) = delete;

    // Movable
    ScopedIpv6Masquerade(ScopedIpv6Masquerade &&other) noexcept;
    ScopedIpv6Masquerade &operator=(ScopedIpv6Masquerade &&other) noexcept;

  private:
    not_null<spdlog::logger *> logger_;
    NfTablesClient nft_;
    std::string source_cidr6_;
    bool owns_ = false; ///< Whether this instance owns the rule
};

} // namespace clv::vpn

#endif // CLV_VPN_SCOPED_IPV6_MASQUERADE_H
