// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SCOPED_MASQUERADE_H
#define CLV_VPN_SCOPED_MASQUERADE_H

#include <util/nftables_client.h>

#include <not_null.h>
#include <spdlog/logger.h>

#include <cstdint>
#include <string>

namespace clv::vpn {

/**
 * @brief RAII guard that adds an nftables MASQUERADE rule on construction
 *        and removes it on destruction.
 *
 * Creates a dedicated nftables table (@c clv_vpn_nat) containing a
 * @c postrouting chain with a rule equivalent to:
 * @code
 *   nft add rule ip clv_vpn_nat postrouting \
 *       ip saddr & <mask> == <network> \
 *       ip daddr & <mask> != <network> \
 *       masquerade
 * @endcode
 *
 * This NATs VPN client traffic destined for external networks while leaving
 * client-to-client traffic untouched.  On destruction the entire table is
 * deleted, which removes all chains and rules atomically.
 *
 * Uses the kernel nf_tables netlink API directly — no shell commands.
 *
 * @note Requires root / CAP_NET_ADMIN.
 *
 * @par Testing
 * This class communicates with the kernel netfilter subsystem and is not
 * unit-testable in isolation without root privileges. It is exercised via
 * integration tests (e.g., vpn_server_integration_tests) that run the full
 * server lifecycle as root.
 */
class ScopedMasquerade
{
  public:
    /**
     * @brief Add masquerade rule via nftables netlink
     * @param source_cidr VPN subnet in CIDR notation (e.g., "10.8.0.0/24")
     * @param logger Logger for diagnostics
     * @throws std::invalid_argument if @p source_cidr is not valid CIDR
     * @throws std::runtime_error if the netlink transaction fails
     */
    ScopedMasquerade(const std::string &source_cidr, spdlog::logger &logger);

    /**
     * @brief Remove the masquerade table/rule
     */
    ~ScopedMasquerade() noexcept;

    // Non-copyable
    ScopedMasquerade(const ScopedMasquerade &) = delete;
    ScopedMasquerade &operator=(const ScopedMasquerade &) = delete;

    // Movable
    ScopedMasquerade(ScopedMasquerade &&other) noexcept;
    ScopedMasquerade &operator=(ScopedMasquerade &&other) noexcept;

  private:
    not_null<spdlog::logger *> logger_;
    NfTablesClient nft_;
    std::string source_cidr_;
    std::uint32_t network_ = 0; ///< Parsed network address (host order)
    std::uint8_t prefix_len_ = 0;
    bool owns_ = false; ///< Whether this instance owns the rule
};

} // namespace clv::vpn

#endif // CLV_VPN_SCOPED_MASQUERADE_H
