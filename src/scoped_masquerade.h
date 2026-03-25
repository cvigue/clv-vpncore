// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SCOPED_MASQUERADE_H
#define CLV_VPN_SCOPED_MASQUERADE_H

#include <util/nftables_client.h>

#include <not_null.h>
#include <spdlog/logger.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace clv::vpn {

/** Parsed CIDR for masquerade rule creation (exposed for unit testing) */
struct MasqueradeTarget
{
    std::uint8_t family;                  ///< NfTablesClient::kIPv4 or kIPv6
    std::array<std::uint8_t, 16> network; ///< Network address, network byte order
    std::uint8_t prefix_len;              ///< CIDR prefix length
};

/**
 * @brief Parse a CIDR string, auto-detecting IPv4 or IPv6.
 *
 * Detection order:
 *  1. Try @c ipv4::ParseCidr — succeeds for dotted-quad notation (e.g. "10.8.0.0/24").
 *  2. If that fails, try @c ipv6::ParseCidr6 — succeeds for any valid IPv6 CIDR
 *     (e.g. "fd00::/112", "::ffff:10.8.0.0/96").
 *
 * IPv4 is tried first because @c ParseCidr6 may accept IPv4-mapped forms
 * (e.g. "::ffff:10.8.0.0"), and we want plain dotted-quad to stay IPv4.
 *
 * @return Parsed target or @c std::nullopt if neither parser accepts the string.
 */
std::optional<MasqueradeTarget> ParseMasqueradeCidr(const std::string &cidr);

/**
 * @brief RAII guard that adds an nftables MASQUERADE rule on construction
 *        and removes it on destruction.
 *
 * Works for both IPv4 and IPv6 — the address family is auto-detected from
 * the CIDR string passed to the constructor.
 *
 * Creates a dedicated nftables table (@c clv_vpn_nat for IPv4,
 * @c clv_vpn_nat6 for IPv6) containing a @c postrouting chain with a rule
 * that masquerades traffic from the VPN subnet whose destination is NOT
 * the VPN subnet.
 *
 * On destruction the entire table is deleted, removing all chains and
 * rules atomically.
 *
 * Uses the kernel nf_tables netlink API directly — no shell commands.
 *
 * @note Requires root / CAP_NET_ADMIN.
 */
class ScopedMasquerade
{
  public:
    /**
     * @brief Add masquerade rule via nftables netlink
     * @param source_cidr VPN subnet in CIDR notation
     *        (e.g., "10.8.0.0/24" for IPv4 or "fd00::/112" for IPv6)
     * @param logger Logger for diagnostics
     * @throws std::invalid_argument if @p source_cidr is not valid IPv4 or IPv6 CIDR
     * @throws std::runtime_error if the netlink transaction fails
     */
    ScopedMasquerade(const std::string &source_cidr, spdlog::logger &logger);

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
    std::string cidr_;
    std::uint8_t family_ = 0;
    bool owns_ = false;
};

} // namespace clv::vpn

#endif // CLV_VPN_SCOPED_MASQUERADE_H
