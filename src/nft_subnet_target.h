// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_NFT_SUBNET_TARGET_H
#define CLV_VPN_NFT_SUBNET_TARGET_H

#include "platform/linux/nftables/nftables_client.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace clv::vpn {

/** Parsed nftables subnet (IPv4 or IPv6, network byte order). */
struct NftSubnetTarget
{
    std::uint8_t family = 0;
    std::array<std::uint8_t, 16> network{};
    std::uint8_t prefix_len = 0;
};

using MasqueradeTarget = NftSubnetTarget;

struct IntraPoolDropTarget : NftSubnetTarget
{
    std::array<std::uint8_t, 16> bridge_ip{};
};

/**
 * @brief Parse a CIDR string, auto-detecting IPv4 or IPv6.
 *
 * IPv4 is tried first because @c ParseCidr6 may accept IPv4-mapped forms.
 */
std::optional<MasqueradeTarget> ParseMasqueradeCidr(const std::string &cidr);

/** Pack @p host_ip into @p network for nft register comparison. */
std::optional<std::array<std::uint8_t, 16>>
ParseHostAddress(std::uint8_t family, const std::string &host_ip);

std::optional<IntraPoolDropTarget>
ParseIntraPoolDropTarget(const std::string &pool_cidr, const std::string &bridge_ip);

} // namespace clv::vpn

#endif // CLV_VPN_NFT_SUBNET_TARGET_H
