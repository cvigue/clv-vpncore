// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_CRYPTO_LOG_H
#define CLV_VPN_OPENVPN_CRYPTO_LOG_H

/**
 * @file crypto_log.h
 * @brief Safe logging helpers for cryptographic material (fingerprints only).
 */

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace clv::vpn::openvpn {

/**
 * @brief One-way fingerprint for correlating key material in logs.
 *
 * Returns the first @p digest_prefix_bytes of SHA-256(@p material) as lowercase
 * hex.  Does not reveal key bytes.
 */
[[nodiscard]] std::string KeyMaterialFingerprint(
    std::span<const std::uint8_t> material,
    std::size_t digest_prefix_bytes = 4);

/**
 * @brief Fingerprint overload for vector key material.
 * @param material Key bytes
 * @param digest_prefix_bytes Hex prefix length of the digest to return
 * @return Short hex fingerprint (does not reveal key bytes)
 */
[[nodiscard]] inline std::string KeyMaterialFingerprint(
    const std::vector<std::uint8_t> &material,
    std::size_t digest_prefix_bytes = 4)
{
    return KeyMaterialFingerprint(std::span<const std::uint8_t>(material), digest_prefix_bytes);
}

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_CRYPTO_LOG_H
