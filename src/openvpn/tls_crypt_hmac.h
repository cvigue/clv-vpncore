// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_TLS_CRYPT_HMAC_H
#define CLV_VPN_OPENVPN_TLS_CRYPT_HMAC_H

/**
 * @file tls_crypt_hmac.h
 * @brief Shared HMAC-SHA256 helper for tls-crypt v1 and v2 wire paths.
 */

#include <HelpSslHmac.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace clv::vpn::openvpn::detail {

constexpr std::size_t kTlsCryptHmacTagSize = 32; ///< HMAC-SHA256 tag length in bytes

/**
 * @brief Compute a fixed 32-byte HMAC-SHA256 tag for tls-crypt authentication.
 * @return Tag bytes, or empty vector if OpenSSL HMAC fails.
 */
inline std::vector<std::uint8_t> TlsCryptHmacSha256(std::span<const std::uint8_t> key,
                                                    std::span<const std::uint8_t> data)
{
    auto tag = clv::OpenSSL::TryHmacSha256(key, data);
    if (!tag)
        return {};
    return std::vector<std::uint8_t>(tag->begin(), tag->end());
}

} // namespace clv::vpn::openvpn::detail

#endif // CLV_VPN_OPENVPN_TLS_CRYPT_HMAC_H
