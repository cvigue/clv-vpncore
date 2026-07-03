// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_AEAD_TRAITS_H
#define CLV_VPN_OPENVPN_AEAD_TRAITS_H

#include "openvpn/crypto_algorithms.h"

#include <HelpSslCipher.h>

namespace clv::vpn::openvpn {

/** Map a @c CipherAlgorithm to its OpenSSL AEAD traits, or @c nullptr if unsupported. */
[[nodiscard]] inline const OpenSSL::AeadCipherTraits *GetAeadTraits(CipherAlgorithm algo) noexcept
{
    switch (algo)
    {
    case CipherAlgorithm::AES_128_GCM:
        return &OpenSSL::AES_128_GCM_TRAITS;
    case CipherAlgorithm::AES_256_GCM:
        return &OpenSSL::AES_256_GCM_TRAITS;
    case CipherAlgorithm::CHACHA20_POLY1305:
        return &OpenSSL::CHACHA20_POLY1305_TRAITS;
    default:
        return nullptr;
    }
}

[[nodiscard]] inline bool IsSupportedAead(CipherAlgorithm algo) noexcept
{
    return GetAeadTraits(algo) != nullptr;
}

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_AEAD_TRAITS_H
