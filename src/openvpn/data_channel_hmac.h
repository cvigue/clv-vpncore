// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_DATA_CHANNEL_HMAC_H
#define CLV_VPN_OPENVPN_DATA_CHANNEL_HMAC_H

/**
 * @file data_channel_hmac.h
 * @brief Free-function HMAC helpers for the data-channel packet authenticator.
 *
 * Extracted from DataChannel private methods so the logic can be unit-tested
 * independently without a friend declaration or a live DataChannel instance.
 */

#include "openvpn/crypto_algorithms.h"
#include "openvpn/data_channel.h"

#include <HelpSslException.h>
#include <HelpSslHmac.h>

#include <cstdint>
#include <span>
#include <vector>

namespace clv::vpn::openvpn::detail {

/**
 * @brief Compute the HMAC tag for a packet using the key's HMAC algorithm.
 *
 * @param key       Encryption key whose hmac_algorithm and hmac_key are used.
 * @param data      Packet bytes to authenticate.
 * @return Tag bytes, or empty vector if algorithm is NONE or computation fails.
 */
inline std::vector<std::uint8_t> ComputeHmac(const EncryptionKey &key,
                                             std::span<const std::uint8_t> data)
{
    if (key.hmac_algorithm == HmacAlgorithm::NONE)
        return {};

    try
    {
        switch (key.hmac_algorithm)
        {
        case HmacAlgorithm::SHA256:
            {
                auto tag = clv::OpenSSL::HmacSha256(key.hmac_key, data);
                return std::vector<std::uint8_t>(tag.begin(), tag.end());
            }
        case HmacAlgorithm::SHA512:
            {
                auto tag = clv::OpenSSL::HmacSha512(key.hmac_key, data);
                return std::vector<std::uint8_t>(tag.begin(), tag.end());
            }
        case HmacAlgorithm::NONE:
            return {};
        }
    }
    catch (const clv::OpenSSL::SslException &)
    {
        return {};
    }

    return {};
}

/**
 * @brief Verify a packet's HMAC tag using constant-time comparison.
 *
 * @param key           Encryption key whose hmac_algorithm and hmac_key are used.
 * @param data          Packet bytes that were authenticated.
 * @param expected_tag  Tag bytes from the packet to compare against.
 * @return true if the algorithm is NONE (no auth required) or if the
 *         recomputed tag matches @p expected_tag byte-for-byte in constant time.
 */
inline bool VerifyHmac(const EncryptionKey &key,
                       std::span<const std::uint8_t> data,
                       std::span<const std::uint8_t> expected_tag)
{
    if (key.hmac_algorithm == HmacAlgorithm::NONE)
        return true;

    auto computed = ComputeHmac(key, data);

    if (computed.size() != expected_tag.size())
        return false;

    return clv::OpenSSL::SslHmacCtx<>::ConstantTimeCompare(computed, expected_tag);
}

} // namespace clv::vpn::openvpn::detail

#endif // CLV_VPN_OPENVPN_DATA_CHANNEL_HMAC_H
