// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_AEAD_UTILS_H
#define CLV_VPN_OPENVPN_AEAD_UTILS_H

#include "crypto_algorithms.h"
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace clv::vpn::openvpn {

/**
 * @brief Reorder AEAD tag from back to front
 *
 * Converts SslHelp format to OpenVPN P_DATA_V2 format:
 * - Input:  [ ciphertext ] [ TAG ]
 * - Output: [ TAG ] [ ciphertext ]
 *
 * @param data Data with tag at the end
 * @return Data with tag moved to front
 */
inline std::vector<std::uint8_t> ReorderTagToFront(std::span<const std::uint8_t> data)
{
    if (data.size() < AEAD_TAG_SIZE)
        return {}; // Invalid data

    const std::size_t ciphertext_len = data.size() - AEAD_TAG_SIZE;
    std::vector<std::uint8_t> reordered(data.size());

    // Copy tag to front
    std::memcpy(reordered.data(), data.data() + ciphertext_len, AEAD_TAG_SIZE);
    // Copy ciphertext after tag
    std::memcpy(reordered.data() + AEAD_TAG_SIZE, data.data(), ciphertext_len);

    return reordered;
}

/**
 * @brief Reorder AEAD tag from front to back
 *
 * Converts OpenVPN P_DATA_V2 format to SslHelp format:
 * - Input:  [ TAG ] [ ciphertext ]
 * - Output: [ ciphertext ] [ TAG ]
 *
 * @param data Data with tag at the front
 * @return Data with tag moved to back
 */
inline std::vector<std::uint8_t> ReorderTagToBack(std::span<const std::uint8_t> data)
{
    if (data.size() < AEAD_TAG_SIZE)
        return {}; // Invalid data

    const std::size_t ciphertext_len = data.size() - AEAD_TAG_SIZE;
    std::vector<std::uint8_t> reordered(data.size());

    // Copy ciphertext to front
    std::memcpy(reordered.data(), data.data() + AEAD_TAG_SIZE, ciphertext_len);
    // Copy tag to back
    std::memcpy(reordered.data() + ciphertext_len, data.data(), AEAD_TAG_SIZE);

    return reordered;
}

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_AEAD_UTILS_H
