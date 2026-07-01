// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_DATA_V2_WIRE_H
#define CLV_VPN_OPENVPN_DATA_V2_WIRE_H

/**
 * @file data_v2_wire.h
 * @brief Legacy §7.4 P_DATA_V2 wire layout constants and nonce construction.
 *
 * Header-only, no OpenSSL dependency — safe to include from public headers.
 */

#include "openvpn/crypto_algorithms.h"

#include <util/byte_packer.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace clv::vpn::openvpn {

/** P_DATA_V2 header: [opcode/key_id (1)] [peer_id (3)] = 4 bytes */
constexpr std::size_t kDataV2HeaderLen = 4;

/** Packet ID field in P_DATA_V2 = 4 bytes */
constexpr std::size_t kDataV2PacketIdLen = 4;

/** AEAD authentication tag in P_DATA_V2 */
constexpr std::size_t kDataV2TagLen = AEAD_TAG_SIZE;

/** Total overhead before ciphertext: header + packet_id + tag = 24 bytes */
constexpr std::size_t kDataV2Overhead = kDataV2HeaderLen + kDataV2PacketIdLen + kDataV2TagLen;

/**
 * @brief Build legacy §7.4 AEAD nonce: packet_id (4 BE) || implicit_iv (8).
 */
[[nodiscard]] inline std::array<std::uint8_t, 12> GenerateLegacyDataV2Nonce(
    std::uint32_t packet_id,
    std::span<const std::uint8_t> cipher_iv) noexcept
{
    std::array<std::uint8_t, 12> nonce{};
    auto pktid_bytes = clv::netcore::uint_to_bytes(packet_id);
    std::memcpy(nonce.data(), pktid_bytes.data(), 4);
    if (cipher_iv.size() >= 8)
        std::memcpy(nonce.data() + 4, cipher_iv.data(), 8);
    return nonce;
}

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_DATA_V2_WIRE_H
