// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_DATA_V2_ENCRYPT_H
#define CLV_VPN_OPENVPN_DATA_V2_ENCRYPT_H

/**
 * @file data_v2_encrypt.h
 * @brief Shared in-place P_DATA_V2 AEAD encrypt (implementation header).
 */

#include "openvpn/data_v2_wire.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "util/byte_packer.h"

#include <HelpSslCipher.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace clv::vpn::openvpn {

/**
 * @brief Encrypt plaintext in-place into a pre-laid-out P_DATA_V2 buffer.
 *
 * Plaintext must already be at @p buf[kDataV2Overhead..].  Writes header,
 * packet ID, AEAD tag, and ciphertext.  Zero heap allocations.
 *
 * @return Total wire length (kDataV2Overhead + payload_len), or 0 on error.
 */
[[nodiscard]] inline std::size_t EncryptDataV2InPlace(
    std::span<std::uint8_t> buf,
    std::size_t payload_len,
    SessionId session_id,
    std::uint32_t packet_id,
    std::uint8_t key_id,
    std::span<const std::uint8_t> cipher_iv,
    OpenSSL::SslCipherCtx &encrypt_ctx)
{
    const std::size_t total_len = kDataV2Overhead + payload_len;
    if (buf.size() < total_len)
        return 0;

    const std::uint32_t peer_id = session_id.value & PEER_ID_MASK;
    const std::uint32_t opcode_peer_id = (MakeOpcodeByte(Opcode::P_DATA_V2, key_id) << 24) | peer_id;
    auto hdr_bytes = clv::netcore::uint_to_bytes(opcode_peer_id);
    std::memcpy(buf.data(), hdr_bytes.data(), kDataV2HeaderLen);

    auto pktid_bytes = clv::netcore::uint_to_bytes(packet_id);
    std::memcpy(buf.data() + kDataV2HeaderLen, pktid_bytes.data(), kDataV2PacketIdLen);

    auto nonce = GenerateLegacyDataV2Nonce(packet_id, cipher_iv);
    auto aad = buf.subspan(0, kDataV2HeaderLen + kDataV2PacketIdLen);

    auto plaintext_span = buf.subspan(kDataV2Overhead, payload_len);
    auto tag = encrypt_ctx.TryEncryptInPlace(nonce, plaintext_span, aad);
    if (!tag)
        return 0;

    std::memcpy(buf.data() + kDataV2HeaderLen + kDataV2PacketIdLen,
                tag->data(),
                kDataV2TagLen);

    return total_len;
}

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_DATA_V2_ENCRYPT_H
