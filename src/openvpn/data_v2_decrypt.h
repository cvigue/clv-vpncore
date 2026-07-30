// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_DATA_V2_DECRYPT_H
#define CLV_VPN_OPENVPN_DATA_V2_DECRYPT_H

/**
 * @file data_v2_decrypt.h
 * @brief Shared in-place P_DATA_V2 AEAD decrypt helper.
 *
 * Selects primary/lame-duck decrypt slots by key_id, runs anti-replay, and
 * authenticates the legacy §7.4 header as AAD. Used by CryptoContext and
 * hot-path decrypt state.
 */

#include "HelpSslException.h"
#include "openvpn/aead_traits.h"
#include "openvpn/crypto_context.h"
#include "openvpn/data_v2_wire.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "util/byte_packer.h"

#include <HelpSslCipher.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <rate_limiter.h>

#include <span>
#include <spdlog/logger.h>

namespace clv::vpn::openvpn {

/**
 * @brief Primary and lame-duck decrypt key slots for key_id lookup.
 */
struct DataV2DecryptSlots
{
    DecryptKeySlot *primary = nullptr;   ///< Active decrypt key
    DecryptKeySlot *lame_duck = nullptr; ///< Previous key during rekey window
};

/**
 * @brief Optional logging / rate-limit hooks for DecryptDataV2InPlace.
 */
struct DataV2DecryptLog
{
    spdlog::logger *logger = nullptr;
    clv::RateLimiter<> *no_key_limiter = nullptr;
    clv::RateLimiter<> *too_old_limiter = nullptr;
    clv::RateLimiter<> *auth_fail_limiter = nullptr;
    std::uint64_t *replayed_packets = nullptr;
    const char *log_prefix = "DecryptDataV2";
    bool warn_on_duplicate_replay = true;
    bool log_packet_too_small = true;
    bool log_not_data_packet = true;
    bool log_unsupported_cipher = true;
};

/**
 * @brief Find the decrypt slot matching @p key_id.
 * @param slots Primary and lame-duck slots
 * @param key_id Key identifier from the packet header
 * @return Matching slot, or nullptr if none
 */
[[nodiscard]] inline DecryptKeySlot *FindDecryptSlotByKeyId(DataV2DecryptSlots slots, std::uint8_t key_id) noexcept
{
    if (slots.primary && slots.primary->key.is_valid && slots.primary->key.key_id == key_id)
        return slots.primary;
    if (slots.lame_duck && slots.lame_duck->key.is_valid && slots.lame_duck->key.key_id == key_id)
        return slots.lame_duck;
    return nullptr;
}

/**
 * @brief Decrypt a P_DATA_V2 AEAD frame in place.
 *
 * Validates opcode, selects the key slot, checks anti-replay, authenticates
 * the header as AAD, and writes plaintext over the ciphertext region.
 *
 * @param slots Primary / lame-duck decrypt slots
 * @param buf Mutable wire buffer (header + ciphertext + tag)
 * @param log Optional logging / counter hooks
 * @return Plaintext span within @p buf, or empty on failure
 */
[[nodiscard]] inline std::span<std::uint8_t> DecryptDataV2InPlace(DataV2DecryptSlots slots,
                                                                  std::span<std::uint8_t> buf,
                                                                  DataV2DecryptLog log)
{
    if (buf.size() < kDataV2Overhead)
    {
        if (log.log_packet_too_small && log.logger)
            log.logger->warn("{}: packet too small ({} bytes)", log.log_prefix, buf.size());
        return {};
    }

    const std::uint8_t opcode_byte = buf[0];
    const auto opcode = static_cast<Opcode>(opcode_byte >> OPCODE_SHIFT);
    const std::uint8_t pkt_key_id = opcode_byte & KEY_ID_MASK;

    if (!IsDataPacket(opcode))
    {
        if (log.log_not_data_packet && log.logger)
            log.logger->debug("{}: not a data packet (opcode={})", log.log_prefix, static_cast<int>(opcode));
        return {};
    }

    DecryptKeySlot *slot = FindDecryptSlotByKeyId(slots, pkt_key_id);
    if (!slot)
    {
        const auto now = std::chrono::steady_clock::now();
        if (log.no_key_limiter && log.no_key_limiter->Due(now) && log.logger)
        {
            log.logger->warn("{}: no key found for key_id {} (primary valid={}, primary key_id={})",
                             log.log_prefix,
                             pkt_key_id,
                             slots.primary ? slots.primary->key.is_valid : false,
                             slots.primary ? slots.primary->key.key_id : 0);
        }
        return {};
    }

    const EncryptionKey &key = slot->key;
    if (!IsSupportedAead(key.cipher_algorithm) || !slot->decrypt_ctx)
    {
        if (log.log_unsupported_cipher && log.logger)
            log.logger->error("{}: unsupported cipher or missing context (cipher={})",
                              log.log_prefix,
                              static_cast<int>(key.cipher_algorithm));
        return {};
    }

    const std::uint32_t pkt_id = clv::netcore::read_uint<4>(buf.subspan(4));

    const auto replay_check = slot->replay.Check(pkt_id);
    if (replay_check == ReplayWindow::CheckResult::TooOld)
    {
        const auto now = std::chrono::steady_clock::now();
        if (log.too_old_limiter && log.too_old_limiter->Due(now) && log.logger)
        {
            log.logger->warn("{}: packet_id {} too old (highest={})",
                             log.log_prefix,
                             pkt_id,
                             slot->replay.highest_id());
        }
        if (log.replayed_packets)
            ++(*log.replayed_packets);
        return {};
    }
    if (replay_check == ReplayWindow::CheckResult::Duplicate)
    {
        if (log.warn_on_duplicate_replay && log.logger)
            log.logger->warn("{}: replay detected (packet_id={})", log.log_prefix, pkt_id);
        if (log.replayed_packets)
            ++(*log.replayed_packets);
        return {};
    }

    const auto nonce = GenerateLegacyDataV2Nonce(pkt_id, key.cipher_iv);
    const auto aad = buf.subspan(0, kDataV2HeaderLen + kDataV2PacketIdLen);
    const std::span<const std::uint8_t, OpenSSL::AEAD_TAG_LENGTH> tag{
        buf.data() + kDataV2HeaderLen + kDataV2PacketIdLen, kDataV2TagLen};

    const std::size_t ct_len = buf.size() - kDataV2Overhead;
    const auto ct_span = buf.subspan(kDataV2Overhead, ct_len);

    auto decrypted = slot->decrypt_ctx->TryDecryptInPlace(nonce, ct_span, tag, aad);
    if (!decrypted)
    {
        if (log.logger)
        {
            const auto now = std::chrono::steady_clock::now();
            if (!log.auth_fail_limiter || log.auth_fail_limiter->Due(now))
            {
                const auto &err = decrypted.error();
                if (err.kind() == OpenSSL::SslErrorKind::AuthTag)
                {
                    log.logger->error(
                        "{}: authentication failed (tag mismatch) pkt_key_id={} key_id={} buf_size={}: {}",
                        log.log_prefix,
                        pkt_key_id,
                        key.key_id,
                        buf.size(),
                        err.message());
                }
                else
                {
                    log.logger->error("{}: AEAD decryption failed: {} pkt_key_id={} key_id={} buf_size={}",
                                      log.log_prefix,
                                      err.message(),
                                      pkt_key_id,
                                      key.key_id,
                                      buf.size());
                }
            }
        }
        return {};
    }

    slot->replay.Accept(pkt_id);
    return ct_span;
}

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_DATA_V2_DECRYPT_H
