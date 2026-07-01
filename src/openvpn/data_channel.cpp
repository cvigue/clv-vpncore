// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/data_channel.h"
#include "openvpn/data_channel_hmac.h"

#include "openvpn/aead_utils.h"
#include "openvpn/crypto_log.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/data_channel_limits.h"
#include "openvpn/data_v2_encrypt.h"
#include "openvpn/data_v2_wire.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"

#include <HelpSslCipher.h>
#include <HelpSslException.h>
#include <HelpSslHmac.h>
#include <atomic>
#include <log_utils.h>
#include <util/byte_packer.h>

#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace clv::vpn::openvpn {

// ============================================================================
// AEAD Cipher Dispatch (runtime algorithm selection)
// ============================================================================

/**
 * @brief Map a CipherAlgorithm to its OpenSSL AEAD traits
 * @return Pointer to traits, or nullptr for unsupported ciphers
 */
static const OpenSSL::AeadCipherTraits *GetAeadTraits(CipherAlgorithm algo)
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

static std::vector<std::uint8_t> EncryptAeadDispatch(CipherAlgorithm algo,
                                                     std::span<const std::uint8_t> key,
                                                     std::span<const std::uint8_t> nonce,
                                                     std::span<const std::uint8_t> plaintext,
                                                     std::span<const std::uint8_t> aad)
{
    const auto *traits = GetAeadTraits(algo);
    if (!traits)
        return {};
    return OpenSSL::EncryptAead(*traits, key, nonce, plaintext, aad);
}

static std::vector<std::uint8_t> DecryptAeadDispatch(CipherAlgorithm algo,
                                                     std::span<const std::uint8_t> key,
                                                     std::span<const std::uint8_t> nonce,
                                                     std::span<const std::uint8_t> ciphertext_with_tag,
                                                     std::span<const std::uint8_t> aad)
{
    const auto *traits = GetAeadTraits(algo);
    if (!traits)
        return {};
    return OpenSSL::DecryptAead(*traits, key, nonce, ciphertext_with_tag, aad);
}

// ============================================================================
// In-place AEAD Cipher Dispatch (zero-copy, runtime algorithm selection)
// ============================================================================

static std::array<std::uint8_t, OpenSSL::AEAD_TAG_LENGTH>
EncryptAeadInPlaceDispatch(CipherAlgorithm algo,
                           std::span<const std::uint8_t> key,
                           std::span<const std::uint8_t> nonce,
                           std::span<std::uint8_t> data,
                           std::span<const std::uint8_t> aad)
{
    const auto *traits = GetAeadTraits(algo);
    if (!traits)
        return {};
    return OpenSSL::EncryptAeadInPlace(*traits, key, nonce, data, aad);
}

static bool DecryptAeadInPlaceDispatch(CipherAlgorithm algo,
                                       std::span<const std::uint8_t> key,
                                       std::span<const std::uint8_t> nonce,
                                       std::span<std::uint8_t> data,
                                       std::span<const std::uint8_t, OpenSSL::AEAD_TAG_LENGTH> tag,
                                       std::span<const std::uint8_t> aad)
{
    const auto *traits = GetAeadTraits(algo);
    if (!traits)
        return false;
    return OpenSSL::DecryptAeadInPlace(*traits, key, nonce, data, tag, aad);
}

static bool IsSupportedAead(CipherAlgorithm algo)
{
    return GetAeadTraits(algo) != nullptr;
}

// ============================================================================
// Persistent AEAD Context Initialization
// ============================================================================

/**
 * @brief Initialize a persistent AEAD cipher context with the given algorithm and key
 * @details Dispatches to the correct cipher traits at initialization time.  After this
 *          call only per-packet nonce updates are needed (SetEncryptNonce / SetDecryptNonce).
 *          The OpenSSL key schedule is cached, eliminating ~250-400 ns of per-packet overhead.
 */
static void InitPersistentAeadCtx(OpenSSL::SslCipherCtx &ctx,
                                  CipherAlgorithm algo,
                                  std::span<const std::uint8_t> key,
                                  bool encrypt)
{
    const auto *traits = GetAeadTraits(algo);
    if (!traits)
        throw std::invalid_argument("Unsupported AEAD cipher for persistent context");

    if (encrypt)
        ctx.InitAeadEncrypt(*traits);
    else
        ctx.InitAeadDecrypt(*traits);

    // Set key with a dummy nonce.  The key schedule is computed and cached by OpenSSL.
    // Per-packet operations only update the nonce via SetEncryptNonce / SetDecryptNonce.
    std::array<std::uint8_t, OpenSSL::AEAD_DEFAULT_NONCE_LENGTH> dummyNonce{};
    if (encrypt)
        ctx.SetEncryptKeyAndNonce(key, dummyNonce);
    else
        ctx.SetDecryptKeyAndNonce(key, dummyNonce);
}

// ============================================================================
// Outbound limits (legacy §7.4 / §7.2.1 Phase A)
// ============================================================================

std::optional<std::uint32_t> DataChannel::AllocateOutboundPacketId() noexcept
{
    if (outbound_encrypt_blocked_.load(std::memory_order_acquire))
        return std::nullopt;

    std::uint32_t id = outbound_packet_id_.load(std::memory_order_relaxed);
    while (true)
    {
        if (id >= kPacketIdWrapTrigger)
        {
            rekey_requested_.store(true, std::memory_order_release);
            outbound_encrypt_blocked_.store(true, std::memory_order_release);
            return std::nullopt;
        }
        if (outbound_packet_id_.compare_exchange_weak(
                id, id + 1, std::memory_order_acq_rel, std::memory_order_relaxed))
        {
            return id;
        }
    }
}

void DataChannel::RecordOutboundEncrypt(std::size_t plaintext_len,
                                        CipherAlgorithm cipher) noexcept
{
    if (!IsLegacyAeadUsageLimited(cipher))
        return;

    const auto delta = LegacyAeadUsageForEncrypt(plaintext_len);
    aead_usage_invocations_.fetch_add(delta.invocations, std::memory_order_relaxed);
    aead_usage_blocks_.fetch_add(delta.blocks, std::memory_order_relaxed);

    const auto flags = LegacyAeadLimitFlagsForUsage(
        aead_usage_invocations_.load(std::memory_order_relaxed),
        aead_usage_blocks_.load(std::memory_order_relaxed));
    if (flags.is_blocked)
    {
        outbound_encrypt_blocked_.store(true, std::memory_order_release);
        rekey_requested_.store(true, std::memory_order_release);
    }
    else if (flags.needs_reneg)
    {
        rekey_requested_.store(true, std::memory_order_release);
    }
}

bool DataChannel::TakeRekeyRequest() noexcept
{
    return rekey_requested_.exchange(false, std::memory_order_acq_rel);
}

bool DataChannel::IsOutboundEncryptBlocked() const noexcept
{
    return outbound_encrypt_blocked_.load(std::memory_order_acquire);
}

// ============================================================================
// DataChannel Implementation
// ============================================================================

std::vector<std::uint8_t> DataChannel::EncryptPacket(std::span<const std::uint8_t> plaintext,
                                                     SessionId session_id)
{
    if (!primary_encrypt_.is_valid || IsOutboundEncryptBlocked())
        return {};

    auto packet_id = AllocateOutboundPacketId();
    if (!packet_id)
        return {};

    return EncryptPacketWithId(plaintext, session_id, *packet_id);
}

std::vector<std::uint8_t> DataChannel::EncryptPacketWithId(std::span<const std::uint8_t> plaintext,
                                                           SessionId session_id,
                                                           std::uint32_t packet_id)
{
    if (!primary_encrypt_.is_valid || IsOutboundEncryptBlocked())
        return {};

    const auto &key = primary_encrypt_;

    std::uint32_t peer_id = session_id.value & PEER_ID_MASK;
    OpenVpnPacket encrypted_packet = OpenVpnPacket::DataV2(current_key_id_, peer_id, packet_id);

    if (!IsSupportedAead(key.cipher_algorithm))
    {
        spdlog::error("EncryptPacketWithId: unsupported cipher algorithm {}", static_cast<int>(key.cipher_algorithm));
        return {};
    }

    auto nonce = GenerateNonce(packet_id, key);

    try
    {
        if (encrypt_ctx_)
        {
            std::vector<std::uint8_t> ct(plaintext.begin(), plaintext.end());
            encrypt_ctx_->SetEncryptNonce(nonce);
            encrypt_ctx_->UpdateEncryptAad(encrypted_packet.aad_);
            encrypt_ctx_->UpdateEncryptInPlace(std::span<std::uint8_t>(ct));
            auto tag = encrypt_ctx_->FinalizeEncryptTag();
            std::vector<std::uint8_t> payload;
            payload.reserve(tag.size() + ct.size());
            payload.insert(payload.end(), tag.begin(), tag.end());
            payload.insert(payload.end(), ct.begin(), ct.end());
            encrypted_packet.payload_ = std::move(payload);
        }
        else
        {
            auto encrypted = EncryptAeadDispatch(
                key.cipher_algorithm,
                std::span<const std::uint8_t>(key.cipher_key.data(), key.cipher_key.size()),
                nonce,
                plaintext,
                encrypted_packet.aad_);
            if (encrypted.empty())
            {
                spdlog::error("EncryptPacketWithId: encryption returned empty result");
                return {};
            }
            encrypted_packet.payload_ = ReorderTagToFront(encrypted);
        }
    }
    catch (const OpenSSL::SslException &e)
    {
        spdlog::error("EncryptPacketWithId: AEAD encryption failed: {}", e.what());
        return {};
    }

    RecordOutboundEncrypt(plaintext.size(), primary_encrypt_.cipher_algorithm);
    return encrypted_packet.Serialize();
}

// ============================================================================
// In-place encrypt/decrypt (zero-copy arena path)
// ============================================================================

std::size_t DataChannel::EncryptPacketInPlaceWithId(std::span<std::uint8_t> buf,
                                                    std::size_t payload_len,
                                                    SessionId session_id,
                                                    std::uint32_t packet_id)
{
    if (!primary_encrypt_.is_valid || IsOutboundEncryptBlocked())
        return 0;

    if (!IsSupportedAead(primary_encrypt_.cipher_algorithm) || !encrypt_ctx_)
    {
        spdlog::error("EncryptPacketInPlaceWithId: unsupported cipher or missing context (cipher={})",
                      static_cast<int>(primary_encrypt_.cipher_algorithm));
        return 0;
    }

    const auto wire_len = EncryptDataV2InPlace(
        buf,
        payload_len,
        session_id,
        packet_id,
        current_key_id_,
        primary_encrypt_.cipher_iv,
        *encrypt_ctx_);
    if (wire_len == 0)
        spdlog::error("EncryptPacketInPlaceWithId: AEAD encryption failed");

    return wire_len;
}

std::size_t DataChannel::EncryptPacketInPlace(std::span<std::uint8_t> buf,
                                              std::size_t payload_len,
                                              SessionId session_id)
{
    if (!primary_encrypt_.is_valid || IsOutboundEncryptBlocked())
        return 0;

    const std::size_t total_len = kDataV2Overhead + payload_len;
    if (buf.size() < total_len)
        return 0;

    auto packet_id = AllocateOutboundPacketId();
    if (!packet_id)
        return 0;

    const auto wire_len = EncryptPacketInPlaceWithId(buf, payload_len, session_id, *packet_id);
    if (wire_len == 0)
        return 0;

    RecordOutboundEncrypt(payload_len, primary_encrypt_.cipher_algorithm);
    return wire_len;
}

std::span<std::uint8_t> DataChannel::DecryptPacketInPlace(std::span<std::uint8_t> buf)
{
    if (buf.size() < kDataV2Overhead)
    {
        logger_->warn("DecryptPacketInPlace: packet too small ({} bytes)", buf.size());
        return {};
    }

    // Parse opcode and key_id from first byte
    std::uint8_t opcode_byte = buf[0];
    auto opcode = static_cast<Opcode>(opcode_byte >> OPCODE_SHIFT);
    std::uint8_t key_id = opcode_byte & KEY_ID_MASK;

    if (!IsDataPacket(opcode))
    {
        logger_->debug("DecryptPacketInPlace: not a data packet (opcode={})", static_cast<int>(opcode));
        return {};
    }

    // Find the decryption slot matching the packet's key_id
    DecryptKeySlot *slot = FindDecryptSlot(key_id);
    if (!slot)
    {
        auto now = std::chrono::steady_clock::now();
        if (no_key_limiter_.Due(now))
            logger_->warn("DecryptPacketInPlace: no key found for key_id {} (primary valid={}, primary key_id={})",
                          key_id,
                          primary_decrypt_.key.is_valid,
                          primary_decrypt_.key.key_id);
        return {};
    }

    const EncryptionKey &key = slot->key;

    if (!IsSupportedAead(key.cipher_algorithm) || !slot->decrypt_ctx)
    {
        logger_->error("DecryptPacketInPlace: unsupported cipher or missing context (cipher={})",
                       static_cast<int>(key.cipher_algorithm));
        return {};
    }

    // Extract packet_id from [4..8) (big-endian)
    std::uint32_t pkt_id = (static_cast<std::uint32_t>(buf[4]) << 24)
                           | (static_cast<std::uint32_t>(buf[5]) << 16)
                           | (static_cast<std::uint32_t>(buf[6]) << 8)
                           | static_cast<std::uint32_t>(buf[7]);

    // Anti-replay validation
    auto replay_check = slot->replay.Check(pkt_id);
    if (replay_check == ReplayWindow::CheckResult::TooOld)
    {
        auto now = std::chrono::steady_clock::now();
        if (too_old_limiter_.Due(now))
            logger_->warn("DecryptPacketInPlace: packet_id {} too old (highest={})", pkt_id, slot->replay.highest_id());
        replayed_packets_++;
        return {};
    }
    if (replay_check == ReplayWindow::CheckResult::Duplicate)
    {
        logger_->warn("DecryptPacketInPlace: replay detected (packet_id={})", pkt_id);
        replayed_packets_++;
        return {};
    }

    // Generate nonce
    auto nonce = GenerateNonce(pkt_id, key);

    // AAD = first 8 bytes of wire packet
    auto aad = buf.subspan(0, kDataV2HeaderLen + kDataV2PacketIdLen);

    // Tag is at [8..24)
    std::span<const std::uint8_t, OpenSSL::AEAD_TAG_LENGTH> tag{buf.data() + kDataV2HeaderLen + kDataV2PacketIdLen,
                                                                kDataV2TagLen};

    // Ciphertext is at [24..end)
    std::size_t ct_len = buf.size() - kDataV2Overhead;
    auto ct_span = buf.subspan(kDataV2Overhead, ct_len);

    try
    {
        // Decrypt ciphertext at [24..end) in-place via persistent context
        slot->decrypt_ctx->SetDecryptNonce(nonce);
        slot->decrypt_ctx->UpdateDecryptAad(aad);
        slot->decrypt_ctx->UpdateDecryptInPlace(ct_span);
        bool ok = slot->decrypt_ctx->FinalizeDecryptCheck(tag);

        if (!ok)
        {
            logger_->error("DecryptPacketInPlace: authentication failed (tag mismatch)");
            logger_->error("  pkt_id={} key_id={} cipher={} buf_size={}",
                           pkt_id,
                           key_id,
                           static_cast<int>(key.cipher_algorithm),
                           buf.size());
            return {};
        }

        // Update anti-replay window after successful decryption
        slot->replay.Accept(pkt_id);

        // Plaintext is now at [kDataV2Overhead..kDataV2Overhead+ct_len)
        return ct_span;
    }
    catch (const OpenSSL::SslException &e)
    {
        logger_->error("DecryptPacketInPlace: AEAD decryption failed: {}", e.what());
        return {};
    }
}

// Zero-copy arena path uses DecryptPacketInPlace above.  This allocating path
// is used by the TCP slow path and unit tests.
std::vector<std::uint8_t> DataChannel::DecryptPacket(const OpenVpnPacket &packet)
{
    // Validate packet is a data packet
    if (!IsDataPacket(packet.opcode_))
    {
        logger_->debug("DecryptPacket: not a data packet (opcode={})", static_cast<int>(packet.opcode_));
        return {};
    }

    // Find the decryption slot matching the packet's key_id
    DecryptKeySlot *slot = FindDecryptSlot(packet.key_id_);
    if (!slot)
    {
        auto now = std::chrono::steady_clock::now();
        if (no_key_limiter_.Due(now))
            logger_->warn("DecryptPacket: no key found for key_id {} (primary valid={}, primary key_id={} ({}x))",
                          packet.key_id_,
                          primary_decrypt_.key.is_valid,
                          primary_decrypt_.key.key_id,
                          no_key_limiter_.SuppressedCount() + 1);
        return {};
    }

    const EncryptionKey &key = slot->key;

    logger_->debug("DecryptPacket: using key_id={}, cipher={}",
                   packet.key_id_,
                   static_cast<int>(key.cipher_algorithm));

    // Validate packet ID for anti-replay
    if (!packet.packet_id_)
    {
        logger_->warn("DecryptPacket: packet_id missing");
        return {}; // Data packets must have packet_id
    }

    // Use slot's anti-replay state
    std::uint32_t pkt_id = packet.packet_id_.value();

    auto replay_check = slot->replay.Check(pkt_id);
    if (replay_check == ReplayWindow::CheckResult::TooOld)
    {
        auto now = std::chrono::steady_clock::now();
        if (too_old_limiter_.Due(now))
            logger_->warn("DecryptPacket: packet_id {} too old (highest={})", pkt_id, slot->replay.highest_id());
        replayed_packets_++;
        return {};
    }
    if (replay_check == ReplayWindow::CheckResult::Duplicate)
    {
        logger_->warn("DecryptPacket: replay detected (packet_id={})", pkt_id);
        replayed_packets_++;
        return {};
    }

    // Decrypt payload with AEAD cipher
    if (!IsSupportedAead(key.cipher_algorithm))
    {
        logger_->error("DecryptPacket: unsupported cipher algorithm {}", static_cast<int>(key.cipher_algorithm));
        return {};
    }

    // OpenVPN P_DATA_V2 AEAD format: [ TAG (16 bytes) ] [ ciphertext ]
    // But our DecryptAead expects: [ ciphertext ] [ TAG ]
    // So we need to reorder the payload

    if (packet.payload_.size() < AEAD_TAG_SIZE)
    {
        logger_->warn("DecryptPacket: payload too small ({} bytes, need at least {})",
                      packet.payload_.size(),
                      AEAD_TAG_SIZE);
        return {}; // Too small for tag
    }

    // Reorder: move tag from front to back
    // Use stack buffer for common packet sizes (MTU + overhead), heap only for jumbo packets
    constexpr size_t STACK_BUFFER_SIZE = 1600;
    std::array<std::uint8_t, STACK_BUFFER_SIZE> stack_buffer;
    std::vector<std::uint8_t> heap_buffer;
    std::span<const std::uint8_t> reordered_payload;

    const size_t payload_size = packet.payload_.size();
    const size_t ciphertext_len = payload_size - AEAD_TAG_SIZE;

    if (payload_size <= STACK_BUFFER_SIZE)
    {
        // Common case: use stack buffer
        std::memcpy(stack_buffer.data(), packet.payload_.data() + AEAD_TAG_SIZE, ciphertext_len);
        std::memcpy(stack_buffer.data() + ciphertext_len, packet.payload_.data(), AEAD_TAG_SIZE);
        reordered_payload = std::span<const std::uint8_t>(stack_buffer.data(), payload_size);
    }
    else
    {
        // Uncommon case: jumbo packet, use heap
        heap_buffer.resize(payload_size);
        std::memcpy(heap_buffer.data(), packet.payload_.data() + AEAD_TAG_SIZE, ciphertext_len);
        std::memcpy(heap_buffer.data() + ciphertext_len, packet.payload_.data(), AEAD_TAG_SIZE);
        reordered_payload = std::span<const std::uint8_t>(heap_buffer.data(), payload_size);
    }

    // Generate nonce: packet_id || implicit_iv
    auto nonce = GenerateNonce(packet.packet_id_.value(), key);

    logger_->debug("DecryptPacket: nonce={}, AAD={}",
                   HexDump(nonce, 0, ""),
                   HexDump(packet.aad_, 16, ""));

    try
    {
        // Dispatch to correct AEAD cipher based on key's algorithm
        auto plaintext = DecryptAeadDispatch(
            key.cipher_algorithm,
            key.cipher_key,
            nonce,
            reordered_payload,
            packet.aad_);

        if (plaintext.empty() && !reordered_payload.empty())
        {
            // Empty result with non-empty input means unsupported cipher
            logger_->error("DecryptPacket: decryption returned empty result");
            return {};
        }

        spdlog::debug("DecryptPacket: successfully decrypted {} bytes with cipher {}",
                      plaintext.size(),
                      static_cast<int>(key.cipher_algorithm));

        // Update anti-replay window after successful decryption
        slot->replay.Accept(pkt_id);

        return plaintext;
    }
    catch (const OpenSSL::SslException &e)
    {
        logger_->error("DecryptPacket: AEAD decryption failed: {}", e.what());
        return {};
    }
}

std::array<std::uint8_t, 12> DataChannel::GenerateNonce(std::uint32_t packet_id,
                                                        const EncryptionKey &key)
{
    if (key.IsAead() && key.cipher_iv.size() < 8)
    {
        logger_->error("GenerateNonce: cipher_iv too small ({}), expected 8 bytes. Using zero-padding (INSECURE!).",
                       key.cipher_iv.size());
    }

    return GenerateLegacyDataV2Nonce(packet_id, key.cipher_iv);
}

std::vector<std::uint8_t> DataChannel::ComputeHmac(const EncryptionKey &key,
                                                   std::span<const std::uint8_t> packet_data)
{
    return detail::ComputeHmac(key, packet_data);
}

bool DataChannel::VerifyHmac(const EncryptionKey &key, std::span<const std::uint8_t> packet_data,
                             std::span<const std::uint8_t> expected_hmac)
{
    return detail::VerifyHmac(key, packet_data, expected_hmac);
}

void DataChannel::InstallNewKeys(const EncryptionKey &decrypt_key,
                                 const EncryptionKey &encrypt_key,
                                 std::uint8_t new_key_id)
{
    // If we have a valid primary key, move it to lame duck
    if (primary_decrypt_.key.is_valid)
    {
        // Move primary to lame duck, preserving its anti-replay state.
        // Lame duck lives until the next renegotiation overwrites it.
        lame_duck_decrypt_ = std::move(primary_decrypt_);

        logger_->debug("Moved key_id {} to lame duck", lame_duck_decrypt_->key.key_id);
    }

    // Install new primary keys
    primary_decrypt_.key = decrypt_key;
    primary_decrypt_.key.key_id = new_key_id;
    primary_decrypt_.key.is_valid = true;
    primary_decrypt_.replay.Reset();

    primary_encrypt_ = encrypt_key;
    primary_encrypt_.key_id = new_key_id;
    primary_encrypt_.is_valid = true;

    // Initialize persistent AEAD cipher contexts (one-time key schedule per key install).
    // After this, per-packet operations only update the nonce (~10-20 ns vs ~250-400 ns).
    if (IsSupportedAead(encrypt_key.cipher_algorithm))
    {
        encrypt_ctx_.emplace();
        InitPersistentAeadCtx(*encrypt_ctx_, encrypt_key.cipher_algorithm, encrypt_key.cipher_key, true);
    }
    else
    {
        encrypt_ctx_.reset();
    }
    if (IsSupportedAead(decrypt_key.cipher_algorithm))
    {
        primary_decrypt_.decrypt_ctx.emplace();
        InitPersistentAeadCtx(*primary_decrypt_.decrypt_ctx, decrypt_key.cipher_algorithm, decrypt_key.cipher_key, false);
    }
    else
    {
        primary_decrypt_.decrypt_ctx.reset();
    }

    // Update current key_id for outbound packets
    current_key_id_ = new_key_id & KEY_ID_MASK;

    // Clear limit state after TLS soft reset.  Preserve the monotonic outbound
    // packet ID across normal rekeys (new implicit IV still yields fresh nonces).
    // If wrap/limit logic blocked encrypt at the trigger, restart the counter.
    rekey_requested_.store(false, std::memory_order_relaxed);
    outbound_encrypt_blocked_.store(false, std::memory_order_relaxed);
    aead_usage_blocks_.store(0, std::memory_order_relaxed);
    aead_usage_invocations_.store(0, std::memory_order_relaxed);
    if (outbound_packet_id_.load(std::memory_order_relaxed) >= kPacketIdWrapTrigger)
        outbound_packet_id_.store(1, std::memory_order_relaxed);

    logger_->debug("Installed new keys with key_id {}, decrypt_key_fp={}, iv_fp={}",
                   new_key_id,
                   KeyMaterialFingerprint(primary_decrypt_.key.cipher_key),
                   KeyMaterialFingerprint(primary_decrypt_.key.cipher_iv));
    logger_->debug("  encrypt_key_fp={}, iv_fp={}",
                   KeyMaterialFingerprint(primary_encrypt_.cipher_key),
                   KeyMaterialFingerprint(primary_encrypt_.cipher_iv));
}

DecryptKeySlot *DataChannel::FindDecryptSlot(std::uint8_t key_id)
{
    // First check primary key
    if (primary_decrypt_.key.is_valid && primary_decrypt_.key.key_id == key_id)
    {
        return &primary_decrypt_;
    }

    // Then check lame duck key (if exists and not expired)
    if (lame_duck_decrypt_ && lame_duck_decrypt_->key.is_valid && lame_duck_decrypt_->key.key_id == key_id)
    {
        return &lame_duck_decrypt_.value();
    }

    return nullptr;
}

} // namespace clv::vpn::openvpn
