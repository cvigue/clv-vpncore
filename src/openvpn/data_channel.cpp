// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "data_channel.h"
#include "aead_utils.h"
#include "crypto_algorithms.h"
#include "packet.h"
#include "protocol_constants.h"
#include <log_utils.h>
#include "HelpSslCipher.h"
#include "HelpSslException.h"
#include "HelpSslHmac.h"
#include "util/byte_packer.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <optional>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace clv::vpn::openvpn {

// ============================================================================
// AEAD Cipher Dispatch (runtime algorithm selection)
// ============================================================================

/**
 * @brief Encrypt using AEAD cipher selected at runtime
 * @param algo Cipher algorithm from key
 * @param key Encryption key
 * @param nonce 12-byte nonce
 * @param plaintext Data to encrypt
 * @param aad Additional authenticated data
 * @return Ciphertext with 16-byte tag appended, or empty on unsupported cipher
 */
static std::vector<std::uint8_t> EncryptAeadDispatch(CipherAlgorithm algo,
                                                     std::span<const std::uint8_t> key,
                                                     std::span<const std::uint8_t> nonce,
                                                     std::span<const std::uint8_t> plaintext,
                                                     std::span<const std::uint8_t> aad)
{
    switch (algo)
    {
    case CipherAlgorithm::AES_128_GCM:
        return OpenSSL::EncryptAead(OpenSSL::AES_128_GCM_TRAITS, key, nonce, plaintext, aad);
    case CipherAlgorithm::AES_256_GCM:
        return OpenSSL::EncryptAead(OpenSSL::AES_256_GCM_TRAITS, key, nonce, plaintext, aad);
    case CipherAlgorithm::CHACHA20_POLY1305:
        return OpenSSL::EncryptAead(OpenSSL::CHACHA20_POLY1305_TRAITS, key, nonce, plaintext, aad);
    default:
        return {}; // Unsupported cipher
    }
}

/**
 * @brief Decrypt using AEAD cipher selected at runtime
 * @param algo Cipher algorithm from key
 * @param key Decryption key
 * @param nonce 12-byte nonce
 * @param ciphertext_with_tag Ciphertext with 16-byte tag appended
 * @param aad Additional authenticated data
 * @return Plaintext, or empty on unsupported cipher
 * @throws OpenSSL::SslException on authentication failure
 */
static std::vector<std::uint8_t> DecryptAeadDispatch(CipherAlgorithm algo,
                                                     std::span<const std::uint8_t> key,
                                                     std::span<const std::uint8_t> nonce,
                                                     std::span<const std::uint8_t> ciphertext_with_tag,
                                                     std::span<const std::uint8_t> aad)
{
    switch (algo)
    {
    case CipherAlgorithm::AES_128_GCM:
        return OpenSSL::DecryptAead(OpenSSL::AES_128_GCM_TRAITS, key, nonce, ciphertext_with_tag, aad);
    case CipherAlgorithm::AES_256_GCM:
        return OpenSSL::DecryptAead(OpenSSL::AES_256_GCM_TRAITS, key, nonce, ciphertext_with_tag, aad);
    case CipherAlgorithm::CHACHA20_POLY1305:
        return OpenSSL::DecryptAead(OpenSSL::CHACHA20_POLY1305_TRAITS, key, nonce, ciphertext_with_tag, aad);
    default:
        return {}; // Unsupported cipher
    }
}

// ============================================================================
// In-place AEAD Cipher Dispatch (zero-copy, runtime algorithm selection)
// ============================================================================

/**
 * @brief Encrypt in-place using AEAD cipher selected at runtime
 * @return 16-byte authentication tag, or empty array on unsupported cipher
 */
static std::array<std::uint8_t, OpenSSL::AEAD_TAG_LENGTH>
EncryptAeadInPlaceDispatch(CipherAlgorithm algo,
                           std::span<const std::uint8_t> key,
                           std::span<const std::uint8_t> nonce,
                           std::span<std::uint8_t> data,
                           std::span<const std::uint8_t> aad)
{
    switch (algo)
    {
    case CipherAlgorithm::AES_128_GCM:
        return OpenSSL::EncryptAeadInPlace(OpenSSL::AES_128_GCM_TRAITS, key, nonce, data, aad);
    case CipherAlgorithm::AES_256_GCM:
        return OpenSSL::EncryptAeadInPlace(OpenSSL::AES_256_GCM_TRAITS, key, nonce, data, aad);
    case CipherAlgorithm::CHACHA20_POLY1305:
        return OpenSSL::EncryptAeadInPlace(OpenSSL::CHACHA20_POLY1305_TRAITS, key, nonce, data, aad);
    default:
        return {}; // Unsupported cipher
    }
}

/**
 * @brief Decrypt in-place using AEAD cipher selected at runtime
 * @return true if decryption and tag verification succeeded
 */
static bool DecryptAeadInPlaceDispatch(CipherAlgorithm algo,
                                       std::span<const std::uint8_t> key,
                                       std::span<const std::uint8_t> nonce,
                                       std::span<std::uint8_t> data,
                                       std::span<const std::uint8_t, OpenSSL::AEAD_TAG_LENGTH> tag,
                                       std::span<const std::uint8_t> aad)
{
    switch (algo)
    {
    case CipherAlgorithm::AES_128_GCM:
        return OpenSSL::DecryptAeadInPlace(OpenSSL::AES_128_GCM_TRAITS, key, nonce, data, tag, aad);
    case CipherAlgorithm::AES_256_GCM:
        return OpenSSL::DecryptAeadInPlace(OpenSSL::AES_256_GCM_TRAITS, key, nonce, data, tag, aad);
    case CipherAlgorithm::CHACHA20_POLY1305:
        return OpenSSL::DecryptAeadInPlace(OpenSSL::CHACHA20_POLY1305_TRAITS, key, nonce, data, tag, aad);
    default:
        return false; // Unsupported cipher
    }
}

/**
 * @brief Check if cipher algorithm is a supported AEAD cipher
 */
static bool IsSupportedAead(CipherAlgorithm algo)
{
    switch (algo)
    {
    case CipherAlgorithm::AES_128_GCM:
    case CipherAlgorithm::AES_256_GCM:
    case CipherAlgorithm::CHACHA20_POLY1305:
        return true;
    default:
        return false;
    }
}

// ============================================================================
// Persistent AEAD Context Initialization
// ============================================================================

/**
 * @brief Initialize a persistent AEAD cipher context with the given algorithm and key
 * @details Dispatches to the correct cipher traits at initialization time.  After this
 *          call only per-packet nonce updates are needed (SetEncryptNonce / SetDecryptNonce).
 *          The OpenSSL key schedule is cached, eliminating ~250-400 ns of per-packet overhead.
 * @param ctx   Cipher context to initialize (must be freshly constructed)
 * @param algo  Cipher algorithm to use
 * @param key   Cipher key material
 * @param encrypt true for encryption context, false for decryption
 * @throws std::invalid_argument if algo is not a supported AEAD cipher
 * @throws OpenSSL::SslException on OpenSSL initialization failure
 */
static void InitPersistentAeadCtx(OpenSSL::SslCipherCtx &ctx,
                                  CipherAlgorithm algo,
                                  std::span<const std::uint8_t> key,
                                  bool encrypt)
{
    // Map algorithm to traits
    const OpenSSL::AeadCipherTraits *traits = nullptr;
    switch (algo)
    {
    case CipherAlgorithm::AES_128_GCM:
        traits = &OpenSSL::AES_128_GCM_TRAITS;
        break;
    case CipherAlgorithm::AES_256_GCM:
        traits = &OpenSSL::AES_256_GCM_TRAITS;
        break;
    case CipherAlgorithm::CHACHA20_POLY1305:
        traits = &OpenSSL::CHACHA20_POLY1305_TRAITS;
        break;
    default:
        throw std::invalid_argument("Unsupported AEAD cipher for persistent context");
    }

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
// DataChannel Implementation
// ============================================================================

std::vector<std::uint8_t> DataChannel::EncryptPacket(std::span<const std::uint8_t> plaintext,
                                                     SessionId session_id)
{
    if (!primary_encrypt_.is_valid)
        return {};

    const auto &key = primary_encrypt_;

    // Get packet ID and increment counter
    std::uint32_t packet_id = outbound_packet_id_++;

    // Build packet header for P_DATA_V2
    std::uint32_t peer_id = session_id.value & PEER_ID_MASK;
    OpenVpnPacket encrypted_packet = OpenVpnPacket::DataV2(current_key_id_, peer_id, packet_id);

    // Encrypt payload with AEAD cipher
    if (!IsSupportedAead(key.cipher_algorithm))
    {
        spdlog::error("EncryptPacket: unsupported cipher algorithm {}", static_cast<int>(key.cipher_algorithm));
        return {};
    }

    // Generate nonce: packet_id (4 bytes BE) || implicit_iv (8 bytes)
    auto nonce = GenerateNonce(packet_id, key);

    try
    {
        if (encrypt_ctx_)
        {
            // Fast path: persistent context — copy plaintext, encrypt in-place, reorder tag
            std::vector<std::uint8_t> ct(plaintext.begin(), plaintext.end());

            encrypt_ctx_->SetEncryptNonce(nonce);
            encrypt_ctx_->UpdateEncryptAad(encrypted_packet.aad_);
            encrypt_ctx_->UpdateEncryptInPlace(std::span<std::uint8_t>(ct));
            auto tag = encrypt_ctx_->FinalizeEncryptTag();

            // Wire format: TAG (16) | ciphertext — prepend tag
            std::vector<std::uint8_t> payload;
            payload.reserve(tag.size() + ct.size());
            payload.insert(payload.end(), tag.begin(), tag.end());
            payload.insert(payload.end(), ct.begin(), ct.end());
            encrypted_packet.payload_ = std::move(payload);
        }
        else
        {
            // Fallback: per-call context (tests with non-AEAD ciphers)
            auto encrypted = EncryptAeadDispatch(
                key.cipher_algorithm,
                std::span<const std::uint8_t>(key.cipher_key.data(), key.cipher_key.size()),
                nonce,
                plaintext,
                encrypted_packet.aad_);

            if (encrypted.empty())
            {
                spdlog::error("EncryptPacket: encryption returned empty result");
                return {};
            }

            // SslHelp returns [ciphertext][tag] — reorder to [tag][ciphertext]
            encrypted_packet.payload_ = ReorderTagToFront(encrypted);
        }

        logger_->debug("EncryptPacket: encrypted {} bytes with {}, packet_id={}",
                       plaintext.size(),
                       static_cast<int>(key.cipher_algorithm),
                       packet_id);
        if (packet_id <= 2) // Log details for first few packets
        {
            logger_->debug("  encrypt_key(first 8): {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                           key.cipher_key[0],
                           key.cipher_key[1],
                           key.cipher_key[2],
                           key.cipher_key[3],
                           key.cipher_key[4],
                           key.cipher_key[5],
                           key.cipher_key[6],
                           key.cipher_key[7]);
            logger_->debug("  nonce: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                           nonce[0],
                           nonce[1],
                           nonce[2],
                           nonce[3],
                           nonce[4],
                           nonce[5],
                           nonce[6],
                           nonce[7],
                           nonce[8],
                           nonce[9],
                           nonce[10],
                           nonce[11]);
        }
    }
    catch (const OpenSSL::SslException &e)
    {
        spdlog::error("EncryptPacket: AEAD encryption failed: {}", e.what());
        return {};
    }

    return encrypted_packet.Serialize();
}

// ============================================================================
// In-place encrypt/decrypt (zero-copy arena path)
// ============================================================================

std::size_t DataChannel::EncryptPacketInPlace(std::span<std::uint8_t> buf,
                                              std::size_t payload_len,
                                              SessionId session_id)
{
    if (!primary_encrypt_.is_valid)
        return 0;

    const auto &key = primary_encrypt_;
    const std::size_t total_len = kDataV2Overhead + payload_len;

    if (buf.size() < total_len)
        return 0; // Buffer too small

    if (!IsSupportedAead(key.cipher_algorithm) || !encrypt_ctx_)
    {
        spdlog::error("EncryptPacketInPlace: unsupported cipher or missing context (cipher={})",
                      static_cast<int>(key.cipher_algorithm));
        return 0;
    }

    // Get packet ID and increment counter
    std::uint32_t packet_id = outbound_packet_id_++;

    // Write P_DATA_V2 header: [opcode/key_id (1)][peer_id (3)] at [0..4)
    std::uint32_t peer_id = session_id.value & PEER_ID_MASK;
    std::uint32_t opcode_peer_id = (MakeOpcodeByte(Opcode::P_DATA_V2, current_key_id_) << 24) | peer_id;
    auto hdr_bytes = netcore::uint_to_bytes(opcode_peer_id);
    std::memcpy(buf.data(), hdr_bytes.data(), kDataV2HeaderLen);

    // Write packet_id at [4..8)
    auto pktid_bytes = netcore::uint_to_bytes(packet_id);
    std::memcpy(buf.data() + kDataV2HeaderLen, pktid_bytes.data(), kDataV2PacketIdLen);

    // Generate nonce: packet_id (4 bytes BE) || implicit_iv (8 bytes)
    auto nonce = GenerateNonce(packet_id, key);

    // AAD = first 8 bytes of wire packet (header + packet_id)
    auto aad = buf.subspan(0, kDataV2HeaderLen + kDataV2PacketIdLen);

    try
    {
        // Encrypt plaintext at [24..24+payload_len) in-place via persistent context
        auto plaintext_span = buf.subspan(kDataV2Overhead, payload_len);

        encrypt_ctx_->SetEncryptNonce(nonce);
        encrypt_ctx_->UpdateEncryptAad(aad);
        encrypt_ctx_->UpdateEncryptInPlace(plaintext_span);
        auto tag = encrypt_ctx_->FinalizeEncryptTag();

        // Write tag at [8..24) — directly in its wire position
        std::memcpy(buf.data() + kDataV2HeaderLen + kDataV2PacketIdLen, tag.data(), kDataV2TagLen);

        logger_->debug("EncryptPacketInPlace: encrypted {} bytes, packet_id={}", payload_len, packet_id);
        if (packet_id <= 2) // Log details for first few packets
        {
            logger_->debug("  encrypt_key(first 8): {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                           key.cipher_key[0],
                           key.cipher_key[1],
                           key.cipher_key[2],
                           key.cipher_key[3],
                           key.cipher_key[4],
                           key.cipher_key[5],
                           key.cipher_key[6],
                           key.cipher_key[7]);
            logger_->debug("  nonce: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                           nonce[0],
                           nonce[1],
                           nonce[2],
                           nonce[3],
                           nonce[4],
                           nonce[5],
                           nonce[6],
                           nonce[7],
                           nonce[8],
                           nonce[9],
                           nonce[10],
                           nonce[11]);
            logger_->debug("  aad: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                           aad[0],
                           aad[1],
                           aad[2],
                           aad[3],
                           aad[4],
                           aad[5],
                           aad[6],
                           aad[7]);
        }
    }
    catch (const OpenSSL::SslException &e)
    {
        spdlog::error("EncryptPacketInPlace: AEAD encryption failed: {}", e.what());
        return 0;
    }

    return total_len;
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
        if (no_key_limiter_.ShouldLog(now))
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
        if (too_old_limiter_.ShouldLog(now))
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
            logger_->error("  decrypt_key(first 8): {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                           key.cipher_key[0],
                           key.cipher_key[1],
                           key.cipher_key[2],
                           key.cipher_key[3],
                           key.cipher_key[4],
                           key.cipher_key[5],
                           key.cipher_key[6],
                           key.cipher_key[7]);
            logger_->error("  nonce: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                           nonce[0],
                           nonce[1],
                           nonce[2],
                           nonce[3],
                           nonce[4],
                           nonce[5],
                           nonce[6],
                           nonce[7],
                           nonce[8],
                           nonce[9],
                           nonce[10],
                           nonce[11]);
            logger_->error("  aad: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                           aad[0],
                           aad[1],
                           aad[2],
                           aad[3],
                           aad[4],
                           aad[5],
                           aad[6],
                           aad[7]);
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
        if (no_key_limiter_.ShouldLog(now))
            logger_->warn("DecryptPacket: no key found for key_id {} (primary valid={}, primary key_id={})",
                          packet.key_id_,
                          primary_decrypt_.key.is_valid,
                          primary_decrypt_.key.key_id);
        return {};
    }

    const EncryptionKey &key = slot->key;

    logger_->debug("DecryptPacket: using key_id={}, cipher={}, is_lame_duck={}",
                   packet.key_id_,
                   static_cast<int>(key.cipher_algorithm),
                   slot->expiry.has_value());

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
        if (too_old_limiter_.ShouldLog(now))
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
    std::array<std::uint8_t, 12> nonce{}; // Zero-initialize

    // For AEAD modes, create 96-bit (12-byte) nonce
    // OpenVPN non-epoch format: packet_id (4 bytes BE) || implicit_iv (8 bytes)
    // Where implicit_iv comes from hmac[0-7] of the key material

    if (key.IsAead())
    {
        // First 4 bytes: packet_id in big-endian (network byte order)
        auto packet_id_bytes = netcore::uint_to_bytes(packet_id);
        std::memcpy(nonce.data(), packet_id_bytes.data(), 4);

        // Next 8 bytes: implicit IV from key material (cipher_iv should be 8 bytes)
        if (key.cipher_iv.size() >= 8)
        {
            std::memcpy(nonce.data() + 4, key.cipher_iv.data(), 8);
        }
        else
        {
            // Configuration error: insufficient IV material will result in weak nonces
            logger_->error("GenerateNonce: cipher_iv too small ({}), expected 8 bytes. Using zero-padding (INSECURE!).",
                           key.cipher_iv.size());
            // Already zero-initialized, so just log error
        }
    }

    return nonce;
}

std::vector<std::uint8_t> DataChannel::ComputeHmac(const EncryptionKey &key,
                                                   std::span<const std::uint8_t> packet_data)
{
    if (key.hmac_algorithm == HmacAlgorithm::NONE)
        return {};

    try
    {
        switch (key.hmac_algorithm)
        {
        case HmacAlgorithm::SHA256:
            {
                auto hmac = clv::OpenSSL::HmacSha256(key.hmac_key, packet_data);
                return std::vector<std::uint8_t>(hmac.begin(), hmac.end());
            }
        case HmacAlgorithm::SHA512:
            {
                auto hmac = clv::OpenSSL::HmacSha512(key.hmac_key, packet_data);
                return std::vector<std::uint8_t>(hmac.begin(), hmac.end());
            }
        case HmacAlgorithm::NONE:
            return {};
        }
    }
    catch (const clv::OpenSSL::SslException &)
    {
        return {}; // HMAC computation failed
    }

    return {}; // Unknown algorithm
}

bool DataChannel::VerifyHmac(const EncryptionKey &key, std::span<const std::uint8_t> packet_data,
                             std::span<const std::uint8_t> expected_hmac)
{
    if (key.hmac_algorithm == HmacAlgorithm::NONE)
        return true; // No HMAC required

    auto computed_hmac = ComputeHmac(key, packet_data);

    if (computed_hmac.size() != expected_hmac.size())
        return false;

    // Use constant-time comparison from SslHelp
    return clv::OpenSSL::SslHmacCtx<>::ConstantTimeCompare(computed_hmac, expected_hmac);
}

void DataChannel::InstallNewKeys(const EncryptionKey &decrypt_key,
                                 const EncryptionKey &encrypt_key,
                                 std::uint8_t new_key_id,
                                 int transition_window_seconds)
{
    // If we have a valid primary key, move it to lame duck
    if (primary_decrypt_.key.is_valid)
    {
        // Move primary to lame duck, preserving its anti-replay state.
        // transition_window_seconds <= 0 means "never expire" — key lives
        // until the next renegotiation overwrites it.
        if (transition_window_seconds > 0)
            primary_decrypt_.expiry = std::chrono::steady_clock::now() + std::chrono::seconds(transition_window_seconds);
        else
            primary_decrypt_.expiry = std::nullopt; // no expiry
        lame_duck_decrypt_ = std::move(primary_decrypt_);

        logger_->info("Moved key_id {} to lame duck ({})",
                      lame_duck_decrypt_->key.key_id,
                      transition_window_seconds > 0
                          ? "expires in " + std::to_string(transition_window_seconds) + "s"
                          : "no expiry, lives until next rekey");
    }

    // Install new primary keys
    primary_decrypt_.key = decrypt_key;
    primary_decrypt_.key.key_id = new_key_id;
    primary_decrypt_.key.is_valid = true;
    primary_decrypt_.replay.Reset();
    primary_decrypt_.expiry = std::nullopt; // Primary has no expiry

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
    // Log key and salt for debugging
    std::string key_hex = HexDump(
        std::span<const std::uint8_t>(primary_decrypt_.key.cipher_key.data(),
                                      std::min(primary_decrypt_.key.cipher_key.size(), size_t(16))),
        16,
        "");
    std::string salt_hex = HexDump(primary_decrypt_.key.cipher_iv, 0, "");
    std::string enc_key_hex = HexDump(
        std::span<const std::uint8_t>(primary_encrypt_.cipher_key.data(),
                                      std::min(primary_encrypt_.cipher_key.size(), size_t(16))),
        16,
        "");
    std::string enc_salt_hex = HexDump(primary_encrypt_.cipher_iv, 0, "");
    logger_->debug("Installed new keys with key_id {}, decrypt_key(first 16)={}, salt={}",
                   new_key_id,
                   key_hex,
                   salt_hex);
    logger_->debug("  encrypt_key(first 16)={}, salt={}", enc_key_hex, enc_salt_hex);
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
        // No expiry (nullopt) means key lives until next rekey
        if (!lame_duck_decrypt_->expiry || std::chrono::steady_clock::now() < *lame_duck_decrypt_->expiry)
        {
            return &lame_duck_decrypt_.value();
        }
    }

    return nullptr;
}

void DataChannel::CleanupExpiredKeys()
{
    if (lame_duck_decrypt_ && lame_duck_decrypt_->expiry
        && std::chrono::steady_clock::now() >= *lame_duck_decrypt_->expiry)
    {
        logger_->debug("Cleaning up expired lame duck key_id {}",
                       lame_duck_decrypt_->key.key_id);

        // Clear the lame duck key (optional becomes nullopt)
        lame_duck_decrypt_ = std::nullopt;
    }
}

} // namespace clv::vpn::openvpn
