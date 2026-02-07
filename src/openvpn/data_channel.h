// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_DATA_CHANNEL_H
#define CLV_VPN_OPENVPN_DATA_CHANNEL_H

#include "packet.h"
#include "crypto_algorithms.h"
#include "protocol_constants.h"
#include "HelpSslCipher.h"

#include <array>
#include <cstddef>
#include <not_null.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

namespace spdlog {
class logger;
}

namespace clv::vpn::openvpn {

// ============================================================================
// P_DATA_V2 AEAD wire format constants
// ============================================================================

/// P_DATA_V2 header: [opcode/key_id (1)] [peer_id (3)] = 4 bytes
constexpr std::size_t kDataV2HeaderLen = 4;

/// Packet ID field: 4 bytes big-endian
constexpr std::size_t kDataV2PacketIdLen = 4;

/// AEAD authentication tag: 16 bytes
constexpr std::size_t kDataV2TagLen = AEAD_TAG_SIZE;

/// Total overhead before ciphertext: header + packet_id + tag = 24 bytes
constexpr std::size_t kDataV2Overhead = kDataV2HeaderLen + kDataV2PacketIdLen + kDataV2TagLen;

/**
 * @brief Encryption key material for a single TLS key slot
 *
 * Derived from TLS master secret via PRF (Pseudo-Random Function).
 * OpenVPN uses HMAC-SHA256 as the PRF.
 */
struct EncryptionKey
{
    /// Cipher to use for this key
    CipherAlgorithm cipher_algorithm = CipherAlgorithm::NONE;

    /// HMAC algorithm for packet authentication (tls-auth)
    HmacAlgorithm hmac_algorithm = HmacAlgorithm::NONE;

    /// Encryption key material (length depends on cipher)
    std::vector<std::uint8_t> cipher_key;

    /// IV (initialization vector) for CBC modes, or salt for AEAD
    std::vector<std::uint8_t> cipher_iv;

    /// HMAC key material (length depends on HMAC algorithm)
    std::vector<std::uint8_t> hmac_key;

    /// Whether this key slot is active and ready to use
    bool is_valid = false;

    /// The key_id associated with this key (0-7, from TLS renegotiation)
    std::uint8_t key_id = 0;

    /**
     * @brief Check if cipher is authenticated encryption (AEAD)
     */
    bool IsAead() const
    {
        if (cipher_algorithm == CipherAlgorithm::NONE)
            return false;
        try
        {
            return GetCipherInfo(cipher_algorithm).is_aead;
        }
        catch (const std::invalid_argument &)
        {
            // Unknown cipher algorithm - treat as non-AEAD for safety
            return false;
        }
    }
};

/**
 * @brief 2048-bit sliding window for anti-replay protection
 *
 * Tracks which packet IDs have been seen within a window of the highest
 * received ID.  At multi-Gbps rates, the 2048-bit window handles reordering
 * spans of up to 2048 packets across parallel TCP streams through the tunnel.
 */
class ReplayWindow
{
  public:
    static constexpr std::size_t kWords = 32;
    static constexpr std::size_t kBits = kWords * 64;

    /// Result of checking a packet ID against the window.
    enum class CheckResult
    {
        Accept,   ///< Packet ID not seen before — proceed to decrypt
        TooOld,   ///< Packet ID is older than the window can track
        Duplicate ///< Packet ID was already seen (replay)
    };

    /// Check whether a packet ID should be accepted (pre-decrypt).
    [[nodiscard]] CheckResult Check(std::uint32_t pkt_id) const noexcept
    {
        if (pkt_id > highest_id_)
            return CheckResult::Accept;
        std::uint32_t diff = highest_id_ - pkt_id;
        if (diff >= kBits)
            return CheckResult::TooOld;
        if (BitTest(diff))
            return CheckResult::Duplicate;
        return CheckResult::Accept;
    }

    /// Record a successfully-decrypted packet ID (post-decrypt).
    void Accept(std::uint32_t pkt_id) noexcept
    {
        if (pkt_id > highest_id_)
        {
            Shift(pkt_id - highest_id_);
            highest_id_ = pkt_id;
        }
        else
        {
            BitSet(highest_id_ - pkt_id);
        }
    }

    /// Reset all state (new key install).
    void Reset() noexcept
    {
        highest_id_ = 0;
        bits_.fill(0);
    }

    [[nodiscard]] std::uint32_t highest_id() const noexcept
    {
        return highest_id_;
    }

  private:
    [[nodiscard]] bool BitTest(std::uint32_t pos) const noexcept
    {
        return (bits_[pos / 64] >> (pos % 64)) & 1;
    }

    void BitSet(std::uint32_t pos) noexcept
    {
        bits_[pos / 64] |= (1ULL << (pos % 64));
    }

    void Shift(std::uint32_t shift) noexcept
    {
        if (shift >= kBits)
        {
            bits_.fill(0);
        }
        else if (shift > 0)
        {
            const std::size_t word_shift = shift / 64;
            const unsigned bit_shift = shift % 64;

            if (bit_shift == 0)
            {
                for (std::size_t i = kWords; i-- > word_shift;)
                    bits_[i] = bits_[i - word_shift];
            }
            else
            {
                for (std::size_t i = kWords; i-- > word_shift + 1;)
                    bits_[i] = (bits_[i - word_shift] << bit_shift)
                               | (bits_[i - word_shift - 1] >> (64 - bit_shift));
                bits_[word_shift] = bits_[0] << bit_shift;
            }
            for (std::size_t i = 0; i < word_shift; ++i)
                bits_[i] = 0;
        }
        bits_[0] |= 1; // Mark current highest_id as seen
    }

    std::uint32_t highest_id_ = 0;
    std::array<std::uint64_t, kWords> bits_{};
};

/**
 * @brief Lightweight rate limiter for log messages (single-threaded).
 *
 * Tracks a timestamp; ShouldLog() returns true at most once per interval.
 * Designed for hot-path warning suppression (e.g., anti-replay "too old").
 */
struct RateLimiter
{
    std::chrono::steady_clock::time_point last{};

    bool ShouldLog(std::chrono::steady_clock::time_point now,
                   std::chrono::seconds interval = std::chrono::seconds{1}) noexcept
    {
        if (now - last >= interval)
        {
            last = now;
            return true;
        }
        return false;
    }
};

/**
 * @brief Decryption key slot with anti-replay state
 *
 * Each decryption key maintains its own replay window since they track
 * different packet ID sequences. The expiry field is used for lame duck keys
 * to track when they should be cleaned up (nullopt = primary or no-expiry).
 */
struct DecryptKeySlot
{
    EncryptionKey key;
    ReplayWindow replay;

    std::optional<std::chrono::steady_clock::time_point> expiry; // nullopt = primary

    /// Persistent AEAD decrypt context (nonce-only updates per packet; nullopt until key install)
    std::optional<OpenSSL::SslCipherCtx> decrypt_ctx;
};

/**
 * @brief Data channel packet encryption/decryption
 *
 * Implements OpenVPN data channel protocol:
 * - Packet ID sequencing for anti-replay protection
 * - AEAD encryption (AES-GCM, ChaCha20-Poly1305)
 * - Optional HMAC-based authentication (tls-auth)
 * - Sliding window anti-replay validation
 */
class DataChannel
{
  public:
    /**
     * @brief Construct DataChannel with required logger
     * @param logger Logger instance (must remain valid for lifetime of DataChannel)
     */
    explicit DataChannel(spdlog::logger &logger) : logger_(&logger)
    {
    }

    ~DataChannel() = default;

    // Non-copyable, movable
    DataChannel(const DataChannel &) = delete;
    DataChannel &operator=(const DataChannel &) = delete;
    DataChannel(DataChannel &&) = default;
    DataChannel &operator=(DataChannel &&) = default;

    /**
     * @brief Encrypt plaintext IP packet for transmission
     *
     * Encrypts with primary encryption key, adds packet ID and IV,
     * and wraps in OpenVpnPacket with opcode P_DATA_V2.
     *
     * @param plaintext IP packet data to encrypt
     * @param session_id Session ID for the connection
     * @return Serialized encrypted packet ready for transmission, or empty on error
     */
    [[nodiscard]] std::vector<std::uint8_t> EncryptPacket(std::span<const std::uint8_t> plaintext,
                                                          SessionId session_id);

    /**
     * @brief Decrypt and validate received data packet
     *
     * Validates packet ID against anti-replay window, decrypts ciphertext,
     * and optionally validates HMAC (tls-auth).
     *
     * @param packet Parsed data packet from wire
     * @return Decrypted plaintext IP packet, or empty on validation/decryption error
     */
    [[nodiscard]] std::vector<std::uint8_t> DecryptPacket(const OpenVpnPacket &packet);

    // ========================================================================================
    // Zero-copy in-place encrypt/decrypt (arena path)
    // ========================================================================================

    /**
     * @brief Encrypt plaintext in-place within a pre-laid-out buffer
     *
     * The caller must place plaintext (compress framing + IP data) at buf[kDataV2Overhead..]
     * before calling this. The method:
     *   1. Writes P_DATA_V2 header (opcode/key_id/peer_id) at [0..4)
     *   2. Writes packet_id at [4..8)
     *   3. Computes AAD from [0..8)
     *   4. Encrypts [24..24+payload_len) in-place
     *   5. Writes 16-byte AEAD tag at [8..24)
     *
     * @param buf Buffer with at least (kDataV2Overhead + payload_len) bytes.
     *            Plaintext must already be at offset kDataV2Overhead.
     * @param payload_len Length of plaintext at buf[kDataV2Overhead..]
     * @param session_id Session ID for P_DATA_V2 peer_id field
     * @return Total wire packet length (kDataV2Overhead + payload_len), or 0 on error
     * @note Zero heap allocations on the hot path.
     */
    [[nodiscard]] std::size_t EncryptPacketInPlace(std::span<std::uint8_t> buf,
                                                   std::size_t payload_len,
                                                   SessionId session_id);

    /**
     * @brief Decrypt a P_DATA_V2 packet in-place
     *
     * The buffer must contain a complete P_DATA_V2 wire packet:
     * [opcode+peer_id (4)][packet_id (4)][tag (16)][ciphertext...]
     *
     * After successful decryption, plaintext occupies [kDataV2Overhead..kDataV2Overhead+pt_len).
     *
     * @param buf Buffer containing the full wire datagram
     * @return Span to decrypted plaintext within buf, or empty span on error
     * @note Zero heap allocations. Anti-replay window is updated on success.
     */
    [[nodiscard]] std::span<std::uint8_t> DecryptPacketInPlace(std::span<std::uint8_t> buf);

    /**
     * @brief Get current outbound packet ID for statistics/debugging
     */
    std::uint32_t GetOutboundPacketId() const
    {
        return outbound_packet_id_;
    }

    /**
     * @brief Get number of replayed packets detected
     */
    std::uint64_t GetReplayedPacketCount() const
    {
        return replayed_packets_;
    }

    /**
     * @brief Reset anti-replay window (for renegotiation)
     */
    void ResetAntiReplayWindow()
    {
        primary_decrypt_.replay.Reset();
    }

    /**
     * @brief Set the current key_id for outbound packets
     *
     * After TLS renegotiation, the key_id increments (0-7 wrapping).
     * This key_id is embedded in P_DATA_V2 packet headers.
     *
     * @param key_id Key ID (0-7)
     */
    void SetCurrentKeyId(std::uint8_t key_id)
    {
        current_key_id_ = key_id & KEY_ID_MASK;
    }

    /**
     * @brief Get the current key_id used for outbound packets
     */
    std::uint8_t GetCurrentKeyId() const
    {
        return current_key_id_;
    }

    /**
     * @brief Check if valid encryption/decryption keys are installed
     * @return true if primary keys are installed and ready for use
     */
    bool HasValidKeys() const
    {
        return dco_keys_installed_ || (primary_decrypt_.key.is_valid && primary_encrypt_.is_valid);
    }

    /**
     * @brief Mark that DCO keys are installed in kernel
     *
     * In DCO mode, keys are pushed to kernel via netlink and never stored
     * in userspace. This flag tracks that keys are installed for session
     * state management purposes.
     *
     * @param installed true if DCO keys are installed
     */
    void SetDcoKeysInstalled(bool installed)
    {
        dco_keys_installed_ = installed;
    }

    /**
     * @brief Install new keys for a key renegotiation
     *
     * This moves the current primary keys to "lame duck" status and installs
     * new keys as primary. The lame duck keys remain valid for decrypting
     * in-flight packets for transition_window_seconds.
     *
     * @param decrypt_key Key for decrypting incoming packets (client→server)
     * @param encrypt_key Key for encrypting outgoing packets (server→client)
     * @param new_key_id The key_id for the new keys (0-7)
     * @param transition_window_seconds How long to keep old keys valid (default 60s)
     */
    void InstallNewKeys(const EncryptionKey &decrypt_key,
                        const EncryptionKey &encrypt_key,
                        std::uint8_t new_key_id,
                        int transition_window_seconds = 60);

    /**
     * @brief Find a decryption key slot matching the given key_id
     *
     * Searches primary and lame duck keys for one matching the packet's key_id.
     * Returns the full slot with anti-replay state for decryption operations.
     *
     * @param key_id The key_id from the incoming packet
     * @return Pointer to matching slot, or nullptr if not found/expired
     */
    [[nodiscard]] DecryptKeySlot *FindDecryptSlot(std::uint8_t key_id);

    /**
     * @brief Clean up expired lame duck keys
     *
     * Should be called periodically to remove keys past their transition window.
     */
    void CleanupExpiredKeys();

  private:
    /// Primary decryption key with anti-replay state
    DecryptKeySlot primary_decrypt_;

    /// Primary encryption key (never lame ducked, simpler)
    EncryptionKey primary_encrypt_;

    /// Lame duck decryption key (old key kept for transition, includes expiry)
    std::optional<DecryptKeySlot> lame_duck_decrypt_;

    /// Persistent AEAD encrypt context (nonce-only updates per packet; nullopt until key install)
    std::optional<OpenSSL::SslCipherCtx> encrypt_ctx_;


    /// Current key_id for outbound packets (0-7, increments on renegotiation)
    std::uint8_t current_key_id_ = 0;

    /**
     * Flag indicating keys are managed externally (e.g., DCO kernel module).
     * When true, HasValidKeys() returns true even though userspace key structs are empty.
     * Revisit if other external key management scenarios arise.
     */
    bool dco_keys_installed_ = false;

    /// Outbound packet ID counter
    std::uint32_t outbound_packet_id_ = 1;

    /// Counter of replayed packets for statistics
    std::uint64_t replayed_packets_ = 0;

    /// Logger for debug output (never null)
    clv::not_null<spdlog::logger *> logger_;

    /// Rate limiters for hot-path warnings (avoid log flooding)
    RateLimiter no_key_limiter_;
    RateLimiter too_old_limiter_;

    /// Helper: Generate IV/nonce for encryption
    std::array<std::uint8_t, 12> GenerateNonce(std::uint32_t packet_id, const EncryptionKey &key);

    /// Helper: Compute HMAC-SHA256 for packet authentication
    std::vector<std::uint8_t> ComputeHmac(const EncryptionKey &key,
                                          std::span<const std::uint8_t> packet_data);

    /// Helper: Verify HMAC against expected value
    bool VerifyHmac(const EncryptionKey &key, std::span<const std::uint8_t> packet_data,
                    std::span<const std::uint8_t> expected_hmac);
};

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_DATA_CHANNEL_H
