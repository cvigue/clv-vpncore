// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_KEY_DERIVATION_H
#define CLV_VPN_OPENVPN_KEY_DERIVATION_H

#include "data_channel.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/packet.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace clv::vpn::openvpn {

/**
 * @brief OpenVPN key material derivation using PRF
 * @details Implements the OpenVPN PRF (Pseudo-Random Function) for deriving
 * session keys and IV material from TLS master secret. OpenVPN uses
 * HMAC-SHA256 based PRF as defined in the OpenVPN protocol.
 *
 * Key derivation follows this pattern:
 * ```
 * Key Material = PRF(master_secret, "OpenVPN" || counter)
 * PRF = HMAC-SHA256(secret, data)
 * ```
 *
 * The derived material is structured as:
 * ```
 * [Client→Server Cipher Key] [Server→Client Cipher Key]
 * [Client→Server IV]         [Server→Client IV]
 * [Client→Server HMAC Key]   [Server→Client HMAC Key]
 * ```
 *
 * Example usage:
 * @code
 * // After TLS handshake
 * auto master_secret = tls_connection.GetMasterSecret();
 *
 * auto key_material = KeyDerivation::DeriveKeyMaterial(
 *     master_secret,
 *     "OpenVPN key material",
 *     256  // bytes needed
 * );
 *
 * // Install into data channel
 * KeyDerivation::InstallKeys(data_channel, key_material, cipher_algo, hmac_algo);
 * @endcode
 */
/** @brief Identifies which peer role is installing keys. */
enum class PeerRole : std::uint8_t
{
    Server,
    Client
};

class KeyDerivation
{
  public:
    /**
     * @brief Derive key material using OpenVPN PRF
     * @param master_secret TLS master secret from handshake
     * @param label Label string for PRF (typically "OpenVPN key material")
     * @param output_bytes Number of bytes to derive
     * @return Derived key material
     * @throws std::runtime_error if derivation fails
     *
     * Implements: PRF(master_secret, label) = HMAC-SHA256(master_secret, label || counter)
     * Counter increments each iteration if more than 32 bytes needed.
     */
    static std::vector<std::uint8_t>
    DeriveKeyMaterial(std::span<const std::uint8_t> master_secret,
                      const std::string &label,
                      size_t output_bytes);

    /**
     * @brief Install derived keys into data channel with proper key transition
     * @param data_channel Data channel to install keys into
     * @param key_material Derived key material (minimum 128 bytes for AEAD)
     * @param cipher_algorithm Cipher to use for keys
     * @param hmac_algorithm HMAC to use for keys
     * @param key_id The key_id (0-7) for this key generation
     * @param transition_window_seconds How long to keep the old keys valid (default 60s)
     * @return true if installation successful
     *
     * Handles key transition properly:
     * - Moves current primary keys to "lame duck" status
     * - Installs new keys as primary
     * - Lame duck keys remain valid for transition_window_seconds
     * - Packets are matched to keys by key_id embedded in packet header
     */
    static bool InstallKeys(DataChannel &data_channel,
                            std::span<const std::uint8_t> key_material,
                            CipherAlgorithm cipher_algorithm,
                            HmacAlgorithm hmac_algorithm,
                            std::uint8_t key_id,
                            int transition_window_seconds = 60,
                            PeerRole role = PeerRole::Server);

    /**
     * @brief Calculate required key material size for cipher
     * @param cipher Cipher algorithm
     * @param hmac HMAC algorithm
     * @return Bytes needed for bidirectional keys + IVs + HMACs
     *
     * For AEAD ciphers:
     * - AES-128-GCM: 16 (key) + 16 (key) + 4 (salt) + 4 (salt) = 40 bytes minimum
     * - AES-256-GCM: 32 (key) + 32 (key) + 4 (salt) + 4 (salt) = 72 bytes minimum
     * - ChaCha20-Poly1305: 32 + 32 + 12 (nonce) + 12 (nonce) = 88 bytes minimum
     *
     * For HMAC: add 32 (SHA256) or 64 (SHA512) per direction
     */
    static size_t GetRequiredKeyMaterialSize(CipherAlgorithm cipher,
                                             HmacAlgorithm hmac);

    /**
     * @brief Derive key material using OpenVPN PRF with separate secret and seed
     * @param secret HMAC secret (pre_master for OpenVPN key-method 2)
     * @param label Label string for PRF (typically "OpenVPN key expansion")
     * @param seed Seed data (concatenated random values)
     * @param output_bytes Number of bytes to derive
     * @return Derived key material
     *
     * This implements the correct OpenVPN PRF:
     * PRF(secret, label, seed) using HMAC-MD5 XOR HMAC-SHA1 expansion
     * For modern OpenVPN, uses HMAC-SHA256 based expansion.
     */
    static std::vector<std::uint8_t>
    DeriveKeyMaterialWithSecret(std::span<const std::uint8_t> secret,
                                const std::string &label,
                                std::span<const std::uint8_t> seed,
                                size_t output_bytes);

    /**
     * @brief Result of two-phase PRF key derivation (key-method 2)
     */
    struct KeyMethod2Result
    {
        KeyMethod2Result(std::vector<std::uint8_t> key_material,
                         CipherAlgorithm cipher_algo,
                         HmacAlgorithm hmac_algo)
            : key_material(std::move(key_material)), cipher_algo(cipher_algo), hmac_algo(hmac_algo)
        {
        }

        std::vector<std::uint8_t> key_material; ///< Raw derived key material (256 bytes)
        CipherAlgorithm cipher_algo;            ///< Resolved cipher algorithm
        HmacAlgorithm hmac_algo;                ///< Resolved HMAC algorithm (NONE for AEAD)
    };

    /**
     * @brief Perform the OpenVPN key-method 2 two-phase PRF derivation
     * @note 'Method 2' refers to the OpenVPN documented key derivation method used in TLS-based
     *       handshakes, which derives keys from the TLS master secret and random values.
     *
     * Encapsulates the full two-phase PRF used by both client and server:
     *   Phase 1: master = PRF(pre_master, "OpenVPN master secret", client_random1 || server_random1)
     *   Phase 2: keys   = PRF(master, "OpenVPN key expansion", client_random2 || server_random2 || client_sid || server_sid)
     *
     * @param client_random Client random bytes (112 bytes: 48 pre_master + 32 random1 + 32 random2)
     * @param server_random Server random bytes (64 bytes: 32 random1 + 32 random2)
     * @param client_session_id Client session ID
     * @param server_session_id Server session ID
     * @param cipher_name Cipher name string (e.g., "AES-256-GCM")
     * @return KeyMethod2Result with derived key material and resolved cipher
     * @throws std::runtime_error on invalid inputs or derivation failure
     * @throws std::invalid_argument on unknown cipher name
     */
    static KeyMethod2Result DeriveKeyMethod2(std::span<const std::uint8_t> client_random,
                                             std::span<const std::uint8_t> server_random,
                                             const SessionId &client_session_id,
                                             const SessionId &server_session_id,
                                             std::string_view cipher_name);

  private:
    /// Size of HMAC-SHA256 output (32 bytes)
    static constexpr size_t PRF_OUTPUT_SIZE = 32;

    /// Label used for OpenVPN key material derivation
    static constexpr const char *OPENVPN_KEY_LABEL = "OpenVPN key material";

    /**
     * @brief Single iteration of HMAC-SHA256 PRF
     * @param key HMAC key (master secret)
     * @param label Label data
     * @param counter Counter byte (0, 1, 2, ...)
     * @return 32 bytes of PRF output
     */
    static std::vector<std::uint8_t> PrfIteration(
        std::span<const std::uint8_t> key,
        const std::string &label,
        std::uint8_t counter);

    /**
     * @brief Extract key material for one direction
     * @param material Derived key material
     * @param offset Starting offset
     * @param cipher Cipher algorithm
     * @param hmac HMAC algorithm
     * @return EncryptionKey struct with all material filled
     */
    static EncryptionKey ExtractDirectionalKey(
        std::span<const std::uint8_t> material,
        size_t offset,
        CipherAlgorithm cipher,
        HmacAlgorithm hmac);
};

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_KEY_DERIVATION_H
