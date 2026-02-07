// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_CRYPTO_ALGORITHMS_H
#define CLV_VPN_OPENVPN_CRYPTO_ALGORITHMS_H

#include <array>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

#include "ci_string.h"

namespace clv::vpn::openvpn {

// ================================================================================================
// Constants
// ================================================================================================

/**
 * @brief AEAD authentication tag size in bytes
 * @note Used by all AEAD ciphers (AES-GCM, ChaCha20-Poly1305) in OpenVPN protocol
 */
constexpr std::size_t AEAD_TAG_SIZE = 16;

/**
 * @brief Cipher algorithms supported for data channel encryption
 * @note See CIPHER_REGISTRY for detailed properties (key sizes, nonce sizes, etc.)
 */
enum class CipherAlgorithm
{
    AES_128_GCM,       ///< AES-128 in GCM mode (AEAD)
    AES_256_GCM,       ///< AES-256 in GCM mode (AEAD)
    CHACHA20_POLY1305, ///< ChaCha20-Poly1305 (AEAD)
    NONE               ///< No encryption (plaintext, auth only)
};

/**
 * @brief HMAC algorithms for packet authentication (tls-auth)
 * @note HMAC is separate from AEAD cipher authentication. See HMAC_REGISTRY for properties.
 */
enum class HmacAlgorithm
{
    SHA256, ///< HMAC-SHA256
    SHA512, ///< HMAC-SHA512
    NONE    ///< No HMAC (rely on cipher authentication)
};


/**
 * @brief Metadata for cipher algorithms
 * @details Central registry for cipher properties used across config validation,
 *          key derivation, and data channel encryption
 */
struct CipherInfo
{
    CipherAlgorithm algo;   ///< Internal algorithm enum
    const char *name;       ///< OpenVPN protocol name (e.g., "AES-128-GCM")
    std::size_t key_size;   ///< Key size in bytes
    std::size_t nonce_size; ///< Nonce/IV size in bytes
    bool is_aead;           ///< True if AEAD cipher (includes authentication tag)
    bool deprecated;        ///< True if algorithm should be rejected in strict mode
    const char *warning;    ///< Optional deprecation/security warning message
};

/**
 * @brief Metadata for HMAC algorithms
 * @details Used for tls-auth packet authentication and key derivation PRF
 */
struct HmacInfo
{
    HmacAlgorithm algo;      ///< Internal algorithm enum
    const char *name;        ///< OpenVPN protocol name (e.g., "SHA256")
    std::size_t output_size; ///< HMAC output size in bytes
    bool deprecated;         ///< True if algorithm should be rejected in strict mode
    const char *warning;     ///< Optional deprecation/security warning message
};

/**
 * @brief Central cipher algorithm registry
 * @note Update this table when adding new cipher support
 */
constexpr std::array<CipherInfo, 3> CIPHER_REGISTRY = {{
    {CipherAlgorithm::AES_128_GCM, "AES-128-GCM", 16, 12, true, false, nullptr},
    {CipherAlgorithm::AES_256_GCM, "AES-256-GCM", 32, 12, true, false, nullptr},
    {CipherAlgorithm::CHACHA20_POLY1305, "ChaCha20-Poly1305", 32, 12, true, false, nullptr},
    // Legacy/deprecated algorithms - supported for compatibility but flagged
    // Note: These are not yet implemented in data_channel but included for config validation
    // {CipherAlgorithm::BF_CBC, "BF-CBC", 16, 8, false, true, "Blowfish has weak key schedule"},
    // {CipherAlgorithm::AES_128_CBC, "AES-128-CBC", 16, 16, false, true, "CBC mode lacks authentication"},
}};

/**
 * @brief Central HMAC algorithm registry
 * @note Update this table when adding new HMAC support
 */
constexpr std::array<HmacInfo, 2> HMAC_REGISTRY = {{
    {HmacAlgorithm::SHA256, "SHA256", 32, false, nullptr},
    {HmacAlgorithm::SHA512, "SHA512", 64, false, nullptr},
    // Legacy/deprecated
    // {HmacAlgorithm::SHA1, "SHA1", 20, true, "SHA1 is cryptographically weak"},
}};

// ================================================================================================
// Lookup Functions
// ================================================================================================

/**
 * @brief Find cipher metadata by protocol name (case-insensitive)
 * @param name OpenVPN cipher name (e.g., "AES-128-GCM", "aes-128-gcm", "CHACHA20-POLY1305")
 * @return Reference to CipherInfo
 * @throws std::invalid_argument if cipher not found
 */
inline const CipherInfo &FindCipherByName(std::string_view name)
{
    clv::ci_string_view ci_name(name);
    for (std::size_t i = 0; i < CIPHER_REGISTRY.size(); ++i)
    {
        if (ci_name == clv::ci_string_view(CIPHER_REGISTRY[i].name))
            return CIPHER_REGISTRY[i];
    }
    throw std::invalid_argument(std::string("Unknown cipher: ") + std::string(name));
}

/**
 * @brief Get cipher metadata by algorithm enum
 * @param algo Cipher algorithm enum value
 * @return Reference to CipherInfo
 * @throws std::invalid_argument if algorithm not found in registry
 */
inline const CipherInfo &GetCipherInfo(CipherAlgorithm algo)
{
    for (std::size_t i = 0; i < CIPHER_REGISTRY.size(); ++i)
    {
        if (CIPHER_REGISTRY[i].algo == algo)
            return CIPHER_REGISTRY[i];
    }
    throw std::invalid_argument("Cipher algorithm not found in registry");
}

/**
 * @brief Find HMAC metadata by protocol name
 * @param name OpenVPN HMAC name (e.g., "SHA256")
 * @return Reference to HmacInfo
 * @throws std::invalid_argument if HMAC not found
 */
inline const HmacInfo &FindHmacByName(std::string_view name)
{
    clv::ci_string_view ci_name(name);
    for (std::size_t i = 0; i < HMAC_REGISTRY.size(); ++i)
    {
        if (ci_name == clv::ci_string_view(HMAC_REGISTRY[i].name))
            return HMAC_REGISTRY[i];
    }
    throw std::invalid_argument(std::string("Unknown HMAC: ") + std::string(name));
}

/**
 * @brief Get HMAC metadata by algorithm enum
 * @param algo HMAC algorithm enum value
 * @return Reference to HmacInfo
 * @throws std::invalid_argument if algorithm not found in registry
 */
inline const HmacInfo &GetHmacInfo(HmacAlgorithm algo)
{
    for (std::size_t i = 0; i < HMAC_REGISTRY.size(); ++i)
    {
        if (HMAC_REGISTRY[i].algo == algo)
            return HMAC_REGISTRY[i];
    }
    throw std::invalid_argument("HMAC algorithm not found in registry");
}

/**
 * @brief Validate cipher and HMAC combination for security policy
 * @param cipher_name Cipher name from config
 * @param hmac_name HMAC name from config (may be empty for AEAD-only)
 * @param strict If true, reject deprecated algorithms
 * @return true if combination is valid and allowed by policy
 */
inline bool ValidateAlgorithmCombination(std::string_view cipher_name,
                                         std::string_view hmac_name,
                                         bool strict)
{
    // Validate cipher
    if (!cipher_name.empty())
    {
        try
        {
            const CipherInfo &cipher = FindCipherByName(cipher_name);
            if (strict && cipher.deprecated)
                return false; // Deprecated cipher in strict mode
        }
        catch (const std::invalid_argument &)
        {
            return false; // Unknown cipher
        }
    }

    // Validate HMAC
    if (!hmac_name.empty())
    {
        try
        {
            const HmacInfo &hmac = FindHmacByName(hmac_name);
            if (strict && hmac.deprecated)
                return false; // Deprecated HMAC in strict mode
        }
        catch (const std::invalid_argument &)
        {
            return false; // Unknown HMAC
        }
    }

    // Additional validation: AEAD ciphers don't require separate HMAC
    // (though tls-auth can still add an outer HMAC layer)

    return true;
}

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_CRYPTO_ALGORITHMS_H
