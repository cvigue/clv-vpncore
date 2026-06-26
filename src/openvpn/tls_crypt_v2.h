// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_TLS_CRYPT_V2_H
#define CLV_VPN_OPENVPN_TLS_CRYPT_V2_H

#include <cstddef>
#include <not_null.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace spdlog {
class logger;
}

namespace clv::vpn::openvpn {

/**
 * @brief Per-client key sizes matching OpenVPN's struct key2 layout
 * @details Two keys of 128 bytes each (cipher[64] + hmac[64]) = 256 bytes total.
 *          Only the first 32 bytes of each sub-field are used (AES-256 / HMAC-SHA256).
 */
constexpr std::size_t TLS_CRYPT_V2_CLIENT_KEY_LEN = 256;

/**
 * @brief Server wrapping key size matching OpenVPN's struct key layout
 * @details cipher[64] + hmac[64] = 128 bytes. Only the first 32 bytes of each used.
 */
constexpr std::size_t TLS_CRYPT_V2_SERVER_KEY_LEN = 128;

/** @brief Minimum WKc blob size: HMAC-SHA256 tag (32) + encrypted client key (256) + net_len field (2) */
constexpr std::size_t TLS_CRYPT_V2_MIN_WKC_LEN = 290;

/** @brief Maximum WKc blob size (same as OpenVPN's TLS_CRYPT_V2_MAX_WKC_LEN) */
constexpr std::size_t TLS_CRYPT_V2_MAX_WKC_LEN = 1024;

/** @brief Maximum metadata size (same limit as OpenVPN) */
constexpr std::size_t TLS_CRYPT_V2_MAX_METADATA_LEN = 256;

/** @brief Metadata type: user-defined opaque binary blob */
constexpr std::uint8_t TLS_CRYPT_METADATA_TYPE_USER = 0x00;

/** @brief Metadata type: 64-bit unix timestamp in network byte order */
constexpr std::uint8_t TLS_CRYPT_METADATA_TYPE_TIMESTAMP = 0x01;

/**
 * @brief TLS-Crypt-V2 server-side key management for per-client keys
 *
 * @details Implements the tls-crypt-v2 protocol extension which provides each client
 * with a unique key (Kc), wrapped with the server's secret wrapping key (Ks) into
 * a WKc blob.  At session start, the client sends WKc; the server unwraps it using
 * Ks to recover Kc, then uses Kc for all subsequent tls-crypt packet operations.
 *
 * WKc blob wire format (OpenVPN-compatible):
 * @code
 *   [hmac_tag: 32 bytes]
 *   [AES-256-CTR encrypted (Kc: 256 bytes || metadata: N bytes)]
 *   [net_len: 2 bytes big-endian]   <- total blob size including this field
 * @endcode
 *
 * HMAC is computed over: net_len || Kc || metadata (plaintext, before encryption).
 * First 16 bytes of the HMAC tag serve as the AES-256-CTR synthetic IV.
 * Same HMAC+CTR-SIV construction as tls-crypt V1 packet wrapping.
 *
 * Server key (Ks): 128 bytes (cipher[64] + hmac[64]), base64 PEM encoded.
 * PEM label: "OpenVPN tls-crypt-v2 server key".
 *
 * Client key file: base64 PEM containing Kc (256 bytes) || WKc blob.
 * PEM label: "OpenVPN tls-crypt-v2 client key".
 */
class TlsCryptV2
{
  public:
    /**
     * @brief Result of unwrapping a WKc blob
     */
    struct UnwrapResult
    {
        std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key; ///< Per-client key (Kc)
        std::vector<std::uint8_t> metadata;                               ///< Raw metadata (type byte + payload)
    };

    /**
     * @brief Result of generating a new client key
     */
    struct GenerateResult
    {
        std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key; ///< Per-client key (Kc)
        std::vector<std::uint8_t> wkc_blob;                               ///< Wrapped key for server delivery
    };

    /**
     * @brief Result of loading a client key file (client-side)
     */
    struct ClientKeyData
    {
        std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key; ///< Per-client key (Kc)
        std::vector<std::uint8_t> wkc_blob;                               ///< Wrapped key to send to server
    };

    // ── Construction ────────────────────────────────────────────────────

    /**
     * @brief Load server wrapping key from a PEM file
     * @param path Path to PEM file with label "OpenVPN tls-crypt-v2 server key"
     * @param logger Logger for diagnostics
     * @return TlsCryptV2 instance or nullopt on error
     */
    static std::optional<TlsCryptV2> FromKeyFile(const std::string &path, spdlog::logger &logger);

    /**
     * @brief Load server wrapping key from inline PEM content
     * @param pem_content PEM string with label "OpenVPN tls-crypt-v2 server key"
     * @param logger Logger for diagnostics
     * @return TlsCryptV2 instance or nullopt on error
     */
    static std::optional<TlsCryptV2> FromKeyString(const std::string &pem_content, spdlog::logger &logger);

    /**
     * @brief Load server wrapping key from raw key data
     * @param key_data 128 bytes of server key material (cipher[64] + hmac[64])
     * @param logger Logger for diagnostics
     * @return TlsCryptV2 instance or nullopt on error
     */
    static std::optional<TlsCryptV2> FromKeyData(std::span<const std::uint8_t> key_data, spdlog::logger &logger);

    ~TlsCryptV2();

    // Non-copyable
    TlsCryptV2(const TlsCryptV2 &) = delete;
    TlsCryptV2 &operator=(const TlsCryptV2 &) = delete;

    // Movable
    TlsCryptV2(TlsCryptV2 &&) noexcept;
    TlsCryptV2 &operator=(TlsCryptV2 &&) noexcept;

    // ── WKc Operations ──────────────────────────────────────────────────

    /**
     * @brief Wrap a client key and metadata into a WKc blob
     * @param client_key 256 bytes of client key material (Kc)
     * @param metadata Raw metadata (must include type byte prefix, max TLS_CRYPT_V2_MAX_METADATA_LEN)
     * @return WKc blob or nullopt on error
     */
    std::optional<std::vector<std::uint8_t>> WrapClientKey(
        std::span<const std::uint8_t> client_key,
        std::span<const std::uint8_t> metadata) const;

    /**
     * @brief Unwrap a WKc blob to recover client key and metadata
     * @param wrapped_key WKc blob (as received from client)
     * @return UnwrapResult containing Kc and metadata, or nullopt on auth/format failure
     */
    std::optional<UnwrapResult> UnwrapClientKey(std::span<const std::uint8_t> wrapped_key) const;

    /**
     * @brief Generate a new random client key and wrap it
     * @param metadata Raw metadata (must include type byte prefix)
     * @return GenerateResult with Kc and WKc blob, or nullopt on error
     */
    std::optional<GenerateResult> GenerateClientKey(std::span<const std::uint8_t> metadata) const;

    // ── Client Key File Helpers (static) ────────────────────────────────

    /**
     * @brief Load a tls-crypt-v2 client key file
     * @param path Path to PEM file with label "OpenVPN tls-crypt-v2 client key"
     * @param logger Logger for diagnostics
     * @return ClientKeyData with Kc and WKc, or nullopt on error
     */
    static std::optional<ClientKeyData> LoadClientKeyFile(const std::string &path, spdlog::logger &logger);

    /**
     * @brief Load a tls-crypt-v2 client key from inline PEM content
     * @param pem_content PEM string with label "OpenVPN tls-crypt-v2 client key"
     * @param logger Logger for diagnostics
     * @return ClientKeyData with Kc and WKc, or nullopt on error
     */
    static std::optional<ClientKeyData> LoadClientKeyString(const std::string &pem_content, spdlog::logger &logger);

    /**
     * @brief Encode a client key + WKc blob as a PEM string
     * @param client_key 256 bytes of Kc
     * @param wkc_blob WKc blob
     * @return PEM-encoded string with label "OpenVPN tls-crypt-v2 client key"
     */
    static std::optional<std::string> EncodeClientKeyPem(
        std::span<const std::uint8_t> client_key,
        std::span<const std::uint8_t> wkc_blob);

  private:
    TlsCryptV2(std::vector<std::uint8_t> server_key, spdlog::logger &logger);

    std::vector<std::uint8_t> server_key_; ///< 128-byte server wrapping key (Ks)
    clv::not_null<spdlog::logger *> logger_;
};

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_TLS_CRYPT_V2_H
