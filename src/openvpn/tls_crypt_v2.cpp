// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/tls_crypt_v2.h"

#include <HelpSslStreamCipher.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace clv::vpn::openvpn {

namespace {

constexpr size_t CIPHER_KEY_SIZE = 32;    // AES-256 key: first 32 bytes of cipher[64]
constexpr size_t HMAC_KEY_SIZE = 32;      // HMAC-SHA256 key: first 32 bytes of hmac[64]
constexpr size_t CIPHER_FIELD_SIZE = 64;  // struct key::cipher[64]
constexpr size_t TLS_CRYPT_TAG_SIZE = 32; // HMAC-SHA256 output
constexpr size_t AES_CTR_IV_SIZE = 16;    // AES-256-CTR IV

constexpr char SERVER_PEM_LABEL[] = "OpenVPN tls-crypt-v2 server key";
constexpr char CLIENT_PEM_LABEL[] = "OpenVPN tls-crypt-v2 client key";

/**
 * @brief RAII wrapper for OpenSSL PEM read output.
 */
struct PemReadResult
{
    char *name = nullptr;
    char *header = nullptr;
    unsigned char *data = nullptr;
    long len = 0;

    ~PemReadResult()
    {
        OPENSSL_free(name);
        OPENSSL_free(header);
        if (data)
        {
            OPENSSL_cleanse(data, static_cast<size_t>(len));
            OPENSSL_free(data);
        }
    }

    PemReadResult() = default;
    PemReadResult(const PemReadResult &) = delete;
    PemReadResult &operator=(const PemReadResult &) = delete;
    PemReadResult(PemReadResult &&) = delete;
    PemReadResult &operator=(PemReadResult &&) = delete;
};

/**
 * Read a PEM block from a BIO, verify the label matches expected, and return raw bytes.
 */
std::optional<std::vector<std::uint8_t>> ReadPemFromBio(BIO *bio,
                                                        const char *expected_label,
                                                        spdlog::logger &logger)
{
    PemReadResult pem;
    if (PEM_read_bio(bio, &pem.name, &pem.header, &pem.data, &pem.len) != 1)
    {
        logger.error("Failed to read PEM block");
        return std::nullopt;
    }

    if (std::strcmp(pem.name, expected_label) != 0)
    {
        logger.error("PEM label mismatch: expected '{}', got '{}'",
                     expected_label,
                     pem.name);
        return std::nullopt;
    }

    return std::vector<std::uint8_t>(pem.data, pem.data + pem.len);
}

/**
 * Read a PEM block from a string.
 */
std::optional<std::vector<std::uint8_t>> ReadPemFromString(const std::string &pem_content,
                                                           const char *expected_label,
                                                           spdlog::logger &logger)
{
    BIO *bio = BIO_new_mem_buf(pem_content.data(), static_cast<int>(pem_content.size()));
    if (!bio)
    {
        logger.error("Failed to create BIO for PEM parsing");
        return std::nullopt;
    }

    auto result = ReadPemFromBio(bio, expected_label, logger);
    BIO_free(bio);
    return result;
}

/**
 * Read a PEM block from a file.
 */
std::optional<std::vector<std::uint8_t>> ReadPemFromFile(const std::string &path,
                                                         const char *expected_label,
                                                         spdlog::logger &logger)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
    {
        logger.error("Failed to open PEM file: {}", path);
        return std::nullopt;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    return ReadPemFromString(content, expected_label, logger);
}

/**
 * Write a PEM block to a string.
 */
std::optional<std::string> WritePemToString(const char *label,
                                            std::span<const std::uint8_t> data)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        return std::nullopt;

    if (PEM_write_bio(bio, label, "", data.data(), static_cast<long>(data.size())) == 0)
    {
        BIO_free(bio);
        return std::nullopt;
    }

    char *buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    std::string result(buf, static_cast<size_t>(len));
    BIO_free(bio);
    return result;
}

/**
 * Compute HMAC-SHA256.
 */
std::vector<std::uint8_t> ComputeHmac(std::span<const std::uint8_t> key,
                                      std::span<const std::uint8_t> data)
{
    std::vector<std::uint8_t> hmac(TLS_CRYPT_TAG_SIZE);
    unsigned int hmac_len = 0;

    HMAC(EVP_sha256(),
         key.data(),
         static_cast<int>(key.size()),
         data.data(),
         data.size(),
         hmac.data(),
         &hmac_len);

    if (hmac_len != TLS_CRYPT_TAG_SIZE)
        return {};

    return hmac;
}

} // anonymous namespace

// ── Construction / Destruction ──────────────────────────────────────────────

TlsCryptV2::TlsCryptV2(std::vector<std::uint8_t> server_key, spdlog::logger &logger)
    : server_key_(std::move(server_key)), logger_(&logger)
{
}

TlsCryptV2::~TlsCryptV2()
{
    if (!server_key_.empty())
        OPENSSL_cleanse(server_key_.data(), server_key_.size());
}

TlsCryptV2::TlsCryptV2(TlsCryptV2 &&other) noexcept
    : server_key_(std::move(other.server_key_)), logger_(other.logger_)
{
}

TlsCryptV2 &TlsCryptV2::operator=(TlsCryptV2 &&other) noexcept
{
    if (this != &other)
    {
        if (!server_key_.empty())
            OPENSSL_cleanse(server_key_.data(), server_key_.size());
        server_key_ = std::move(other.server_key_);
        logger_ = other.logger_;
    }
    return *this;
}

// ── Server Key Loading ──────────────────────────────────────────────────────

std::optional<TlsCryptV2> TlsCryptV2::FromKeyFile(const std::string &path, spdlog::logger &logger)
{
    auto data = ReadPemFromFile(path, SERVER_PEM_LABEL, logger);
    if (!data)
        return std::nullopt;

    return FromKeyData(*data, logger);
}

std::optional<TlsCryptV2> TlsCryptV2::FromKeyString(const std::string &pem_content, spdlog::logger &logger)
{
    auto data = ReadPemFromString(pem_content, SERVER_PEM_LABEL, logger);
    if (!data)
        return std::nullopt;

    return FromKeyData(*data, logger);
}

std::optional<TlsCryptV2> TlsCryptV2::FromKeyData(std::span<const std::uint8_t> key_data, spdlog::logger &logger)
{
    if (key_data.size() != TLS_CRYPT_V2_SERVER_KEY_LEN)
    {
        logger.error("Invalid tls-crypt-v2 server key size: {} (expected {})",
                     key_data.size(),
                     TLS_CRYPT_V2_SERVER_KEY_LEN);
        return std::nullopt;
    }

    std::vector<std::uint8_t> key(key_data.begin(), key_data.end());
    return TlsCryptV2(std::move(key), logger);
}

// ── WKc Wrap ────────────────────────────────────────────────────────────────

std::optional<std::vector<std::uint8_t>> TlsCryptV2::WrapClientKey(
    std::span<const std::uint8_t> client_key,
    std::span<const std::uint8_t> metadata) const
{
    if (client_key.size() != TLS_CRYPT_V2_CLIENT_KEY_LEN)
    {
        logger_->error("Invalid client key size: {} (expected {})",
                       client_key.size(),
                       TLS_CRYPT_V2_CLIENT_KEY_LEN);
        return std::nullopt;
    }

    if (metadata.size() > TLS_CRYPT_V2_MAX_METADATA_LEN)
    {
        logger_->error("Metadata too large: {} (max {})", metadata.size(), TLS_CRYPT_V2_MAX_METADATA_LEN);
        return std::nullopt;
    }

    // Calculate sizes per OpenVPN convention:
    // data_len = |Kc| + |metadata| + sizeof(uint16_t)   (uint16_t for net_len itself)
    // tagged_len = data_len + TLS_CRYPT_TAG_SIZE
    // net_len = htons(tagged_len)
    auto data_len = client_key.size() + metadata.size() + sizeof(std::uint16_t);
    auto tagged_len = data_len + TLS_CRYPT_TAG_SIZE;
    // tagged_len is bounded by validated inputs: max = TLS_CRYPT_TAG_SIZE + TLS_CRYPT_V2_CLIENT_KEY_LEN
    // + TLS_CRYPT_V2_MAX_METADATA_LEN + sizeof(uint16_t) = 546, well within uint16_t.
    static_assert(TLS_CRYPT_TAG_SIZE + TLS_CRYPT_V2_CLIENT_KEY_LEN +
                      TLS_CRYPT_V2_MAX_METADATA_LEN + sizeof(std::uint16_t) <=
                  std::numeric_limits<std::uint16_t>::max(),
                  "WKc tagged_len cannot overflow uint16_t given bounded inputs");
    auto net_len = htons(static_cast<std::uint16_t>(tagged_len));

    // Server key layout: cipher[64] + hmac[64]
    // Cipher key: first 32 bytes (CIPHER_KEY_SIZE)
    // HMAC key: bytes 64-95 (offset CIPHER_FIELD_SIZE, length HMAC_KEY_SIZE)
    std::span<const std::uint8_t> cipher_key(server_key_.data(), CIPHER_KEY_SIZE);
    std::span<const std::uint8_t> hmac_key(server_key_.data() + CIPHER_FIELD_SIZE, HMAC_KEY_SIZE);

    // Build HMAC input: net_len || Kc || metadata
    std::vector<std::uint8_t> hmac_input;
    hmac_input.reserve(sizeof(net_len) + client_key.size() + metadata.size());

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) — network byte order
    auto *net_len_bytes = reinterpret_cast<const std::uint8_t *>(&net_len);
    hmac_input.insert(hmac_input.end(), net_len_bytes, net_len_bytes + sizeof(net_len));
    hmac_input.insert(hmac_input.end(), client_key.begin(), client_key.end());
    hmac_input.insert(hmac_input.end(), metadata.begin(), metadata.end());

    auto tag = ComputeHmac(hmac_key, hmac_input);
    if (tag.size() != TLS_CRYPT_TAG_SIZE)
    {
        logger_->error("HMAC computation failed during WKc wrap");
        return std::nullopt;
    }

    // Use first 16 bytes of tag as AES-256-CTR IV (synthetic IV)
    std::span<const std::uint8_t> iv(tag.data(), AES_CTR_IV_SIZE);

    // Encrypt Kc || metadata
    std::vector<std::uint8_t> plaintext;
    plaintext.reserve(client_key.size() + metadata.size());
    plaintext.insert(plaintext.end(), client_key.begin(), client_key.end());
    plaintext.insert(plaintext.end(), metadata.begin(), metadata.end());

    std::vector<std::uint8_t> ciphertext;
    try
    {
        ciphertext = OpenSSL::Encrypt<OpenSSL::AES_256_CTR_TRAITS>(cipher_key, iv, plaintext);
    }
    catch (const OpenSSL::SslException &e)
    {
        logger_->error("AES-256-CTR encryption failed during WKc wrap: {}", e.what());
        return std::nullopt;
    }

    // Build WKc blob: tag || ciphertext || net_len
    std::vector<std::uint8_t> wkc;
    wkc.reserve(tag.size() + ciphertext.size() + sizeof(net_len));
    wkc.insert(wkc.end(), tag.begin(), tag.end());
    wkc.insert(wkc.end(), ciphertext.begin(), ciphertext.end());
    wkc.insert(wkc.end(), net_len_bytes, net_len_bytes + sizeof(net_len));

    return wkc;
}

// ── WKc Unwrap ──────────────────────────────────────────────────────────────

std::optional<TlsCryptV2::UnwrapResult> TlsCryptV2::UnwrapClientKey(
    std::span<const std::uint8_t> wrapped_key) const
{
    if (wrapped_key.size() < TLS_CRYPT_V2_MIN_WKC_LEN)
    {
        logger_->error("WKc blob too small: {} (minimum {})", wrapped_key.size(), TLS_CRYPT_V2_MIN_WKC_LEN);
        return std::nullopt;
    }

    if (wrapped_key.size() > TLS_CRYPT_V2_MAX_WKC_LEN)
    {
        logger_->error("WKc blob too large: {} (maximum {})", wrapped_key.size(), TLS_CRYPT_V2_MAX_WKC_LEN);
        return std::nullopt;
    }

    // Read net_len from last 2 bytes
    std::uint16_t net_len_raw = 0;
    std::memcpy(&net_len_raw,
                wrapped_key.data() + wrapped_key.size() - sizeof(std::uint16_t),
                sizeof(std::uint16_t));
    auto net_len_host = ntohs(net_len_raw);

    if (net_len_host != wrapped_key.size())
    {
        logger_->error("WKc net_len mismatch: {} vs actual size {}", net_len_host, wrapped_key.size());
        return std::nullopt;
    }

    // Extract tag (first 32 bytes)
    std::span<const std::uint8_t> tag(wrapped_key.data(), TLS_CRYPT_TAG_SIZE);

    // Ciphertext is between tag and net_len
    auto ct_begin = wrapped_key.data() + TLS_CRYPT_TAG_SIZE;
    auto ct_size = wrapped_key.size() - TLS_CRYPT_TAG_SIZE - sizeof(std::uint16_t);
    std::span<const std::uint8_t> ciphertext(ct_begin, ct_size);

    // Server key layout: cipher[64] + hmac[64]
    std::span<const std::uint8_t> cipher_key(server_key_.data(), CIPHER_KEY_SIZE);
    std::span<const std::uint8_t> hmac_key(server_key_.data() + CIPHER_FIELD_SIZE, HMAC_KEY_SIZE);

    // Use first 16 bytes of tag as IV
    std::span<const std::uint8_t> iv(tag.data(), AES_CTR_IV_SIZE);

    // Decrypt
    std::vector<std::uint8_t> plaintext;
    try
    {
        plaintext = OpenSSL::Decrypt<OpenSSL::AES_256_CTR_TRAITS>(cipher_key, iv, ciphertext);
    }
    catch (const OpenSSL::SslException &e)
    {
        logger_->error("AES-256-CTR decryption failed during WKc unwrap: {}", e.what());
        return std::nullopt;
    }

    // Verify HMAC over: net_len || plaintext
    std::vector<std::uint8_t> hmac_input;
    hmac_input.reserve(sizeof(net_len_raw) + plaintext.size());

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *net_len_bytes = reinterpret_cast<const std::uint8_t *>(&net_len_raw);
    hmac_input.insert(hmac_input.end(), net_len_bytes, net_len_bytes + sizeof(net_len_raw));
    hmac_input.insert(hmac_input.end(), plaintext.begin(), plaintext.end());

    auto computed_tag = ComputeHmac(hmac_key, hmac_input);
    if (computed_tag.size() != TLS_CRYPT_TAG_SIZE)
    {
        logger_->error("HMAC computation failed during WKc unwrap");
        return std::nullopt;
    }

    // Constant-time comparison
    if (CRYPTO_memcmp(tag.data(), computed_tag.data(), TLS_CRYPT_TAG_SIZE) != 0)
    {
        logger_->error("WKc authentication failed (HMAC mismatch). "
                       "This might be a client key generated for a different server key.");
        return std::nullopt;
    }

    // Extract Kc (first 256 bytes of plaintext)
    if (plaintext.size() < TLS_CRYPT_V2_CLIENT_KEY_LEN)
    {
        logger_->error("Decrypted WKc too short for client key: {}", plaintext.size());
        return std::nullopt;
    }

    UnwrapResult result;
    std::copy_n(plaintext.begin(), TLS_CRYPT_V2_CLIENT_KEY_LEN, result.client_key.begin());
    result.metadata.assign(plaintext.begin() + TLS_CRYPT_V2_CLIENT_KEY_LEN, plaintext.end());

    // Cleanse plaintext (contains key material)
    OPENSSL_cleanse(plaintext.data(), plaintext.size());

    return result;
}

// ── Client Key Generation ───────────────────────────────────────────────────

std::optional<TlsCryptV2::GenerateResult> TlsCryptV2::GenerateClientKey(
    std::span<const std::uint8_t> metadata) const
{
    if (metadata.size() > TLS_CRYPT_V2_MAX_METADATA_LEN)
    {
        logger_->error("Metadata too large for client key generation: {}", metadata.size());
        return std::nullopt;
    }

    // Generate 256 random bytes for Kc
    GenerateResult result;
    if (RAND_bytes(result.client_key.data(), static_cast<int>(result.client_key.size())) != 1)
    {
        logger_->error("RAND_bytes failed generating client key");
        return std::nullopt;
    }

    // Wrap Kc with server key
    auto wkc = WrapClientKey(result.client_key, metadata);
    if (!wkc)
        return std::nullopt;

    result.wkc_blob = std::move(*wkc);
    return result;
}

// ── Client Key File Helpers ─────────────────────────────────────────────────

std::optional<TlsCryptV2::ClientKeyData> TlsCryptV2::LoadClientKeyFile(
    const std::string &path, spdlog::logger &logger)
{
    auto data = ReadPemFromFile(path, CLIENT_PEM_LABEL, logger);
    if (!data)
        return std::nullopt;

    if (data->size() < TLS_CRYPT_V2_CLIENT_KEY_LEN)
    {
        logger.error("Client key file too short: {} bytes (need at least {})",
                     data->size(),
                     TLS_CRYPT_V2_CLIENT_KEY_LEN);
        return std::nullopt;
    }

    ClientKeyData result;
    std::copy_n(data->begin(), TLS_CRYPT_V2_CLIENT_KEY_LEN, result.client_key.begin());
    result.wkc_blob.assign(data->begin() + TLS_CRYPT_V2_CLIENT_KEY_LEN, data->end());

    OPENSSL_cleanse(data->data(), data->size());
    return result;
}

std::optional<TlsCryptV2::ClientKeyData> TlsCryptV2::LoadClientKeyString(
    const std::string &pem_content, spdlog::logger &logger)
{
    auto data = ReadPemFromString(pem_content, CLIENT_PEM_LABEL, logger);
    if (!data)
        return std::nullopt;

    if (data->size() < TLS_CRYPT_V2_CLIENT_KEY_LEN)
    {
        logger.error("Client key data too short: {} bytes (need at least {})",
                     data->size(),
                     TLS_CRYPT_V2_CLIENT_KEY_LEN);
        return std::nullopt;
    }

    ClientKeyData result;
    std::copy_n(data->begin(), TLS_CRYPT_V2_CLIENT_KEY_LEN, result.client_key.begin());
    result.wkc_blob.assign(data->begin() + TLS_CRYPT_V2_CLIENT_KEY_LEN, data->end());

    OPENSSL_cleanse(data->data(), data->size());
    return result;
}

std::optional<std::string> TlsCryptV2::EncodeClientKeyPem(
    std::span<const std::uint8_t> client_key,
    std::span<const std::uint8_t> wkc_blob)
{
    if (client_key.size() != TLS_CRYPT_V2_CLIENT_KEY_LEN)
        return std::nullopt;

    // Concatenate Kc || WKc
    std::vector<std::uint8_t> combined;
    combined.reserve(client_key.size() + wkc_blob.size());
    combined.insert(combined.end(), client_key.begin(), client_key.end());
    combined.insert(combined.end(), wkc_blob.begin(), wkc_blob.end());

    auto result = WritePemToString(CLIENT_PEM_LABEL, combined);
    OPENSSL_cleanse(combined.data(), combined.size());
    return result;
}

} // namespace clv::vpn::openvpn
