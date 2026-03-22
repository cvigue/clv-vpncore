#include "tls_crypt.h"
#include <log_utils.h>
#include "util/byte_packer.h"

#include <numeric_util.h>
#include <openssl/crypto.h>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <sstream>
#include <HelpSslStreamCipher.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/types.h>
#include <optional>
#include <span>
#include <spdlog/spdlog.h>
#include <string>
#include <utility>
#include <vector>

namespace clv::vpn::openvpn {

namespace {

// OpenVPN static key format: 2048 bits (256 bytes) as hex
constexpr size_t OPENVPN_KEY_SIZE = 256;
constexpr size_t TLS_CRYPT_KEY_SIZE = 32;      // 256 bits
constexpr size_t TLS_CRYPT_TAG_SIZE = 32;      // HMAC-SHA256
constexpr size_t TLS_CRYPT_PACKET_ID_SIZE = 8; // 4-byte timestamp + 4-byte counter

/**
 * Parse hex-encoded key data from a sequence of lines.
 *
 * Recognises the OpenVPN static-key PEM envelope (-----BEGIN / -----END).
 * Skips blank lines and # comments.  Collects pairs of hex digits.
 */
std::optional<std::vector<std::uint8_t>> ParseHexKeyLines(std::istream &input)
{
    std::vector<std::uint8_t> key_data;
    key_data.reserve(OPENVPN_KEY_SIZE);

    std::string line;
    bool in_key = false;

    while (std::getline(input, line))
    {
        if (line.empty() || line[0] == '#')
            continue;
        if (line.find("-----BEGIN") != std::string::npos)
        {
            in_key = true;
            continue;
        }
        if (line.find("-----END") != std::string::npos)
        {
            in_key = false;
            break;
        }
        if (in_key)
        {
            for (size_t i = 0; i < line.length(); ++i)
            {
                if (std::isxdigit(line[i]) && i + 1 < line.length() && std::isxdigit(line[i + 1]))
                {
                    std::string hex_pair = line.substr(i, 2);
                    key_data.push_back(static_cast<std::uint8_t>(std::stoul(hex_pair, nullptr, 16)));
                    ++i;
                }
            }
        }
    }

    if (key_data.size() != OPENVPN_KEY_SIZE)
        return std::nullopt;

    return key_data;
}

/**
 * Parse OpenVPN static key file format
 */
std::optional<std::vector<std::uint8_t>> ParseKeyFile(const std::string &filename, spdlog::logger &logger)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        logger.error("Failed to open TLS-Crypt key file: {}", filename);
        return std::nullopt;
    }

    auto result = ParseHexKeyLines(file);
    if (!result)
    {
        logger.error("Invalid key size in file: {} (expected {})", filename, OPENVPN_KEY_SIZE);
        return std::nullopt;
    }
    return result;
}

/**
 * Compute HMAC-SHA256
 */
std::vector<std::uint8_t> ComputeHmac(std::span<const std::uint8_t> key,
                                      std::span<const std::uint8_t> data,
                                      spdlog::logger &logger)
{
    std::vector<std::uint8_t> hmac(TLS_CRYPT_TAG_SIZE);
    unsigned int hmac_len = 0;

    HMAC(EVP_sha256(),
         key.data(),
         safe_cast<int>(key.size()),
         data.data(),
         data.size(),
         hmac.data(),
         &hmac_len);

    if (hmac_len != TLS_CRYPT_TAG_SIZE)
    {
        logger.error("HMAC size mismatch: {}", hmac_len);
        return {};
    }

    return hmac;
}

} // anonymous namespace

TlsCrypt::TlsCrypt(std::vector<std::uint8_t> key_material, spdlog::logger &logger)
    : key_material_(std::move(key_material)), logger_(&logger)
{
}

std::optional<TlsCrypt> TlsCrypt::FromKeyFile(const std::string &filename, spdlog::logger &logger)
{
    auto key_data = ParseKeyFile(filename, logger);
    if (!key_data)
        return std::nullopt;

    return FromKeyData(*key_data, logger);
}

std::optional<TlsCrypt> TlsCrypt::FromKeyString(const std::string &key_content, spdlog::logger &logger)
{
    std::istringstream stream(key_content);
    auto key_data = ParseHexKeyLines(stream);
    if (!key_data)
    {
        logger.error("Invalid inline key size (expected {})", OPENVPN_KEY_SIZE);
        return std::nullopt;
    }

    return FromKeyData(*key_data, logger);
}

std::optional<TlsCrypt> TlsCrypt::FromKeyData(std::span<const std::uint8_t> key_data, spdlog::logger &logger)
{
    if (key_data.size() != OPENVPN_KEY_SIZE)
    {
        logger.error("Invalid TLS-Crypt key size: {} (expected {})", key_data.size(), OPENVPN_KEY_SIZE);
        return std::nullopt;
    }

    // OpenVPN key layout (256 bytes total, 2 keys of 128 bytes each):
    // struct key { uint8_t cipher[64]; uint8_t hmac[64]; };
    // struct key2 { int n; struct key keys[2]; };
    //
    // keys[0] (bytes 0-127):   Used by SERVER to SEND, CLIENT to RECEIVE
    //   - cipher[0-31]:  AES-256 encrypt key (first 32 bytes used)
    //   - hmac[64-95]:   HMAC-SHA256 key (first 32 bytes used, offset 64 within key)
    //
    // keys[1] (bytes 128-255): Used by SERVER to RECEIVE, CLIENT to SEND
    //   - cipher[128-159]: AES-256 encrypt key
    //   - hmac[192-223]:   HMAC-SHA256 key
    //
    // For server:
    //   Receive from client: decrypt with bytes 128-159, verify with bytes 192-223
    //   Send to client: encrypt with bytes 0-31, sign with bytes 64-95
    //
    // For client:
    //   Receive from server: decrypt with bytes 0-31, verify with bytes 64-95
    //   Send to server: encrypt with bytes 128-159, sign with bytes 192-223

    std::vector<std::uint8_t> key_material(key_data.begin(), key_data.end());
    return TlsCrypt(std::move(key_material), logger);
}

std::optional<std::vector<std::uint8_t>> TlsCrypt::Unwrap(std::span<const std::uint8_t> wrapped,
                                                          bool server_mode)
{
    // OpenVPN tls-crypt wire format:
    // [opcode:1] [session_id:8] [packet_id:8] [hmac:32] [ciphertext]
    //
    // Algorithm:
    // 1. Extract header = opcode || session_id || packet_id (17 bytes)
    // 2. Extract HMAC tag (32 bytes)
    // 3. Use first 16 bytes of HMAC tag as IV for AES-256-CTR
    // 4. Decrypt ciphertext to get plaintext
    // 5. Verify HMAC over: header || plaintext

    constexpr size_t SESSION_ID_SIZE = 8;
    constexpr size_t HEADER_SIZE = 1 + SESSION_ID_SIZE + TLS_CRYPT_PACKET_ID_SIZE; // 17 bytes
    constexpr size_t MIN_PACKET_SIZE = HEADER_SIZE + TLS_CRYPT_TAG_SIZE;           // 49 bytes minimum

    if (wrapped.size() < MIN_PACKET_SIZE)
    {
        logger_->error("Packet too small for tls-crypt: {} bytes", wrapped.size());
        return std::nullopt;
    }

    // Debug: show first 60 bytes of wrapped packet
    if (logger_->should_log(spdlog::level::trace))
    {
        logger_->trace("TLS-Crypt Unwrap - first 60 bytes: {}", HexDump(wrapped));
    }

    // Extract header (bytes 0-16: opcode + session_id + packet_id)
    std::vector<std::uint8_t> header(wrapped.begin(), wrapped.begin() + HEADER_SIZE);

    // Extract HMAC tag (bytes 17-48)
    constexpr size_t HMAC_OFFSET = HEADER_SIZE;
    auto hmac_tag = std::vector<std::uint8_t>(wrapped.begin() + HMAC_OFFSET,
                                              wrapped.begin() + HMAC_OFFSET + TLS_CRYPT_TAG_SIZE);

    // Ciphertext starts after HMAC tag (byte 49+)
    constexpr size_t CT_OFFSET = HEADER_SIZE + TLS_CRYPT_TAG_SIZE;
    std::vector<std::uint8_t> ciphertext(wrapped.begin() + CT_OFFSET, wrapped.end());

    // Select decryption key based on direction:
    // Server decrypts client packets: use keys[1].cipher (bytes 128-159)
    // Client decrypts server packets: use keys[0].cipher (bytes 0-31)
    size_t decrypt_key_offset = server_mode ? 128 : 0;
    const std::uint8_t *decrypt_key = key_material_.data() + decrypt_key_offset;

    // Use first 16 bytes of HMAC tag as IV (the "synthetic IV" in OpenVPN's SIV construction)
    std::vector<std::uint8_t> iv(hmac_tag.begin(), hmac_tag.begin() + 16);

    // Decrypt ciphertext using RAII cipher context
    std::span<const std::uint8_t> key_span(decrypt_key, TLS_CRYPT_KEY_SIZE);
    std::vector<std::uint8_t> plaintext;
    try
    {
        plaintext = OpenSSL::Decrypt<OpenSSL::AES_256_CTR_TRAITS>(key_span, iv, ciphertext);
    }
    catch (const OpenSSL::SslException &e)
    {
        logger_->error("AES-256-CTR decryption failed: {}", e.what());
        return std::nullopt;
    }

    // Verify HMAC over: header || plaintext (DECRYPTED data!)
    std::vector<std::uint8_t> hmac_data;
    hmac_data.insert(hmac_data.end(), header.begin(), header.end());
    hmac_data.insert(hmac_data.end(), plaintext.begin(), plaintext.end());

    // Select HMAC verification key based on direction:
    // Server receives from client: verify with keys[1].hmac (bytes 192-223)
    // Client receives from server: verify with keys[0].hmac (bytes 64-95)
    size_t hmac_key_offset = server_mode ? 192 : 64;
    std::vector<std::uint8_t> verify_key(key_material_.begin() + hmac_key_offset,
                                         key_material_.begin() + hmac_key_offset + TLS_CRYPT_KEY_SIZE);

    auto computed_hmac = ComputeHmac(verify_key, hmac_data, *logger_);

    // Constant-time comparison to prevent timing side-channels
    bool hmac_ok = (computed_hmac.size() == hmac_tag.size())
                   && (CRYPTO_memcmp(computed_hmac.data(), hmac_tag.data(), hmac_tag.size()) == 0);

    if (!hmac_ok)
    {
        if (logger_->should_log(spdlog::level::trace))
        {
            logger_->error("HMAC verification failed");
            logger_->trace("  HMAC key offset: {} (server_mode={})", hmac_key_offset, server_mode);
            logger_->trace("  Received HMAC: {}...", HexDump(hmac_tag, 8, ""));
            logger_->trace("  Computed HMAC: {}...", HexDump(computed_hmac, 8, ""));
            logger_->trace("  Decrypted plaintext (first 20 bytes): {}...", HexDump(plaintext, 20, ""));
        }
        else
        {
            logger_->error("HMAC verification failed");
        }
        return std::nullopt;
    }

    // Validate packet ID (replay protection for TLS-Crypt wrapper)
    // packet_id is at header bytes 9-16 (after opcode and session_id)
    std::uint64_t packet_id = 0;
    for (size_t i = 0; i < TLS_CRYPT_PACKET_ID_SIZE; ++i)
    {
        packet_id = (packet_id << 8) | header[1 + SESSION_ID_SIZE + i];
    }

    // Extract session_id for per-session replay protection
    std::uint64_t session_id = 0;
    for (size_t i = 0; i < SESSION_ID_SIZE; ++i)
    {
        session_id = (session_id << 8) | header[1 + i];
    }

    // Check replay per-session
    auto &last_packet_id = session_packet_ids_[session_id];
    if (packet_id <= last_packet_id)
    {
        logger_->warn("Replay attack detected: session {:016x} tls_crypt packet_id {} <= {}",
                      session_id,
                      packet_id,
                      last_packet_id);
        return std::nullopt;
    }
    last_packet_id = packet_id;

    // Return: [opcode] [session_id] [plaintext]
    // The tls_crypt packet_id is NOT included - it's only for wrapper replay protection
    // The control channel expects: [opcode][session_id][ack_array][control_packet_id][payload]
    std::vector<std::uint8_t> result;
    result.push_back(header[0]);                                                           // opcode
    result.insert(result.end(), header.begin() + 1, header.begin() + 1 + SESSION_ID_SIZE); // session_id
    result.insert(result.end(), plaintext.begin(), plaintext.end());                       // decrypted payload

    return result;
}

std::optional<std::vector<std::uint8_t>> TlsCrypt::Wrap(std::span<const std::uint8_t> plaintext,
                                                        bool server_mode)
{
    // OpenVPN tls-crypt wire format:
    // Input plaintext: [opcode:1] [session_id:8] [payload...]
    // Output: [opcode:1] [session_id:8] [packet_id:8] [hmac:32] [encrypted_payload]
    //
    // Algorithm:
    // 1. Build header = opcode || session_id || packet_id
    // 2. Compute HMAC over: header || payload
    // 3. Use first 16 bytes of HMAC as IV for AES-256-CTR
    // 4. Encrypt payload
    // 5. Output: header || hmac || ciphertext

    constexpr size_t SESSION_ID_SIZE = 8;
    constexpr size_t MIN_INPUT_SIZE = 1 + SESSION_ID_SIZE; // opcode + session_id

    if (plaintext.size() < MIN_INPUT_SIZE)
        return std::nullopt;

    // Extract opcode and session_id from input
    const std::uint8_t opcode = plaintext[0];
    std::uint64_t session_id = netcore::read_uint<8>(plaintext.subspan(1, SESSION_ID_SIZE));
    auto payload = std::span<const std::uint8_t>(plaintext.begin() + 1 + SESSION_ID_SIZE, plaintext.end());

    // Increment TLS-Crypt wrapper packet ID counter
    ++tls_crypt_packet_id_send_;

    // Build header: opcode || session_id || packet_id (counter || timestamp)
    // packet_id format: [4-byte counter][4-byte timestamp] (network byte order)
    auto now = static_cast<std::uint32_t>(std::time(nullptr));
    auto counter = static_cast<std::uint32_t>(tls_crypt_packet_id_send_);
    auto header = netcore::multi_uint_to_bytes(opcode, session_id, counter, now);

    // Build HMAC data: header || payload (BEFORE encryption!)
    std::vector<std::uint8_t> hmac_data;
    hmac_data.insert(hmac_data.end(), header.begin(), header.end());
    hmac_data.insert(hmac_data.end(), payload.begin(), payload.end());

    // Select HMAC signing key based on direction:
    // Server sends to client: sign with keys[0].hmac (bytes 64-95)
    // Client sends to server: sign with keys[1].hmac (bytes 192-223)
    size_t hmac_key_offset = server_mode ? 64 : 192;
    std::vector<std::uint8_t> sign_key(key_material_.begin() + hmac_key_offset,
                                       key_material_.begin() + hmac_key_offset + TLS_CRYPT_KEY_SIZE);

    auto hmac_tag = ComputeHmac(sign_key, hmac_data, *logger_);
    if (hmac_tag.empty())
        return std::nullopt;

    // Use first 16 bytes of HMAC as IV (the "synthetic IV")
    std::vector<std::uint8_t> iv(hmac_tag.begin(), hmac_tag.begin() + 16);

    // Select encryption key based on direction:
    // Server encrypts to client: use keys[0].cipher (bytes 0-31)
    // Client encrypts to server: use keys[1].cipher (bytes 128-159)
    size_t encrypt_key_offset = server_mode ? 0 : 128;
    const std::uint8_t *encrypt_key = key_material_.data() + encrypt_key_offset;

    // Encrypt payload using AES-256-CTR with HMAC-derived IV (RAII cipher context)
    std::span<const std::uint8_t> key_span(encrypt_key, TLS_CRYPT_KEY_SIZE);
    std::vector<std::uint8_t> ciphertext;
    try
    {
        ciphertext = OpenSSL::Encrypt<OpenSSL::AES_256_CTR_TRAITS>(key_span, iv, payload);
    }
    catch (const OpenSSL::SslException &e)
    {
        logger_->error("AES-256-CTR encryption failed: {}", e.what());
        return std::nullopt;
    }

    // Build final packet: header || hmac || ciphertext
    std::vector<std::uint8_t> result;
    result.insert(result.end(), header.begin(), header.end());
    result.insert(result.end(), hmac_tag.begin(), hmac_tag.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    return result;
}

} // namespace clv::vpn::openvpn
