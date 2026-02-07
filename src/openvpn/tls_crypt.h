#pragma once

#include <not_null.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace spdlog {
class logger;
}

namespace clv::vpn::openvpn {

/**
 * @brief TLS-Crypt wrapper for OpenVPN control channel encryption
 *
 * Implements the tls-crypt protocol which encrypts control channel packets
 * using a pre-shared key. This provides:
 * - Authentication of control packets before TLS handshake
 * - Protection against DoS attacks
 * - Obfuscation of control channel traffic
 *
 * Wire format:
 * [opcode:1] [session_id:8] [packet_id:8] [hmac_tag:32] [encrypted_payload]
 *
 * header = opcode || session_id || packet_id (17 bytes)
 * auth_tag = HMAC-SHA256(Ka, header || plaintext)
 * IV = first 16 bytes of auth_tag
 * ciphertext = AES-256-CTR(Ke, IV, plaintext)
 *
 * Key layout (128 bytes from static key file):
 * - Bytes 0-31:   Client encrypt key (client uses to encrypt TO server)
 * - Bytes 32-63:  Client HMAC key (client uses to sign TO server)
 * - Bytes 64-95:  Server encrypt key (server uses to encrypt TO client)
 * - Bytes 96-127: Server HMAC key (server uses to sign TO client)
 */
class TlsCrypt
{
  public:
    /**
     * @brief Initialize TLS-Crypt with a key file
     * @param key_file Path to OpenVPN static key file
     * @param logger Logger for debug output
     * @return true if successful
     */
    static std::optional<TlsCrypt> FromKeyFile(const std::string &key_file, spdlog::logger &logger);

    /**
     * @brief Initialize TLS-Crypt with raw key material
     * @param key_data 256 bytes of key material
     * @param logger Logger for debug output
     * @return TlsCrypt instance or nullopt on error
     */
    static std::optional<TlsCrypt> FromKeyData(std::span<const std::uint8_t> key_data, spdlog::logger &logger);

    /**
     * @brief Initialize TLS-Crypt from inline key string content
     * @param key_content The content of an OpenVPN static key (same hex format as key file)
     * @param logger Logger for debug output
     * @return TlsCrypt instance or nullopt on error
     */
    static std::optional<TlsCrypt> FromKeyString(const std::string &key_content, spdlog::logger &logger);

    /**
     * @brief Unwrap (decrypt and verify) a tls-crypt packet
     * @param wrapped Wrapped packet data (including opcode)
     * @param server_mode Whether we're operating as server
     * @return Unwrapped packet data or nullopt on error
     */
    std::optional<std::vector<std::uint8_t>> Unwrap(std::span<const std::uint8_t> wrapped,
                                                    bool server_mode);

    /**
     * @brief Wrap (encrypt and authenticate) a control packet
     * @param plaintext Plaintext packet (including opcode)
     * @param server_mode Whether we're operating as server
     * @return Wrapped packet data or nullopt on error
     */
    std::optional<std::vector<std::uint8_t>> Wrap(std::span<const std::uint8_t> plaintext,
                                                  bool server_mode);

  private:
    TlsCrypt(std::vector<std::uint8_t> key_material, spdlog::logger &logger);

    std::vector<std::uint8_t> key_material_;    ///< Full 256-byte key material (2 keys: cipher+hmac for each direction)
    std::uint64_t tls_crypt_packet_id_send_{0}; ///< TLS-Crypt wrapper packet ID for sending (8-byte: timestamp + counter)
    clv::not_null<spdlog::logger *> logger_;    ///< Logger for debug output (never null)

    /// Per-session replay protection: maps session_id to last received packet_id
    std::unordered_map<std::uint64_t, std::uint64_t> session_packet_ids_;
};

} // namespace clv::vpn::openvpn
