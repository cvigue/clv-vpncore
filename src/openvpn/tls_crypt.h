// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_TLS_CRYPT_H
#define CLV_VPN_OPENVPN_TLS_CRYPT_H

#include "openvpn/crypto_context.h"

#include <not_null.h>
#include <util/byte_packer.h>

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
 * @brief Session-scoped tls-crypt inbound anti-replay state
 *
 * Wire packet_id is [4-byte counter][4-byte timestamp]; the sliding window
 * tracks the 32-bit counter only (see _planning/tls-crypt-replay-state.md §5).
 * Owned by Connection (server) or the client control adapter — not by TlsCrypt.
 */
class TlsCryptReplayState
{
  public:
    /** HMAC-verified wire packet_id: derive counter, accept if in-window and unseen. */
    [[nodiscard]] bool CheckAndAccept(std::uint64_t packet_id) noexcept
    {
        const auto counter = static_cast<std::uint32_t>(packet_id >> 32);
        if (window_.Check(counter) != ReplayWindow::CheckResult::Accept)
            return false;
        window_.Accept(counter);
        return true;
    }

    /** @brief Clear the replay window (new session key). */
    void Reset() noexcept
    {
        window_.Reset();
    }

    /** @brief Highest accepted packet ID in the replay window. */
    [[nodiscard]] std::uint32_t highest() const noexcept
    {
        return window_.highest_id();
    }

  private:
    ReplayWindow window_;
};

/**
 * @brief Peek the cleartext session_id from a tls-crypt (or control) header
 *
 * Layout: [opcode:1][session_id:8][...]. Safe before HMAC — the id is not encrypted.
 */
[[nodiscard]] inline std::optional<std::uint64_t>
PeekWireSessionId(std::span<const std::uint8_t> data) noexcept
{
    constexpr std::size_t kNeed = 1 + 8;
    if (data.size() < kNeed)
        return std::nullopt;
    return clv::netcore::read_uint<8>(data.subspan(1));
}

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
 *
 * Inbound replay state is session-scoped and passed into Unwrap by the caller
 * (TlsCryptReplayState). The outbound send counter remains key-scoped here.
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
     * @param replay Session-scoped anti-replay state (updated on success)
     * @return Unwrapped packet data or nullopt on error
     */
    std::optional<std::vector<std::uint8_t>> Unwrap(std::span<const std::uint8_t> wrapped,
                                                    bool server_mode,
                                                    TlsCryptReplayState &replay);

    /**
     * @brief Wrap (encrypt and authenticate) a control packet
     * @param plaintext Plaintext packet (including opcode)
     * @param server_mode Whether we're operating as server
     * @param counter_override If set, use this tls-crypt wrapper counter instead of
     *        the internal send counter (e.g. EARLY_NEG_START = 0x0f000000). Does not
     *        advance the internal counter when overridden.
     * @return Wrapped packet data or nullopt on error
     */
    std::optional<std::vector<std::uint8_t>> Wrap(std::span<const std::uint8_t> plaintext,
                                                  bool server_mode,
                                                  std::optional<std::uint32_t> counter_override = std::nullopt);

  private:
    TlsCrypt(std::vector<std::uint8_t> key_material, spdlog::logger &logger);

    std::vector<std::uint8_t> key_material_; ///< Full 256-byte key material (2 keys: cipher+hmac for each direction)
    /** Outbound wrapper packet-id counter (high 32 bits on the wire; timestamp is separate). */
    std::uint64_t tls_crypt_packet_id_send_{0};
    clv::not_null<spdlog::logger *> logger_; ///< Logger for debug output (never null)
};

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_TLS_CRYPT_H
