// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_PSID_COOKIE_H
#define CLV_VPN_OPENVPN_PSID_COOKIE_H

/**
 * @file psid_cookie.h
 * @brief OpenVPN-compatible HMAC session-id (psid) cookie helpers.
 *
 * Server-local SYN-cookie style defense: derive the server's 64-bit protocol
 * session ID from HMAC-SHA256(secret, time_bucket || sockaddr || client_sid)
 * so session/TLS state can be deferred until the client echoes the cookie.
 *
 * Matches OpenVPN 2's calculate_session_id_hmac / check_session_id_hmac
 * (bucket offsets -2..1). See _planning/psid-cookie.md.
 */

#include "openvpn/packet.h"

#include <util/byte_packer.h>

#include <asio/ip/address.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace clv::vpn::openvpn {

/** @brief Early-negotiation marker in the tls-crypt wrapper packet-id counter. */
inline constexpr std::uint32_t EARLY_NEG_MASK = 0xff000000u;
inline constexpr std::uint32_t EARLY_NEG_START = 0x0f000000u;

/** @brief HARD_RESET payload TLV: early-negotiation flags (OpenVPN ssl_pkt.h). */
inline constexpr std::uint16_t TLV_TYPE_EARLY_NEG_FLAGS = 0x0001;
inline constexpr std::uint16_t EARLY_NEG_FLAG_RESEND_WKC = 0x0001;

/** @brief OpenVPN control TLV framing: [type:u16][length:u16][value...]. */
inline constexpr std::size_t kTlvTypeSize = 2;
inline constexpr std::size_t kTlvLengthSize = 2;
inline constexpr std::size_t kTlvHeaderSize = kTlvTypeSize + kTlvLengthSize;
/** @brief Length of the EARLY_NEG_FLAGS value (flags u16). */
inline constexpr std::uint16_t kEarlyNegFlagsLength = 2;

/** @brief Default handshake_window (seconds) used as cookie time-bucket size. */
inline constexpr int kDefaultHandshakeWindow = 60;

/**
 * @brief Process-lifetime HMAC key for psid cookies (32 random bytes).
 */
class PsidCookieKey
{
  public:
    /** @brief Generate a fresh random key (SHA-256 length). */
    [[nodiscard]] static PsidCookieKey Generate();

    /** @brief Construct from explicit key material (tests). Must be 32 bytes. */
    [[nodiscard]] static std::optional<PsidCookieKey> FromBytes(std::span<const std::uint8_t> key);

    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept
    {
        return key_;
    }

  private:
    explicit PsidCookieKey(std::array<std::uint8_t, 32> key)
        : key_(key)
    {
    }

    std::array<std::uint8_t, 32> key_{};
};

/**
 * @brief Peer address+port used as HMAC input (matches OpenVPN sockaddr packing).
 */
struct PsidCookieEndpoint
{
    asio::ip::address addr;
    std::uint16_t port = 0;
};

/**
 * @brief Derive the server session-id cookie for one time-bucket offset.
 *
 * @param key            Server HMAC secret
 * @param client_sid     Client's protocol session ID (host uint64; fed as BE wire bytes)
 * @param endpoint       Client source address/port
 * @param handshake_window  OpenVPN handshake_window (seconds); bucket = handwindow/2
 * @param offset         Added to time_bucket (OpenVPN 2 verify uses -2..1)
 * @param now_seconds    Wall clock seconds since epoch (injectable for tests)
 */
[[nodiscard]] SessionId CalculateSessionIdHmac(const PsidCookieKey &key,
                                               SessionId client_sid,
                                               const PsidCookieEndpoint &endpoint,
                                               int handshake_window,
                                               int offset,
                                               std::uint32_t now_seconds);

/**
 * @brief True if @p server_sid matches HMAC for any offset in [-2, 1].
 */
[[nodiscard]] bool CheckSessionIdHmac(const PsidCookieKey &key,
                                      SessionId server_sid,
                                      SessionId client_sid,
                                      const PsidCookieEndpoint &endpoint,
                                      int handshake_window,
                                      std::uint32_t now_seconds);

/**
 * @brief Pack OpenVPN early-neg flags TLV into HARD_RESET payload.
 *
 * Layout: [type:u16 BE][length:u16 BE][flags:u16 BE], type=1, length=2,
 * flags includes EARLY_NEG_FLAG_RESEND_WKC.
 */
[[nodiscard]] std::vector<std::uint8_t> BuildEarlyNegFlagsTlv(std::uint16_t flags = EARLY_NEG_FLAG_RESEND_WKC);

/**
 * @brief Parse early-neg flags from a HARD_RESET_SERVER payload.
 * @return flags value if TLV present; nullopt otherwise.
 */
[[nodiscard]] std::optional<std::uint16_t> ParseEarlyNegFlagsTlv(std::span<const std::uint8_t> payload);

/**
 * @brief True if tls-crypt wrapper counter advertises early negotiation.
 *
 * Counter is the high 32 bits of the 64-bit wire packet_id
 * (counter << 32 | timestamp). Matches `(id & EARLY_NEG_MASK) == EARLY_NEG_START`.
 */
[[nodiscard]] constexpr bool SupportsEarlyNegotiation(std::uint32_t tls_crypt_counter) noexcept
{
    return (tls_crypt_counter & EARLY_NEG_MASK) == EARLY_NEG_START;
}

/**
 * @brief Build a stateless HARD_RESET_SERVER challenge (no ControlChannel).
 *
 * @param client_opcode   Client HARD_RESET opcode (selects response opcode)
 * @param server_sid      Cookie session id
 * @param client_sid      Peer's session id (for ACK remote_session_id)
 * @param ack_packet_id   Client control packet_id to ACK (usually 0)
 * @param key_id          Key slot from client packet
 * @param payload         Optional TLV payload (V2 early-neg flags)
 * @param our_packet_id   Server control packet_id (usually 0)
 * @param force_server_v2 When true, emit P_CONTROL_HARD_RESET_SERVER_V2
 *                        (OpenVPN cookie path for tls-crypt-v2 early-neg)
 */
[[nodiscard]] OpenVpnPacket BuildCookieHardResetResponse(Opcode client_opcode,
                                                         std::uint64_t server_sid,
                                                         std::uint64_t client_sid,
                                                         std::uint32_t ack_packet_id,
                                                         std::uint8_t key_id,
                                                         std::vector<std::uint8_t> payload = {},
                                                         std::uint32_t our_packet_id = 0,
                                                         bool force_server_v2 = false);

/**
 * @brief Peek tls-crypt wrapper packet-id counter (high 32 bits) from wire bytes.
 *
 * Layout: [opcode:1][session_id:8][counter:4][timestamp:4]...
 */
[[nodiscard]] inline std::optional<std::uint32_t>
PeekWireTlsCryptCounter(std::span<const std::uint8_t> data) noexcept
{
    constexpr std::size_t kNeed = 1 + 8 + 4;
    if (data.size() < kNeed)
        return std::nullopt;
    return static_cast<std::uint32_t>(clv::netcore::read_uint<4>(data.subspan(1 + 8)));
}

/**
 * @brief Validate that a pre-session control packet carries a plausible cookie echo.
 *
 * Requires ack_count == 1, ack id and own packet_id in {0,1} (own id skipped for P_ACK_V1),
 * and remote_session_id present. Does not verify HMAC (caller does).
 */
[[nodiscard]] bool IsEarlyHandshakeCookieEcho(const OpenVpnPacket &packet, bool has_own_packet_id);

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_PSID_COOKIE_H
