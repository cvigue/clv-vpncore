// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_PACKET_H
#define CLV_VPN_OPENVPN_PACKET_H

#include <concepts>
#include <cstdint>
#include <optional>
#include <ranges>
#include <span>
#include <vector>

#include "protocol_constants.h"
#include "spdlog/fmt/bundled/core.h"

namespace clv::vpn::openvpn {

/**
 * @brief OpenVPN packet opcodes (RFC-style documentation)
 * @details Upper 5 bits of first byte determine packet type.
 *
 * Packet format (simplified):
 *   Byte 0: [opcode:5 | key_id:3]
 *   Bytes 1-8: Session ID (optional, depends on opcode)
 *   Bytes N-M: Packet ID (for replay protection)
 *   Remaining: Payload (encrypted or plaintext control)
 */
enum class Opcode : std::uint8_t
{
    // Control channel opcodes (0x20 - 0x60 range)
    P_CONTROL_HARD_RESET_CLIENT_V1 = 0x01, ///< Initial client handshake (deprecated)
    P_CONTROL_HARD_RESET_SERVER_V1 = 0x02, ///< Initial server response (deprecated)
    P_CONTROL_SOFT_RESET_V1 = 0x03,        ///< Renegotiation request
    P_CONTROL_V1 = 0x04,                   ///< Control channel data (TLS)
    P_ACK_V1 = 0x05,                       ///< Control packet acknowledgment
    P_DATA_V1 = 0x06,                      ///< Data channel (encrypted IP packets)

    // Modern control opcodes (OpenVPN 2.4+)
    P_CONTROL_HARD_RESET_CLIENT_V2 = 0x07, ///< Client handshake with tls-auth
    P_CONTROL_HARD_RESET_SERVER_V2 = 0x08, ///< Server response with tls-auth
    P_DATA_V2 = 0x09,                      ///< Data channel with peer-id (modern)
    P_CONTROL_HARD_RESET_CLIENT_V3 = 0x0A, ///< Client handshake with tls-crypt (preferred)
    P_CONTROL_HARD_RESET_SERVER_V3 = 0x0C, ///< Server response with tls-crypt (preferred)
    P_CONTROL_WKC_V1 = 0x0B,               ///< Wrapped client key (tls-crypt-v2)
};

/**
 * @brief Extract opcode from raw packet byte
 * @param first_byte First byte of OpenVPN packet
 * @return Opcode enum value (upper 5 bits)
 */
constexpr Opcode GetOpcode(std::uint8_t first_byte)
{
    return static_cast<Opcode>(first_byte >> 3);
}

/**
 * @brief Extract key ID from raw packet byte
 * @param first_byte First byte of OpenVPN packet
 * @return Key ID (0-7, lower 3 bits)
 */
constexpr std::uint8_t GetKeyId(std::uint8_t first_byte)
{
    return first_byte & KEY_ID_MASK;
}

/**
 * @brief Construct opcode byte from opcode and key ID
 * @param opcode Packet opcode
 * @param key_id Key ID (0-7)
 * @return Packed byte [opcode:5 | key_id:3]
 */
constexpr std::uint8_t MakeOpcodeByte(Opcode opcode, std::uint8_t key_id)
{
    return static_cast<std::uint8_t>((static_cast<std::uint8_t>(opcode) << OPCODE_SHIFT) | (key_id & KEY_ID_MASK));
}

/**
 * @brief Check if opcode is a control channel packet
 */
constexpr bool IsControlPacket(Opcode opcode)
{
    switch (opcode)
    {
    case Opcode::P_CONTROL_HARD_RESET_CLIENT_V1:
    case Opcode::P_CONTROL_HARD_RESET_SERVER_V1:
    case Opcode::P_CONTROL_SOFT_RESET_V1:
    case Opcode::P_CONTROL_V1:
    case Opcode::P_ACK_V1:
    case Opcode::P_CONTROL_HARD_RESET_CLIENT_V2:
    case Opcode::P_CONTROL_HARD_RESET_SERVER_V2:
    case Opcode::P_CONTROL_HARD_RESET_CLIENT_V3:
    case Opcode::P_CONTROL_WKC_V1:
        return true;
    default:
        return false;
    }
}

/**
 * @brief Check if opcode is a data channel packet
 */
constexpr bool IsDataPacket(Opcode opcode)
{
    return opcode == Opcode::P_DATA_V1 || opcode == Opcode::P_DATA_V2;
}

/**
 * @brief Check if opcode is any hard reset (client or server, any version)
 */
constexpr bool IsHardReset(Opcode opcode)
{
    switch (opcode)
    {
    case Opcode::P_CONTROL_HARD_RESET_CLIENT_V1:
    case Opcode::P_CONTROL_HARD_RESET_SERVER_V1:
    case Opcode::P_CONTROL_HARD_RESET_CLIENT_V2:
    case Opcode::P_CONTROL_HARD_RESET_SERVER_V2:
    case Opcode::P_CONTROL_HARD_RESET_CLIENT_V3:
    case Opcode::P_CONTROL_HARD_RESET_SERVER_V3:
        return true;
    default:
        return false;
    }
}

/**
 * @brief Check if opcode is a client hard reset (V1, V2, or V3)
 */
constexpr bool IsHardResetClient(Opcode opcode)
{
    return opcode == Opcode::P_CONTROL_HARD_RESET_CLIENT_V1
           || opcode == Opcode::P_CONTROL_HARD_RESET_CLIENT_V2
           || opcode == Opcode::P_CONTROL_HARD_RESET_CLIENT_V3;
}

/**
 * @brief Check if opcode is a server hard reset (V1, V2, or V3)
 */
constexpr bool IsHardResetServer(Opcode opcode)
{
    return opcode == Opcode::P_CONTROL_HARD_RESET_SERVER_V1
           || opcode == Opcode::P_CONTROL_HARD_RESET_SERVER_V2
           || opcode == Opcode::P_CONTROL_HARD_RESET_SERVER_V3;
}

/**
 * @brief Check if opcode is a soft reset
 */
constexpr bool IsSoftReset(Opcode opcode)
{
    return opcode == Opcode::P_CONTROL_SOFT_RESET_V1;
}

/**
 * @brief Check if opcode is an ACK packet
 */
constexpr bool IsAck(Opcode opcode)
{
    return opcode == Opcode::P_ACK_V1;
}

/**
 * @brief OpenVPN packet structure
 * @details Represents a parsed OpenVPN packet with all fields.
 *
 * Control packets (P_CONTROL_*):
 *   - session_id present
 *   - packet_id_array (may contain multiple IDs for ACKs, max 8)
 *   - hmac (if using tls-auth)
 *   - payload (TLS handshake data, encrypted)
 *
 * Data packets (P_DATA_*):
 *   - packet_id (single counter for replay protection)
 *   - payload (encrypted IP packet)
 *
 * @note Maximum 8 ACKs per packet (OpenVPN standard)
 */
struct OpenVpnPacket
{
    /// Maximum number of ACKs per packet (standard OpenVPN limit)
    static constexpr std::uint8_t MAX_ACK_COUNT = 8;
    Opcode opcode_;                                  ///< Packet type
    std::uint8_t key_id_;                            ///< Key slot (0-7)
    std::optional<std::uint64_t> session_id_;        ///< Session identifier (control packets only)
    std::optional<std::uint64_t> remote_session_id_; ///< Remote session ID (required when ack_count > 0)
    std::optional<std::uint32_t> peer_id_;           ///< Peer ID (P_DATA_V2 only, lower 24 bits used)
    std::optional<std::uint32_t> packet_id_;         ///< Replay protection counter (data packets)
    std::vector<std::uint32_t> packet_id_array_;     ///< ACK array (control packets)
    std::vector<std::uint8_t> payload_;              ///< Encrypted or plaintext data (after TLS-Crypt unwrap)
    std::vector<std::uint8_t> aad_;                  ///< Additional Authenticated Data for AEAD ciphers (packet header)

    // ========== Static Factory Methods ==========

    /**
     * @brief Create a hard reset packet (client or server)
     * @param is_client True for client reset, false for server response
     * @param version Protocol version (1, 2, or 3)
     * @param key_id Key slot (0-7)
     * @param session_id Local session ID
     * @param packet_id Packet sequence number
     * @return Configured packet ready for serialization
     */
    static OpenVpnPacket HardReset(bool is_client, int version, std::uint8_t key_id,
                                   std::uint64_t session_id, std::uint32_t packet_id);

    /**
     * @brief Create a hard reset server response matching client's version
     * @param client_opcode The opcode from the client's hard reset packet
     * @param key_id Key slot (0-7)
     * @param session_id Local session ID
     * @param packet_id Packet sequence number
     * @return Configured packet ready for serialization
     * @note Use withAcks() to add piggybacked ACKs
     */
    static OpenVpnPacket HardResetResponse(Opcode client_opcode, std::uint8_t key_id,
                                           std::uint64_t session_id, std::uint32_t packet_id);

    /**
     * @brief Create a soft reset packet
     * @param key_id Key slot (0-7)
     * @param session_id Local session ID
     * @param packet_id Packet sequence number
     * @return Configured packet ready for serialization
     * @note Use withAcks() to add piggybacked ACKs
     */
    static OpenVpnPacket SoftReset(std::uint8_t key_id, std::uint64_t session_id,
                                   std::uint32_t packet_id);

    /**
     * @brief Create a control channel data packet (P_CONTROL_V1)
     * @param key_id Key slot (0-7)
     * @param session_id Local session ID
     * @param packet_id Packet sequence number
     * @param payload TLS or application data
     * @return Configured packet ready for serialization
     */
    static OpenVpnPacket Control(std::uint8_t key_id, std::uint64_t session_id,
                                 std::uint32_t packet_id, std::vector<std::uint8_t> payload);

    /**
     * @brief Create an ACK-only packet (P_ACK_V1)
     * @param key_id Key slot (0-7)
     * @param session_id Local session ID
     * @param remote_session_id Peer's session ID (required for ACKs)
     * @param ack_ids Packet IDs to acknowledge
     * @return Configured packet ready for serialization
     */
    static OpenVpnPacket Ack(std::uint8_t key_id, std::uint64_t session_id,
                             std::uint64_t remote_session_id, std::vector<std::uint32_t> ack_ids);

    /**
     * @brief Create a data channel packet (P_DATA_V2)
     * @param key_id Key slot (0-7)
     * @param peer_id Peer identifier (24-bit, from session_id)
     * @param packet_id Replay protection counter
     * @return Configured packet ready for encryption and serialization
     * @note Payload should be set after encryption
     */
    static OpenVpnPacket DataV2(std::uint8_t key_id, std::uint32_t peer_id, std::uint32_t packet_id);

    // ========== Modifier Methods ==========

    /**
     * @brief Add piggyback ACKs to this packet
     * @param ack_ids Packet IDs to acknowledge (any range of uint32_t)
     * @param remote_session_id Peer's session ID
     * @return Reference to this packet for chaining
     * @note Truncates to MAX_ACK_COUNT (8) if more ACKs provided
     */
    template <std::ranges::input_range R>
        requires std::same_as<std::ranges::range_value_t<R>, std::uint32_t>
    OpenVpnPacket &withAcks(R &&ack_ids, std::uint64_t remote_session_id)
    {
        auto limited = std::forward<R>(ack_ids) | std::views::take(MAX_ACK_COUNT);
        packet_id_array_.assign(std::ranges::begin(limited), std::ranges::end(limited));
        remote_session_id_ = remote_session_id;
        return *this;
    }

    // ========== Parsing and Serialization ==========

    /**
     * @brief Parse OpenVPN packet from raw bytes
     * @param data Raw packet bytes (UDP payload after TLS-Crypt unwrap)
     * @return Parsed packet or nullopt on error
     */
    static std::optional<OpenVpnPacket> Parse(std::span<const std::uint8_t> data);

    /**
     * @brief Build AAD (Additional Authenticated Data) for AEAD ciphers
     * @return 8-byte AAD: [opcode/key_id/peer_id (4 bytes)] [packet_id (4 bytes)]
     * @note For P_DATA_V2 packets only. Returns empty vector for other packet types.
     * @note AAD is the authenticated-but-not-encrypted packet header.
     */
    std::vector<std::uint8_t> BuildAad() const;

    /**
     * @brief Serialize packet to raw bytes
     * @return Byte vector suitable for UDP transmission
     */
    std::vector<std::uint8_t> Serialize() const;

    /**
     * @brief Check if packet is valid
     */
    bool IsValid() const;

    // ========== Opcode Query Methods ==========

    /// Check if this is a control channel packet
    constexpr bool IsControl() const
    {
        return IsControlPacket(opcode_);
    }

    /// Check if this is a data channel packet
    constexpr bool IsData() const
    {
        return IsDataPacket(opcode_);
    }

    /// Check if this is any hard reset (client or server, any version)
    constexpr bool IsHardReset() const
    {
        return openvpn::IsHardReset(opcode_);
    }

    /// Check if this is a client hard reset (V1, V2, or V3)
    constexpr bool IsHardResetClient() const
    {
        return openvpn::IsHardResetClient(opcode_);
    }

    /// Check if this is a server hard reset (V1, V2, or V3)
    constexpr bool IsHardResetServer() const
    {
        return openvpn::IsHardResetServer(opcode_);
    }

    /// Check if this is a soft reset
    constexpr bool IsSoftReset() const
    {
        return openvpn::IsSoftReset(opcode_);
    }

    /// Check if this is an ACK packet
    constexpr bool IsAck() const
    {
        return openvpn::IsAck(opcode_);
    }
};

/**
 * @brief OpenVPN session ID (64-bit random value)
 * @details Generated once per session for replay protection.
 * Transmitted in network byte order (big-endian).
 */
struct SessionId
{
    std::uint64_t value;

    static SessionId Generate();
    static SessionId FromBytes(std::span<const std::uint8_t> data);
    std::vector<std::uint8_t> ToBytes() const;
};

} // namespace clv::vpn::openvpn

// Add formatter for SessionId to spdlog
namespace fmt {
template <>
struct formatter<clv::vpn::openvpn::SessionId>
{
    template <typename ParseContext>
    constexpr auto parse(ParseContext &ctx)
    {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const clv::vpn::openvpn::SessionId &id, FormatContext &ctx) const
    {
        return fmt::format_to(ctx.out(), "0x{:016x}", id.value);
    }
};
} // namespace fmt

#endif // CLV_VPN_OPENVPN_PACKET_H
