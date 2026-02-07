// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_PROTOCOL_CONSTANTS_H
#define CLV_VPN_OPENVPN_PROTOCOL_CONSTANTS_H

#include <cstddef>
#include <cstdint>

namespace clv::vpn::openvpn {

// ================================================================================================
// OpenVPN Protocol Bit Masks and Sizes
// ================================================================================================

/**
 * @brief Key ID field mask (lower 3 bits of opcode byte)
 * @note OpenVPN protocol spec: key_id occupies bits 0-2
 */
constexpr std::uint8_t KEY_ID_MASK = 0x07;

/**
 * @brief Opcode field shift (upper 5 bits of opcode byte)
 * @note OpenVPN protocol spec: opcode occupies bits 3-7
 */
constexpr std::uint8_t OPCODE_SHIFT = 3;

/**
 * @brief Peer ID mask (lower 24 bits)
 * @note Used in P_DATA_V2 packets to identify client sessions
 */
constexpr std::uint32_t PEER_ID_MASK = 0x00FFFFFF;

/**
 * @brief Maximum valid key ID value
 * @note Valid range: 0-7 (3 bits)
 */
constexpr std::uint8_t MAX_KEY_ID = 7;

/**
 * @brief IPv4 version nibble mask
 * @note Used to extract version from first byte of IP packet
 */
constexpr std::uint8_t IP_VERSION_MASK = 0x0F;

/**
 * @brief IPv4 version nibble shift
 * @note IP version is in upper 4 bits of first byte
 */
constexpr std::uint8_t IP_VERSION_SHIFT = 4;

/**
 * @brief Byte mask for extracting single byte
 * @note Used in IP address formatting and byte extraction
 */
constexpr std::uint32_t BYTE_MASK = 0xFF;

// ================================================================================================
// OpenVPN Key-Method 2 Constants
// ================================================================================================

/**
 * @brief Client random data size for key-method 2 exchange
 * @details Composed of pre_master(48) + random1(32) + random2(32)
 */
constexpr std::size_t CLIENT_KEY_SOURCE_SIZE = 112;

/**
 * @brief Server random data size for key-method 2 exchange
 * @details Composed of random1(32) + random2(32)
 */
constexpr std::size_t SERVER_KEY_SOURCE_SIZE = 64;

/**
 * @brief Default key transition window in seconds
 * @details After key renegotiation, old ("lame duck") keys remain valid
 *          for this duration so in-flight packets are not dropped.
 */
constexpr int KEY_TRANSITION_WINDOW_SECONDS = 120;

// ================================================================================================
// OpenVPN Compression Framing Bytes
// ================================================================================================

/**
 * @brief NO_COMPRESS framing byte — payload is uncompressed
 * @note Prepended to data channel payloads when compression framing is negotiated
 */
constexpr std::uint8_t COMPRESS_NONE = 0xFA;

/**
 * @brief COMP_STUB (LZO no-op) framing byte — payload is uncompressed
 * @note Sent by clients configured with \c comp-lzo\ when data is not actually compressed
 */
constexpr std::uint8_t COMPRESS_STUB_LZO = 0xFB;

// ================================================================================================
// OpenVPN Keepalive / Internal Ping
// ================================================================================================

/**
 * @brief Size of the OpenVPN keepalive ping payload (bytes)
 */
constexpr std::size_t KEEPALIVE_PING_SIZE = 16;

/**
 * @brief OpenVPN internal keepalive ping magic payload
 * @details Exact 16-byte pattern used by all OpenVPN implementations
 */
constexpr std::uint8_t KEEPALIVE_PING_PAYLOAD[KEEPALIVE_PING_SIZE] = {
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48};

// ================================================================================================
// IPv4 Packet Constants
// ================================================================================================

/** @brief Minimum IPv4 header length in bytes */
constexpr std::size_t IPV4_MIN_HEADER_SIZE = 20;

/** @brief IPv4 version nibble value */
constexpr std::uint8_t IP_VERSION_4 = 4;

/** @brief IPv6 version nibble value */
constexpr std::uint8_t IP_VERSION_6 = 6;

// ================================================================================================
// TCP Framing Limits
// ================================================================================================

/**
 * @brief Maximum allowed TCP frame payload (bytes).
 * @details Standard MTU (1500) + P_DATA_V2 header (4) + AEAD overhead (49)
 *          rounded up with headroom.  Frames larger than this are rejected
 *          to prevent memory-amplification attacks over TCP.
 */
constexpr std::uint16_t MAX_TCP_FRAME_SIZE = 1600;

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_PROTOCOL_CONSTANTS_H
