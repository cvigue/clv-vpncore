// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_PROTOCOL_CONSTANTS_H
#define CLV_VPN_OPENVPN_PROTOCOL_CONSTANTS_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

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

/**
 * @brief Test whether a decrypted payload is the keepalive ping magic.
 */
inline bool IsKeepalivePing(const std::uint8_t *data, std::size_t len) noexcept
{
    return len == KEEPALIVE_PING_SIZE
           && std::memcmp(data, KEEPALIVE_PING_PAYLOAD, KEEPALIVE_PING_SIZE) == 0;
}

/** @overload Accepts a std::span. */
inline bool IsKeepalivePing(std::span<const std::uint8_t> buf) noexcept
{
    return IsKeepalivePing(buf.data(), buf.size());
}

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
// Framing Limits
// ================================================================================================

/**
 * @brief Maximum allowed TCP frame payload (bytes).
 * @details Standard MTU (1500) + P_DATA_V2 header (4) + AEAD overhead (49)
 *          rounded up with headroom.  Frames larger than this are rejected
 *          to prevent memory-amplification attacks over TCP.
 */
constexpr std::uint16_t MAX_TCP_FRAME_SIZE = 1600;

/**
 * @brief Receive buffer size for single-datagram UDP reads (bytes).
 * @details Used by `UdpTransport::Receive()` for control-plane packets.
 *          Sized above the link-MTU ceiling (jumbo frames aside) so that
 *          any standards-compliant OpenVPN datagram fits without truncation.
 */
constexpr std::size_t MAX_UDP_RECEIVE_SIZE = 4096;

// ================================================================================================
// IV_PROTO Peer-Capability Bitmask (sent in peer-info as IV_PROTO=<n>)
//
// These bits are OR'd together and announced by the client during the TLS
// key-method 2 handshake so the server knows which features it may push.
// Any client that sets any bit MUST also set IV_PROTO_DATA_V2 (bit 1),
// because older servers compare IV_PROTO >= 2 to enable P_DATA_V2.
//
// Currently this client sends no peer-info at all, so none of these bits
// are advertised.  Add a bit to the outgoing peer-info string only after
// the corresponding receive-side handling is implemented.
// ================================================================================================

/** Support P_DATA_V2 (mandatory companion bit for all other IV_PROTO flags) */
constexpr std::uint32_t IV_PROTO_DATA_V2 = (1u << 1);

/** Client will not wait for server PUSH_REQUEST before sending PUSH_REPLY */
constexpr std::uint32_t IV_PROTO_REQUEST_PUSH = (1u << 2);

/** Data-channel key derivation via TLS key material exporter [RFC 5705] */
constexpr std::uint32_t IV_PROTO_TLS_KEY_EXPORT = (1u << 3);

/** Supports keyword arguments in AUTH_PENDING (e.g. timeout=xy) */
constexpr std::uint32_t IV_PROTO_AUTH_PENDING_KW = (1u << 4);

/** Supports NCP cipher negotiation in P2P mode */
constexpr std::uint32_t IV_PROTO_NCP_P2P = (1u << 5);

/** Supports the --dns option (v2.6 era, superseded — do not send) */
constexpr std::uint32_t IV_PROTO_DNS_OPTION = (1u << 6);

/** Supports explicit exit notify via control channel */
constexpr std::uint32_t IV_PROTO_CC_EXIT_NOTIFY = (1u << 7);

/** Supports AUTH_FAIL,TEMP messages */
constexpr std::uint32_t IV_PROTO_AUTH_FAIL_TEMP = (1u << 8);

/** Supports dynamic tls-crypt (renegotiation with TLS-EKM derived key) */
constexpr std::uint32_t IV_PROTO_DYN_TLS_CRYPT = (1u << 9);

/** Supports extended packet-id / epoch format for data-channel packets */
constexpr std::uint32_t IV_PROTO_DATA_EPOCH = (1u << 10);

/**
 * Supports the --dns option in its stable post-2.6 form.
 * When this bit is present the server MAY push:
 *   dns server <n> address <addr[:port]> [...]
 *   dns server <n> resolve-domains <domain> [...]
 *   dns search-domains <domain> [...]
 * instead of (or in addition to) legacy dhcp-option DNS/DNS6/DOMAIN entries.
 * Do NOT advertise until config_exchange can parse dns server ... options.
 */
constexpr std::uint32_t IV_PROTO_DNS_OPTION_V2 = (1u << 11);

/** Supports PUSH_UPDATE (incremental push changes after connection is up) */
constexpr std::uint32_t IV_PROTO_PUSH_UPDATE = (1u << 12);

// ================================================================================================
// IV_PROTO helpers
// ================================================================================================

/**
 * @brief Returns the IV_PROTO bitmask this client should advertise.
 *
 * Only set bits for features that are fully implemented on the receive side.
 * Add new bits here (with a comment) as each feature lands.
 */
inline constexpr std::uint32_t SupportedIvProto() noexcept
{
    return IV_PROTO_DATA_V2          // always: we use P_DATA_V2
           | IV_PROTO_REQUEST_PUSH   // always: we send push-request first
           | IV_PROTO_DNS_OPTION_V2; // config_exchange parses dns server/search-domains

    // Future bits to add when implemented:
    //   | IV_PROTO_CC_EXIT_NOTIFY    -- once control-channel exit path is wired
}

/**
 * @brief Builds the peer-info string sent to the server during key-method 2.
 *
 * Format mirrors OpenVPN ssl.c push_peer_info().  Each variable is on its own
 * line terminated by '\n'.  The whole string is then sent as a length-prefixed
 * null-terminated field after username/password.
 *
 * @param app_version  Human-readable version string, e.g. "clv-vpncore/1.0.0".
 *                     Sent as IV_VER.
 * @param data_ciphers Effective NCP cipher allowlist sent as IV_CIPHERS.
 */
inline std::string BuildClientPeerInfo(const std::string &app_version,
                                       const std::vector<std::string> &data_ciphers)
{
    std::string info;
    info += "IV_VER=" + app_version + "\n";
    info += "IV_PLAT=linux\n";
    info += "IV_PROTO=" + std::to_string(SupportedIvProto()) + "\n";
    if (!data_ciphers.empty())
    {
        std::string joined;
        for (std::size_t i = 0; i < data_ciphers.size(); ++i)
        {
            if (i > 0)
                joined += ":";
            joined += data_ciphers[i];
        }
        info += "IV_CIPHERS=" + joined + "\n";
    }
    return info;
}

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_PROTOCOL_CONSTANTS_H
