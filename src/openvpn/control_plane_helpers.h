// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CONTROL_PLANE_HELPERS_H
#define CLV_VPN_CONTROL_PLANE_HELPERS_H

/**
 * @file control_plane_helpers.h
 * @brief Shared control-plane helpers used by both VpnClient and VpnServer.
 *
 * These free functions extract the common patterns that were previously
 * duplicated between the client and server orchestrators:
 * - TLS-Crypt wrapping + transport send
 * - Fragmenting TLS data through the control channel and sending
 * - Flushing queued control-channel fragments and retransmissions
 */

#include "control_channel.h"
#include "key_derivation.h"
#include "packet.h"
#include "tls_crypt.h"
#include "transport/transport.h"

#include <asio/awaitable.hpp>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace clv::vpn {

/**
 * @brief Wrap a control packet with TLS-Crypt and send it.
 *
 * If @p tls_crypt is nullopt the packet is sent unwrapped (useful for testing,
 * though in production TLS-Crypt is always enabled).
 *
 * @param tls_crypt   TLS-Crypt instance (optional).
 * @param data        Control packet data (consumed/moved).
 * @param is_server   true when wrapping for the server role.
 * @param transport   Transport handle to send through.
 * @param logger      Logger for diagnostics.
 */
asio::awaitable<void> WrapAndSend(std::optional<openvpn::TlsCrypt> &tls_crypt,
                                  std::vector<std::uint8_t> data,
                                  bool is_server,
                                  transport::TransportHandle &transport,
                                  spdlog::logger &logger);

/**
 * @brief Encrypt data through TLS, fragment via the control channel, and send.
 *
 * Equivalent to the server's `SendTlsControlData`: calls
 * `control_channel.PrepareTlsEncryptedData()` to produce fragments, then
 * wraps and sends each one.
 *
 * @param control_channel  Control channel (produces fragments).
 * @param tls_crypt        TLS-Crypt instance.
 * @param data             Plaintext to encrypt inside TLS and fragment.
 * @param is_server        Role flag for TLS-Crypt wrapping.
 * @param transport        Transport handle.
 * @param logger           Logger.
 * @param description      Human-readable label for log messages.
 * @return true if at least one fragment was sent.
 */
asio::awaitable<bool> SendTlsControlData(openvpn::ControlChannel &control_channel,
                                         std::optional<openvpn::TlsCrypt> &tls_crypt,
                                         std::span<const std::uint8_t> data,
                                         bool is_server,
                                         transport::TransportHandle &transport,
                                         spdlog::logger &logger,
                                         std::string_view description = "TLS control data");

/**
 * @brief Flush queued control-channel fragments and retransmissions.
 *
 * Both VpnClient and VpnServer perform this identical sequence at the tail
 * of every control-packet handler:
 *   1. `GetPacketsToSend()` — drain queued fragments produced by TLS processing.
 *   2. `ProcessRetransmissions()` — re-send packets that need retransmission.
 *
 * @param control_channel  Control channel to drain.
 * @param tls_crypt        TLS-Crypt instance for wrapping.
 * @param is_server        Role flag for TLS-Crypt wrapping.
 * @param transport        Transport handle.
 * @param logger           Logger.
 */
asio::awaitable<void> FlushControlQueue(openvpn::ControlChannel &control_channel,
                                        std::optional<openvpn::TlsCrypt> &tls_crypt,
                                        bool is_server,
                                        transport::TransportHandle &transport,
                                        spdlog::logger &logger);

/**
 * @brief Process a P_CONTROL_V1 TLS data packet and send responses.
 *
 * Feeds the packet to the control channel's TLS engine, then sends any
 * response fragments that were produced.  If no TLS data came back, sends
 * a standalone explicit ACK (unless @p suppress_ack is true).
 *
 * @param control_channel  Control channel (owns the TLS engine).
 * @param tls_crypt        TLS-Crypt instance for wrapping outbound packets.
 * @param is_server        Role flag for TLS-Crypt wrapping.
 * @param transport        Transport handle.
 * @param packet           Incoming P_CONTROL_V1 packet.
 * @param logger           Logger.
 * @param suppress_ack     If true, don't send standalone ACK when there's
 *                         no TLS response data.
 */
asio::awaitable<void> ProcessTlsDataAndRespond(openvpn::ControlChannel &control_channel,
                                               std::optional<openvpn::TlsCrypt> &tls_crypt,
                                               bool is_server,
                                               transport::TransportHandle &transport,
                                               const openvpn::OpenVpnPacket &packet,
                                               spdlog::logger &logger,
                                               bool suppress_ack = false);

/**
 * @brief Handle an ACK packet and drain any queued fragments.
 *
 * Acknowledges the packet via the control channel, then sends any fragments
 * that were waiting for window space.
 *
 * @param control_channel  Control channel.
 * @param tls_crypt        TLS-Crypt instance for wrapping.
 * @param is_server        Role flag for TLS-Crypt wrapping.
 * @param transport        Transport handle.
 * @param packet           Incoming P_ACK_V1 packet.
 * @param logger           Logger.
 */
asio::awaitable<void> HandleAckAndDrain(openvpn::ControlChannel &control_channel,
                                        std::optional<openvpn::TlsCrypt> &tls_crypt,
                                        bool is_server,
                                        transport::TransportHandle &transport,
                                        const openvpn::OpenVpnPacket &packet,
                                        spdlog::logger &logger);

/**
 * @brief Derive data-channel keys from key-method 2 exchange material.
 *
 * Validates that the control channel has both local and peer session IDs,
 * then calls the OpenVPN PRF (`DeriveKeyMethod2`).  The caller is
 * responsible for installing the resulting key material — this function
 * only performs the derivation.
 *
 * @param control_channel  Control channel (provides session IDs).
 * @param client_random    Client random bytes (112 bytes).
 * @param server_random    Server random bytes (64 bytes).
 * @param cipher_name      Cipher name string (e.g. "AES-256-GCM").
 * @param is_server        true if the local side is the server.
 * @param logger           Logger for diagnostics.
 * @return KeyMethod2Result on success, or std::nullopt on failure.
 */
std::optional<openvpn::KeyDerivation::KeyMethod2Result>
DeriveDataChannelKeys(openvpn::ControlChannel &control_channel,
                      std::span<const std::uint8_t> client_random,
                      std::span<const std::uint8_t> server_random,
                      std::string_view cipher_name,
                      bool is_server,
                      spdlog::logger &logger);

/**
 * @brief Unwrap TLS-Crypt (for control packets) and parse an OpenVPN packet.
 *
 * Combines the common receive-side pipeline that both VpnClient and VpnServer
 * perform on every inbound packet:
 *
 *   1. Reject empty data
 *   2. Classify opcode (data vs. control)
 *   3. If control: unwrap via TLS-Crypt
 *   4. Parse into OpenVpnPacket
 *
 * Data packets pass through without unwrapping (they use session-key
 * encryption, not TLS-Crypt).
 *
 * @param data       Raw packet data (modified in-place for control packets).
 * @param tls_crypt  TLS-Crypt instance (may be nullopt if not configured).
 * @param is_server  true ⇒ server unwrap direction; false ⇒ client.
 * @param logger     Logger for diagnostics.
 * @return Parsed OpenVpnPacket on success, or std::nullopt on error.
 */
std::optional<openvpn::OpenVpnPacket> UnwrapAndParse(
    std::vector<std::uint8_t> &data,
    std::optional<openvpn::TlsCrypt> &tls_crypt,
    bool is_server,
    spdlog::logger &logger);

/**
 * @brief Callbacks for role-specific operations during session control-packet dispatch.
 *
 * The orchestrator (VpnClient or VpnServer) provides these when calling
 * DispatchSessionControlPacket.  Each handles a protocol-asymmetric aspect
 * of the OpenVPN control channel:
 *
 * - **on_soft_reset** — key renegotiation (server provides; client may leave null).
 * - **on_plaintext** — TLS produced plaintext (key-method 2, PUSH_REQUEST/REPLY).
 * - **on_handshake_complete** — TLS handshake done, no plaintext yet (client sends
 *   key-method 2; server ensures IP allocated).
 */
struct SessionControlCallbacks
{
    /**
     * Handle P_CONTROL_SOFT_RESET_V1.
     * Server provides this for key renegotiation.  Client may set to nullptr.
     */
    std::function<asio::awaitable<void>(const openvpn::OpenVpnPacket &)> on_soft_reset;

    /**
     * TLS engine produced plaintext after handshake completion.
     * Receives the decrypted application data (key-method 2, PUSH_REQUEST, PUSH_REPLY, etc.).
     */
    std::function<asio::awaitable<void>(std::vector<std::uint8_t>)> on_plaintext;

    /**
     * TLS handshake reached KeyMaterialReady but no plaintext is available yet.
     * Client: send key-method 2.  Server: ensure IP allocated.  May be nullptr.
     */
    std::function<asio::awaitable<void>()> on_handshake_complete;
};

/**
 * @brief Dispatch a per-session control packet through the shared state machine.
 *
 * Handles the common sequence used by both VpnClient and VpnServer *after*
 * hard-reset handling:
 *
 *   1. Classify opcode → delegate to shared helper or role callback
 *      - P_CONTROL_V1       → ProcessTlsDataAndRespond
 *      - P_ACK_V1           → HandleAckAndDrain
 *      - P_CONTROL_SOFT_RESET_V1 → callbacks.on_soft_reset
 *   2. FlushControlQueue (retransmissions + queued fragments)
 *   3. Post-TLS check: if KeyMaterialReady
 *      - has plaintext → callbacks.on_plaintext
 *      - no plaintext  → callbacks.on_handshake_complete
 *
 * Hard-reset opcodes (P_CONTROL_HARD_RESET_*) must be handled by the caller
 * before calling this function — they involve session creation/lookup that
 * is orchestrator-specific.
 *
 * @param control_channel  Per-connection control channel.
 * @param tls_crypt        TLS-Crypt instance for wrapping outbound packets.
 * @param is_server        Role flag for TLS-Crypt wrapping direction.
 * @param transport        Transport handle for sending packets.
 * @param packet           Incoming control packet (NOT a hard reset).
 * @param logger           Logger for diagnostics.
 * @param callbacks        Role-specific hooks for soft reset, plaintext, etc.
 */
asio::awaitable<void> DispatchSessionControlPacket(
    openvpn::ControlChannel &control_channel,
    std::optional<openvpn::TlsCrypt> &tls_crypt,
    bool is_server,
    transport::TransportHandle &transport,
    const openvpn::OpenVpnPacket &packet,
    spdlog::logger &logger,
    const SessionControlCallbacks &callbacks);

/**
 * @brief Build the OpenVPN key-method 2 options string.
 *
 * Assembles the comma-separated options string exchanged during the
 * key-method 2 handshake.  The format is shared between client and server
 * with small role-specific differences:
 *   - TCP proto suffix: TCPv4_SERVER vs TCPv4_CLIENT
 *   - Server includes ,auth [null-digest],keysize 256
 *   - Server defaults cipher to AES-256-GCM when not specified
 *   - Trailing role tag: tls-server vs tls-client
 *
 * @param is_server    true for server role (tls-server), false for client.
 * @param configProto  Transport protocol from config ("tcp", "udp", "udp6").
 * @param cipher       Cipher name (e.g. "AES-256-GCM"); empty to use default.
 * @param tunMtu       TUN MTU (link-mtu is derived as tunMtu + 49).
 */
inline std::string BuildKeyMethod2Options(bool is_server,
                                          std::string_view configProto,
                                          std::string_view cipher,
                                          int tunMtu = 1500)
{
    // Map transport protocol → OpenVPN wire-format proto string
    std::string proto_str;
    if (configProto == "tcp")
        proto_str = is_server ? "TCPv4_SERVER" : "TCPv4_CLIENT";
    else if (configProto == "udp6")
        proto_str = "UDPv6";
    else
        proto_str = "UDPv4";

    int linkMtu = tunMtu + 49; // IP+UDP (28) + OpenVPN AEAD overhead (21)

    std::string opts = "V4,dev-type tun,link-mtu " + std::to_string(linkMtu)
                       + ",tun-mtu " + std::to_string(tunMtu)
                       + ",proto " + proto_str;

    if (!cipher.empty())
        opts += ",cipher " + std::string(cipher);
    else if (is_server)
        opts += ",cipher AES-256-GCM";

    if (is_server)
        opts += ",auth [null-digest],keysize 256";

    opts += ",key-method 2,tls-";
    opts += is_server ? "server" : "client";
    return opts;
}

} // namespace clv::vpn

#endif // CLV_VPN_CONTROL_PLANE_HELPERS_H
