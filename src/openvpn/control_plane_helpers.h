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

#include "openvpn/control_channel.h"
#include "openvpn/key_derivation.h"
#include "openvpn/packet.h"
#include "openvpn/tls_crypt.h"
#include "transport/transport.h"

#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/error.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <concepts>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
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
 * @param role        Caller's peer role (Server or Client).
 * @param transport   Transport handle to send through.
 * @param logger      Logger for diagnostics.
 */
asio::awaitable<void> WrapAndSend(std::optional<openvpn::TlsCrypt> &tls_crypt,
                                  std::vector<std::uint8_t> data,
                                  openvpn::PeerRole role,
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
 * @param role             Caller's peer role (Server or Client).
 * @param transport        Transport handle.
 * @param logger           Logger.
 * @param description      Human-readable label for log messages.
 * @return true if at least one fragment was sent.
 */
asio::awaitable<bool> SendTlsControlData(openvpn::ControlChannel &control_channel,
                                         std::optional<openvpn::TlsCrypt> &tls_crypt,
                                         std::span<const std::uint8_t> data,
                                         openvpn::PeerRole role,
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
 * @param role             Caller's peer role (Server or Client).
 * @param transport        Transport handle.
 * @param logger           Logger.
 */
asio::awaitable<void> FlushControlQueue(openvpn::ControlChannel &control_channel,
                                        std::optional<openvpn::TlsCrypt> &tls_crypt,
                                        openvpn::PeerRole role,
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
 * @param role             Caller's peer role (Server or Client).
 * @param transport        Transport handle.
 * @param packet           Incoming P_CONTROL_V1 packet.
 * @param logger           Logger.
 * @param suppress_ack     If true, don't send standalone ACK when there's
 *                         no TLS response data.
 */
asio::awaitable<void> ProcessTlsDataAndRespond(openvpn::ControlChannel &control_channel,
                                               std::optional<openvpn::TlsCrypt> &tls_crypt,
                                               openvpn::PeerRole role,
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
 * @param role             Caller's peer role (Server or Client).
 * @param transport        Transport handle.
 * @param packet           Incoming P_ACK_V1 packet.
 * @param logger           Logger.
 */
asio::awaitable<void> HandleAckAndDrain(openvpn::ControlChannel &control_channel,
                                        std::optional<openvpn::TlsCrypt> &tls_crypt,
                                        openvpn::PeerRole role,
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
 * @param role             Caller's peer role (Server or Client).
 * @param logger           Logger for diagnostics.
 * @return KeyMethod2Result on success, or std::nullopt on failure.
 */
std::optional<openvpn::KeyDerivation::KeyMethod2Result>
DeriveDataChannelKeys(openvpn::ControlChannel &control_channel,
                      std::span<const std::uint8_t> client_random,
                      std::span<const std::uint8_t> server_random,
                      std::string_view cipher_name,
                      openvpn::PeerRole role,
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
 * @param role       Caller's peer role (Server or Client).
 * @param logger     Logger for diagnostics.
 * @param replay     Session-scoped tls-crypt anti-replay state (required when tls_crypt is set).
 * @return Parsed OpenVpnPacket on success, or std::nullopt on error.
 */
std::optional<openvpn::OpenVpnPacket> UnwrapAndParse(
    std::vector<std::uint8_t> &data,
    std::optional<openvpn::TlsCrypt> &tls_crypt,
    openvpn::PeerRole role,
    spdlog::logger &logger,
    openvpn::TlsCryptReplayState &replay);

/**
 * @brief Type contract for role-specific hooks in DispatchSessionControlPacket.
 *
 * Closed set: server and client each pass a local action object (same pattern
 * as ServerPushActions / ClientPushActions). No std::function.
 *
 * - **OnSoftReset** — P_CONTROL_SOFT_RESET_V1 (key renegotiation).
 * - **OnPlaintext** — TLS produced plaintext (key-method 2, PUSH_REQUEST/REPLY).
 * - **OnHandshakeComplete** — KeyMaterialReady with no plaintext yet.
 */
template <typename A>
concept SessionControlActions = requires(A &a,
                                         const openvpn::OpenVpnPacket &pkt,
                                         std::vector<std::uint8_t> plain) {
    { a.OnSoftReset(pkt) } -> std::same_as<asio::awaitable<void>>;
    { a.OnPlaintext(std::move(plain)) } -> std::same_as<asio::awaitable<void>>;
    { a.OnHandshakeComplete() } -> std::same_as<asio::awaitable<void>>;
};

/**
 * @brief Dispatch a per-session control packet through the shared state machine.
 *
 * Handles the common sequence used by both VpnClient and VpnServer *after*
 * hard-reset handling:
 *
 *   1. Classify opcode → delegate to shared helper or role action
 *      - P_CONTROL_V1       → ProcessTlsDataAndRespond
 *      - P_ACK_V1           → HandleAckAndDrain
 *      - P_CONTROL_SOFT_RESET_V1 → actions.OnSoftReset
 *   2. FlushControlQueue (retransmissions + queued fragments)
 *   3. Post-TLS check: if KeyMaterialReady
 *      - has plaintext → actions.OnPlaintext
 *      - no plaintext  → actions.OnHandshakeComplete
 *
 * Hard-reset opcodes (P_CONTROL_HARD_RESET_*) must be handled by the caller
 * before calling this function — they involve session creation/lookup that
 * is orchestrator-specific.
 *
 * @param actions  Role-specific hooks; must satisfy SessionControlActions.
 */
template <SessionControlActions Actions>
asio::awaitable<void> DispatchSessionControlPacket(openvpn::ControlChannel &control_channel,
                                                   std::optional<openvpn::TlsCrypt> &tls_crypt,
                                                   openvpn::PeerRole role,
                                                   transport::TransportHandle &transport,
                                                   const openvpn::OpenVpnPacket &packet,
                                                   spdlog::logger &logger,
                                                   Actions &actions)
{
    switch (packet.opcode_)
    {
    case openvpn::Opcode::P_CONTROL_V1:
        co_await ProcessTlsDataAndRespond(control_channel,
                                          tls_crypt,
                                          role,
                                          transport,
                                          packet,
                                          logger);
        break;

    case openvpn::Opcode::P_ACK_V1:
        co_await HandleAckAndDrain(control_channel, tls_crypt, role, transport, packet, logger);
        break;

    case openvpn::Opcode::P_CONTROL_SOFT_RESET_V1:
        // Soft-reset may carry piggybacked ACKs (same as CONTROL).
        if (!packet.packet_id_array_.empty())
            control_channel.ApplyAckIds(packet.packet_id_array_);
        co_await actions.OnSoftReset(packet);
        break;

    default:
        logger.warn("DispatchSessionControlPacket: unhandled opcode {}",
                    static_cast<int>(packet.opcode_));
        break;
    }

    co_await FlushControlQueue(control_channel, tls_crypt, role, transport, logger);

    if (control_channel.GetState() == openvpn::ControlChannel::State::KeyMaterialReady)
    {
        if (control_channel.HasPlaintext())
        {
            auto plaintext = control_channel.ReadPlaintext();
            co_await actions.OnPlaintext(std::move(plaintext));
        }
        else
        {
            co_await actions.OnHandshakeComplete();
        }
    }
}

inline constexpr int kDefaultTunMtu = 1500; ///< Default TUN MTU used in key-method 2 options

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
 * @param role         Caller's peer role (Server or Client).
 * @param configProto  Transport protocol from config ("tcp" or "udp").
 * @param cipher       Cipher name (e.g. "AES-256-GCM"); empty to use default.
 * @param tunMtu       TUN MTU (link-mtu is derived as tunMtu + 49).
 * @param ipv6_only    When true and proto is "udp", emits "UDPv6" on the wire
 *                     (derived from udp6 in .ovpn files).
 */
inline std::string BuildKeyMethod2Options(openvpn::PeerRole role,
                                          std::string_view configProto,
                                          std::string_view cipher,
                                          int tunMtu = kDefaultTunMtu,
                                          bool ipv6_only = false)
{
    // Map transport protocol → OpenVPN wire-format proto string
    std::string proto_str;
    const char *tcp_proto = "TCPv4_CLIENT";
    const char *tls_role = "client";
    if (role == openvpn::PeerRole::Server)
    {
        tcp_proto = "TCPv4_SERVER";
        tls_role = "server";
    }

    if (configProto == "tcp")
        proto_str = tcp_proto;
    else if (ipv6_only)
        proto_str = "UDPv6";
    else
        proto_str = "UDPv4";

    int linkMtu = tunMtu + 49; // IP+UDP (28) + OpenVPN AEAD overhead (21)

    std::string opts = "V4,dev-type tun,link-mtu " + std::to_string(linkMtu)
                       + ",tun-mtu " + std::to_string(tunMtu)
                       + ",proto " + proto_str;

    if (!cipher.empty())
        opts += ",cipher " + std::string(cipher);
    else if (role == openvpn::PeerRole::Server)
        opts += ",cipher AES-256-GCM";

    if (role == openvpn::PeerRole::Server)
        opts += ",auth [null-digest],keysize 256";

    opts += ",key-method 2,tls-";
    opts += tls_role;
    return opts;
}

/**
 * Outcome of @ref PollUntilRekey. Callers keep trigger / re-arm policy.
 */
enum class RekeyPollResult : std::uint8_t
{
    Expired,        ///< Deadline reached without a limit-driven request
    RekeyRequested, ///< @c TakeRekeyRequest (or equivalent) returned true
    Cancelled,      ///< Shutdown, session gone, generation mismatch, or timer abort
};

/**
 * Poll until @p deadline (≤1 s steps), a rekey request, or cancellation.
 *
 * @param still_active         Returns false to cancel (running/session/generation).
 * @param take_rekey_request   Returns true when a limit-driven rekey should fire now.
 */
template <typename StillActive, typename TakeRekeyRequest>
asio::awaitable<RekeyPollResult> PollUntilRekey(
    asio::io_context &io_context,
    std::chrono::steady_clock::time_point deadline,
    StillActive still_active,
    TakeRekeyRequest take_rekey_request)
{
    asio::steady_timer timer(io_context);
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (!still_active())
            co_return RekeyPollResult::Cancelled;
        if (take_rekey_request())
            co_return RekeyPollResult::RekeyRequested;

        auto remaining = deadline - std::chrono::steady_clock::now();
        if (remaining <= std::chrono::seconds(0))
            break;

        constexpr auto one_second = std::chrono::seconds(1);
        timer.expires_after(remaining < one_second ? remaining : one_second);
        auto [ec] = co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec)
            co_return RekeyPollResult::Cancelled;

        if (!still_active())
            co_return RekeyPollResult::Cancelled;
    }
    co_return RekeyPollResult::Expired;
}

} // namespace clv::vpn

#endif // CLV_VPN_CONTROL_PLANE_HELPERS_H
