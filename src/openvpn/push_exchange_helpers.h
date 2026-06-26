// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_PUSH_EXCHANGE_HELPERS_H
#define CLV_VPN_PUSH_EXCHANGE_HELPERS_H

/**
 * @file push_exchange_helpers.h
 * @brief Free functions for PUSH_REQUEST / PUSH_REPLY exchange logic.
 *
 * Extracted from ServerControlBase::HandlePushRequest and
 * ClientControlAdapter::HandlePushReply so the exchange logic can be
 * reasoned about and tested independently of the CRTP class hierarchy.
 *
 * Each free function takes its dependencies as explicit parameters,
 * making the coupling map visible.  CRTP-specific operations (key
 * installation, network configuration, rekey scheduling) are provided
 * as callable callbacks by the thin class-method wrappers.
 */

#include "openvpn/config_exchange.h"
#include "openvpn/connection.h"
#include "openvpn/control_plane_helpers.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/packet.h"
#include "openvpn/session_manager.h"
#include "openvpn/tls_crypt.h"
#include "openvpn/vpn_config.h"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>

#include <spdlog/logger.h>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace clv::vpn {

// ---------------------------------------------------------------------------
// Server IP / renegotiation helpers (relocated from detail:: in
// server_control_base.h; now testable and findable in their own header)
// ---------------------------------------------------------------------------

/**
 * @brief Derive the server-side tunnel IPv4 gateway address.
 *
 * Returns srv.bridge_ip if set; otherwise computes network_addr + 1 from
 * the srv.network CIDR.
 *
 * @param srv  Server configuration.
 * @return     Dotted-decimal IPv4 string for the tunnel gateway.
 * @throws std::invalid_argument if srv.network is not a valid CIDR.
 */
std::string DeriveServerIp(const VpnConfig::ServerConfig &srv);

/**
 * @brief Derive the server-side tunnel IPv6 gateway address.
 *
 * Computes the first address in the srv.network_v6 prefix.
 *
 * @param srv  Server configuration.
 * @return     Colon-hex IPv6 string for the tunnel gateway.
 * @throws std::invalid_argument if srv.network_v6 is not a valid IPv6 CIDR.
 */
std::string DeriveServerIpv6(const VpnConfig::ServerConfig &srv);

/**
 * @brief Return the effective renegotiation interval in seconds.
 *
 * Returns 0 if srv.renegotiate_seconds is <=0 (disabled).  Clamps values
 * below VpnConfig::ServerConfig::kMinRenegotiateSeconds up to that minimum.
 *
 * @param srv  Server configuration.
 * @return     Effective interval in seconds, or 0 if disabled.
 */
std::uint32_t EffectiveRenegotiateSeconds(const VpnConfig::ServerConfig &srv);

// ---------------------------------------------------------------------------
// Pure push-reply config builder
// ---------------------------------------------------------------------------

/**
 * @brief Build the NegotiatedConfig to include in a PUSH_REPLY.
 *
 * Pure function: reads @p srv and @p session, returns a fully populated
 * NegotiatedConfig.  Does not log, send, or modify any state.
 *
 * @param srv      Server configuration.
 * @param session  The connected client session (must have an assigned IPv4).
 * @return         Populated NegotiatedConfig ready for ConfigExchange::Serialize.
 * @throws std::runtime_error if the session has no assigned IPv4 or the
 *         server network CIDR is invalid.
 */
openvpn::NegotiatedConfig BuildServerPushReplyConfig(const VpnConfig::ServerConfig &srv,
                                                     const Connection &session);

// ---------------------------------------------------------------------------
// Server HandlePushRequest as a free function template
// ---------------------------------------------------------------------------

/**
 * @brief Type contract for the CRTP-side actions required by HandleServerPushRequest.
 *
 * Any type exposing DeriveAndInstallKeys(Connection*) and
 * ScheduleRekey(SessionId, uint32_t) satisfies this concept.
 */
template <typename T>
concept ServerPushActions = requires(T &t, Connection *c, openvpn::SessionId sid, std::uint32_t sec) {
    t.DeriveAndInstallKeys(c);
    t.ScheduleRekey(sid, sec);
};

/**
 * @brief Handle a PUSH_REQUEST from a connected client.
 *
 * Builds and sends a PUSH_REPLY, then schedules a per-session rekey timer
 * if configured.
 *
 * @param session    Active client session (must have assigned IPs).
 * @param srv        Server configuration.
 * @param server_tls_crypt  Server-level TLS-Crypt fallback.
 * @param logger     Logger for diagnostics.
 * @param actions    CRTP-side action object; must satisfy ServerPushActions.
 */
template <ServerPushActions Actions>
asio::awaitable<void> HandleServerPushRequest(
    Connection *session,
    const VpnConfig::ServerConfig &srv,
    std::optional<openvpn::TlsCrypt> &server_tls_crypt,
    spdlog::logger &logger,
    Actions &actions)
{
    logger.info("Client sent PUSH_REQUEST, sending PUSH_REPLY");

    if (!session->GetDataChannel().HasValidKeys())
    {
        logger.warn("PUSH_REQUEST received but keys not yet installed");
        if (!session->GetClientRandom().empty() && !session->GetServerRandom().empty())
            actions.DeriveAndInstallKeys(session);
        else
            logger.error("Cannot derive keys - missing random data");
    }

    if (!session->HasTransport())
    {
        logger.error("PUSH_REPLY: session has no transport");
        co_return;
    }

    auto push_config = BuildServerPushReplyConfig(srv, *session);
    std::string push_reply = openvpn::ConfigExchange::Serialize(push_config);
    logger.info("PUSH_REPLY: {}", push_reply);

    std::vector<std::uint8_t> reply_data(push_reply.begin(), push_reply.end());
    reply_data.push_back(0);

    // Select the effective TLS-Crypt key: prefer the per-session V2 key if
    // present, fall back to the server-level key.
    auto &eff_crypt = session->GetSessionTlsCrypt().has_value() ? session->GetSessionTlsCrypt()
                                                                : server_tls_crypt;
    auto transport = session->GetTransport();
    bool ok = co_await SendTlsControlData(session->GetControlChannel(),
                                          eff_crypt,
                                          reply_data,
                                          openvpn::PeerRole::Server,
                                          transport,
                                          logger,
                                          "PUSH_REPLY");
    if (ok)
        session->UpdateLastOutbound();

    if (push_config.reneg_sec > 0 && session->TryArmRekeyTimer())
        actions.ScheduleRekey(session->GetSessionId(), push_config.reneg_sec);
}

// ---------------------------------------------------------------------------
// Client HandlePushReply as a free function template
// ---------------------------------------------------------------------------

/**
 * @brief Plain-data bundle passed to HandleClientPushReply.
 *
 * References to the session state the handler reads and writes.
 * Action callbacks are separated into the Actions type parameter so the
 * coupling map is explicit and the call is zero-cost at the call site.
 */
struct ClientPushReplyData
{
    openvpn::ConfigExchange &config_exchange;        ///< Owns NegotiatedConfig; ProcessPushReply called on entry
    const std::vector<std::string> &allowed_ciphers; ///< Effective operator data-cipher policy
    const std::string &current_cipher;               ///< Config-level cipher (before any NCP override)
    std::uint32_t client_renegotiate_seconds;        ///< Client-side rekey interval fallback
    std::string &negotiated_cipher;                  ///< [in/out] Updated when the server pushes an NCP cipher
    std::uint32_t &server_peer_id;                   ///< [out] Populated from pushed peer_id if present
    bool is_connected;                               ///< True when the tunnel is already up (rekey path)
    bool &rekey_timer_armed;                         ///< [in/out] Guard; set to true when timer is started
    std::uint64_t rekey_generation;                  ///< Passed to ScheduleRekey to invalidate stale loops
    spdlog::logger &logger;                          ///< Logger for diagnostics
};

/**
 * @brief Type contract for the CRTP-side actions required by HandleClientPushReply.
 *
 * Any type that exposes the four named methods satisfies this concept.
 * The concrete type is always known at the (single) call site in
 * ClientControlAdapter::HandlePushReply, so the compiler devirtualises
 * everything — no vtable, no heap allocation.
 */
template <typename T>
concept ClientPushActions = requires(T &t, std::uint32_t reneg, std::uint64_t gen) {
    t.DeriveAndInstallKeys();
    t.ApplyNetworkConfig();
    t.MarkConnected();
    t.ScheduleRekey(reneg, gen);
};

/**
 * @brief Handle a PUSH_REPLY received from the server.
 *
 * Validates the pushed cipher against the operator policy, applies NCP
 * cipher overrides, configures the network interface on first connect,
 * and arms the client-side rekey timer.
 *
 * @param reply    PUSH_REPLY payload (the portion after "PUSH_REPLY,").
 * @param data     References to session state to read/update.
 * @param actions  CRTP-side action object; must satisfy ClientPushActions.
 */
template <ClientPushActions Actions>
asio::awaitable<void> HandleClientPushReply(const std::string &reply,
                                            ClientPushReplyData data,
                                            Actions &actions)
{
    data.logger.debug("PUSH_REPLY: {}", reply);
    data.config_exchange.ProcessPushReply(reply);
    const auto &negotiated = data.config_exchange.GetNegotiatedConfig();

    if (!negotiated.cipher.empty()
        && !openvpn::IsCipherAllowedByPolicy(negotiated.cipher, data.allowed_ciphers))
    {
        throw std::runtime_error("Server pushed disallowed cipher: " + negotiated.cipher);
    }

    // NCP cipher override: store the negotiated cipher and re-derive keys so
    // the new cipher takes effect for the current session.
    if (!negotiated.cipher.empty() && negotiated.cipher != data.current_cipher)
    {
        data.logger.info("NCP: cipher '{}' overrides '{}'", negotiated.cipher, data.current_cipher);
        data.negotiated_cipher = negotiated.cipher;
        actions.DeriveAndInstallKeys();
    }

    if (negotiated.peer_id >= 0)
    {
        data.server_peer_id = static_cast<std::uint32_t>(negotiated.peer_id);
        data.logger.info("Server peer-id: {}", data.server_peer_id);
    }

    if (!negotiated.ifconfig.first.empty())
        data.logger.info("Assigned IP: {} / {}",
                         negotiated.ifconfig.first,
                         negotiated.ifconfig.second);

    if (data.is_connected)
    {
        data.logger.info("Rekey complete \u2014 new keys installed");
        co_return;
    }

    // Throws on failure \u2014 propagates to the coroutine chain's top-level catch.
    actions.ApplyNetworkConfig();
    actions.MarkConnected();

    // Arm the client-side rekey timer.  Prefer the server-pushed value;
    // fall back to the client's own configured interval.
    const auto pushed = data.config_exchange.GetNegotiatedConfig().reneg_sec;
    const auto effective_reneg = (pushed > 0) ? pushed : data.client_renegotiate_seconds;
    if (effective_reneg > 0 && !data.rekey_timer_armed)
    {
        data.rekey_timer_armed = true;
        actions.ScheduleRekey(effective_reneg, data.rekey_generation);
        data.logger.info("Client rekey timer armed: {}s", effective_reneg);
    }
}

} // namespace clv::vpn

#endif // CLV_VPN_PUSH_EXCHANGE_HELPERS_H
