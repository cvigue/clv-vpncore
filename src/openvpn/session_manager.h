// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SESSION_MANAGER_H
#define CLV_VPN_SESSION_MANAGER_H

#include "connection.h"
#include "openvpn/packet.h"
#include "openvpn/tls_context.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

namespace spdlog {
class logger;
}

namespace clv::vpn {

/**
 * @brief Manages multiple VPN client sessions
 *
 * Maintains active client sessions, routes incoming packets to the correct session,
 * and handles session lifecycle (creation, cleanup, timeout).
 */
class SessionManager
{
  public:
    /**
     * @brief Create or retrieve a client session
     * @param session_id The session identifier
     * @param endpoint Remote endpoint
     * @param is_server True if server-side, false if client-side
     * @param cert_config Optional TLS certificate configuration
     * @param logger Structured logger (must remain valid for session lifetime)
     * @return Reference to the session (newly created or existing)
     */
    Connection &GetOrCreateSession(openvpn::SessionId session_id,
                                   const Connection::Endpoint &endpoint,
                                   bool is_server,
                                   std::optional<openvpn::TlsCertConfig> cert_config,
                                   spdlog::logger &logger);

    /**
     * @brief Retrieve an existing session
     * @param session_id The session identifier
     * @return Pointer to the session or nullptr if not found
     */
    Connection *FindSession(openvpn::SessionId session_id);

    /**
     * @brief Get a session by remote endpoint
     * @param endpoint The remote endpoint
     * @return Pointer to the session or nullptr if not found
     */
    Connection *FindSessionByEndpoint(const Connection::Endpoint &endpoint);

    /**
     * @brief Remove a session
     * @param session_id The session to remove
     * @return True if removed, false if not found
     */
    bool RemoveSession(openvpn::SessionId session_id);

    /**
     * @brief Get count of active sessions
     */
    size_t GetSessionCount() const
    {
        return sessions_.size();
    }

    /**
     * @brief Get list of all session IDs
     */
    std::vector<openvpn::SessionId> GetAllSessionIds() const;

    /**
     * @brief Clean up sessions that haven't been active for a timeout period
     * @param timeout_duration Duration of inactivity before session cleanup
     * @return Number of sessions removed
     */
    size_t CleanupStaleSession(std::chrono::steady_clock::duration timeout_duration);

    /**
     * @brief Clear all sessions
     */
    void ClearAllSessions()
    {
        endpoint_index_.clear();
        sessions_.clear();
    }

  private:
    // Map from SessionId to Connection
    std::unordered_map<uint64_t, std::unique_ptr<Connection>> sessions_;

    // Secondary index: endpoint → raw pointer into sessions_ for O(1) lookup.
    // Kept in sync by GetOrCreateSession, RemoveSession, CleanupStaleSession,
    // and ClearAllSessions.
    std::unordered_map<Connection::Endpoint, Connection *> endpoint_index_;

    // Helper: convert SessionId to uint64_t for hashing
    static uint64_t HashSessionId(openvpn::SessionId sid)
    {
        return sid.value;
    }
};

} // namespace clv::vpn

#endif // CLV_VPN_SESSION_MANAGER_H
