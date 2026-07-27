// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SERVER_KEEPALIVE_H
#define CLV_VPN_SERVER_KEEPALIVE_H

/**
 * @file server_keepalive.h
 * @brief Shared server keepalive SessionView + session-list collect (DRY F2).
 */

#include "openvpn/connection.h"
#include "openvpn/session_manager.h"

#include <chrono>
#include <vector>

namespace clv::vpn {

/** Thin Connection adapter for KeepaliveLoop (UDP and TCP monitors). */
struct ConnectionKeepaliveView
{
    Connection *conn = nullptr;

    bool HasValidKeys() const
    {
        return conn->GetCryptoContext().HasValidKeys();
    }
    std::chrono::steady_clock::time_point GetLastActivity() const
    {
        return conn->GetLastActivity();
    }
    std::chrono::steady_clock::time_point GetLastOutbound() const
    {
        return conn->GetLastOutbound();
    }
    void UpdateLastOutbound()
    {
        conn->UpdateLastOutbound();
    }
};

[[nodiscard]] inline std::vector<ConnectionKeepaliveView>
CollectKeepaliveSessions(SessionManager &session_manager)
{
    std::vector<ConnectionKeepaliveView> result;
    for (auto id : session_manager.GetAllSessionIds())
    {
        if (auto *s = session_manager.FindSession(id))
            result.push_back(ConnectionKeepaliveView{s});
    }
    return result;
}

} // namespace clv::vpn

#endif // CLV_VPN_SERVER_KEEPALIVE_H
