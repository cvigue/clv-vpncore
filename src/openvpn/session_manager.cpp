// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "session_manager.h"
#include "connection.h"
#include "openvpn/packet.h"
#include "openvpn/tls_context.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace clv::vpn {

Connection &SessionManager::GetOrCreateSession(openvpn::SessionId session_id,
                                                  const Connection::Endpoint &endpoint,
                                                  bool is_server,
                                                  std::optional<openvpn::TlsCertConfig> cert_config,
                                                  spdlog::logger &logger)
{
    uint64_t key = HashSessionId(session_id);

    auto it = sessions_.find(key);
    if (it != sessions_.end())
    {
        // Session already exists
        // NOTE: Do NOT update activity here - activity should only be updated
        // when receiving actual client packets, not on lookup
        return *it->second;
    }

    // Create new session with certificate configuration
    auto session = std::make_unique<Connection>(session_id, endpoint, is_server, cert_config, logger);
    auto &ref = *session;
    sessions_[key] = std::move(session);
    return ref;
}

Connection *SessionManager::FindSession(openvpn::SessionId session_id)
{
    uint64_t key = HashSessionId(session_id);
    auto it = sessions_.find(key);
    if (it != sessions_.end())
    {
        // NOTE: Do NOT update activity here - activity should only be updated
        // when receiving actual client packets, not on lookup
        return it->second.get();
    }
    return nullptr;
}

Connection *SessionManager::FindSessionByEndpoint(const Connection::Endpoint &endpoint)
{
    auto it = std::ranges::find_if(sessions_, [&](const auto &pair)
    {
        const auto &ep = pair.second->GetEndpoint();
        return ep.addr == endpoint.addr && ep.port == endpoint.port;
    });

    if (it != sessions_.end())
    {
        // NOTE: Do NOT update activity here - activity should only be updated
        // when receiving actual client packets, not on lookup
        return it->second.get();
    }
    return nullptr;
}

bool SessionManager::RemoveSession(openvpn::SessionId session_id)
{
    uint64_t key = HashSessionId(session_id);
    return sessions_.erase(key) > 0;
}

std::vector<openvpn::SessionId> SessionManager::GetAllSessionIds() const
{
    std::vector<openvpn::SessionId> ids;
    ids.reserve(sessions_.size());
    std::ranges::transform(sessions_, std::back_inserter(ids), [](const auto &pair)
    { return pair.second->GetSessionId(); });
    return ids;
}

size_t SessionManager::CleanupStaleSession(std::chrono::steady_clock::duration timeout_duration)
{
    auto now = std::chrono::steady_clock::now();

    return std::erase_if(sessions_, [&](const auto &pair)
    {
        return (now - pair.second->GetLastActivity()) > timeout_duration;
    });
}

} // namespace clv::vpn
