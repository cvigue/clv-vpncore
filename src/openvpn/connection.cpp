// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "connection.h"
#include "openvpn/packet.h"
#include "openvpn/tls_context.h"
#include <optional>
#include <stdexcept>
#include <string>

namespace clv::vpn {

Connection::Connection(openvpn::SessionId session_id,
                       const Endpoint &endpoint,
                       ConnectionRole role,
                       std::optional<openvpn::TlsCertConfig> cert_config,
                       spdlog::logger &logger)
    : session_id_(session_id),
      endpoint_(endpoint),
      role_(role),
      control_channel_(logger),
      data_channel_(logger),
      logger_(&logger)
{
    bool is_server = (role == ConnectionRole::Server);
    if (!control_channel_.Initialize(is_server, session_id, cert_config))
    {
        throw std::runtime_error("Failed to initialize control channel for session");
    }

    UpdateLastActivity();
}

Connection::Connection(openvpn::SessionId session_id,
                       const Endpoint &endpoint,
                       bool is_server,
                       std::optional<openvpn::TlsCertConfig> cert_config,
                       spdlog::logger &logger)
    : Connection(session_id,
                 endpoint,
                 is_server ? ConnectionRole::Server : ConnectionRole::Client,
                 std::move(cert_config),
                 logger)
{
}

std::string Connection::GetCipherSuite() const
{
    return control_channel_.GetCipherName();
}

} // namespace clv::vpn
