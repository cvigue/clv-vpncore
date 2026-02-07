// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "client_session.h"
#include "openvpn/packet.h"
#include "openvpn/tls_context.h"
#include <optional>
#include <stdexcept>
#include <string>

namespace clv::vpn {

ClientSession::ClientSession(openvpn::SessionId session_id,
                             const Endpoint &endpoint,
                             bool is_server,
                             std::optional<openvpn::TlsCertConfig> cert_config,
                             spdlog::logger &logger)
    : session_id_(session_id),
      endpoint_(endpoint),
      control_channel_(logger),
      data_channel_(logger),
      logger_(&logger)
{
    // Initialize the control channel with the TLS context and certificates
    if (!control_channel_.Initialize(is_server, session_id, cert_config))
    {
        throw std::runtime_error("Failed to initialize control channel for session");
    }

    // Update activity timestamp
    UpdateLastActivity();
}

std::string ClientSession::GetCipherSuite() const
{
    return control_channel_.GetCipherName();
}

} // namespace clv::vpn
