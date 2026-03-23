// Copyright (c) 2025- Charlie Vigue. All rights reserved.

/**
 * @file client_session.h
 * @brief Backward-compatibility shim — includes connection.h and provides
 *        a type alias so existing code using ClientSession keeps compiling.
 *
 * New code should include "openvpn/connection.h" and use Connection directly.
 */

#ifndef CLV_VPN_CLIENT_SESSION_H
#define CLV_VPN_CLIENT_SESSION_H

#include "openvpn/connection.h"

namespace clv::vpn {

/// Backward-compatible alias.  Prefer @c Connection in new code.
using ClientSession = Connection;

} // namespace clv::vpn

#endif // CLV_VPN_CLIENT_SESSION_H
