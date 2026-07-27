// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_TYPES_H
#define CLV_VPN_TRANSPORT_TYPES_H

/**
 * @file transport_types.h
 * @brief Concrete transport engine aliases.
 *
 * Server leaves are concrete classes owning Channel + ServerDataAdapter.
 * Client leaves are ClientControlPlane parameterized on the channel type.
 */

#include "client_control_adapter.h"
#include "client_dco_channel.h"
#include "client_tcp_channel.h"
#include "client_udp_channel.h"
#include "server_dco_control_adapter.h"
#include "server_tcp_control_adapter.h"
#include "server_udp_control_adapter.h"

namespace clv::vpn {

// Server transports are the leaf classes themselves.
// (aliases kept for VpnServer / DataPlane readability)

using ClientUdpTransport = ClientControlPlane<ClientUdpChannel>;
using ClientDcoTransport = ClientControlPlane<ClientDcoChannel>;
using ClientTcpTransport = ClientControlPlane<ClientTcpChannel>;

} // namespace clv::vpn

#endif // CLV_VPN_TRANSPORT_TYPES_H
