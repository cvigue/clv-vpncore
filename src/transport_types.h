// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_TYPES_H
#define CLV_VPN_TRANSPORT_TYPES_H

/**
 * @file transport_types.h
 * @brief Concrete client transport engine aliases.
 *
 * Client leaves are ClientControlPlane parameterized on the channel template.
 * Server leaves are the concrete ServerUdp/Dco/TcpTransport types (include
 * those headers directly where needed).
 */

#include "client_control_adapter.h"
#include "client_dco_channel.h"
#include "client_tcp_channel.h"
#include "client_udp_channel.h"

namespace clv::vpn {

using ClientUdpTransport = ClientControlPlane<ClientUdpChannel>;
using ClientDcoTransport = ClientControlPlane<ClientDcoChannel>;
using ClientTcpTransport = ClientControlPlane<ClientTcpChannel>;

} // namespace clv::vpn

#endif // CLV_VPN_TRANSPORT_TYPES_H
