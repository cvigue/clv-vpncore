// Copyright (c) 2025- Charlie Vigue. All rights reserved.

/**
 * @file channel_concept_checks.cpp
 * @brief Compile-time proof that concrete engines satisfy Channel concepts.
 */

#include "channel_concept.h"
#include "server_dco_control_adapter.h"
#include "server_tcp_control_adapter.h"
#include "server_udp_control_adapter.h"
#include "transport_types.h"

namespace clv::vpn {
namespace {

static_assert(ServerTransportLeaf<ServerUdpTransport>);
static_assert(ServerTransportLeaf<ServerDcoTransport>);
static_assert(ServerTransportLeaf<ServerTcpTransport>);

static_assert(ServerControlForAdapter<ServerUdpTransport>);
static_assert(ServerControlForAdapter<ServerDcoTransport>);
static_assert(ServerControlForAdapter<ServerTcpTransport>);

static_assert(Channel<typename ServerUdpTransport::channel_type>);
static_assert(ServerChannel<typename ServerUdpTransport::channel_type>);

static_assert(Channel<typename ServerDcoTransport::channel_type>);
static_assert(ServerChannel<typename ServerDcoTransport::channel_type>);

static_assert(Channel<typename ServerTcpTransport::channel_type>);
static_assert(ServerChannel<typename ServerTcpTransport::channel_type>);

static_assert(ClientControlForAdapter<ClientUdpTransport>);
static_assert(ClientControlForAdapter<ClientDcoTransport>);
static_assert(ClientControlForAdapter<ClientTcpTransport>);

static_assert(Channel<typename ClientUdpTransport::channel_type>);
static_assert(ClientChannel<typename ClientUdpTransport::channel_type>);

static_assert(Channel<typename ClientDcoTransport::channel_type>);
static_assert(ClientChannel<typename ClientDcoTransport::channel_type>);

static_assert(Channel<typename ClientTcpTransport::channel_type>);
static_assert(ClientChannel<typename ClientTcpTransport::channel_type>);

} // namespace
} // namespace clv::vpn
