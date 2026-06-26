// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SERVER_DATA_ADAPTER_H
#define CLV_VPN_SERVER_DATA_ADAPTER_H

/**
 * @file server_data_adapter.h
 * @brief CRTP data-side adapter for server mode.
 *
 * Called from RX/TX hot-path threads when the data channel needs to
 * communicate with the control plane.  Stateless — zero sizeof.
 *
 * OnControlPacket and OnPeerDead marshal to the control-plane io_context
 * via asio::post.  The target methods (ProcessNetworkPacket, HandleDeadPeer)
 * live on the ControlAdapter (reachable through Derived which inherits both).
 *
 * This type is injected into a DataTransport template parameter list to bind
 * the transport to the control-plane logic via CRTP, providing the necessary
 * callback implementations for a server controller. The data channel wrappers
 * all require this interface to be present via a cast ref to 'this' as per
 * typical CRTP, and this provides the necessary glue to marshal calls back
 * to the control plane.
 *
 * @see ServerTcpControlAdapter
 * @see ServerUdpControlAdapter
 */

#include "openvpn/connection.h"
#include "openvpn/packet.h"
#include "transport/transport.h"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/post.hpp>

#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace clv::vpn {

template <typename Derived>
struct ServerDataAdapter
{
    void OnControlPacket(std::vector<std::uint8_t> data,
                         transport::PeerEndpoint sender)
    {
        auto &self = static_cast<Derived &>(*this);
        asio::post(self.io_context(),
                   [&self, d = std::move(data), s = sender]() mutable
        {
            self.OnControlPacketFromDataPath(std::move(d), s);
        });
    }

    // 3-arg overload for TCP (includes transport handle from per-client socket)
    void OnControlPacket(std::vector<std::uint8_t> data,
                         transport::PeerEndpoint sender,
                         transport::TransportHandle transport)
    {
        auto &self = static_cast<Derived &>(*this);
        asio::post(self.io_context(),
                   [&self, d = std::move(data), s = sender, t = std::move(transport)]() mutable
        {
            self.OnControlPacketFromDataPath(std::move(d), s, std::move(t));
        });
    }

    void OnDisconnect(transport::PeerEndpoint sender)
    {
        auto &self = static_cast<Derived &>(*this);
        asio::post(self.io_context(),
                   [&self, s = sender]()
        {
            self.HandleTcpDisconnect(s);
        });
    }

    void OnPeerDead(openvpn::SessionId sid)
    {
        auto &self = static_cast<Derived &>(*this);
        asio::post(self.io_context(),
                   [&self, sid]()
        {
            self.HandleDeadPeer(sid);
        });
    }

    void OnRxActivity()
    {
        // Server tracks per-connection activity inside MultiPeerPolicy — no-op.
    }

    // Encrypt plaintext with the session's data channel and send directly to
    // the session's transport.  Intended for slow-path server-initiated packets
    // (keepalive pings, future push-updates) that bypass the TUN hot path.
    asio::awaitable<void> SendEncryptedToSession(Connection *session,
                                                 std::span<const std::uint8_t> plaintext)
    {
        if (!session || !session->HasTransport())
            co_return;

        auto packet_id = session->GetAndIncrementOutboundPacketId();
        auto encrypted = session->GetDataChannel().EncryptPacketWithId(
            plaintext, session->GetSessionId(), packet_id);
        if (encrypted.empty())
            co_return;

        auto transport = session->GetTransport();
        co_await transport.Send(encrypted);
        session->UpdateLastOutbound();
    }
};

} // namespace clv::vpn

#endif // CLV_VPN_SERVER_DATA_ADAPTER_H
