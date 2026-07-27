// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SERVER_DATA_ADAPTER_H
#define CLV_VPN_SERVER_DATA_ADAPTER_H

/**
 * @file server_data_adapter.h
 * @brief Data→control marshal adapter for server channels (template DI).
 *
 * Holds Control* satisfying ServerControlForAdapter. Channels call these
 * methods from RX/TX threads; posts hop onto the control io_context.
 */

#include "channel_concept.h"
#include "openvpn/connection.h"
#include "openvpn/packet.h"
#include "transport/transport.h"

#include <not_null.h>

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/post.hpp>

#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace clv::vpn {

template <typename Control>
struct ServerDataAdapter
{
    explicit ServerDataAdapter(Control &control)
        : control_(&control)
    {
        static_assert(ServerControlForAdapter<Control>,
                      "Control must satisfy ServerControlForAdapter");
    }

    void OnControlPacket(std::vector<std::uint8_t> data,
                         transport::PeerEndpoint sender)
    {
        asio::post(control_->io_context(),
                   [c = control_, d = std::move(data), s = sender]() mutable
        {
            c->OnControlPacketFromDataPath(std::move(d), s);
        });
    }

    void OnControlPacket(std::vector<std::uint8_t> data,
                         transport::PeerEndpoint sender,
                         transport::TransportHandle transport)
    {
        asio::post(control_->io_context(),
                   [c = control_, d = std::move(data), s = sender,
                    t = std::move(transport)]() mutable
        {
            c->OnControlPacketFromDataPath(std::move(d), s, std::move(t));
        });
    }

    void OnDisconnect(transport::PeerEndpoint sender)
    {
        asio::post(control_->io_context(),
                   [c = control_, s = sender]
        {
            c->HandleTcpDisconnect(s);
        });
    }

    void OnPeerDead(openvpn::SessionId sid)
    {
        asio::post(control_->io_context(),
                   [c = control_, sid]
        {
            c->HandleDeadPeer(sid);
        });
    }

    void OnRxActivity()
    {
        // Server tracks per-connection activity inside MultiPeerPolicy — no-op.
    }

    asio::awaitable<void> SendEncryptedToSession(Connection *session,
                                                 std::span<const std::uint8_t> plaintext)
    {
        if (!session || !session->HasTransport())
            co_return;

        auto packet_id = session->TryAllocateOutboundPacketId();
        if (!packet_id)
            co_return;
        auto encrypted = session->GetCryptoContext().EncryptPacketWithId(
            plaintext, session->GetSessionId(), *packet_id);
        if (encrypted.empty())
            co_return;

        auto transport = session->GetTransport();
        co_await transport.Send(encrypted);
        session->UpdateLastOutbound();
    }

  private:
    not_null<Control *> control_;
};

} // namespace clv::vpn

#endif // CLV_VPN_SERVER_DATA_ADAPTER_H
