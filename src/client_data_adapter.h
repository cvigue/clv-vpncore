// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CLIENT_DATA_ADAPTER_H
#define CLV_VPN_CLIENT_DATA_ADAPTER_H

/**
 * @file client_data_adapter.h
 * @brief CRTP data-side adapter for the VPN client.
 *
 * Called from the RX/TX hot-path threads when the data channel needs to
 * communicate with the control plane.  Stateless — zero sizeof (EBO).
 *
 * OnControlPacket marshals control packets to the control-plane io_context.
 * OnRxActivity records the last-receive timestamp for keepalive timeout.
 *
 * @tparam Derived  DataTransport<ClientUdpChannel, ClientDataAdapter, ClientControlAdapter>
 */

#include "openvpn/packet.h"
#include "transport/transport.h"

#include <asio/io_context.hpp>
#include <asio/post.hpp>

#include <cstdint>
#include <utility>
#include <vector>

namespace clv::vpn {

template <typename Derived>
struct ClientDataAdapter
{
    /// Control packet received on RX thread — marshal to control io_context.
    void OnControlPacket(std::vector<std::uint8_t> data,
                         transport::PeerEndpoint /*sender*/)
    {
        auto &self = static_cast<Derived &>(*this);
        asio::post(self.io_context(),
                   [&self, d = std::move(data)]() mutable
        {
            self.OnControlPacketFromDataPath(std::move(d));
        });
    }

    /// RX activity — update last-receive timestamp for keepalive timeout.
    /// Called from the RX thread; TouchLastRx() uses atomics (thread-safe).
    void OnRxActivity()
    {
        auto &self = static_cast<Derived &>(*this);
        self.TouchLastRx();
    }

    /// Dead peer notification — unused for P2P client.
    void OnPeerDead(openvpn::SessionId /*sid*/)
    {
    }
};

} // namespace clv::vpn

#endif // CLV_VPN_CLIENT_DATA_ADAPTER_H
