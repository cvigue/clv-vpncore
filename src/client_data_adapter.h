// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CLIENT_DATA_ADAPTER_H
#define CLV_VPN_CLIENT_DATA_ADAPTER_H

/**
 * @file client_data_adapter.h
 * @brief Data→control marshal adapter for client channels (template DI).
 */

#include "channel_concept.h"
#include "openvpn/packet.h"
#include "transport/transport.h"

#include <not_null.h>

#include <asio/io_context.hpp>
#include <asio/post.hpp>

#include <cstdint>
#include <utility>
#include <vector>

namespace clv::vpn {

template <typename Control>
struct ClientDataAdapter
{
    explicit ClientDataAdapter(Control &control)
        : control_(&control)
    {
        static_assert(ClientControlForAdapter<Control>,
                      "Control must satisfy ClientControlForAdapter");
    }

    void OnControlPacket(std::vector<std::uint8_t> data,
                         transport::PeerEndpoint /*sender*/)
    {
        asio::post(control_->io_context(),
                   [c = control_, d = std::move(data)]() mutable
        {
            c->OnControlPacketFromDataPath(std::move(d));
        });
    }

    void OnRxActivity()
    {
        control_->TouchLastRx();
    }

    void OnPeerDead(openvpn::SessionId /*sid*/)
    {
    }

  private:
    not_null<Control *> control_;
};

} // namespace clv::vpn

#endif // CLV_VPN_CLIENT_DATA_ADAPTER_H
