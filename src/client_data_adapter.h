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
    /**
     * @brief Bind to a control plane satisfying ClientControlForAdapter.
     * @param control Control plane that receives marshalled packets
     */
    explicit ClientDataAdapter(Control &control)
        : control_(&control)
    {
        static_assert(ClientControlForAdapter<Control>,
                      "Control must satisfy ClientControlForAdapter");
    }

    /**
     * @brief Post a control packet to the control io_context.
     * @param data Serialized OpenVPN control frame
     * @param sender Source endpoint (unused on client)
     */
    void OnControlPacket(std::vector<std::uint8_t> data,
                         transport::PeerEndpoint /*sender*/)
    {
        asio::post(control_->io_context(),
                   [c = control_, d = std::move(data)]() mutable
        {
            c->OnControlPacketFromDataPath(std::move(d));
        });
    }

    /** @brief Post an RX activity touch to the control plane. */
    void OnRxActivity()
    {
        control_->TouchLastRx();
    }

    /** @brief No-op on client (dead-peer handled by keepalive loop). */
    void OnPeerDead(openvpn::SessionId /*sid*/)
    {
    }

  private:
    not_null<Control *> control_;
};

} // namespace clv::vpn

#endif // CLV_VPN_CLIENT_DATA_ADAPTER_H
