// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_DCO_DATA_CHANNEL_H
#define CLV_VPN_DCO_DATA_CHANNEL_H

/**
 * @file dco_data_channel.h
 * @brief Server MP DCO data channel — composed from DcoCore + DcoServerDataMixin.
 *
 * The kernel handles all data-plane encrypt/decrypt; userspace only processes
 * the control channel.  Composed from shared netlink ops (DcoCore) and
 * server-specific multi-peer lifecycle (DcoServerDataMixin).
 *
 * CRTP dispatch: the mixin's recv loop and keepalive monitor call
 * OnControlPacket / OnPeerDead on this class, which forward directly
 * to the statically-typed DataAdapter — no function pointers, no type erasure.
 *
 * @tparam Adapter  DataAdapter CRTP base (e.g. ServerUdpDataAdapter<DataTransport<...>>).
 */

#include "dco_core.h"
#include "dco_server_data_mixin.h"

#include "openvpn/packet.h"
#include "openvpn/session_manager.h"
#include "transport/transport.h"

#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>

#include <spdlog/logger.h>

#include <atomic>
#include <cstdint>
#include <utility>
#include <vector>

namespace clv::vpn {

/**
 * @brief Server MP DCO data channel — composed from DcoCore + DcoServerDataMixin.
 *
 * @tparam Adapter  DataAdapter CRTP base type.
 */
template <typename Adapter>
class DcoDataChannel : public DcoServerDataMixin<DcoDataChannel<Adapter>>
{
    using DcoServerMixinBase = DcoServerDataMixin<DcoDataChannel<Adapter>>;
    friend DcoServerMixinBase;
    friend DcoCore<DcoDataChannel<Adapter>>;

  public:
    using NetworkConfig = DcoServerMixinBase::NetworkConfig;

    DcoDataChannel(asio::io_context &io_context,
                   asio::ip::udp::socket &socket,
                   const NetworkConfig &network_config,
                   spdlog::logger &logger,
                   const std::atomic<bool> &running_flag)
        : DcoServerMixinBase(io_context, socket, network_config, logger, running_flag)
    {
    }

    ~DcoDataChannel() = default;

    DcoDataChannel(const DcoDataChannel &) = delete;
    DcoDataChannel &operator=(const DcoDataChannel &) = delete;
    DcoDataChannel(DcoDataChannel &&) = delete;
    DcoDataChannel &operator=(DcoDataChannel &&) = delete;

    // -- Pull public API from mixin -----------------------------------------

    using DcoServerMixinBase::ConfigureDataPlane;
    using DcoServerMixinBase::DecryptAndStripInPlace;
    using DcoServerMixinBase::GetBatchSize;
    using DcoServerMixinBase::GetPeerId;
    using DcoServerMixinBase::InstallKeys;
    using DcoServerMixinBase::ProcessIncomingDataPacket;
    using DcoServerMixinBase::ProcessOutgoingTunPacket;
    using DcoServerMixinBase::RemoveDcoPeer;

    asio::awaitable<void> SendKeepalivePing()
    {
        // DCO keepalives are handled by the kernel via netlink.
        co_return;
    }
    using DcoServerMixinBase::RunKeepaliveMonitor;
    using DcoServerMixinBase::SendKeepAlivePing;
    using DcoServerMixinBase::SetBatchSize;
    using DcoServerMixinBase::SnapshotStats;
    using DcoServerMixinBase::StartDataPath;
    using DcoServerMixinBase::StopDataPath;
    using DcoServerMixinBase::StopKeepaliveMonitor;

    // -- Static adapter binding (called by DataTransport after construction) --

    void SetAdapter(Adapter &adapter)
    {
        adapter_ = &adapter;
    }

  private:
    // -- CRTP targets (called by DcoServerDataMixin) ------------------------

    void OnControlPacket(std::vector<std::uint8_t> data,
                         transport::PeerEndpoint sender)
    {
        adapter_->OnControlPacket(std::move(data), sender);
    }

    void OnPeerDead(openvpn::SessionId sid)
    {
        adapter_->OnPeerDead(sid);
    }

    Adapter *adapter_ = nullptr;
};

} // namespace clv::vpn

#endif // CLV_VPN_DCO_DATA_CHANNEL_H
