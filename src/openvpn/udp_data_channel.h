// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_UDP_DATA_CHANNEL_H
#define CLV_VPN_UDP_DATA_CHANNEL_H

/**
 * @file udp_data_channel.h
 * @brief Server-side UDP data channel (multi-peer, TUN-based).
 *
 * Composed from UdpServerMixin, which inherits UdpCore.
 * The core IS the engine — dedicated RX/TX threads, recvmmsg/sendmmsg
 * batching, Option 2 baton-ring TX workers, QSBR multi-peer dispatch.
 *
 * CRTP dispatch: the core's RxLoop calls OnControlPacket / OnRxActivity
 * on the derived type, and RunKeepaliveMonitor calls OnPeerDead.
 * Templated on the DataAdapter for fully static dispatch —
 * no function pointers, no type erasure.
 *
 * @tparam Adapter  DataAdapter CRTP base (e.g. ServerUdpDataAdapter<DataTransport<...>>).
 */

#include "multi_peer_policy.h"
#include "openvpn/connection.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "udp_core.h"
#include "udp_server_mixin.h"

#include "openvpn/session_manager.h"
#include "openvpn/vpn_config.h"
#include "routing_table.h"
#include "transport/transport.h"

#include <tun/tun_device.h>

#include <asio/io_context.hpp>

#include <spdlog/logger.h>

#include <atomic>
#include <cstdint>
#include <span>
#include <unistd.h>
#include <utility>
#include <vector>

namespace clv::vpn {

template <typename Adapter>
class UdpDataChannel
    : public UdpServerMixin<UdpDataChannel<Adapter>>
{
    using UdpServerMixinBase = UdpServerMixin<UdpDataChannel<Adapter>>;
    friend UdpServerMixinBase;
    friend UdpCore<UdpDataChannel<Adapter>, MultiPeerPolicy>;

  public:
    UdpDataChannel(asio::io_context &io_context,
                   RoutingTableIpv4 &routing_table,
                   RoutingTableIpv6 &routing_table_v6,
                   SessionManager &session_manager,
                   spdlog::logger &logger,
                   const VpnConfig::PerformanceConfig &perf_config,
                   int keepalive_interval,
                   int keepalive_timeout,
                   const std::atomic<bool> &running_flag)
        : UdpServerMixinBase(io_context,
                             routing_table,
                             routing_table_v6,
                             session_manager,
                             logger,
                             perf_config,
                             keepalive_interval,
                             keepalive_timeout,
                             running_flag)
    {
    }

    ~UdpDataChannel() = default;

    UdpDataChannel(const UdpDataChannel &) = delete;
    UdpDataChannel &operator=(const UdpDataChannel &) = delete;
    UdpDataChannel(UdpDataChannel &&) = delete;
    UdpDataChannel &operator=(UdpDataChannel &&) = delete;

    // -- Pull public API from mixin into this scope -------------------------

    using UdpServerMixinBase::ConfigureDataPlane;
    using UdpServerMixinBase::DecryptAndStripInPlace;
    using UdpServerMixinBase::GetBatchSize;
    using UdpServerMixinBase::GetRxBatchWindow;
    using UdpServerMixinBase::GetTxBurstAvgWindow;
    using UdpServerMixinBase::InstallKeys;
    using UdpServerMixinBase::ProcessIncomingDataPacket;

    // Client-side keepalive interface (no-arg): called by the generic KeepaliveLoop
    // via derived().SendKeepalivePing().  Injects the raw ping payload into the TUN
    // fd so TxSpsc encrypts and sends it through the unified outbound_packet_id counter.
    asio::awaitable<void> SendKeepalivePing()
    {
        int fd = this->TunNativeHandle();
        if (fd >= 0)
            ::write(fd, openvpn::KEEPALIVE_PING_PAYLOAD, openvpn::KEEPALIVE_PING_SIZE);
        co_return;
    }
    using UdpServerMixinBase::RunKeepaliveMonitor;
    // Server-side keepalive interface (Connection* arg): exposed from UdpServerMixin,
    // encrypts via SendEncryptedToSession and sends directly to the session's transport.
    // Different name casing (capital A) is intentional — different call sites, different roles.
    using UdpServerMixinBase::SendKeepAlivePing;
    using UdpServerMixinBase::SetBatchSize;
    using UdpServerMixinBase::SetSocketFd;
    using UdpServerMixinBase::SetSplitContext;
    using UdpServerMixinBase::SnapshotStats;
    using UdpServerMixinBase::StartDataPath;
    using UdpServerMixinBase::StopDataPath;
    using UdpServerMixinBase::StopKeepaliveMonitor;

    // -- Static adapter binding (called by DataTransport after construction) --

    void SetAdapter(Adapter &adapter)
    {
        adapter_ = &adapter;
    }

  private:
    // -- CRTP targets (called by UdpCore RxLoop / mixin keepalive) ----------

    void OnControlPacket(std::vector<std::uint8_t> data,
                         transport::PeerEndpoint sender)
    {
        adapter_->OnControlPacket(std::move(data), sender);
    }

    void OnRxActivity()
    {
        adapter_->OnRxActivity();
    }

    void OnPeerDead(openvpn::SessionId sid)
    {
        adapter_->OnPeerDead(sid);
    }

    // Called by UdpServerMixin::SendKeepAlivePing via this->derived()
    asio::awaitable<void> SendEncryptedToSession(Connection *session,
                                                 std::span<const std::uint8_t> plaintext)
    {
        co_await adapter_->SendEncryptedToSession(session, plaintext);
    }

    Adapter *adapter_ = nullptr;
};

} // namespace clv::vpn

#endif // CLV_VPN_UDP_DATA_CHANNEL_H
