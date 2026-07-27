// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SERVER_DCO_CONTROL_ADAPTER_H
#define CLV_VPN_SERVER_DCO_CONTROL_ADAPTER_H

/**
 * @file server_dco_control_adapter.h
 * @brief Server DCO transport — owns channel + data adapter.
 */

#include "data_path_stats.h"
#include "log_subsystems.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/dco_data_channel.h"
#include "openvpn/push_exchange_helpers.h"
#include "server_control_base.h"
#include "server_data_adapter.h"
#include "transport/batch_constants.h"
#include "transport/listener.h"
#include "transport/transport.h"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

namespace clv::vpn {

class ServerDcoTransport : public ServerControlBase<ServerDcoTransport>
{
  public:
    using channel_type = DcoDataChannel<ServerDataAdapter<ServerDcoTransport>>;

    explicit ServerDcoTransport(ServerControlConfig cfg)
        : ServerControlBase(std::move(cfg))
        , data_adapter_(*this)
        , listener_(std::in_place,
                    *io_context_,
                    config_->server->host,
                    config_->server->port)
        , channel_(*io_context_,
                   listener_->RawSocket(),
                   channel_type::NetworkConfig{
                       .server_network = config_->server->network,
                       .server_ip = DeriveServerIp(*config_->server),
                       .server_network_v6 = config_->server->network_v6,
                       .keepalive_interval =
                           static_cast<uint32_t>(config_->server->keepalive.first),
                       .keepalive_timeout =
                           static_cast<uint32_t>(config_->server->keepalive.second),
                       .tun_mtu = static_cast<uint16_t>(
                           config_->server->tun_mtu > 0 ? config_->server->tun_mtu : 0),
                   },
                   logger_manager_->GetLogger(logging::Subsystem::dataio),
                   *running_,
                   data_adapter_)
    {
        listener_->ApplySocketBuffers(config_->performance.socket_recv_buffer,
                                      config_->performance.socket_send_buffer,
                                      *logger_);
        currentBatchSize_ = transport::EffectiveBatchSize(config_->performance.batch_size);
    }

    channel_type &channel() noexcept { return channel_; }
    const channel_type &channel() const noexcept { return channel_; }

    void Start()
    {
        ConfigureDataPlane();
        asio::co_spawn(*io_context_, channel_.StartDataPath(), asio::detached);
        logger_->info("DCO mode active — kernel handles data path");
        StartBase();
    }

    void Stop()
    {
        StopBase();
        listener_.reset();
    }

    using ServerControlBase::OnControlPacketFromDataPath;
    using ServerControlBase::HandleTcpDisconnect;

    void LogStats(const DataPathStats &delta, double elapsedSec)
    {
        int actualRcvBuf = 0;
        int actualSndBuf = 0;
        if (listener_)
            std::tie(actualRcvBuf, actualSndBuf) = listener_->GetSocketBufferSizes();

        auto rates = ComputeStatsRates(delta, elapsedSec, actualRcvBuf, actualSndBuf);
        logger_->info("[stats/dco] {:.1f}s: "
                      "rx={} pkts ({:.1f} Mbps) "
                      "tx={} pkts ({:.1f} Mbps) "
                      "buf_rx={}ms buf_tx={}ms "
                      "peers={}",
                      elapsedSec,
                      delta.packetsReceived,
                      rates.rxMbps,
                      delta.packetsSent,
                      rates.txMbps,
                      FormatBufMs(rates.rxBufMs),
                      FormatBufMs(rates.txBufMs),
                      session_manager_.GetSessionCount());
    }

    void OnControlPacketFromDataPath(std::vector<std::uint8_t> data,
                                     transport::PeerEndpoint sender)
    {
        auto transport_handle = transport::TransportHandle(listener_->TransportFor(sender));
        asio::co_spawn(*io_context_,
                       ProcessNetworkPacket(std::move(data), sender, std::move(transport_handle)),
                       asio::detached);
    }

  private:
    ServerDataAdapter<ServerDcoTransport> data_adapter_;
    std::optional<transport::UdpListener> listener_;
    channel_type channel_;
    std::size_t currentBatchSize_ = 0;
};

} // namespace clv::vpn

#endif // CLV_VPN_SERVER_DCO_CONTROL_ADAPTER_H
