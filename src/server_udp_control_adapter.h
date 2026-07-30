// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SERVER_UDP_CONTROL_ADAPTER_H
#define CLV_VPN_SERVER_UDP_CONTROL_ADAPTER_H

/**
 * @file server_udp_control_adapter.h
 * @brief Server UDP userspace transport — owns channel + data adapter.
 */

#include "data_path_stats.h"
#include "log_subsystems.h"
#include "openvpn/udp_data_channel.h"
#include "server_control_base.h"
#include "server_data_adapter.h"
#include "transport/batch_constants.h"
#include "transport/listener.h"
#include "transport/transport.h"
#include "udp_engine_types.h"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>

namespace clv::vpn {

/**
 * @brief Server UDP userspace transport leaf.
 *
 * Owns UdpListener, UdpDataChannel, and the shared ServerControlBase engine.
 */
class ServerUdpTransport : public ServerControlBase<ServerUdpTransport>
{
  public:
    using channel_type = UdpDataChannel<ServerDataAdapter<ServerUdpTransport>>;

    /**
     * @brief Construct the UDP server transport leaf.
     * @param cfg Control-plane resources (io_context, config, loggers, zone)
     */
    explicit ServerUdpTransport(ServerControlConfig cfg)
        : ServerControlBase(std::move(cfg)), data_adapter_(*this), listener_(std::in_place,
                                                                             *io_context_,
                                                                             config_->server->host,
                                                                             config_->server->port),
          channel_(*io_context_,
                   routing_table_,
                   routing_table_v6_,
                   session_manager_,
                   logger_manager_->GetLogger(logging::Subsystem::dataio),
                   config_->performance,
                   config_->server->keepalive.first,
                   config_->server->keepalive.second,
                   *running_,
                   data_adapter_)
    {
        listener_->ApplySocketBuffers(config_->performance.socket_recv_buffer,
                                      config_->performance.socket_send_buffer,
                                      *logger_);
        currentBatchSize_ = transport::EffectiveBatchSize(config_->performance.batch_size);
    }

    /** @brief Owned UDP multi-peer data channel. */
    channel_type &channel() noexcept
    {
        return channel_;
    }
    /** @brief Owned UDP multi-peer data channel (const). */
    const channel_type &channel() const noexcept
    {
        return channel_;
    }

    /** @brief Start split-datapath workers and the control-plane base loops. */
    void Start()
    {
        ConfigureDataPlane();
        split_ctx_ = std::make_unique<UdpEngineContext>();
        channel_.SetSplitContext(split_ctx_.get());
        channel_.SetSocketFd(listener_->RawSocket().native_handle());
        asio::co_spawn(*io_context_, channel_.StartDataPath(), asio::detached);
        logger_->info("Split-datapath enabled: TX + RX on dedicated threads");
        StartBase();
    }

    /** @brief Stop control loops and tear down the UDP listener. */
    void Stop()
    {
        StopBase();
        listener_.reset();
    }

    using ServerControlBase::HandleTcpDisconnect;
    using ServerControlBase::OnControlPacketFromDataPath;

    /**
     * @brief Log periodic data-path stats with batch histograms.
     * @param delta Counter delta since last tick
     * @param elapsedSec Wall time since last tick
     */
    void LogStats(const DataPathStats &delta, double elapsedSec)
    {
        int actualRcvBuf = 0;
        int actualSndBuf = 0;
        if (listener_)
            std::tie(actualRcvBuf, actualSndBuf) = listener_->GetSocketBufferSizes();

        auto rates = ComputeStatsRates(delta, elapsedSec, actualRcvBuf, actualSndBuf);
        auto rxHist = channel_.GetRxBatchWindow().SnapshotAndReset();
        auto [burstTotal, burstCount] = channel_.GetTxBurstAvgWindow().SnapshotAndReset();
        auto rxHistStr = FormatBatchHist(rxHist, delta.batchSaturations);
        auto txBstStr = FormatAvgBurst(burstTotal, burstCount);

        logger_->info("[stats] {:.1f}s: "
                      "rx={} ({:.0f}M) tx={} ({:.0f}M) "
                      "rx{} bst={} "
                      "buf={}/{}ms "
                      "dec={}/{} rmiss={} serr={} spf={}",
                      elapsedSec,
                      delta.packetsReceived,
                      rates.rxMbps,
                      delta.packetsSent,
                      rates.txMbps,
                      rxHistStr,
                      txBstStr,
                      FormatBufMs(rates.rxBufMs),
                      FormatBufMs(rates.txBufMs),
                      delta.packetsDecrypted,
                      delta.decryptFailures,
                      delta.routeLookupMisses,
                      delta.sendErrors,
                      delta.txSmallPktFlush);
    }

    /**
     * @brief Entry point for control packets from the UDP data adapter.
     * @param data Serialized OpenVPN control frame
     * @param sender Source endpoint of the datagram
     */
    void OnControlPacketFromDataPath(std::vector<std::uint8_t> data,
                                     transport::PeerEndpoint sender)
    {
        auto transport_handle = transport::TransportHandle(listener_->TransportFor(sender));
        asio::co_spawn(*io_context_,
                       ProcessNetworkPacket(std::move(data), sender, std::move(transport_handle)),
                       asio::detached);
    }

  private:
    ServerDataAdapter<ServerUdpTransport> data_adapter_;
    std::optional<transport::UdpListener> listener_;
    channel_type channel_;
    std::size_t currentBatchSize_ = 0;
};

} // namespace clv::vpn

#endif // CLV_VPN_SERVER_UDP_CONTROL_ADAPTER_H
