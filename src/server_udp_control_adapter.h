// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SERVER_UDP_CONTROL_ADAPTER_H
#define CLV_VPN_SERVER_UDP_CONTROL_ADAPTER_H

/**
 * @file server_udp_control_adapter.h
 * @brief CRTP control-side adapter for server UDP + DCO modes.
 *
 * Inherits ServerControlBase for the shared protocol engine and adds
 * UDP-specific transport wiring: UdpListener, split-datapath context,
 * batch statistics, and the DCO channel-construction path.
 *
 * @tparam Derived  DataTransport<UdpDataChannel|DcoDataChannel, ...>
 */

#include "log_subsystems.h"
#include "server_control_base.h"

#include "data_path_stats.h"
#include "udp_engine_types.h"
#include "transport/batch_constants.h"
#include "transport/listener.h"
#include "transport/transport.h"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace clv::vpn {

/**
 * @brief Server control adapter for UDP transport (both UDP-userspace and DCO).
 *
 * Owns: UdpListener, batch counters/windows, and the split-datapath setup.
 * Protocol engine (sessions, handshake, routing, etc.) lives in ServerControlBase.
 */
template <typename Derived>
class ServerUdpControlAdapter : public ServerControlBase<Derived>
{
    using UdpControlBase = ServerControlBase<Derived>;

  public:
    explicit ServerUdpControlAdapter(ServerControlConfig cfg)
    {
        this->InitializeBase(cfg);

        const auto &server_cfg = *this->config_->server;

        // Create UDP listener
        if (server_cfg.proto != "tcp")
        {
            listener_.emplace(cfg.io_context, server_cfg.host, server_cfg.port);
            listener_->ApplySocketBuffers(
                this->config_->performance.socket_recv_buffer,
                this->config_->performance.socket_send_buffer,
                *this->logger_);
        }

        // Batch size
        currentBatchSize_ = transport::EffectiveBatchSize(this->config_->performance.batch_size);
    }

  protected:
    auto ChannelArgs()
    {
        // All refs are stable for object lifetime; consumed immediately in
        // DataTransport ctor. Do not store the returned tuple.
        return std::forward_as_tuple(
            *this->io_context_,
            this->routing_table_,
            this->routing_table_v6_,
            this->session_manager_,
            this->logger_manager_->GetLogger(logging::Subsystem::dataio),
            this->config_->performance,
            this->config_->server->keepalive.first,
            this->config_->server->keepalive.second,
            *this->running_);
    }

  public:
    void Start()
    {
        this->ConfigureDataPlane();

        this->split_ctx_ = std::make_unique<UdpEngineContext>();
        this->derived().ConfigureSplitContext(this->split_ctx_.get());
        this->derived().ConfigureSocketFd(listener_->RawSocket().native_handle());

        asio::co_spawn(*this->io_context_, this->derived().StartDataPath(), asio::detached);
        this->logger_->info("Split-datapath enabled: TX + RX on dedicated threads");

        this->StartBase();
    }

    void Stop()
    {
        this->StopBase();
        listener_.reset();
    }

    // -- Called from DataAdapter (via asio::post to control thread) -----------

    void OnControlPacketFromDataPath(std::vector<std::uint8_t> data,
                                     transport::PeerEndpoint sender)
    {
        auto transport_handle = transport::TransportHandle(
            listener_->TransportFor(sender));
        asio::co_spawn(*this->io_context_,
                       this->ProcessNetworkPacket(std::move(data), sender, std::move(transport_handle)),
                       asio::detached);
    }

    // -- Control adapter methods (control → data) ----------------------------

    void ConfigureSplitContext(UdpEngineContext *ctx)
    {
        this->ch().SetSplitContext(ctx);
    }
    void ConfigureSocketFd(int fd)
    {
        this->ch().SetSocketFd(fd);
    }

    // -- Stats hook (called by base StatsLoop) -------------------------------

    void LogStats(const DataPathStats &delta, double elapsedSec)
    {
        int actualRcvBuf = 0;
        int actualSndBuf = 0;
        if (listener_)
            std::tie(actualRcvBuf, actualSndBuf) = listener_->GetSocketBufferSizes();

        auto rates = ComputeStatsRates(delta, elapsedSec, actualRcvBuf, actualSndBuf);

        auto rxHist = this->ch().GetRxBatchWindow().SnapshotAndReset();
        auto [burstTotal, burstCount] = this->ch().GetTxBurstAvgWindow().SnapshotAndReset();
        auto rxHistStr = FormatBatchHist(rxHist, delta.batchSaturations);
        auto txBstStr = FormatAvgBurst(burstTotal, burstCount);

        this->logger_->info("[stats] {:.1f}s: "
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

    // -- Accessors -----------------------------------------------------------

    transport::UdpListener *udp_listener() noexcept
    {
        return listener_ ? &*listener_ : nullptr;
    }

  private:
    std::optional<transport::UdpListener> listener_;
    std::size_t currentBatchSize_ = 0;
};

} // namespace clv::vpn

#endif // CLV_VPN_SERVER_UDP_CONTROL_ADAPTER_H
