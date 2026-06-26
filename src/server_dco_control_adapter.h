// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SERVER_DCO_CONTROL_ADAPTER_H
#define CLV_VPN_SERVER_DCO_CONTROL_ADAPTER_H

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
#include <functional>
#include <optional>
#include <tuple>
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
class ServerDcoControlAdapter : public ServerControlBase<Derived>
{
    using DcoControlBase = ServerControlBase<Derived>;

  public:
    explicit ServerDcoControlAdapter(ServerControlConfig cfg)
    {
        this->InitializeBase(cfg);

        const auto &server_cfg = *this->config_->server;

        // Create listener
        listener_.emplace(cfg.io_context, server_cfg.host, server_cfg.port);
        listener_->ApplySocketBuffers(
            this->config_->performance.socket_recv_buffer,
            this->config_->performance.socket_send_buffer,
            *this->logger_);

        // Batch size
        currentBatchSize_ = transport::EffectiveBatchSize(this->config_->performance.batch_size);
    }

  protected:
    auto ChannelArgs()
    {
        // net_cfg is a value type whose type is only known when Derived is
        // complete (method bodies are instantiated lazily — safe here).
        // Stored by value inside the tuple; refs wrapped with std::ref.
        // Tuple is consumed immediately in DataTransport ctor; do not store.
        const auto &srv = *this->config_->server;
        return std::make_tuple(
            std::ref(*this->io_context_),
            std::ref(listener_->RawSocket()),
            typename Derived::channel_type::NetworkConfig{
                .server_network = srv.network,
                .server_ip = DeriveServerIp(srv),
                .server_network_v6 = srv.network_v6,
                .keepalive_interval = static_cast<uint32_t>(srv.keepalive.first),
                .keepalive_timeout = static_cast<uint32_t>(srv.keepalive.second),
                .tun_mtu = static_cast<uint16_t>(srv.tun_mtu > 0 ? srv.tun_mtu : 0),
            },
            std::ref(this->logger_manager_->GetLogger(logging::Subsystem::dataio)),
            std::ref(*this->running_));
    }

  public:
    void Start()
    {
        this->ConfigureDataPlane();
        asio::co_spawn(*this->io_context_, this->derived().StartDataPath(), asio::detached);
        this->logger_->info("DCO mode active — kernel handles data path");
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

        this->logger_->info("[stats/dco] {:.1f}s: "
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
                            this->session_manager_.GetSessionCount());
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

#endif // CLV_VPN_SERVER_DCO_CONTROL_ADAPTER_H
