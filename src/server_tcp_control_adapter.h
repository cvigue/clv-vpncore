// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SERVER_TCP_CONTROL_ADAPTER_H
#define CLV_VPN_SERVER_TCP_CONTROL_ADAPTER_H

/**
 * @file server_tcp_control_adapter.h
 * @brief CRTP control-side adapter for server TCP mode.
 *
 * Inherits ServerControlBase for the shared protocol engine and adds
 * TCP-specific transport wiring: channel construction with port-based
 * TcpDataChannel, callback setup, and TCP disconnect handling.
 *
 * TcpDataChannel owns its own io_context + background thread; the TUN
 * device is created on that internal context.  Control packets arrive
 * via TcpControlCallback (3-arg with TransportHandle) and are marshalled
 * to the server's io_context by the DataAdapter.
 *
 * @tparam Derived  DataTransport<TcpDataChannel, ServerUdpDataAdapter, ServerTcpControlAdapter>
 */

#include "log_subsystems.h"
#include "openvpn/connection.h"
#include "server_control_base.h"

#include "data_path_stats.h"
#include "transport/transport.h"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

#include <cstdint>
#include <tuple>
#include <utility>
#include <vector>

namespace clv::vpn {

/**
 * @brief Server control adapter for TCP transport.
 *
 * No additional state beyond the base — TcpDataChannel owns its listener,
 * internal thread, and per-client sockets.
 */
template <typename Derived>
class ServerTcpControlAdapter : public ServerControlBase<Derived>
{
    using TcpControlBase = ServerControlBase<Derived>;

  public:
    explicit ServerTcpControlAdapter(ServerControlConfig cfg)
    {
        this->InitializeBase(cfg);
    }

  protected:
    auto ChannelArgs()
    {
        // port and logger can't use forward_as_tuple: port is a cast rvalue,
        // logger is a raw ref via the manager (stable — manager owns loggers
        // for object lifetime). tuple_cat stores port by value; forward_as_tuple
        // refs all stable members.
        return std::tuple_cat(
            std::make_tuple(this->config_->server->host, this->config_->server->port),
            std::forward_as_tuple(
                this->routing_table_,
                this->routing_table_v6_,
                this->session_manager_,
                this->logger_manager_->GetLogger(logging::Subsystem::dataio),
                this->rx_counters_,
                this->tx_counters_,
                this->config_->server->keepalive.first,
                this->config_->server->keepalive.second,
                *this->running_));
    }

  public:
    void Start()
    {
        // Configure data plane (creates TUN device on the channel's internal thread)
        this->ConfigureDataPlane();

        // Start TCP accept loop + TUN transmit loop on internal thread
        asio::co_spawn(*this->io_context_, this->derived().StartDataPath(), asio::detached);
        this->logger_->info("TCP mode active — per-client coroutines on internal thread");

        this->StartBase();
    }

    void Stop()
    {
        this->StopBase();
        // TcpDataChannel::StopDataPath() joins the internal thread.
    }

    // -- Called from DataAdapter (via asio::post to control thread) -----------

    void OnControlPacketFromDataPath(std::vector<std::uint8_t> data,
                                     transport::PeerEndpoint sender,
                                     transport::TransportHandle transport)
    {
        asio::co_spawn(*this->io_context_,
                       this->ProcessNetworkPacket(std::move(data), sender, std::move(transport)),
                       asio::detached);
    }

    // -- TCP disconnect handling (called from DataAdapter) --------------------

    void HandleTcpDisconnect(transport::PeerEndpoint sender)
    {
        Connection::Endpoint endpoint{.addr = sender.addr, .port = sender.port};
        auto *session = this->session_manager_.FindSessionByEndpoint(endpoint);
        if (session)
        {
            this->logger_->info("TCP client disconnected: {}:{}",
                                sender.addr.to_string(),
                                sender.port);
            this->HandleDeadPeer(session->GetSessionId());
        }
    }

    // -- Stats hook (called by base StatsLoop) -------------------------------

    void LogStats(const DataPathStats &delta, double elapsedSec)
    {
        auto rates = ComputeStatsRates(delta, elapsedSec, 0, 0);
        this->logger_->info("[stats/tcp] {:.1f}s: "
                            "rx={} ({:.1f} Mbps) tx={} ({:.1f} Mbps) "
                            "dec={}/{} rmiss={} serr={} peers={}",
                            elapsedSec,
                            delta.packetsReceived,
                            rates.rxMbps,
                            delta.packetsSent,
                            rates.txMbps,
                            delta.packetsDecrypted,
                            delta.decryptFailures,
                            delta.routeLookupMisses,
                            delta.sendErrors,
                            this->session_manager_.GetSessionCount());
    }
};

} // namespace clv::vpn

#endif // CLV_VPN_SERVER_TCP_CONTROL_ADAPTER_H
