// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SERVER_TCP_CONTROL_ADAPTER_H
#define CLV_VPN_SERVER_TCP_CONTROL_ADAPTER_H

/**
 * @file server_tcp_control_adapter.h
 * @brief Server TCP transport — owns channel + data adapter.
 */

#include "data_path_stats.h"
#include "log_subsystems.h"
#include "openvpn/connection.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/tcp_data_channel.h"
#include "server_control_base.h"
#include "server_data_adapter.h"
#include "transport/transport.h"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

#include <cstdint>
#include <utility>
#include <vector>

namespace clv::vpn {

class ServerTcpTransport : public ServerControlBase<ServerTcpTransport>
{
  public:
    using channel_type = TcpDataChannel<ServerDataAdapter<ServerTcpTransport>>;

    explicit ServerTcpTransport(ServerControlConfig cfg)
        : ServerControlBase(std::move(cfg))
        , data_adapter_(*this)
        , channel_(config_->server->host,
                   config_->server->port,
                   routing_table_,
                   routing_table_v6_,
                   session_manager_,
                   logger_manager_->GetLogger(logging::Subsystem::dataio),
                   rx_counters_,
                   tx_counters_,
                   config_->server->keepalive.first,
                   config_->server->keepalive.second,
                   *running_,
                   data_adapter_)
    {
    }

    channel_type &channel() noexcept { return channel_; }
    const channel_type &channel() const noexcept { return channel_; }

    void Start()
    {
        ConfigureDataPlane();
        asio::co_spawn(*io_context_, channel_.StartDataPath(), asio::detached);
        logger_->info("TCP mode active — per-client coroutines on internal thread");
        StartBase();
    }

    void Stop()
    {
        StopBase();
    }

    using ServerControlBase::OnControlPacketFromDataPath;

    void LogStats(const DataPathStats &delta, double elapsedSec)
    {
        auto rates = ComputeStatsRates(delta, elapsedSec, 0, 0);
        logger_->info("[stats/tcp] {:.1f}s: "
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
                      session_manager_.GetSessionCount());
    }

    void OnControlPacketFromDataPath(std::vector<std::uint8_t> data,
                                     transport::PeerEndpoint sender,
                                     transport::TransportHandle transport)
    {
        asio::co_spawn(*io_context_,
                       ProcessNetworkPacket(std::move(data), sender, std::move(transport)),
                       asio::detached);
    }

    void HandleTcpDisconnect(transport::PeerEndpoint sender)
    {
        Connection::Endpoint endpoint{.addr = sender.addr, .port = sender.port};
        auto *session = session_manager_.FindSessionByEndpoint(endpoint);
        if (session)
        {
            logger_->info("TCP client disconnected: {}:{}",
                          sender.addr.to_string(),
                          sender.port);
            HandleDeadPeer(session->GetSessionId());
        }
    }

  private:
    ServerDataAdapter<ServerTcpTransport> data_adapter_;
    channel_type channel_;
};

} // namespace clv::vpn

#endif // CLV_VPN_SERVER_TCP_CONTROL_ADAPTER_H
