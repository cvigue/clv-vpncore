// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_UDP_SERVER_MIXIN_H
#define CLV_VPN_UDP_SERVER_MIXIN_H

/**
 * @file udp_server_mixin.h
 * @brief Server-side CRTP mixin for UDP multi-peer data channel.
 *
 * Inherits UdpCore<Derived, MultiPeerPolicy> and adds multi-peer
 * lifecycle: QSBR context, keepalive monitor, per-connection key install,
 * and slow-path decrypt/encrypt helpers.
 *
 * Derived must provide OnControlPacket(vector<uint8_t>, PeerEndpoint),
 * OnRxActivity(), and OnPeerDead(SessionId) — all dispatched via
 * SetAdapter in the final channel.
 *
 * @tparam Derived  Final CRTP type (e.g. UdpDataChannel).
 */

#include "multi_peer_policy.h"
#include "keepalive_loop.h"
#include "udp_core.h"

#include "data_path_stats.h"
#include "openvpn/connection.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/data_channel.h"
#include "openvpn/key_derivation.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/session_manager.h"
#include "openvpn/vpn_config.h"
#include "routing_table.h"
#include "udp_engine_types.h"
#include "transport/batch_constants.h"


#include <stdexcept>
#include <string>
#include <tun/tun_device.h>

#include <net/ipv4_utils.h>
#include <net/ipv6_utils.h>

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <spdlog/logger.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace clv::vpn {

namespace ipv4 = clv::net::ipv4;
namespace ipv6 = clv::net::ipv6;

template <typename Derived>
class UdpServerMixin : public UdpCore<Derived, MultiPeerPolicy>
{
    using Core = UdpCore<Derived, MultiPeerPolicy>;

  public:
    // -- Data plane setup (called from ServerControlBase::ConfigureDataPlane) ---

    std::string ConfigureDataPlane(const VpnConfig::ServerConfig &srv,
                                   asio::io_context &io_ctx)
    {
        tun_device_ = std::make_unique<tun::TunDevice>(io_ctx);

        std::string dev_name = srv.dev;
        if (dev_name == "tun")
            dev_name = "";

        std::string actual_name = tun_device_->Create(dev_name);
        Core::logger().info("Created TUN device: {}", actual_name);

        auto parsed = ipv4::ParseCidr(srv.network);
        if (!parsed)
            throw std::invalid_argument("Invalid server network CIDR: " + srv.network);
        auto [network_addr, prefix_len] = *parsed;

        std::string server_ip = srv.bridge_ip.empty()
                                    ? ipv4::Ipv4ToString(network_addr + 1)
                                    : srv.bridge_ip;

        tun_device_->SetAddress(server_ip, prefix_len);
        Core::logger().info("Set TUN address: {}/{}", server_ip, static_cast<int>(prefix_len));
        tun_device_->SetMtu(srv.tun_mtu);

        if (srv.tun_txqueuelen > 0)
        {
            tun_device_->SetTxQueueLen(srv.tun_txqueuelen);
            Core::logger().info("Set TUN txqueuelen: {}", srv.tun_txqueuelen);
        }

        tun_device_->BringUp();
        Core::logger().info("TUN device is up");

        if (!srv.network_v6.empty())
        {
            auto parsed_v6 = ipv6::ParseCidr6(srv.network_v6);
            if (parsed_v6)
            {
                auto [net_v6, prefix_v6] = *parsed_v6;
                ipv6::Ipv6Address server_v6 = net_v6;
                server_v6[15] += 1;
                std::string server_v6_str = ipv6::Ipv6ToString(server_v6);
                tun_device_->AddIpv6Address(server_v6_str, prefix_v6);
                Core::logger().info("Set TUN IPv6 address: {}/{}", server_v6_str, prefix_v6);
            }
        }

        return actual_name;
    }

    // -- Pre-start configuration ---------------------------------------------

    void SetSplitContext(UdpEngineContext *ctx)
    {
        split_ctx_ = ctx;
    }

    void SetSocketFd(int fd)
    {
        socket_fd_ = fd;
    }

    // -- Engine lifecycle ----------------------------------------------------

    asio::awaitable<void> StartDataPath()
    {
        if (!split_ctx_ || !tun_device_ || socket_fd_ < 0)
        {
            Core::logger().error("UdpServerMixin::StartDataPath: "
                                 "missing split context, TUN device, or socket fd");
            co_return;
        }

        Core::CoreBind(socket_fd_, *tun_device_);

        // Wire QSBR context and socket into the multi-peer policy
        auto &pol = Core::policy();
        pol.ctx = split_ctx_;
        pol.socket_fd = socket_fd_;

        Core::CoreStart();

        Core::logger().info("Server multi-peer engine started (batch_size={})",
                            GetBatchSize());
        co_return;
    }

    void StopDataPath()
    {
        Core::CoreStop();
        if (tun_device_)
            tun_device_->Close();
    }

    // -- Slow-path packet processing (control-plane thread) ------------------

    asio::awaitable<void> ProcessIncomingDataPacket(Connection *session,
                                                    const openvpn::OpenVpnPacket &packet)
    {
        auto plaintext = session->GetDataChannel().DecryptPacket(packet);

        Core::logger().debug("DecryptPacket returned {} bytes", plaintext.size());

        if (!plaintext.empty())
        {
            if (openvpn::IsKeepalivePing(plaintext))
            {
                Core::logger().debug("Received OpenVPN keepalive ping from client");
                co_return;
            }

            if (plaintext.size() >= openvpn::IPV4_MIN_HEADER_SIZE)
            {
                tun::IpPacket ip_packet;
                ip_packet.data = std::move(plaintext);
                co_await SendToTun(ip_packet);
            }
        }
        else
        {
            Core::logger().warn("DecryptPacket returned empty (decryption failed)");
        }

        co_return;
    }

    std::span<std::uint8_t> DecryptAndStripInPlace(Connection *session,
                                                   std::span<std::uint8_t> datagram)
    {
        auto plaintext = session->GetDataChannel().DecryptPacketInPlace(datagram);

        if (plaintext.empty())
            return {};

        if (openvpn::IsKeepalivePing(plaintext))
        {
            Core::logger().debug("Received OpenVPN keepalive ping from peer");
            return {};
        }

        if (plaintext.size() < openvpn::IPV4_MIN_HEADER_SIZE)
            return {};

        return plaintext;
    }

    // -- Key management ------------------------------------------------------

    bool InstallKeys(Connection *session,
                     const std::vector<uint8_t> &key_material,
                     openvpn::CipherAlgorithm cipher_algo,
                     openvpn::HmacAlgorithm hmac_algo,
                     std::uint8_t key_id)
    {
        bool keys_installed = openvpn::KeyDerivation::InstallKeys(
            session->GetDataChannel(),
            key_material,
            cipher_algo,
            hmac_algo,
            key_id);

        if (keys_installed)
        {
            Core::logger().info("Data channel session keys installed successfully (key_id={})", key_id);
            session->GetDataChannel().SetCurrentKeyId(key_id);
        }
        else
        {
            Core::logger().error("Failed to install data channel session keys");
        }

        return keys_installed;
    }

    // -- Keepalive -----------------------------------------------------------

    asio::awaitable<void> SendKeepAlivePing(Connection *session)
    {
        co_await this->derived().SendEncryptedToSession(
            session, std::span<const std::uint8_t>{openvpn::KEEPALIVE_PING_PAYLOAD, openvpn::KEEPALIVE_PING_SIZE});
    }

    asio::awaitable<void> RunKeepaliveMonitor()
    {
        using tp = std::chrono::steady_clock::time_point;
        struct SessionView
        {
            Connection *conn;
            bool HasValidKeys() const
            {
                return conn->GetDataChannel().HasValidKeys();
            }
            tp GetLastActivity() const
            {
                return conn->GetLastActivity();
            }
            tp GetLastOutbound() const
            {
                return conn->GetLastOutbound();
            }
            void UpdateLastOutbound()
            {
                conn->UpdateLastOutbound();
            }
        };

        return KeepaliveLoop(
            "UDP",
            running_,
            keepalive_timer_,
            keepalive_interval_,
            keepalive_timeout_,
            Core::logger(),
            [this]()
        {
            std::vector<SessionView> result;
            for (auto id : session_manager_.GetAllSessionIds())
                if (auto *s = session_manager_.FindSession(id))
                    result.push_back(SessionView{s});
            return result;
        },
            [this](SessionView &sv)
        { return SendKeepAlivePing(sv.conn); },
            [this](SessionView &sv)
        { this->derived().OnPeerDead(sv.conn->GetSessionId()); });
    }

    void StopKeepaliveMonitor()
    {
        keepalive_timer_.cancel();
    }

    // -- Stats ---------------------------------------------------------------

    DataPathStats SnapshotStats() const
    {
        if (Core::CoreRunning())
        {
            auto stats = Core::CoreSnapshotStats();
            stats.routeLookupMisses = Core::policy().route_lookup_misses;
            return stats;
        }
        return {};
    }

    void SetBatchSize(std::size_t newSize)
    {
        perf_config_.batch_size = static_cast<int>(
            std::min(newSize, transport::kMaxBatchSize));
    }

    std::size_t GetBatchSize() const
    {
        return transport::EffectiveBatchSize(perf_config_.batch_size);
    }

    BatchHistWindow &GetRxBatchWindow()
    {
        return Core::CoreRxBatchWindow();
    }

    TxBurstAvgWindow &GetTxBurstAvgWindow()
    {
        return Core::CoreTxBurstAvgWindow();
    }

  protected:
    UdpServerMixin(asio::io_context &io_context,
                   RoutingTableIpv4 &routing_table,
                   RoutingTableIpv6 &routing_table_v6,
                   SessionManager &session_manager,
                   spdlog::logger &logger,
                   const VpnConfig::PerformanceConfig &perf_config,
                   int keepalive_interval,
                   int keepalive_timeout,
                   const std::atomic<bool> &running_flag)
        : Core(typename Core::Config{
                   .batch_size = transport::EffectiveBatchSize(perf_config.batch_size),
                   .cpu_affinity = perf_config.rx_thread_affinity,
                   .tx_affinity = perf_config.tx_thread_affinity,
                   .tx_drain_depth = perf_config.tx_drain_depth,
                   .tx_send_batch = perf_config.tx_send_batch,
                   .tx_small_pkt_flush = perf_config.tx_small_pkt_flush,
                   .max_recv = static_cast<std::size_t>(perf_config.max_recv),
                   .rx_process_batch = static_cast<std::size_t>(perf_config.rx_process_batch),
               },
               io_context, logger),
          routing_table_(routing_table), routing_table_v6_(routing_table_v6), session_manager_(session_manager), perf_config_(perf_config), keepalive_interval_(keepalive_interval > 0 ? keepalive_interval : 10), keepalive_timeout_(keepalive_timeout > 0 ? keepalive_timeout : 120), running_(running_flag), keepalive_timer_(io_context)
    {
    }

    ~UdpServerMixin()
    {
        StopDataPath();
    }

  protected:
    int TunNativeHandle() const noexcept
    {
        return tun_device_ ? tun_device_->NativeHandle() : -1;
    }

  private:
    asio::awaitable<void> SendToTun(const tun::IpPacket &packet)
    {
        try
        {
            co_await tun_device_->WritePacket(packet);
        }
        catch (const std::exception &e)
        {
            Core::logger().error("Error writing to TUN: {}", e.what());
        }
    }

    std::unique_ptr<tun::TunDevice> tun_device_;
    RoutingTableIpv4 &routing_table_;
    RoutingTableIpv6 &routing_table_v6_;
    SessionManager &session_manager_;
    VpnConfig::PerformanceConfig perf_config_;
    std::chrono::seconds keepalive_interval_;
    std::chrono::seconds keepalive_timeout_;
    const std::atomic<bool> &running_;
    UdpEngineContext *split_ctx_ = nullptr;
    int socket_fd_ = -1;
    asio::steady_timer keepalive_timer_;
};

} // namespace clv::vpn

#endif // CLV_VPN_UDP_SERVER_MIXIN_H
