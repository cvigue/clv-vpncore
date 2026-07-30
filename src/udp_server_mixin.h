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
#include "server_keepalive.h"
#include "traffic_policy.h"
#include "tunnel_zone.h"
#include "tunnel_zone_attachment_guard.h"
#include "udp_core.h"

#include "data_path_stats.h"
#include "openvpn/connection.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/crypto_context.h"
#include "openvpn/key_derivation.h"
#include "openvpn/session_key_install.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/session_manager.h"
#include "openvpn/vpn_config.h"
#include "routing_table.h"
#include "udp_engine_types.h"
#include "transport/batch_constants.h"


#include <string>
#include "platform/linux/tun/tun_device.h"
#include "platform/linux/tun/tun_setup.h"

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

template <typename Derived>
class UdpServerMixin : public UdpCore<Derived, MultiPeerPolicy>
{
    using Core = UdpCore<Derived, MultiPeerPolicy>;

  public:
    // -- Data plane setup (called from ServerControlBase::ConfigureDataPlane) ---

    /**
     * @brief Create hub TUN and register with the tunnel zone.
     * @param srv Server configuration (network, dev name, policy)
     * @param io_ctx ASIO context for the TUN device
     * @param zone Tunnel zone for hub attachment (may be null)
     * @return Hub TUN device name
     */
    std::string ConfigureDataPlane(const VpnConfig::ServerConfig &srv,
                                   asio::io_context &io_ctx,
                                   TunnelZone *zone)
    {
        tun_device_ = std::make_unique<tun::TunDevice>(io_ctx);
        std::string dev = tun::SetupServerTun(*tun_device_, srv, Core::logger());
        if (zone && !dev.empty())
            hub_attachment_.Reset(zone, BuildHubAttachmentSpec(srv, dev));
        return dev;
    }

    // -- Pre-start configuration ---------------------------------------------

    /**
     * @brief Wire QSBR publication context before StartDataPath.
     * @param ctx Split-datapath engine context
     */
    void SetSplitContext(UdpEngineContext *ctx)
    {
        split_ctx_ = ctx;
    }

    /**
     * @brief Bind the shared UDP socket before StartDataPath.
     * @param fd Raw socket file descriptor
     */
    void SetSocketFd(int fd)
    {
        socket_fd_ = fd;
    }

    // -- Engine lifecycle ----------------------------------------------------

    /** @brief Start multi-peer RX/TX worker threads. */
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

    /** @brief Stop workers, release hub attachment, and close TUN. */
    void StopDataPath()
    {
        hub_attachment_.Release();
        Core::CoreStop();
        if (tun_device_)
            tun_device_->Close();
    }

    // -- Slow-path packet processing (control-plane thread) ------------------

    /**
     * @brief Decrypt a data packet on the control thread and write to TUN.
     * @param session Owning connection
     * @param packet Encrypted OpenVPN data frame
     */
    asio::awaitable<void> ProcessIncomingDataPacket(Connection *session,
                                                    const openvpn::OpenVpnPacket &packet)
    {
        auto plaintext = session->GetCryptoContext().DecryptPacket(packet);

        Core::logger().debug("DecryptPacket returned {} bytes", plaintext.size());

        switch (openvpn::ClassifyDecryptedPayload(plaintext))
        {
        case openvpn::DecryptedPayloadDisposition::Drop:
            if (plaintext.empty())
                Core::logger().warn("DecryptPacket returned empty (decryption failed)");
            co_return;
        case openvpn::DecryptedPayloadDisposition::Keepalive:
            Core::logger().debug("Received OpenVPN keepalive ping from client");
            co_return;
        case openvpn::DecryptedPayloadDisposition::Forward:
            {
                tun::IpPacket ip_packet;
                ip_packet.data = std::move(plaintext);
                co_await SendToTun(ip_packet);
                co_return;
            }
        }
    }

    /**
     * @brief Decrypt a datagram in place and strip non-forwardable payloads.
     * @param session Owning connection
     * @param datagram Mutable wire buffer
     * @return Plaintext span, or empty for keepalive/drop/failure
     */
    std::span<std::uint8_t> DecryptAndStripInPlace(Connection *session,
                                                   std::span<std::uint8_t> datagram)
    {
        auto plaintext = session->GetCryptoContext().DecryptPacketInPlace(datagram);
        const auto disposition = openvpn::ClassifyDecryptedPayload(plaintext);
        if (disposition == openvpn::DecryptedPayloadDisposition::Keepalive)
            Core::logger().debug("Received OpenVPN keepalive ping from peer");
        if (disposition != openvpn::DecryptedPayloadDisposition::Forward)
            return {};
        return plaintext;
    }

    // -- Key management ------------------------------------------------------

    /**
     * @brief Derive and install session keys on a connection.
     * @return false on key derivation or install failure
     */
    bool InstallKeys(Connection *session,
                     const std::vector<uint8_t> &key_material,
                     openvpn::CipherAlgorithm cipher_algo,
                     openvpn::HmacAlgorithm hmac_algo,
                     std::uint8_t key_id)
    {
        return openvpn::InstallSessionKeys(session,
                                           key_material,
                                           cipher_algo,
                                           hmac_algo,
                                           key_id,
                                           Core::logger());
    }

    // -- Keepalive -----------------------------------------------------------

    /** @brief Send an encrypted keepalive ping to a session. */
    asio::awaitable<void> SendKeepAlivePing(Connection *session)
    {
        co_await this->derived().SendEncryptedToSession(
            session, std::span<const std::uint8_t>{openvpn::KEEPALIVE_PING_PAYLOAD, openvpn::KEEPALIVE_PING_SIZE});
    }

    /** @brief Run the server keepalive monitor coroutine. */
    asio::awaitable<void> RunKeepaliveMonitor()
    {
        return KeepaliveLoop(
            "UDP",
            running_,
            keepalive_timer_,
            keepalive_interval_,
            keepalive_timeout_,
            Core::logger(),
            [this]()
        { return CollectKeepaliveSessions(session_manager_); },
            [this](ConnectionKeepaliveView &sv)
        { return SendKeepAlivePing(sv.conn); },
            [this](ConnectionKeepaliveView &sv)
        { this->derived().OnPeerDead(sv.conn->GetSessionId()); });
    }

    /** @brief Cancel the keepalive monitor timer. */
    void StopKeepaliveMonitor()
    {
        keepalive_timer_.cancel();
    }

    // -- Stats ---------------------------------------------------------------

    /** @brief Data-path counter snapshot including route lookup misses. */
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

    /** @brief Set recvmmsg/sendmmsg batch size. */
    void SetBatchSize(std::size_t newSize)
    {
        perf_config_.batch_size = static_cast<int>(
            std::min(newSize, transport::kMaxBatchSize));
    }

    /** @brief Effective batch size from performance config. */
    std::size_t GetBatchSize() const
    {
        return transport::EffectiveBatchSize(perf_config_.batch_size);
    }

    /** @brief RX batch histogram window for stats logging. */
    BatchHistWindow &GetRxBatchWindow()
    {
        return Core::CoreRxBatchWindow();
    }

    /** @brief TX burst average window for stats logging. */
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
    TunnelZoneAttachmentGuard hub_attachment_;
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
