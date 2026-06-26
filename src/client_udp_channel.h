// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CLIENT_UDP_CHANNEL_H
#define CLV_VPN_CLIENT_UDP_CHANNEL_H

/**
 * @file client_udp_channel.h
 * @brief Client-side UDP data channel (P2P, TUN-based).
 *
 * Composed from UdpClientMixin, which inherits UdpCore.
 * The core IS the engine — dedicated RX/TX threads, recvmmsg/sendmmsg
 * batching, Option 2 baton-ring TX workers.
 *
 * CRTP dispatch: the core's RxLoop calls OnControlPacket / OnRxActivity
 * on the derived type.  Templated on the DataAdapter for fully static
 * dispatch — no function pointers, no type erasure.
 *
 * @tparam Adapter  DataAdapter CRTP base (e.g. ClientDataAdapter<DataTransport<...>>).
 */

#include "openvpn/crypto_algorithms.h"
#include "openvpn/data_channel.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "p2p_policy.h"
#include "transport/batch_constants.h"
#include "udp_client_mixin.h"

#include "iface_utils.h"
#include "openvpn/config_exchange.h"
#include "openvpn/key_derivation.h"
#include "openvpn/vpn_config.h"
#include "route_utils.h"
#include "transport/transport.h"
#include "udp_core.h"
#include "udp_engine_types.h"

#include <chrono>
#include <exception>
#include <span>
#include <stdexcept>
#include <string>
#include <net/ipv4_utils.h>

#include <tun/tun_device.h>

#include <asio/io_context.hpp>

#include <spdlog/logger.h>

#include <array>
#include <atomic>
#include <functional>
#include <cstring>
#include <cstdint>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>
#include <utility>
#include <vector>

namespace clv::vpn {

namespace ipv4 = clv::net::ipv4;

template <typename Adapter>
class ClientUdpChannel
    : public UdpClientMixin<ClientUdpChannel<Adapter>>
{
    using UdpClientMixinBase = UdpClientMixin<ClientUdpChannel<Adapter>>;
    friend UdpClientMixinBase;
    friend UdpCore<ClientUdpChannel<Adapter>, P2PPolicy>;

  public:
    ClientUdpChannel(asio::io_context &io_context,
                     spdlog::logger &logger,
                     const VpnConfig &config,
                     const std::atomic<bool> &running)
        : UdpClientMixinBase(io_context,
                             logger,
                             typename UdpClientMixinBase::Config{
                                 .batch_size = transport::EffectiveBatchSize(config.performance.batch_size),
                                 .cpu_affinity = config.process.cpu_affinity,
                                 .tx_affinity = config.performance.tx_thread_affinity,
                                 .tx_drain_depth = config.performance.tx_drain_depth,
                                 .tx_send_batch = config.performance.tx_send_batch,
                                 .tx_small_pkt_flush = config.performance.tx_small_pkt_flush,
                                 .max_recv = static_cast<std::size_t>(config.performance.max_recv),
                                 .rx_process_batch = static_cast<std::size_t>(config.performance.rx_process_batch),
                             })
    {
    }

    ~ClientUdpChannel()
    {
        this->StopDataPath();
    }

    ClientUdpChannel(const ClientUdpChannel &) = delete;
    ClientUdpChannel &operator=(const ClientUdpChannel &) = delete;
    ClientUdpChannel(ClientUdpChannel &&) = delete;
    ClientUdpChannel &operator=(ClientUdpChannel &&) = delete;

    // -- Pull public API from mixin into this scope -------------------------

    using UdpClientMixinBase::BindSocket;
    using UdpClientMixinBase::DeliverDecryptedPacket;
    using UdpClientMixinBase::GetBatchSize;
    using UdpClientMixinBase::GetRingOccWindow;
    using UdpClientMixinBase::GetRxBatchWindow;
    using UdpClientMixinBase::GetTxBurstAvgWindow;
    using UdpClientMixinBase::SetBatchSize;
    using UdpClientMixinBase::SetPeer;
    using UdpClientMixinBase::SnapshotStats;
    using UdpClientMixinBase::StartDataPath;
    using UdpClientMixinBase::StopDataPath;

    /// Override to also initialise the control-thread ping encrypt context.
    void EngineInstallKeys(const openvpn::EncryptionKey &encrypt_key,
                           const openvpn::EncryptionKey &decrypt_key,
                           std::uint8_t key_id)
    {
        UdpClientMixinBase::EngineInstallKeys(encrypt_key, decrypt_key, key_id);
        ping_tx_state_.ApplySnapshot(encrypt_key, key_id);
    }

    // -- Static adapter binding (called by DataTransport after construction) --

    void SetAdapter(Adapter &adapter)
    {
        adapter_ = &adapter;
        // Wire the P2P TX-engine callback so last_tx_ns_ tracks every outbound packet.
        this->policy().SetTxNsOutput(&last_tx_ns_);
    }

    std::chrono::steady_clock::time_point LastTxTime() const noexcept
    {
        return std::chrono::steady_clock::time_point(
            std::chrono::steady_clock::duration(
                last_tx_ns_.load(std::memory_order_relaxed)));
    }

    asio::awaitable<void> SendKeepalivePing()
    {
        const auto &snap = this->policy().tx_snapshot;
        if (snap.socket_fd < 0 || !ping_tx_state_.valid)
            co_return;

        // Build the wire buffer: kDataV2Overhead header + 16-byte ping payload.
        constexpr std::size_t kBufSize = openvpn::kDataV2Overhead + openvpn::KEEPALIVE_PING_SIZE;
        std::array<std::uint8_t, kBufSize> buf{};
        std::memcpy(buf.data() + openvpn::kDataV2Overhead,
                    openvpn::KEEPALIVE_PING_PAYLOAD,
                    openvpn::KEEPALIVE_PING_SIZE);

        // Claim the next packet ID from the shared counter (same sequence
        // used by TxSpsc) so the server's anti-replay window is never violated.
        const auto pkt_id = this->policy().outbound_pkt_id_.fetch_add(1, std::memory_order_relaxed);

        const auto wire_len = ping_tx_state_.EncryptInPlace(
            std::span<std::uint8_t>(buf.data(), kBufSize),
            openvpn::KEEPALIVE_PING_SIZE,
            snap.session_id,
            pkt_id);

        if (wire_len == 0)
            co_return;

        // Send directly on the raw socket (v4-mapped IPv6 for IPv4 peers).
        struct sockaddr_in6 sa6{};
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons(snap.peer.port);
        asio::ip::address_v6 v6;
        if (snap.peer.addr.is_v4())
            v6 = asio::ip::make_address_v6(asio::ip::v4_mapped, snap.peer.addr.to_v4());
        else
            v6 = snap.peer.addr.to_v6();
        auto v6bytes = v6.to_bytes();
        std::memcpy(&sa6.sin6_addr, v6bytes.data(), 16);

        ::sendto(snap.socket_fd, buf.data(), wire_len, 0, reinterpret_cast<const struct sockaddr *>(&sa6), sizeof(sa6));
        co_return;
    }

    // -- Control adapter hooks (called by ClientControlAdapter) ---------------

    void AttachTransport(transport::TransportHandle &handle,
                         transport::PeerEndpoint peer,
                         std::uint32_t peer_id)
    {
        auto &udp = std::get<transport::UdpTransport>(handle);
        UdpClientMixinBase::BindSocket(udp.RawSocket().native_handle());
        UdpClientMixinBase::SetPeer(peer, openvpn::SessionId{static_cast<std::uint64_t>(peer_id)});
    }

    void InstallDataPathKeys(const std::vector<std::uint8_t> &key_material,
                             openvpn::CipherAlgorithm cipher_algo,
                             openvpn::HmacAlgorithm hmac_algo,
                             std::uint8_t key_id,
                             openvpn::DataChannel &data_channel)
    {
        if (!openvpn::KeyDerivation::InstallKeys(data_channel, key_material, cipher_algo, hmac_algo, key_id, openvpn::PeerRole::Client))
            throw std::runtime_error("UDP: KeyDerivation::InstallKeys failed");
        EngineInstallKeys(data_channel.GetPrimaryEncryptKey(),
                          data_channel.GetPrimaryDecryptKey(),
                          key_id);
    }

    void ConfigureNetworkInterface(const openvpn::NegotiatedConfig &negotiated,
                                   const VpnConfig &config,
                                   asio::io_context &io_ctx)
    {
        this->tun_device_ = std::make_unique<tun::TunDevice>(io_ctx);
        auto *tun = this->tun_device_.get();
        std::string name = tun->Create(config.client->dev_name);
        this->logger().info("Created TUN: {}", name);

        const auto &assigned_ip = negotiated.ifconfig.first;
        const auto &assigned_netmask = negotiated.ifconfig.second;

        if (negotiated.topology == "subnet" && !assigned_netmask.empty())
        {
            auto prefix = ipv4::MaskToPrefix(asio::ip::make_address_v4(assigned_netmask).to_uint());
            tun->SetAddress(assigned_ip, prefix);
        }
        else
        {
            std::string remote_ip = assigned_netmask.empty() ? "255.255.255.255" : assigned_netmask;
            iface::SetPointToPoint(tun->GetName().c_str(), assigned_ip, remote_ip);
        }

        constexpr std::uint16_t kDefaultTunMtu = 1400;
        tun->SetMtu(kDefaultTunMtu);
        tun->BringUp();

        if (!negotiated.ifconfig_ipv6.first.empty())
        {
            auto prefix6 = static_cast<std::uint8_t>(negotiated.ifconfig_ipv6.second);
            tun->AddIpv6Address(negotiated.ifconfig_ipv6.first, prefix6);
        }
    }

    void InstallNegotiatedRoutes(const openvpn::NegotiatedConfig &negotiated)
    {
        auto *tun = this->tun_device_.get();
        if (!tun)
            return;

        std::string dev = tun->GetName();
        if (dev.empty())
            return;

        std::string connected_cidr;
        if (!negotiated.ifconfig.first.empty() && !negotiated.ifconfig.second.empty())
        {
            try
            {
                auto host = asio::ip::make_address_v4(negotiated.ifconfig.first).to_uint();
                auto prefix = ipv4::MaskToPrefix(asio::ip::make_address_v4(negotiated.ifconfig.second).to_uint());
                auto net = host & ipv4::CreateMask(prefix);
                connected_cidr = ipv4::Ipv4ToString(net) + "/" + std::to_string(prefix);
            }
            catch (...)
            {
            }
        }

        for (const auto &[network, gw, metric] : negotiated.routes)
        {
            std::string cidr;
            if (network.find('/') != std::string::npos)
                cidr = network;
            else if (!gw.empty())
            {
                try
                {
                    auto prefix = ipv4::MaskToPrefix(asio::ip::make_address_v4(gw).to_uint());
                    cidr = network + "/" + std::to_string(prefix);
                }
                catch (...)
                {
                    cidr = network + "/32";
                }
            }
            else
                cidr = network + "/32";

            if (!connected_cidr.empty() && cidr == connected_cidr)
            {
                this->logger().debug("Route: {} skipped (connected subnet, kernel-managed)", cidr);
                continue;
            }

            std::string via;
            if (!negotiated.route_gateway.empty())
                via = negotiated.route_gateway;
            this->logger().info("Route: {} dev {}{}", cidr, dev, via.empty() ? "" : " via " + via);
            try
            {
                route::ReplaceRoute4(dev, cidr, via);
            }
            catch (const std::exception &e)
            {
                this->logger().error("Route failed: {}", e.what());
            }
        }

        for (const auto &[network, gw, metric] : negotiated.routes_ipv6)
        {
            this->logger().info("IPv6 route: {} dev {}", network, dev);
            try
            {
                route::ReplaceRoute6(dev, network);
            }
            catch (const std::exception &e)
            {
                this->logger().error("IPv6 route failed: {}", e.what());
            }
        }
    }

    void OnTeardown()
    {
        if (this->tun_device_)
            this->tun_device_->Close();
    }

    void LaunchKeepalive(asio::io_context &io_ctx,
                         std::function<asio::awaitable<void>()> fn,
                         int interval)
    {
        if (interval > 0)
            asio::co_spawn(io_ctx, fn(), asio::detached);
    }

  private:
    // -- CRTP targets (called by UdpCore RxLoop) ----------------------------

    void OnControlPacket(std::vector<std::uint8_t> data,
                         transport::PeerEndpoint sender)
    {
        adapter_->OnControlPacket(std::move(data), sender);
    }

    void OnRxActivity()
    {
        adapter_->OnRxActivity();
    }

    Adapter *adapter_ = nullptr;
    std::atomic<std::int64_t> last_tx_ns_{0};
    TxEncryptState ping_tx_state_; ///< Control-thread-only encrypt context for keepalive pings.
};

} // namespace clv::vpn

#endif // CLV_VPN_CLIENT_UDP_CHANNEL_H
