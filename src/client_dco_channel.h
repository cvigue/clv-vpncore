// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CLIENT_DCO_CHANNEL_H
#define CLV_VPN_CLIENT_DCO_CHANNEL_H

/**
 * @file client_dco_channel.h
 * @brief Client-side DCO data channel (P2P, kernel offload).
 *
 * Composed from DcoCore (shared netlink ops) + DcoClientDataMixin (single-peer
 * lifecycle, recv loop with CRTP callbacks).  The kernel handles all data-plane
 * encrypt/decrypt; userspace only processes the control channel.
 *
 * Lifecycle: construct → BindSocket → SetPeer →
 * EngineInstallKeys → StartTunReceiver → StopTunReceiver.
 *
 * CRTP dispatch: the mixin's recv loop calls OnControlPacket / OnRxActivity
 * on this class, which forward directly to the statically-typed DataAdapter
 * — no function pointers, no type erasure.
 *
 * @tparam Adapter  DataAdapter CRTP base (e.g. ClientDataAdapter<DataTransport<...>>).
 */

#include "dco_client_data_mixin.h"

#include "client_network_setup.h"
#include "dco_core.h"
#include "openvpn/config_exchange.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/crypto_context.h"
#include "openvpn/packet.h"
#include "openvpn/vpn_config.h"
#include "transport/transport.h"
#include <net/ipv4_utils.h>

#include <asio/io_context.hpp>

#include <chrono>
#include <exception>
#include <spdlog/logger.h>

#include <atomic>
#include <concepts>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace clv::vpn {

namespace ipv4 = clv::net::ipv4;

/**
 * @brief Client P2P DCO data channel — composed from DcoCore + DcoClientDataMixin.
 *
 * @tparam Adapter  DataAdapter CRTP base type.
 */
template <typename Adapter>
class ClientDcoChannel : public DcoClientDataMixin<ClientDcoChannel<Adapter>>
{
    using DataMixinBase = DcoClientDataMixin<ClientDcoChannel<Adapter>>;
    friend DataMixinBase;
    friend DcoCore<ClientDcoChannel<Adapter>>;

  public:
    /**
     * @brief Construct the client DCO data channel.
     * @param io_context ASIO context for the control recv loop
     * @param logger Logger for DCO events
     * @param config Client configuration (keepalive intervals)
     * @param running Shared stop flag
     * @param adapter Data→control adapter
     */
    ClientDcoChannel(asio::io_context &io_context,
                     spdlog::logger &logger,
                     const VpnConfig &config,
                     const std::atomic<bool> &running,
                     Adapter &adapter)
        : DataMixinBase(io_context,
                        logger,
                        static_cast<std::uint32_t>(config.client->keepalive_interval),
                        static_cast<std::uint32_t>(config.client->keepalive_timeout),
                        running),
          adapter_(&adapter)
    {
    }

    /** @brief Default destructor; mixin tears down DCO resources. */
    ~ClientDcoChannel() = default;

    ClientDcoChannel(const ClientDcoChannel &) = delete;
    ClientDcoChannel &operator=(const ClientDcoChannel &) = delete;
    ClientDcoChannel(ClientDcoChannel &&) = delete;
    ClientDcoChannel &operator=(ClientDcoChannel &&) = delete;

    // -- Pull public API from mixin into this scope -------------------------

    using DataMixinBase::BindSocket;
    using DataMixinBase::ConfigureDcoInterface;
    using DataMixinBase::DeliverDecryptedPacket;
    using DataMixinBase::EngineInstallKeys;
    using DataMixinBase::GetBatchSize;
    using DataMixinBase::GetIfName;
    using DataMixinBase::InstallRoute;
    using DataMixinBase::PushKeysToKernel;
    using DataMixinBase::SetBatchSize;
    using DataMixinBase::SetPeer;
    using DataMixinBase::SnapshotStats;
    using DataMixinBase::StartDataPath;
    using DataMixinBase::StopDataPath;


    /**
     * @brief Report "just now" so KeepaliveLoop skips userspace PINGs.
     *
     * DCO keepalives are handled by the kernel.
     */
    std::chrono::steady_clock::time_point LastTxTime() const noexcept
    {
        // DCO keepalives are managed by the kernel; always report "just now" so
        // KeepaliveLoop never sends redundant userspace PINGs.
        return std::chrono::steady_clock::now();
    }

    // -- Control adapter hooks (called by ClientControlAdapter) ---------------

    /** @brief Bind UDP socket, peer, and push any pending keys to the kernel. */
    void AttachTransport(transport::TransportHandle &handle,
                         transport::PeerEndpoint peer,
                         std::uint32_t peer_id)
    {
        auto &udp = std::get<transport::UdpTransport>(handle);
        DataMixinBase::BindSocket(udp.SharedSocket());
        DataMixinBase::SetPeer(peer, openvpn::SessionId{static_cast<std::uint64_t>(peer_id)});

        if (!pending_key_material_.empty())
        {
            if (!DataMixinBase::PushKeysToKernel(pending_key_material_, pending_cipher_algo_, pending_key_id_))
                throw std::runtime_error("DCO: AttachTransport: PushKeysToKernel failed");
            pending_key_material_.clear();
        }
    }

    /** @brief Stage or push data-path keys to the DCO kernel peer. */
    void InstallDataPathKeys(const std::vector<std::uint8_t> &key_material,
                             openvpn::CipherAlgorithm cipher_algo,
                             openvpn::HmacAlgorithm /*hmac_algo*/,
                             std::uint8_t key_id,
                             openvpn::CryptoContext &crypto_context)
    {
        limits_crypto_ = &crypto_context;
        pending_key_material_ = key_material;
        pending_cipher_algo_ = cipher_algo;
        pending_key_id_ = key_id;
        if (DataMixinBase::HasPeer())
        {
            if (!DataMixinBase::PushKeysToKernel(pending_key_material_, pending_cipher_algo_, pending_key_id_))
                throw std::runtime_error("DCO: InstallDataPathKeys: PushKeysToKernel failed");
            pending_key_material_.clear();
        }
    }

    /** @brief Configure the DCO netdev from negotiated PUSH settings. */
    void ConfigureNetworkInterface(const openvpn::NegotiatedConfig &negotiated,
                                   const VpnConfig & /*config*/,
                                   asio::io_context & /*io_ctx*/)
    {
        const auto &assigned_ip = negotiated.ifconfig.first;
        const auto &assigned_netmask = negotiated.ifconfig.second;

        std::uint8_t prefix = 24;
        if (negotiated.topology == "subnet" && !assigned_netmask.empty())
            prefix = ipv4::MaskToPrefix(asio::ip::make_address_v4(assigned_netmask).to_uint());

        std::string ipv6_addr;
        std::uint8_t ipv6_prefix = 0;
        if (!negotiated.ifconfig_ipv6.first.empty())
        {
            ipv6_addr = negotiated.ifconfig_ipv6.first;
            ipv6_prefix = static_cast<std::uint8_t>(negotiated.ifconfig_ipv6.second);
        }

        DataMixinBase::ConfigureDcoInterface(assigned_ip,
                                             prefix,
                                             ipv6_addr,
                                             ipv6_prefix,
                                             static_cast<std::uint16_t>(negotiated.tun_mtu));
    }

    /** @brief Install negotiated routes on the DCO interface. */
    void InstallNegotiatedRoutes(const openvpn::NegotiatedConfig &negotiated)
    {
        for (const auto &[network, gw, metric] : negotiated.routes)
        {
            (void)metric;
            const std::string cidr = NormalizeNegotiatedRoute4(network, gw);

            this->logger_->info("Route: {} dev {}", cidr, DataMixinBase::GetIfName());
            DataMixinBase::InstallRoute(cidr);
        }

        for (const auto &[network, gw, metric] : negotiated.routes_ipv6)
        {
            (void)gw;
            (void)metric;
            this->logger_->info("IPv6 route: {} dev {}", network, DataMixinBase::GetIfName());
            DataMixinBase::InstallRoute(network, /*is_ipv6=*/true);
        }
    }

    /** @brief No-op; DCO netdev lifetime is managed by the mixin. */
    void OnTeardown()
    {
    }

    // For DCO this is a NoOp, as the kernel handles keepalives autonomously.
    /** @brief No-op; kernel handles keepalives. */
    template <std::invocable Fn>
    void LaunchKeepalive(asio::io_context & /*io_ctx*/, Fn && /*fn*/, int /*interval*/)
    {
    }

    /** @brief No-op; kernel handles keepalives. */
    asio::awaitable<void> SendKeepalivePing()
    {
        co_return; // DCO kernel handles keepalives autonomously
    }

    /** @brief CryptoContext used for outbound limits bookkeeping. */
    openvpn::CryptoContext &GetLimitsCryptoContext()
    {
        if (!limits_crypto_)
            throw std::runtime_error("DCO: outbound limits CryptoContext not configured");
        return *limits_crypto_;
    }

  private:
    // -- CRTP targets (called by DcoClientDataMixin recv loop) --------------

    void OnControlPacket(std::vector<std::uint8_t> data,
                         transport::PeerEndpoint sender)
    {
        adapter_->OnControlPacket(std::move(data), sender);
    }

    void OnRxActivity()
    {
        adapter_->OnRxActivity();
    }

    Adapter *adapter_;
    openvpn::CryptoContext *limits_crypto_ = nullptr;

    // -- Pending key state (held until AttachTransport establishes peer) -----
    std::vector<std::uint8_t> pending_key_material_;
    openvpn::CipherAlgorithm pending_cipher_algo_{};
    std::uint8_t pending_key_id_ = 0;
};

} // namespace clv::vpn

#endif // CLV_VPN_CLIENT_DCO_CHANNEL_H
