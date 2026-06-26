// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CLIENT_TCP_CHANNEL_H
#define CLV_VPN_CLIENT_TCP_CHANNEL_H

/**
 * @file client_tcp_channel.h
 * @brief Client-side TCP data channel (single-packet coroutine path).
 *
 * Coroutine-based single-packet encrypt/decrypt on the main io_context.
 * No batching, no raw FD, no extra threads — just TCP recv → decrypt →
 * TUN write and TUN read → encrypt → TCP send.
 *
 * Lifecycle: construct → SetAdapter → SetTransport (provides TcpTransport*)
 * → EngineInstallKeys → StartTunReceiver (launches coroutine loops)
 * → StopTunReceiver.
 *
 * @tparam Adapter  DataAdapter CRTP base (e.g. ClientDataAdapter<DataTransport<...>>).
 *
 * @see ClientUdpChannel for the batched UDP equivalent.
 * @see ClientDcoChannel for the kernel-offload equivalent.
 */

#include "data_path_stats.h"
#include "iface_utils.h"
#include "openvpn/config_exchange.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/data_channel.h"
#include "openvpn/key_derivation.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/vpn_config.h"
#include "route_utils.h"
#include "transport/transport.h"

#include <chrono>
#include <not_null.h>
#include <stdexcept>
#include <string>
#include <tun/tun_device.h>
#include <net/ipv4_utils.h>

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/use_awaitable.hpp>

#include <spdlog/logger.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace clv::vpn {

namespace ipv4 = clv::net::ipv4;

/**
 * @brief Client P2P TCP data channel — coroutine single-packet path.
 *
 * Templated on the DataAdapter type for fully static dispatch —
 * no function pointers, no type erasure.  The compiler can inline
 * the entire control-packet and RX-activity dispatch chain.
 *
 * @tparam Adapter  DataAdapter CRTP base type.
 */
template <typename Adapter>
class ClientTcpChannel
{
  public:
    ClientTcpChannel(asio::io_context &io_context,
                     spdlog::logger &logger,
                     const VpnConfig & /*config*/,
                     const std::atomic<bool> &running)
        : io_context_(io_context),
          logger_(&logger),
          running_(running),
          data_channel_(logger)
    {
        logger_->info("Client TCP channel initialized");
    }

    ~ClientTcpChannel()
    {
        StopDataPath();
    }

    ClientTcpChannel(const ClientTcpChannel &) = delete;
    ClientTcpChannel &operator=(const ClientTcpChannel &) = delete;
    ClientTcpChannel(ClientTcpChannel &&) = delete;
    ClientTcpChannel &operator=(ClientTcpChannel &&) = delete;

    // -- Static adapter binding (called by DataTransport after construction) --

    void SetAdapter(Adapter &adapter)
    {
        adapter_ = &adapter;
    }

    asio::awaitable<void> SendKeepalivePing()
    {
        if (!tcp_)
            co_return;
        std::vector<std::uint8_t> payload(
            openvpn::KEEPALIVE_PING_PAYLOAD,
            openvpn::KEEPALIVE_PING_PAYLOAD + openvpn::KEEPALIVE_PING_SIZE);
        auto encrypted = data_channel_.EncryptPacket(payload, openvpn::SessionId{});
        if (encrypted.empty())
            co_return;
        co_await tcp_->Send(encrypted);
        last_tx_ns_.store(
            std::chrono::steady_clock::now().time_since_epoch().count(),
            std::memory_order_relaxed);
    }

    // -- TCP lifecycle (called by ClientControlAdapter) ----------------------

    void SetTransport(transport::TcpTransport *tcp)
    {
        tcp_ = tcp;
    }

    void EngineInstallKeys(const openvpn::EncryptionKey &encrypt_key,
                           const openvpn::EncryptionKey &decrypt_key,
                           std::uint8_t key_id)
    {
        pending_encrypt_ = encrypt_key;
        pending_decrypt_ = decrypt_key;
        pending_key_id_ = key_id;
        keys_installed_ = true;

        data_channel_.InstallNewKeys(decrypt_key, encrypt_key, key_id);

        logger_->debug("TCP: Keys installed (key_id={})", key_id);
    }

    asio::awaitable<void> StartDataPath()
    {
        if (!tcp_)
        {
            logger_->error("TCP: StartDataPath called without transport");
            co_return;
        }
        if (!tun_device_)
        {
            logger_->error("TCP: StartDataPath called without TUN device");
            co_return;
        }
        if (!keys_installed_)
        {
            logger_->error("TCP: StartDataPath called without keys");
            co_return;
        }

        logger_->debug("TCP: data path coroutines starting");

        asio::co_spawn(io_context_, TunToTcpLoop(), asio::detached);
        co_await TcpToTunLoop();
    }

    void StopDataPath()
    {
        if (tun_device_)
            tun_device_->Close();
        // running_ flag is cleared by the control adapter — loops will exit.
        // TCP socket close is also handled by the control adapter's Disconnect().
    }

    // -- Inbound data delivery (called by ClientControlAdapter) --------------

    asio::awaitable<void> DeliverDecryptedPacket(std::vector<std::uint8_t> plaintext)
    {
        if (!tun_device_)
            co_return;
        tun::IpPacket ip_packet;
        ip_packet.data = std::move(plaintext);
        co_await tun_device_->WritePacket(ip_packet);
        tun_writes_.fetch_add(1, std::memory_order_relaxed);
    }

    // -- Control adapter hooks (called by ClientControlAdapter) ---------------

    void AttachTransport(transport::TransportHandle &handle,
                         transport::PeerEndpoint /*peer*/,
                         std::uint32_t /*peer_id*/)
    {
        SetTransport(std::get_if<transport::TcpTransport>(&handle));
    }

    void InstallDataPathKeys(const std::vector<std::uint8_t> &key_material,
                             openvpn::CipherAlgorithm cipher_algo,
                             openvpn::HmacAlgorithm hmac_algo,
                             std::uint8_t key_id,
                             openvpn::DataChannel &data_channel)
    {
        if (!openvpn::KeyDerivation::InstallKeys(data_channel, key_material, cipher_algo, hmac_algo, key_id, openvpn::PeerRole::Client))
            throw std::runtime_error("TCP: KeyDerivation::InstallKeys failed");
        EngineInstallKeys(data_channel.GetPrimaryEncryptKey(),
                          data_channel.GetPrimaryDecryptKey(),
                          key_id);
    }

    void ConfigureNetworkInterface(const openvpn::NegotiatedConfig &negotiated,
                                   const VpnConfig &config,
                                   asio::io_context &io_ctx)
    {
        tun_device_ = std::make_unique<tun::TunDevice>(io_ctx);
        auto *tun = tun_device_.get();
        std::string name = tun->Create(config.client->dev_name);
        logger_->info("Created TUN: {}", name);

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
        auto *tun = tun_device_.get();
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
                logger_->debug("Route: {} skipped (connected subnet, kernel-managed)", cidr);
                continue;
            }

            std::string via;
            if (!negotiated.route_gateway.empty())
                via = negotiated.route_gateway;
            logger_->info("Route: {} dev {}{}", cidr, dev, via.empty() ? "" : " via " + via);
            try
            {
                route::ReplaceRoute4(dev, cidr, via);
            }
            catch (const std::exception &e)
            {
                logger_->error("Route failed: {}", e.what());
            }
        }

        for (const auto &[network, gw, metric] : negotiated.routes_ipv6)
        {
            logger_->info("IPv6 route: {} dev {}", network, dev);
            try
            {
                route::ReplaceRoute6(dev, network);
            }
            catch (const std::exception &e)
            {
                logger_->error("IPv6 route failed: {}", e.what());
            }
        }
    }

    void OnTeardown()
    {
        if (tun_device_)
            tun_device_->Close();
    }

    void LaunchKeepalive(asio::io_context &io_ctx,
                         std::function<asio::awaitable<void>()> fn,
                         int interval)
    {
        if (interval > 0)
            asio::co_spawn(io_ctx, fn(), asio::detached);
    }

    // -- Stats ---------------------------------------------------------------

    DataPathStats SnapshotStats() const
    {
        DataPathStats s{};
        s.bytesSent = bytes_sent_.load(std::memory_order_relaxed);
        s.bytesReceived = bytes_received_.load(std::memory_order_relaxed);
        s.packetsSent = packets_sent_.load(std::memory_order_relaxed);
        s.packetsReceived = packets_received_.load(std::memory_order_relaxed);
        s.packetsDecrypted = packets_decrypted_.load(std::memory_order_relaxed);
        s.decryptFailures = decrypt_failures_.load(std::memory_order_relaxed);
        s.tunReads = tun_reads_.load(std::memory_order_relaxed);
        s.tunWrites = tun_writes_.load(std::memory_order_relaxed);
        s.sendErrors = send_errors_.load(std::memory_order_relaxed);
        return s;
    }

    void SetBatchSize(std::size_t)
    { /* no-op */
    }
    std::size_t GetBatchSize() const
    {
        return 1;
    }

    std::chrono::steady_clock::time_point LastTxTime() const noexcept
    {
        return std::chrono::steady_clock::time_point(
            std::chrono::steady_clock::duration(
                last_tx_ns_.load(std::memory_order_relaxed)));
    }

  private:
    asio::awaitable<void> TcpToTunLoop()
    {
        while (running_)
        {
            std::vector<std::uint8_t> wire;
            try
            {
                wire = co_await tcp_->Receive();
            }
            catch (const std::exception &e)
            {
                if (running_)
                    logger_->error("TCP recv error: {}", e.what());
                break;
            }

            if (wire.empty())
                break;

            bytes_received_.fetch_add(wire.size(), std::memory_order_relaxed);
            packets_received_.fetch_add(1, std::memory_order_relaxed);

            if (adapter_)
                adapter_->OnRxActivity();

            auto parsed = openvpn::OpenVpnPacket::Parse(wire);
            if (!parsed)
                continue;

            if (parsed->IsControl())
            {
                if (adapter_)
                    adapter_->OnControlPacket(std::move(wire), transport::PeerEndpoint{});
                continue;
            }

            if (!parsed->IsData())
                continue;

            auto plaintext = data_channel_.DecryptPacket(*parsed);
            if (plaintext.empty())
            {
                decrypt_failures_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            packets_decrypted_.fetch_add(1, std::memory_order_relaxed);

            tun::IpPacket pkt;
            pkt.data = std::move(plaintext);

            try
            {
                co_await tun_device_->WritePacket(pkt);
                tun_writes_.fetch_add(1, std::memory_order_relaxed);
            }
            catch (const std::exception &e)
            {
                if (running_)
                    logger_->error("TUN write error: {}", e.what());
                break;
            }
        }
    }

    asio::awaitable<void> TunToTcpLoop()
    {
        openvpn::SessionId session_id{};

        while (running_)
        {
            tun::IpPacket pkt;
            try
            {
                pkt = co_await tun_device_->ReadPacket();
                tun_reads_.fetch_add(1, std::memory_order_relaxed);
            }
            catch (const std::exception &e)
            {
                if (running_)
                    logger_->error("TUN read error: {}", e.what());
                break;
            }

            if (pkt.data.empty())
                continue;

            auto encrypted = data_channel_.EncryptPacket(pkt.data, session_id);
            if (encrypted.empty())
            {
                send_errors_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            try
            {
                co_await tcp_->Send(encrypted);
                packets_sent_.fetch_add(1, std::memory_order_relaxed);
                bytes_sent_.fetch_add(encrypted.size(), std::memory_order_relaxed);
                last_tx_ns_.store(
                    std::chrono::steady_clock::now().time_since_epoch().count(),
                    std::memory_order_relaxed);
            }
            catch (const std::exception &e)
            {
                if (running_)
                    logger_->error("TCP send error: {}", e.what());
                send_errors_.fetch_add(1, std::memory_order_relaxed);
                break;
            }
        }
    }

    asio::io_context &io_context_;
    std::unique_ptr<tun::TunDevice> tun_device_;
    clv::not_null<spdlog::logger *> logger_;
    const std::atomic<bool> &running_;

    Adapter *adapter_ = nullptr;

    transport::TcpTransport *tcp_ = nullptr;
    openvpn::DataChannel data_channel_;

    openvpn::EncryptionKey pending_encrypt_{};
    openvpn::EncryptionKey pending_decrypt_{};
    std::uint8_t pending_key_id_ = 0;
    bool keys_installed_ = false;

    std::atomic<std::uint64_t> bytes_sent_{0};
    std::atomic<std::uint64_t> bytes_received_{0};
    std::atomic<std::uint64_t> packets_sent_{0};
    std::atomic<std::uint64_t> packets_received_{0};
    std::atomic<std::uint64_t> packets_decrypted_{0};
    std::atomic<std::uint64_t> decrypt_failures_{0};
    std::atomic<std::uint64_t> tun_reads_{0};
    std::atomic<std::int64_t> last_tx_ns_{0};
    std::atomic<std::uint64_t> tun_writes_{0};
    std::atomic<std::uint64_t> send_errors_{0};
};

} // namespace clv::vpn

#endif // CLV_VPN_CLIENT_TCP_CHANNEL_H
