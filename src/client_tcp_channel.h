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
 * Lifecycle: construct → SetTransport (provides TcpTransport*)
 * → EngineInstallKeys → StartTunReceiver (launches coroutine loops)
 * → StopTunReceiver.
 *
 * @tparam Adapter  DataAdapter CRTP base (e.g. ClientDataAdapter<DataTransport<...>>).
 *
 * @see ClientUdpChannel for the batched UDP equivalent.
 * @see ClientDcoChannel for the kernel-offload equivalent.
 */

#include "client_network_setup.h"
#include "data_path_stats.h"
#include "openvpn/config_exchange.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/crypto_context.h"
#include "openvpn/session_key_install.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/vpn_config.h"
#include "platform/linux/tun/tun_device.h"
#include "transport/transport.h"

#include <chrono>
#include <not_null.h>
#include <stdexcept>

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/use_awaitable.hpp>

#include <spdlog/logger.h>

#include <atomic>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace clv::vpn {

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
    /**
     * @brief Construct the client TCP data channel.
     * @param io_context ASIO context for coroutine loops
     * @param logger Logger for data-path events
     * @param config Client configuration (unused at construction)
     * @param running Shared stop flag
     * @param adapter Data→control adapter
     */
    ClientTcpChannel(asio::io_context &io_context,
                     spdlog::logger &logger,
                     const VpnConfig & /*config*/,
                     const std::atomic<bool> &running,
                     Adapter &adapter)
        : io_context_(io_context),
          logger_(&logger),
          running_(running),
          crypto_context_(logger),
          adapter_(&adapter)
    {
        logger_->info("Client TCP channel initialized");
    }

    /** @brief Stop the data path and close the TUN device. */
    ~ClientTcpChannel()
    {
        StopDataPath();
    }

    ClientTcpChannel(const ClientTcpChannel &) = delete;
    ClientTcpChannel &operator=(const ClientTcpChannel &) = delete;
    ClientTcpChannel(ClientTcpChannel &&) = delete;
    ClientTcpChannel &operator=(ClientTcpChannel &&) = delete;


    /** @brief Send an encrypted keepalive ping on the TCP transport. */
    asio::awaitable<void> SendKeepalivePing()
    {
        if (!tcp_)
            co_return;
        std::vector<std::uint8_t> payload(
            openvpn::KEEPALIVE_PING_PAYLOAD,
            openvpn::KEEPALIVE_PING_PAYLOAD + openvpn::KEEPALIVE_PING_SIZE);
        auto encrypted = crypto_context_.EncryptPacket(payload, openvpn::SessionId{});
        if (encrypted.empty())
            co_return;
        co_await tcp_->Send(encrypted);
        last_tx_ns_.store(
            std::chrono::steady_clock::now().time_since_epoch().count(),
            std::memory_order_relaxed);
    }

    // -- TCP lifecycle (called by ClientControlAdapter) ----------------------

    /**
     * @brief Bind the TCP transport for encrypt/decrypt loops.
     * @param tcp Connected TCP transport (non-owning)
     */
    void SetTransport(transport::TcpTransport *tcp)
    {
        tcp_ = tcp;
    }

    /**
     * @brief Install encrypt/decrypt keys on the channel CryptoContext.
     * @param encrypt_key Outbound encryption key
     * @param decrypt_key Inbound decryption key
     * @param key_id OpenVPN key slot identifier
     */
    void EngineInstallKeys(const openvpn::EncryptionKey &encrypt_key,
                           const openvpn::EncryptionKey &decrypt_key,
                           std::uint8_t key_id)
    {
        pending_encrypt_ = encrypt_key;
        pending_decrypt_ = decrypt_key;
        pending_key_id_ = key_id;
        keys_installed_ = true;

        crypto_context_.InstallNewKeys(decrypt_key, encrypt_key, key_id);

        logger_->debug("TCP: Keys installed (key_id={})", key_id);
    }

    /** @brief CryptoContext used for encrypt/decrypt and outbound limits. */
    openvpn::CryptoContext &GetLimitsCryptoContext()
    {
        return crypto_context_;
    }

    /** @brief Start TUN↔TCP coroutine loops (requires transport, TUN, and keys). */
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

    /** @brief Close the TUN device; TCP close is handled by the control adapter. */
    void StopDataPath()
    {
        if (tun_device_)
            tun_device_->Close();
        // running_ flag is cleared by the control adapter — loops will exit.
        // TCP socket close is also handled by the control adapter's Disconnect().
    }

    // -- Inbound data delivery (called by ClientControlAdapter) --------------

    /**
     * @brief Write decrypted plaintext to the TUN device.
     * @param plaintext IP packet bytes
     */
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

    /** @brief Extract TCP transport from a variant handle after handshake. */
    void AttachTransport(transport::TransportHandle &handle,
                         transport::PeerEndpoint /*peer*/,
                         std::uint32_t /*peer_id*/)
    {
        SetTransport(std::get_if<transport::TcpTransport>(&handle));
    }

    /** @brief Derive and install data-path keys (see ClientUdpChannel). */
    void InstallDataPathKeys(const std::vector<std::uint8_t> &key_material,
                             openvpn::CipherAlgorithm cipher_algo,
                             openvpn::HmacAlgorithm hmac_algo,
                             std::uint8_t key_id,
                             openvpn::CryptoContext &crypto_context)
    {
        openvpn::InstallClientCryptoKeysOrThrow(crypto_context,
                                                key_material,
                                                cipher_algo,
                                                hmac_algo,
                                                key_id,
                                                "TCP");
        EngineInstallKeys(crypto_context.GetPrimaryEncryptKey(),
                          crypto_context.GetPrimaryDecryptKey(),
                          key_id);
    }

    /** @brief Create the client TUN device from negotiated config. */
    void ConfigureNetworkInterface(const openvpn::NegotiatedConfig &negotiated,
                                   const VpnConfig &config,
                                   asio::io_context &io_ctx)
    {
        tun_device_ = std::make_unique<tun::TunDevice>(io_ctx);
        ConfigureClientTun(*tun_device_, negotiated, config.client->dev_name, *logger_);
    }

    /** @brief Install routes pushed by the server onto the TUN device. */
    void InstallNegotiatedRoutes(const openvpn::NegotiatedConfig &negotiated)
    {
        if (!tun_device_)
            return;
        InstallClientNegotiatedRoutes(*tun_device_, negotiated, *logger_);
    }

    /** @brief Close the TUN device on session teardown. */
    void OnTeardown()
    {
        if (tun_device_)
            tun_device_->Close();
    }

    /** @brief Spawn the keepalive coroutine when interval > 0. */
    template <std::invocable Fn>
    void LaunchKeepalive(asio::io_context &io_ctx, Fn &&fn, int interval)
    {
        if (interval > 0)
            asio::co_spawn(io_ctx, std::forward<Fn>(fn)(), asio::detached);
    }

    // -- Stats ---------------------------------------------------------------

    /** @brief Data-path counter snapshot. */
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

    /** @brief No-op; TCP path processes one packet at a time. */
    void SetBatchSize(std::size_t)
    { /* no-op */
    }
    /** @brief Always 1 for the single-packet TCP path. */
    std::size_t GetBatchSize() const
    {
        return 1;
    }

    /** @brief Timestamp of the last outbound TCP transmission. */
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

            const auto opcode = openvpn::GetOpcode(wire[0]);
            if (openvpn::IsDataPacket(opcode) && keys_installed_ && crypto_context_.HasValidKeys())
            {
                auto plaintext = crypto_context_.DecryptPacketInPlace(wire);
                if (plaintext.empty())
                {
                    decrypt_failures_.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }

                packets_decrypted_.fetch_add(1, std::memory_order_relaxed);

                switch (openvpn::ClassifyDecryptedPayload(plaintext))
                {
                case openvpn::DecryptedPayloadDisposition::Keepalive:
                    continue;
                case openvpn::DecryptedPayloadDisposition::Drop:
                    continue;
                case openvpn::DecryptedPayloadDisposition::Forward:
                    {
                        tun::IpPacket pkt;
                        pkt.data.assign(plaintext.begin(), plaintext.end());

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
                        continue;
                    }
                }
            }

            if (adapter_)
                adapter_->OnControlPacket(std::move(wire), transport::PeerEndpoint{});
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

            auto encrypted = crypto_context_.EncryptPacket(pkt.data, session_id);
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

    Adapter *adapter_;

    transport::TcpTransport *tcp_ = nullptr;
    openvpn::CryptoContext crypto_context_;

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
