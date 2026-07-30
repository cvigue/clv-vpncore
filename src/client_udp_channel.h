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
#include "openvpn/crypto_context.h"
#include "openvpn/data_v2_wire.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "p2p_policy.h"
#include "transport/batch_constants.h"
#include "udp_client_mixin.h"

#include "client_network_setup.h"
#include "openvpn/config_exchange.h"
#include "openvpn/session_key_install.h"
#include "openvpn/vpn_config.h"
#include "transport/transport.h"
#include "udp_core.h"
#include "udp_engine_types.h"

#include <chrono>
#include <span>
#include <stdexcept>

#include "platform/linux/tun/tun_device.h"

#include <asio/io_context.hpp>

#include <spdlog/logger.h>

#include <array>
#include <atomic>
#include <concepts>
#include <cstring>
#include <cstdint>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>
#include <utility>
#include <vector>

namespace clv::vpn {

template <typename Adapter>
class ClientUdpChannel
    : public UdpClientMixin<ClientUdpChannel<Adapter>>
{
    using UdpClientMixinBase = UdpClientMixin<ClientUdpChannel<Adapter>>;
    friend UdpClientMixinBase;
    friend UdpCore<ClientUdpChannel<Adapter>, P2PPolicy>;

  public:
    /**
     * @brief Construct the client UDP data channel.
     * @param io_context ASIO context for coroutines
     * @param logger Logger for data-path events
     * @param config Client configuration
     * @param running Shared stop flag
     * @param adapter Data→control adapter
     */
    ClientUdpChannel(asio::io_context &io_context,
                     spdlog::logger &logger,
                     const VpnConfig &config,
                     const std::atomic<bool> &running,
                     Adapter &adapter)
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
                             }),
          adapter_(&adapter)
    {
        // Wire the P2P TX-engine callback so last_tx_ns_ tracks every outbound packet.
        this->policy().SetTxNsOutput(&last_tx_ns_);
    }

    /** @brief Stop the data path and release resources. */
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
    using UdpClientMixinBase::GetRxBatchWindow;
    using UdpClientMixinBase::GetTxBurstAvgWindow;
    using UdpClientMixinBase::SetBatchSize;
    using UdpClientMixinBase::SetPeer;
    using UdpClientMixinBase::SnapshotStats;
    using UdpClientMixinBase::StartDataPath;
    using UdpClientMixinBase::StopDataPath;

    /**
     * @brief Install keys on the P2P engine and keepalive ping context.
     * @param encrypt_key Outbound encryption key
     * @param decrypt_key Inbound decryption key
     * @param key_id OpenVPN key slot identifier
     */
    void EngineInstallKeys(const openvpn::EncryptionKey &encrypt_key,
                           const openvpn::EncryptionKey &decrypt_key,
                           std::uint8_t key_id)
    {
        UdpClientMixinBase::EngineInstallKeys(encrypt_key, decrypt_key, key_id);
        ping_tx_state_.ApplySnapshot(encrypt_key, key_id);
    }

    /** @brief Timestamp of the last outbound data-channel transmission. */
    std::chrono::steady_clock::time_point LastTxTime() const noexcept
    {
        return std::chrono::steady_clock::time_point(
            std::chrono::steady_clock::duration(
                last_tx_ns_.load(std::memory_order_relaxed)));
    }

    /** @brief Send a userspace keepalive ping on the raw UDP socket. */
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

        // Claim the next packet ID from the shared CryptoContext counter (same
        // sequence used by the TX drain loop) so the peer's anti-replay window is never violated.
        auto *limits_crypto = this->policy().OutboundLimitsCryptoContext();
        if (!limits_crypto)
            co_return;
        const auto pkt_id = limits_crypto->AllocateOutboundPacketId();
        if (!pkt_id)
            co_return;

        if (!limits_crypto->TryReserveOutboundEncrypt(openvpn::KEEPALIVE_PING_SIZE,
                                                      ping_tx_state_.cipher_algorithm))
            co_return;

        const auto wire_len = ping_tx_state_.EncryptInPlace(
            std::span<std::uint8_t>(buf.data(), kBufSize),
            openvpn::KEEPALIVE_PING_SIZE,
            snap.session_id,
            *pkt_id);

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

    /**
     * @brief Bind transport socket and peer after handshake.
     * @param handle UDP transport handle
     * @param peer Remote endpoint
     * @param peer_id Assigned peer identifier
     */
    void AttachTransport(transport::TransportHandle &handle,
                         transport::PeerEndpoint peer,
                         std::uint32_t peer_id)
    {
        auto &udp = std::get<transport::UdpTransport>(handle);
        UdpClientMixinBase::BindSocket(udp.RawSocket().native_handle());
        UdpClientMixinBase::SetPeer(peer, openvpn::SessionId{static_cast<std::uint64_t>(peer_id)});
    }

    /**
     * @brief Derive and install data-path keys on the P2P engine.
     * @param key_material Raw key material from control plane
     * @param cipher_algo Negotiated cipher
     * @param hmac_algo Negotiated HMAC (unused on AEAD)
     * @param key_id OpenVPN key slot identifier
     * @param crypto_context Control-plane crypto context for limits
     */
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
                                                "UDP");
        this->policy().SetOutboundLimitsCryptoContext(&crypto_context);
        EngineInstallKeys(crypto_context.GetPrimaryEncryptKey(),
                          crypto_context.GetPrimaryDecryptKey(),
                          key_id);
    }

    /** @brief CryptoContext used for outbound packet-id limits. */
    openvpn::CryptoContext &GetLimitsCryptoContext()
    {
        auto *crypto = this->policy().OutboundLimitsCryptoContext();
        if (!crypto)
            throw std::runtime_error("UDP: outbound limits CryptoContext not configured");
        return *crypto;
    }

    /**
     * @brief Create the client TUN device from negotiated config.
     * @param negotiated PUSH reply network settings
     * @param config Client configuration
     * @param io_ctx ASIO context for the TUN device
     */
    void ConfigureNetworkInterface(const openvpn::NegotiatedConfig &negotiated,
                                   const VpnConfig &config,
                                   asio::io_context &io_ctx)
    {
        this->tun_device_ = std::make_unique<tun::TunDevice>(io_ctx);
        ConfigureClientTun(*this->tun_device_, negotiated, config.client->dev_name, this->logger());
    }

    /** @brief Install routes pushed by the server onto the TUN device. */
    void InstallNegotiatedRoutes(const openvpn::NegotiatedConfig &negotiated)
    {
        if (!this->tun_device_)
            return;
        InstallClientNegotiatedRoutes(*this->tun_device_, negotiated, this->logger());
    }

    /** @brief Close the TUN device on session teardown. */
    void OnTeardown()
    {
        if (this->tun_device_)
            this->tun_device_->Close();
    }

    /**
     * @brief Spawn the keepalive coroutine when interval > 0.
     * @tparam Fn Awaitable factory (no arguments)
     * @param io_ctx ASIO context for co_spawn
     * @param fn Coroutine to run
     * @param interval Keepalive interval in seconds (0 disables)
     */
    template <std::invocable Fn>
    void LaunchKeepalive(asio::io_context &io_ctx, Fn &&fn, int interval)
    {
        if (interval > 0)
            asio::co_spawn(io_ctx, std::forward<Fn>(fn)(), asio::detached);
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

    Adapter *adapter_;
    std::atomic<std::int64_t> last_tx_ns_{0};
    TxEncryptState ping_tx_state_; ///< Control-thread-only encrypt context for keepalive pings.
};

} // namespace clv::vpn

#endif // CLV_VPN_CLIENT_UDP_CHANNEL_H
