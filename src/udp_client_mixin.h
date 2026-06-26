// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_UDP_CLIENT_MIXIN_H
#define CLV_VPN_UDP_CLIENT_MIXIN_H

/**
 * @file udp_client_mixin.h
 * @brief Client-side CRTP mixin for UDP P2P data channel.
 *
 * Inherits UdpCore<Derived, P2PPolicy> and adds single-peer lifecycle:
 * pending state, key install, SetPeer, batch config.
 *
 * Derived must provide OnControlPacket(vector<uint8_t>, PeerEndpoint) and
 * OnRxActivity() (dispatched via SetAdapter in the final channel).
 *
 * @tparam Derived  Final CRTP type (e.g. ClientUdpChannel).
 */

#include "openvpn/packet.h"
#include "p2p_policy.h"
#include "udp_core.h"

#include "data_path_stats.h"
#include "openvpn/data_channel.h"
#include "transport/batch_constants.h"
#include "transport/transport.h"

#include <tun/tun_device.h>

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>

#include <spdlog/logger.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace clv::vpn {

template <typename Derived>
class UdpClientMixin : public UdpCore<Derived, P2PPolicy>
{
    using Core = UdpCore<Derived, P2PPolicy>;

  public:
    using Config = typename Core::Config;

    // -- Inbound data delivery (called by ClientControlAdapter) --------------

    // UDP delivers directly to TUN from the kernel-bypass RX thread;
    // this path is structurally unreachable but must exist for the template.
    asio::awaitable<void> DeliverDecryptedPacket(std::vector<std::uint8_t> /*plaintext*/)
    {
        co_return;
    }

    // -- P2P engine lifecycle ------------------------------------------------

    void BindSocket(int socket_fd)
    {
        socket_fd_ = socket_fd;
    }

    void SetPeer(transport::PeerEndpoint peer, openvpn::SessionId session_id)
    {
        pending_peer_ = peer;
        pending_session_id_ = session_id;
        if (Core::CoreRunning())
            Core::CoreSetPeer(peer, session_id);
    }

    void EngineInstallKeys(const openvpn::EncryptionKey &encrypt_key,
                           const openvpn::EncryptionKey &decrypt_key,
                           std::uint8_t key_id)
    {
        pending_encrypt_ = encrypt_key;
        pending_decrypt_ = decrypt_key;
        pending_key_id_ = key_id;
        if (Core::CoreRunning())
            Core::CoreInstallKeys(encrypt_key, decrypt_key, key_id);
    }

    asio::awaitable<void> StartDataPath()
    {
        if (socket_fd_ < 0 || !tun_device_)
        {
            Core::logger().error("UdpClientMixin::StartDataPath: "
                                 "missing socket or TUN");
            co_return;
        }

        Core::CoreBind(socket_fd_, *tun_device_);

        // Apply pending configuration stored before engine creation
        if (pending_peer_.port != 0)
            Core::CoreSetPeer(pending_peer_, pending_session_id_);
        if (pending_encrypt_.is_valid)
            Core::CoreInstallKeys(pending_encrypt_, pending_decrypt_, pending_key_id_);

        Core::CoreStart();

        Core::logger().info("Client P2P engine started (batch_size={})",
                            GetBatchSize());
        co_return;
    }

    void StopDataPath()
    {
        Core::CoreStop();
        if (tun_device_)
            tun_device_->Close();
    }

    // -- Stats ---------------------------------------------------------------

    DataPathStats SnapshotStats() const
    {
        if (Core::CoreRunning())
            return Core::CoreSnapshotStats();
        return {};
    }

    void SetBatchSize(std::size_t newSize)
    {
        batch_size_ = std::min(newSize, transport::kMaxBatchSize);
    }

    std::size_t GetBatchSize() const
    {
        return batch_size_;
    }

    BatchHistWindow &GetRxBatchWindow()
    {
        return Core::CoreRxBatchWindow();
    }

    TxBurstAvgWindow &GetTxBurstAvgWindow()
    {
        return Core::CoreTxBurstAvgWindow();
    }

    RingOccHistWindow &GetRingOccWindow()
    {
        return Core::CoreRingOccWindow();
    }

  protected:
    UdpClientMixin(asio::io_context &io_context,
                   spdlog::logger &logger,
                   typename Core::Config config)
        : Core(config, io_context, logger),
          batch_size_(config.batch_size)
    {
    }

    ~UdpClientMixin()
    {
        StopDataPath();
    }

  protected:
    int TunNativeHandle() const noexcept
    {
        return tun_device_ ? tun_device_->NativeHandle() : -1;
    }

  protected:
    std::unique_ptr<tun::TunDevice> tun_device_;

  private:
    std::size_t batch_size_;
    int socket_fd_ = -1;

    // Pending state — stored before engine creation, applied in StartTunReceiver
    transport::PeerEndpoint pending_peer_;
    openvpn::SessionId pending_session_id_{};
    openvpn::EncryptionKey pending_encrypt_;
    openvpn::EncryptionKey pending_decrypt_;
    std::uint8_t pending_key_id_ = 0;
};

} // namespace clv::vpn

#endif // CLV_VPN_UDP_CLIENT_MIXIN_H
