// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_DCO_CLIENT_DATA_MIXIN_H
#define CLV_VPN_DCO_CLIENT_DATA_MIXIN_H

/**
 * @file dco_client_data_mixin.h
 * @brief Client P2P DCO mixin — single-peer lifecycle, recv loop with CRTP callbacks.
 *
 * Inherits DcoCore<Derived> and adds: BindSocket, SetPeer, CreatePeer,
 * PushKeysToKernel, ConfigureDcoInterface, InstallRoute, EngineInstallKeys
 * (no-op), and the control-only recv loop (StartTunReceiver).
 *
 * No std::function in this layer.  The recv loop dispatches via CRTP:
 *   this->derived().OnControlPacket(data, sender)
 *   this->derived().OnRxActivity()
 *
 * Derived must provide those two methods.
 */

#include "dco_core.h"

#include "data_path_stats.h"
#include "iface_utils.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/key_derivation.h"
#include "openvpn/ovpn_dco.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "route_utils.h"
#include "transport/transport.h"

#include <sys/socket.h>
#include <unique_fd.h>
#include <net/ipv4_utils.h>

#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/error.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/use_awaitable.hpp>

#include <spdlog/logger.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace clv::vpn {

namespace ipv4 = clv::net::ipv4;

namespace openvpn {
struct EncryptionKey;
} // namespace openvpn

/**
 * @brief Client P2P DCO mixin — sits between DcoCore and the composed channel.
 *
 * @tparam Derived  The final composed class (CRTP).  Must provide:
 *   - void OnControlPacket(std::vector<uint8_t>, transport::PeerEndpoint)
 *   - void OnRxActivity()
 */
template <typename Derived>
class DcoClientDataMixin : public DcoCore<Derived>
{
  protected:
    DcoClientDataMixin(asio::io_context &io_ctx,
                       spdlog::logger &logger,
                       std::uint32_t keepalive_interval,
                       std::uint32_t keepalive_timeout,
                       const std::atomic<bool> &running)
        : DcoCore<Derived>(io_ctx, logger, "ovpn-client0", running),
          keepalive_interval_(keepalive_interval),
          keepalive_timeout_(keepalive_timeout)
    {
        this->InitializeDcoDevice(OVPN_MODE_P2P);
        this->logger_->info("Client DCO channel initialized (ifname={})", this->dco_ifname_);
    }

    ~DcoClientDataMixin()
    {
        StopDataPath();
        this->DestroyDcoDevice();
    }

    DcoClientDataMixin(const DcoClientDataMixin &) = delete;
    DcoClientDataMixin &operator=(const DcoClientDataMixin &) = delete;
    DcoClientDataMixin(DcoClientDataMixin &&) = delete;
    DcoClientDataMixin &operator=(DcoClientDataMixin &&) = delete;

  public:
    // -- DCO lifecycle ------------------------------------------------------

    /**
     * @brief Bind the shared UDP socket used for control traffic.
     * @param socket Shared socket owned by UdpTransport
     */
    void BindSocket(std::shared_ptr<asio::ip::udp::socket> socket)
    {
        socket_fd_ = socket->native_handle();
        socket_ptr_ = socket;
    }

    /**
     * @brief Configure peer endpoint and create the kernel DCO peer.
     * @param peer Remote UDP endpoint
     * @param session_id OpenVPN session identifier (low bits become peer_id)
     */
    void SetPeer(transport::PeerEndpoint peer, openvpn::SessionId session_id)
    {
        peer_ = peer;
        peer_id_ = static_cast<std::uint32_t>(session_id.value & openvpn::PEER_ID_MASK);

        if (this->dco_initialized_ && socket_fd_ >= 0)
            CreatePeer();
    }

    /** @brief No-op; keys are pushed via PushKeysToKernel(). */
    void EngineInstallKeys(const openvpn::EncryptionKey & /*encrypt_key*/,
                           const openvpn::EncryptionKey & /*decrypt_key*/,
                           std::uint8_t /*key_id*/)
    {
        // No-op for DCO — keys are pushed to kernel via PushKeysToKernel().
    }

    /**
     * @brief Push derived key material to the kernel DCO peer.
     * @return false if DCO is not initialized or netlink push fails
     */
    bool PushKeysToKernel(const std::vector<std::uint8_t> &key_material,
                          openvpn::CipherAlgorithm cipher_algo,
                          std::uint8_t key_id)
    {
        if (!this->dco_initialized_ || !peer_created_)
        {
            this->logger_->error("DCO: Cannot push keys — not initialized or no peer");
            return false;
        }

        bool is_renegotiation = has_primary_key_ && current_primary_key_id_ != key_id;
        std::uint8_t key_slot = is_renegotiation ? OVPN_KEY_SLOT_SECONDARY
                                                 : OVPN_KEY_SLOT_PRIMARY;

        if (!this->PushKeysToKernelImpl(peer_id_, key_material, cipher_algo, key_id, key_slot, openvpn::PeerRole::Client))
            return false;

        if (is_renegotiation)
        {
            if (!this->SwapKeysImpl(peer_id_))
            {
                this->logger_->error("DCO: Key swap failed after renegotiation");
                return false;
            }
        }

        current_primary_key_id_ = key_id;
        has_primary_key_ = true;
        return true;
    }

    /**
     * @brief Assign IPv4/IPv6 addresses and bring up the DCO netdev.
     * @param ip Assigned IPv4 address
     * @param prefix IPv4 prefix length
     * @param ipv6_addr Optional assigned IPv6 address
     * @param ipv6_prefix IPv6 prefix length (required with ipv6_addr)
     * @param mtu Interface MTU (0 = leave unchanged)
     */
    void ConfigureDcoInterface(const std::string &ip, std::uint8_t prefix,
                               const std::string &ipv6_addr = {},
                               std::uint8_t ipv6_prefix = 0,
                               std::uint16_t mtu = 0)
    {
        clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));

        iface::SetIpAddress(sock.get(), this->dco_ifname_.c_str(), ip);
        iface::SetNetmask(sock.get(), this->dco_ifname_.c_str(), ipv4::CreateMask(prefix));
        if (mtu > 0)
            iface::SetMtu(sock.get(), this->dco_ifname_.c_str(), mtu);
        iface::BringUp(sock.get(), this->dco_ifname_.c_str());

        this->logger_->info("DCO: Interface {} configured with IP {}/{} mtu={}",
                            this->dco_ifname_,
                            ip,
                            prefix,
                            mtu > 0 ? mtu : 0);

        if (!ipv6_addr.empty() && ipv6_prefix > 0)
        {
            iface::AddIpv6Address(this->dco_ifname_.c_str(), ipv6_addr, ipv6_prefix);
            this->logger_->info("DCO: IPv6 {}/{} added to {}",
                                ipv6_addr,
                                ipv6_prefix,
                                this->dco_ifname_);
        }
    }

    /**
     * @brief Add a route via the DCO interface.
     * @param cidr Route in CIDR notation
     * @param is_ipv6 When true, install an IPv6 route
     */
    void InstallRoute(const std::string &cidr, bool is_ipv6 = false)
    {
        if (is_ipv6)
            route::ReplaceRoute6(this->dco_ifname_, cidr);
        else
            route::ReplaceRoute4(this->dco_ifname_, cidr, "");
    }

    /** @brief DCO netdev name (e.g. "ovpn-dco0"). */
    const std::string &GetIfName() const
    {
        return this->dco_ifname_;
    }

    /** @brief Whether a kernel DCO peer has been created. */
    bool HasPeer() const
    {
        return peer_created_;
    }

    // -- Inbound data delivery (called by ClientControlAdapter) --------------

    /** @brief Unreachable on DCO path (kernel delivers to netdev). */
    asio::awaitable<void> DeliverDecryptedPacket(std::vector<std::uint8_t> /*plaintext*/)
    {
        co_return;
    }

    // -- Receive loop -----------------------------

    /** @brief Run the UDP control-packet receive loop. */
    asio::awaitable<void> StartDataPath()
    {
        auto socket = socket_ptr_.lock();
        if (!socket)
        {
            this->logger_->error("DCO: StartDataPath called without socket");
            co_return;
        }

        constexpr std::size_t kMaxPacket = 4096;
        std::vector<std::uint8_t> buf(kMaxPacket);

        this->logger_->debug("DCO: control receive loop starting on UDP socket (fd={})", socket_fd_);

        while (this->running_)
        {
            asio::ip::udp::endpoint remote;
            // Use the transport's own socket object — not a second ASIO wrapper
            // on the same FD — so the epoll reactor has a single consistent
            // descriptor entry for this FD throughout the session.
            auto [ec, n] = co_await socket->async_receive_from(
                asio::buffer(buf), remote, asio::as_tuple(asio::use_awaitable));
            if (ec)
            {
                if (ec == asio::error::operation_aborted)
                    break;
                this->logger_->warn("DCO: receive error: {}", ec.message());
                continue;
            }

            this->derived().OnRxActivity();

            auto sender = transport::FromAsioEndpoint(remote);
            std::vector<std::uint8_t> data(buf.begin(),
                                           buf.begin() + static_cast<std::ptrdiff_t>(n));
            this->derived().OnControlPacket(std::move(data), sender);
        }

        this->logger_->debug("DCO: control receive loop exiting");
    }

    /** @brief Cancel pending socket operations. */
    void StopDataPath()
    {
        if (auto sp = socket_ptr_.lock())
        {
            if (sp->is_open())
            {
                asio::error_code ec;
                [[maybe_unused]] auto cancelled = sp->cancel(ec);
            }
        }
    }

    // -- Stats --------------------------------------------------------------

    /** @brief Data-path counter snapshot from DcoCore. */
    DataPathStats SnapshotStats() const
    {
        return this->SnapshotStatsImpl();
    }

    /** @brief No-op; DCO has no userspace batching. */
    void SetBatchSize(std::size_t)
    { /* no-op */
    }
    /** @brief Always 0; DCO has no userspace batching. */
    std::size_t GetBatchSize() const
    {
        return 0;
    }

  private:
    void CreatePeer()
    {
        if (peer_created_)
            return;

        if (!this->CreatePeerImpl(peer_id_, peer_, socket_fd_))
            return;

        peer_created_ = true;

        // Configure kernel keepalive
        if (keepalive_interval_ > 0 || keepalive_timeout_ > 0)
        {
            this->SetPeerKeepaliveImpl(peer_id_, keepalive_interval_, keepalive_timeout_);
        }
    }

    // Client-specific state
    std::uint32_t keepalive_interval_;
    std::uint32_t keepalive_timeout_;

    int socket_fd_ = -1;
    transport::PeerEndpoint peer_{};
    std::uint32_t peer_id_ = 0;
    bool peer_created_ = false;

    std::uint8_t current_primary_key_id_ = 0;
    bool has_primary_key_ = false;

    std::weak_ptr<asio::ip::udp::socket> socket_ptr_;
};

} // namespace clv::vpn

#endif // CLV_VPN_DCO_CLIENT_DATA_MIXIN_H
