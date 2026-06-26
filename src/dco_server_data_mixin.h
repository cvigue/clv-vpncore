// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_DCO_SERVER_DATA_MIXIN_H
#define CLV_VPN_DCO_SERVER_DATA_MIXIN_H

/**
 * @file dco_server_data_mixin.h
 * @brief Server MP DCO mixin — multi-peer lifecycle, recv loop, keepalive monitor.
 *
 * Inherits DcoCore<Derived> and adds: per-Connection peer create/remove,
 * InstallKeys (with renegotiation), keepalive monitor (netlink multicast),
 * and the control-only recv loop.
 *
 * No std::function in this layer.  CRTP callbacks:
 *   this->derived().OnControlPacket(data, sender)   — from recv loop
 *   this->derived().OnPeerDead(session_id)          — from keepalive monitor
 *
 * Derived must provide those two methods.
 */

#include "dco_core.h"
#include "dco_netlink_ops.h"

#include "data_path_stats.h"
#include "iface_utils.h"
#include "openvpn/connection.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/key_derivation.h"
#include "openvpn/ovpn_dco.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include "openvpn/session_manager.h"
#include "openvpn/vpn_config.h"
#include "transport/transport.h"
#include "util/nla_helpers.h"

#include <cerrno>
#include <linux/if.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <scope_guard.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <system_error>
#include <unique_fd.h>
#include <net/ipv4_utils.h>
#include <net/ipv6_utils.h>
#include <util/netlink_helper.h>

#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <asio/read.hpp>
#include <asio/use_awaitable.hpp>

#include <spdlog/logger.h>

#include <arpa/inet.h>
#include <linux/genetlink.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace clv::vpn {

using clv::netlink::NetlinkHelper;
namespace ipv4 = clv::net::ipv4;
namespace ipv6 = clv::net::ipv6;
using clv::netlink::NlaReadScalar;

// Forward declarations
namespace tun {
struct IpPacket;
}

/**
 * @brief Server MP DCO mixin — sits between DcoCore and the composed channel.
 *
 * @tparam Derived  The final composed class (CRTP).  Must provide:
 *   - void OnControlPacket(std::vector<uint8_t>, transport::PeerEndpoint)
 *   - void OnPeerDead(openvpn::SessionId)
 */
template <typename Derived>
class DcoServerDataMixin : public DcoCore<Derived>
{
  public:
    struct NetworkConfig
    {
        std::string server_network;    ///< CIDR, e.g. "10.8.0.0/24"
        std::string server_ip;         ///< Server VPN IP, e.g. "10.8.0.1"
        std::string server_network_v6; ///< IPv6 CIDR (empty = disabled)
        uint32_t keepalive_interval;   ///< Seconds (0 = disabled)
        uint32_t keepalive_timeout;    ///< Seconds (0 = disabled)
        uint16_t tun_mtu = 0;          ///< TUN device MTU (0 = kernel default)
    };

  protected:
    DcoServerDataMixin(asio::io_context &io_ctx,
                       asio::ip::udp::socket &socket,
                       const NetworkConfig &network_config,
                       spdlog::logger &logger,
                       const std::atomic<bool> &running)
        : DcoCore<Derived>(io_ctx, logger, "ovpn-dco0", running),
          socket_(socket),
          network_config_(network_config)
    {
        InitializeDco();
        this->logger_->info("DCO data channel initialized successfully (ifname={})",
                            this->dco_ifname_);
    }

    ~DcoServerDataMixin()
    {
        if (this->dco_initialized_ && this->dco_ifindex_ >= 0)
            this->DestroyDcoDevice();
        this->logger_->debug("DCO: Cleaned up resources");
    }

    DcoServerDataMixin(const DcoServerDataMixin &) = delete;
    DcoServerDataMixin &operator=(const DcoServerDataMixin &) = delete;
    DcoServerDataMixin(DcoServerDataMixin &&) = delete;
    DcoServerDataMixin &operator=(DcoServerDataMixin &&) = delete;

  public:
    // -- Data plane setup (called from ServerControlBase::ConfigureDataPlane) ---

    // DCO device is fully configured during construction (InitializeDco).
    // Returns the netdev name for logging.
    std::string ConfigureDataPlane(
        [[maybe_unused]] const VpnConfig::ServerConfig &srv,
        [[maybe_unused]] asio::io_context &io_ctx)
    {
        return std::string{this->dco_ifname_};
    }

    // -- Data-path no-ops (kernel handles everything) -----------------------

    asio::awaitable<void> ProcessIncomingDataPacket(
        [[maybe_unused]] Connection *session,
        [[maybe_unused]] const openvpn::OpenVpnPacket &packet)
    {
        this->logger_->warn("DCO: ProcessIncomingDataPacket called unexpectedly");
        co_return;
    }

    std::span<std::uint8_t> DecryptAndStripInPlace(Connection *, std::span<std::uint8_t>)
    {
        return {};
    }

    asio::awaitable<void> ProcessOutgoingTunPacket([[maybe_unused]] tun::IpPacket &packet)
    {
        this->logger_->warn("DCO: ProcessOutgoingTunPacket called unexpectedly");
        co_return;
    }

    asio::awaitable<void> SendKeepAlivePing([[maybe_unused]] Connection *session)
    {
        co_return; // kernel handles keepalive autonomously
    }

    // -- Key installation ---------------------------------------------------

    bool InstallKeys(Connection *session,
                     const std::vector<uint8_t> &key_material,
                     openvpn::CipherAlgorithm cipher_algo,
                     [[maybe_unused]] openvpn::HmacAlgorithm hmac_algo,
                     std::uint8_t key_id)
    {
        if (!this->dco_initialized_)
        {
            this->logger_->error("DCO: Cannot install keys — not initialized");
            return false;
        }

        if (!CreateDcoPeer(session))
        {
            this->logger_->error("DCO: Failed to create peer");
            return false;
        }

        uint32_t peer_id = GetPeerId(session);

        auto it = peer_primary_key_.find(peer_id);
        bool is_renegotiation = (it != peer_primary_key_.end() && it->second != key_id);
        uint8_t key_slot = is_renegotiation ? OVPN_KEY_SLOT_SECONDARY
                                            : OVPN_KEY_SLOT_PRIMARY;

        this->logger_->info("DCO: Installing keys via netlink (key_id={}, slot={}, renego={})",
                            key_id,
                            key_slot == OVPN_KEY_SLOT_PRIMARY ? "PRIMARY" : "SECONDARY",
                            is_renegotiation);

        if (!this->PushKeysToKernelImpl(peer_id, key_material, cipher_algo, key_id, key_slot, openvpn::PeerRole::Server))
        {
            this->logger_->error("DCO: Failed to push keys to kernel");
            return false;
        }

        if (is_renegotiation)
        {
            if (!this->SwapKeysImpl(peer_id))
            {
                this->logger_->error("DCO: Failed to swap keys after renegotiation");
                return false;
            }
        }

        peer_primary_key_[peer_id] = key_id;

        // Configure kernel keepalive on first key install
        if (!is_renegotiation)
        {
            if (network_config_.keepalive_interval > 0 || network_config_.keepalive_timeout > 0)
            {
                if (!this->SetPeerKeepaliveImpl(peer_id,
                                                network_config_.keepalive_interval,
                                                network_config_.keepalive_timeout))
                {
                    this->logger_->warn("DCO: Failed to set keepalive for peer {} (non-fatal)",
                                        peer_id);
                }
            }
        }

        session->GetDataChannel().SetCurrentKeyId(key_id);
        session->GetDataChannel().SetDcoKeysInstalled(true);

        this->logger_->info("DCO: Keys installed successfully in kernel (key_id={})", key_id);
        return true;
    }

    // -- Peer management ----------------------------------------------------

    uint32_t GetPeerId(Connection *session) const
    {
        return static_cast<uint32_t>(session->GetSessionId().value & openvpn::PEER_ID_MASK);
    }

    void RemoveDcoPeer(Connection *session)
    {
        if (!this->dco_initialized_)
            return;

        uint32_t peer_id = GetPeerId(session);
        this->RemovePeerImpl(peer_id);

        created_peers_.erase(peer_id);
        peer_primary_key_.erase(peer_id);
        peer_to_session_.erase(peer_id);
    }

    // -- Receive loop (CRTP — no std::function) -----------------------------

    asio::awaitable<void> StartDataPath()
    {
        constexpr std::size_t kMaxPacket = 4096;
        std::vector<std::uint8_t> buf(kMaxPacket);

        this->logger_->debug("DCO: control receive loop starting on UDP socket");

        while (this->running_)
        {
            asio::ip::udp::endpoint remote;
            try
            {
                auto n = co_await socket_.async_receive_from(
                    asio::buffer(buf), remote, asio::use_awaitable);

                auto sender = transport::FromAsioEndpoint(remote);
                std::vector<std::uint8_t> data(buf.begin(),
                                               buf.begin() + static_cast<std::ptrdiff_t>(n));
                this->derived().OnControlPacket(std::move(data), sender);
            }
            catch (const asio::system_error &e)
            {
                if (e.code() == asio::error::operation_aborted)
                    break;
                this->logger_->warn("DCO: receive error: {}", e.what());
            }
        }

        this->logger_->debug("DCO: control receive loop exiting");
    }

    void StopDataPath()
    { /* no-op — socket is shared, not owned */
    }

    // -- Keepalive monitor (CRTP — no std::function) ------------------------

    asio::awaitable<void> RunKeepaliveMonitor()
    {
        NetlinkHelper mcast_helper;
        mcast_helper.Open(NETLINK_GENERIC);

        uint32_t mcast_group = mcast_helper.ResolveMulticastGroupId(
            OVPN_NL_NAME, OVPN_NL_MULTICAST_GROUP_PEERS);

        if (mcast_group == 0)
        {
            this->logger_->error("DCO keepalive monitor: failed to resolve multicast group '{}'",
                                 OVPN_NL_MULTICAST_GROUP_PEERS);
            co_return;
        }

        if (!mcast_helper.JoinMulticastGroup(mcast_group))
        {
            this->logger_->error("DCO keepalive monitor: failed to join multicast group {} ({})",
                                 mcast_group,
                                 std::strerror(errno));
            co_return;
        }

        this->logger_->info("DCO keepalive monitor started: multicast group '{}' (id={})",
                            OVPN_NL_MULTICAST_GROUP_PEERS,
                            mcast_group);

        int dup_fd = ::dup(mcast_helper.RawFd());
        if (dup_fd < 0)
        {
            this->logger_->error("DCO keepalive monitor: dup() failed: {}", std::strerror(errno));
            co_return;
        }

        nl_stream_.emplace(this->io_context_, dup_fd);

        std::array<uint8_t, 4096> mbuf;

        while (this->running_)
        {
            std::error_code ec;
            auto bytes = co_await nl_stream_->async_read_some(
                asio::buffer(mbuf), asio::redirect_error(asio::use_awaitable, ec));

            if (ec)
            {
                if (ec == asio::error::operation_aborted)
                    break;
                this->logger_->warn("DCO keepalive monitor: read error: {}", ec.message());
                continue;
            }

            if (bytes < sizeof(struct nlmsghdr))
                continue;

            auto *nlh = reinterpret_cast<struct nlmsghdr *>(mbuf.data());
            int msg_len = static_cast<int>(bytes);
            if (!NLMSG_OK(nlh, msg_len))
                continue;
            if (NLMSG_PAYLOAD(nlh, 0) < static_cast<int>(sizeof(struct genlmsghdr)))
                continue;
            if (nlh->nlmsg_type != this->genl_family_id_)
                continue;

            auto *genlh = static_cast<struct genlmsghdr *>(NLMSG_DATA(nlh));
            if (genlh->cmd != OVPN_CMD_DEL_PEER)
                continue;

            struct nlattr *attr = reinterpret_cast<struct nlattr *>(
                reinterpret_cast<char *>(genlh) + GENL_HDRLEN);
            int attrlen = NLMSG_PAYLOAD(nlh, sizeof(struct genlmsghdr));

            while (NLA_OK(attr, attrlen))
            {
                if ((attr->nla_type & ~NLA_F_NESTED) == OVPN_ATTR_DEL_PEER)
                {
                    struct nlattr *nested = reinterpret_cast<struct nlattr *>(NLA_DATA(attr));
                    int nested_len = attr->nla_len - NLA_HDRLEN;

                    uint32_t dead_peer_id = 0;
                    uint8_t reason = 0;
                    bool has_peer_id = false;
                    bool malformed = false;

                    while (NLA_OK(nested, nested_len))
                    {
                        if (nested->nla_type == OVPN_DEL_PEER_ATTR_PEER_ID)
                        {
                            if (!NlaReadScalar(nested, dead_peer_id))
                            {
                                this->logger_->warn("DCO keepalive monitor: malformed PEER_ID attr payload");
                                malformed = true;
                                break;
                            }
                            has_peer_id = true;
                        }
                        else if (nested->nla_type == OVPN_DEL_PEER_ATTR_REASON)
                        {
                            if (!NlaReadScalar(nested, reason))
                            {
                                this->logger_->warn("DCO keepalive monitor: malformed REASON attr payload");
                                malformed = true;
                                break;
                            }
                        }
                        nested = NLA_NEXT(nested, nested_len);
                    }

                    if (malformed)
                        break;

                    if (!has_peer_id)
                    {
                        this->logger_->warn("DCO keepalive monitor: DEL_PEER without peer-id");
                        break;
                    }

                    const char *reason_str = "unknown";
                    switch (reason)
                    {
                    case OVPN_DEL_PEER_REASON_TEARDOWN:
                        reason_str = "teardown";
                        break;
                    case OVPN_DEL_PEER_REASON_USERSPACE:
                        reason_str = "userspace";
                        break;
                    case OVPN_DEL_PEER_REASON_EXPIRED:
                        reason_str = "expired";
                        break;
                    case OVPN_DEL_PEER_REASON_TRANSPORT_ERROR:
                        reason_str = "transport_error";
                        break;
                    case OVPN_DEL_PEER_REASON_TRANSPORT_DISCONNECT:
                        reason_str = "transport_disconnect";
                        break;
                    }

                    this->logger_->info("DCO: DEL_PEER notification for peer {} (reason={})",
                                        dead_peer_id,
                                        reason_str);

                    if (reason == OVPN_DEL_PEER_REASON_USERSPACE || reason == OVPN_DEL_PEER_REASON_TEARDOWN)
                        break;

                    auto sit = peer_to_session_.find(dead_peer_id);
                    if (sit != peer_to_session_.end())
                    {
                        auto sid = sit->second;
                        created_peers_.erase(dead_peer_id);
                        peer_primary_key_.erase(dead_peer_id);
                        peer_to_session_.erase(sit);

                        this->derived().OnPeerDead(sid);
                    }
                    else
                    {
                        this->logger_->warn("DCO: DEL_PEER for unknown peer {}",
                                            dead_peer_id);
                    }

                    break;
                }
                attr = NLA_NEXT(attr, attrlen);
            }
        }

        this->logger_->info("DCO keepalive monitor stopped");
        nl_stream_.reset();
    }

    void StopKeepaliveMonitor()
    {
        if (nl_stream_)
            nl_stream_->close();
    }

    // -- Stats --------------------------------------------------------------

    DataPathStats SnapshotStats() const
    {
        return this->SnapshotStatsImpl();
    }

    void SetBatchSize(std::size_t)
    { /* no-op */
    }
    std::size_t GetBatchSize() const
    {
        return 0;
    }

  private:
    void InitializeDco()
    {
        clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));
        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, this->dco_ifname_.c_str(), IFNAMSIZ - 1);

        if (ioctl(sock.get(), SIOCGIFINDEX, &ifr) < 0)
        {
            // Device doesn't exist — create it in MP mode
            this->logger_->info("DCO: Device {} not found, creating via rtnetlink",
                                this->dco_ifname_);

            dco::CreateDcoDevice(this->dco_ifname_, OVPN_MODE_MP, *this->logger_);

            auto device_guard = scope_fail([this]()
            {
                this->DestroyDcoDevice();
            });

            this->InitializeNetlink();
            ConfigureDcoInterface();
        }
        else
        {
            // Device already exists — just open netlink
            this->dco_ifindex_ = ifr.ifr_ifindex;
            this->InitializeNetlink();
            ConfigureDcoInterface();
        }

        this->logger_->info("DCO: Device {} initialized (ifindex={})",
                            this->dco_ifname_,
                            this->dco_ifindex_);
    }

    void ConfigureDcoInterface()
    {
        auto parsed = ipv4::ParseCidr(network_config_.server_network);
        if (!parsed)
        {
            throw std::runtime_error(
                "DCO: Invalid server_network CIDR: " + network_config_.server_network);
        }
        auto [network_addr, prefix_length] = *parsed;

        clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));
        iface::SetIpAddress(sock.get(), this->dco_ifname_.c_str(), network_config_.server_ip);
        iface::SetNetmask(sock.get(), this->dco_ifname_.c_str(), ipv4::CreateMask(prefix_length));
        if (network_config_.tun_mtu > 0)
            iface::SetMtu(sock.get(), this->dco_ifname_.c_str(), network_config_.tun_mtu);
        iface::BringUp(sock.get(), this->dco_ifname_.c_str());

        this->logger_->info("DCO: Interface {} configured with IP {}/{} mtu={} and brought up",
                            this->dco_ifname_,
                            network_config_.server_ip,
                            static_cast<int>(prefix_length),
                            network_config_.tun_mtu > 0 ? network_config_.tun_mtu : 0);

        if (!network_config_.server_network_v6.empty())
        {
            auto parsed_v6 = ipv6::ParseCidr6(network_config_.server_network_v6);
            if (parsed_v6)
            {
                auto [net_v6, prefix_v6] = *parsed_v6;
                ipv6::Ipv6Address server_v6 = net_v6;
                server_v6[15] += 1;
                std::string server_v6_str = ipv6::Ipv6ToString(server_v6);

                iface::AddIpv6Address(this->dco_ifname_.c_str(), server_v6_str, prefix_v6);

                this->logger_->info("DCO: Interface {} IPv6 address {}/{} configured",
                                    this->dco_ifname_,
                                    server_v6_str,
                                    prefix_v6);
            }
        }
    }

    bool CreateDcoPeer(Connection *session)
    {
        uint32_t peer_id = GetPeerId(session);

        if (created_peers_.count(peer_id) > 0)
        {
            this->logger_->debug("DCO: Peer {} already exists, skipping creation", peer_id);
            return true;
        }

        const auto &endpoint = session->GetEndpoint();

        this->logger_->debug("DCO: Creating peer {} for {}:{}",
                             peer_id,
                             endpoint.addr.to_string(),
                             endpoint.port);

        // Prepare optional VPN IPs
        std::optional<std::uint32_t> vpn_ipv4;
        if (auto ip = session->GetAssignedIpv4())
            vpn_ipv4 = htonl(*ip);

        const std::uint8_t *vpn_ipv6 = nullptr;
        std::optional<ipv6::Ipv6Address> v6_storage;
        if (auto v6 = session->GetAssignedIpv6())
        {
            v6_storage = *v6;
            vpn_ipv6 = v6_storage->data();
        }

        transport::PeerEndpoint peer_ep{endpoint.addr, endpoint.port};

        if (!this->CreatePeerImpl(peer_id, peer_ep, static_cast<int>(socket_.native_handle()), vpn_ipv4, vpn_ipv6))
            return false;

        created_peers_.insert(peer_id);
        peer_to_session_[peer_id] = session->GetSessionId();
        return true;
    }

    // Server-specific state
    asio::ip::udp::socket &socket_;
    NetworkConfig network_config_;
    std::unordered_set<uint32_t> created_peers_;
    std::unordered_map<uint32_t, uint8_t> peer_primary_key_;
    std::unordered_map<uint32_t, openvpn::SessionId> peer_to_session_;
    std::optional<asio::posix::stream_descriptor> nl_stream_;
};

} // namespace clv::vpn

#endif // CLV_VPN_DCO_SERVER_DATA_MIXIN_H
