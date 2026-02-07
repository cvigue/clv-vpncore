// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "dco_data_channel.h"
#include "dco_netlink_ops.h"
#include "iface_utils.h"
#include "client_session.h"
#include "data_channel.h"
#include "data_path_stats.h"
#include "openvpn/protocol_constants.h"
#include "ovpn_dco.h"

#include <stdexcept>
#include <system_error>
#include <util/ipv4_utils.h>
#include <util/ipv6_utils.h>
#include <tun/tun_device.h>
#include "scope_guard.h"
#include "util/netlink_helper.h"
#include "util/nla_helpers.h"
#include <unique_fd.h>

#include <asio/awaitable.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <asio/read.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <linux/if_link.h>
#include <string>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/ipv6.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>
#include <errno.h>
#include <utility>
#include <vector>

namespace clv::vpn {

// ==================== Local helper functions ====================

// ==================== DcoDataChannel Implementation ====================

DcoDataChannel::DcoDataChannel(asio::io_context &io_context,
                               asio::ip::udp::socket &socket,
                               const NetworkConfig &network_config,
                               spdlog::logger &logger,
                               const bool &running_flag)
    : io_context_(io_context),
      socket_(socket),
      network_config_(network_config),
      logger_(&logger),
      running_(running_flag)
{
    InitializeDco();
    logger_->info("DCO data channel initialized successfully (ifname={})", dco_ifname_);
}

DcoDataChannel::~DcoDataChannel()
{
    // Destroy DCO device if it was created
    if (dco_initialized_ && dco_ifindex_ >= 0)
    {
        DestroyDcoDevice();
    }

    logger_->debug("DCO: Cleaned up resources");
}

asio::awaitable<void> DcoDataChannel::ProcessIncomingDataPacket(
    [[maybe_unused]] ClientSession *session,
    [[maybe_unused]] const openvpn::OpenVpnPacket &packet)
{
    // In DCO mode, kernel handles decryption - userspace should not see data packets
    logger_->warn("DCO: ProcessIncomingDataPacket called unexpectedly (should be handled by kernel)");
    co_return;
}

asio::awaitable<void> DcoDataChannel::ProcessOutgoingTunPacket(
    [[maybe_unused]] tun::IpPacket packet)
{
    // In DCO mode, kernel handles encryption - userspace doesn't process TUN packets
    logger_->warn("DCO: ProcessOutgoingTunPacket called unexpectedly (should be handled by kernel)");
    co_return;
}

asio::awaitable<void> DcoDataChannel::StartTunReceiver()
{
    // In DCO mode, no userspace TUN receiver needed
    logger_->warn("DCO: StartTunReceiver called unexpectedly (kernel handles data path)");
    co_return;
}

bool DcoDataChannel::InstallKeys(ClientSession *session,
                                 const std::vector<uint8_t> &key_material,
                                 openvpn::CipherAlgorithm cipher_algo,
                                 [[maybe_unused]] openvpn::HmacAlgorithm hmac_algo,
                                 std::uint8_t key_id,
                                 [[maybe_unused]] int lame_duck_seconds)
{
    if (!dco_initialized_)
    {
        logger_->error("DCO: Cannot install keys - DCO not initialized");
        return false;
    }

    // First, create the peer in DCO if not already done
    if (!CreateDcoPeer(session))
    {
        logger_->error("DCO: Failed to create peer");
        return false;
    }

    uint32_t peer_id = GetPeerId(session);

    // Determine which slot to use:
    // - First key install (no primary key yet) → PRIMARY slot
    // - Renegotiation (different key_id) → SECONDARY slot, then swap
    auto it = peer_primary_key_.find(peer_id);
    bool is_renegotiation = (it != peer_primary_key_.end() && it->second != key_id);
    uint8_t key_slot = is_renegotiation ? OVPN_KEY_SLOT_SECONDARY : OVPN_KEY_SLOT_PRIMARY;

    logger_->info("DCO: Installing keys via netlink (key_id={}, slot={}, renegotiation={})",
                  key_id,
                  key_slot == OVPN_KEY_SLOT_PRIMARY ? "PRIMARY" : "SECONDARY",
                  is_renegotiation);

    if (!PushKeysToKernel(session, key_material, cipher_algo, key_id, key_slot))
    {
        logger_->error("DCO: Failed to push keys to kernel");
        return false;
    }

    // For renegotiation: swap keys so new key becomes primary
    if (is_renegotiation)
    {
        if (!SwapKeys(session))
        {
            logger_->error("DCO: Failed to swap keys after renegotiation");
            return false;
        }
    }

    // Track this as the current primary key for this peer
    peer_primary_key_[peer_id] = key_id;

    // Configure kernel keepalive timers on first key install
    // (only needed once per peer — kernel retains the timers across key swaps)
    if (!is_renegotiation)
    {
        if (!SetPeerKeepalive(session))
        {
            logger_->warn("DCO: Failed to set keepalive timers for peer {} (non-fatal)", peer_id);
        }
    }

    // Mark keys as installed in session for tracking purposes
    session->GetDataChannel().SetCurrentKeyId(key_id);
    session->GetDataChannel().SetDcoKeysInstalled(true);

    logger_->info("DCO: Keys installed successfully in kernel (key_id={})", key_id);
    return true;
}

void DcoDataChannel::InitializeDco()
{
    // Check if ovpn-dco device exists
    clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, dco_ifname_.c_str(), IFNAMSIZ - 1);

    // Try to get interface index
    if (ioctl(sock.get(), SIOCGIFINDEX, &ifr) < 0)
    {
        // Interface doesn't exist, create it
        logger_->info("DCO: Device {} not found, creating via rtnetlink", dco_ifname_);
        CreateDcoDevice();

        // If anything below fails, destroy the device we just created
        auto device_guard = scope_fail([this]()
        { DestroyDcoDevice(); });

        // Reopen socket and get ifindex
        sock = clv::UniqueFd(::socket(AF_INET, SOCK_DGRAM, 0));
        if (ioctl(sock.get(), SIOCGIFINDEX, &ifr) < 0)
        {
            throw std::system_error(errno, std::system_category(), "DCO: Failed to get ifindex after device creation");
        }
        dco_ifindex_ = ifr.ifr_ifindex;

        // Open generic netlink socket for DCO commands
        netlink_helper_.Open();

        // Resolve the ovpn-dco-v2 family ID
        genl_family_id_ = netlink_helper_.ResolveFamilyId(OVPN_NL_NAME);
        if (genl_family_id_ == 0)
        {
            throw std::runtime_error(
                std::string("DCO: Failed to resolve generic netlink family '") + OVPN_NL_NAME + "'");
        }
        logger_->debug("DCO: Resolved family '{}' to ID {}", OVPN_NL_NAME, genl_family_id_);

        // Bring up the interface and configure IP
        ConfigureDcoInterface();
    }
    else
    {
        dco_ifindex_ = ifr.ifr_ifindex;

        // Open generic netlink socket for DCO commands
        netlink_helper_.Open();

        // Resolve the ovpn-dco-v2 family ID
        genl_family_id_ = netlink_helper_.ResolveFamilyId(OVPN_NL_NAME);
        if (genl_family_id_ == 0)
        {
            throw std::runtime_error(
                std::string("DCO: Failed to resolve generic netlink family '") + OVPN_NL_NAME + "'");
        }
        logger_->debug("DCO: Resolved family '{}' to ID {}", OVPN_NL_NAME, genl_family_id_);

        // Bring up the interface and configure IP
        ConfigureDcoInterface();
    }

    logger_->info("DCO: Device {} initialized (ifindex={})", dco_ifname_, dco_ifindex_);
    dco_initialized_ = true;
}

void DcoDataChannel::CreateDcoDevice()
{
    dco::CreateDcoDevice(dco_ifname_, OVPN_MODE_MP, *logger_);
}

void DcoDataChannel::DestroyDcoDevice()
{
    dco::DestroyDcoDevice(dco_ifindex_, dco_ifname_, *logger_);
    dco_ifindex_ = -1;
    dco_initialized_ = false;
}

void DcoDataChannel::ConfigureDcoInterface()
{
    // Parse server network to get prefix length
    auto parsed = ipv4::ParseCidr(network_config_.server_network);
    if (!parsed)
    {
        throw std::runtime_error(
            "DCO: Invalid server_network CIDR: " + network_config_.server_network);
    }
    auto [network_addr, prefix_length] = *parsed;

    // Create socket for ioctl operations
    clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));

    // Set IP address
    iface::SetIpAddress(sock.get(), dco_ifname_.c_str(), network_config_.server_ip);

    // Set netmask
    iface::SetNetmask(sock.get(), dco_ifname_.c_str(), ipv4::CreateMask(prefix_length));

    // Bring interface up
    iface::BringUp(sock.get(), dco_ifname_.c_str());

    logger_->info("DCO: Interface {} configured with IP {}/{} and brought up",
                  dco_ifname_,
                  network_config_.server_ip,
                  static_cast<int>(prefix_length));

    // Add IPv6 address if configured
    if (!network_config_.server_network_v6.empty())
    {
        auto parsed_v6 = ipv6::ParseCidr6(network_config_.server_network_v6);
        if (parsed_v6)
        {
            auto [net_v6, prefix_v6] = *parsed_v6;
            // Server address = network + 1 (e.g. fd00::1)
            ipv6::Ipv6Address server_v6 = net_v6;
            server_v6[15] += 1;
            std::string server_v6_str = ipv6::Ipv6ToString(server_v6);

            iface::AddIpv6Address(dco_ifname_.c_str(), server_v6_str, prefix_v6);

            logger_->info("DCO: Interface {} IPv6 address {}/{} configured",
                          dco_ifname_,
                          server_v6_str,
                          prefix_v6);
        }
    }
}

uint32_t DcoDataChannel::GetPeerId(ClientSession *session) const
{
    // Use lower 24 bits of session ID as peer ID (matches OpenVPN peer-id format)
    return static_cast<uint32_t>(session->GetSessionId().value & openvpn::PEER_ID_MASK);
}

bool DcoDataChannel::CreateDcoPeer(ClientSession *session)
{
    if (!dco_initialized_ || !netlink_helper_.IsOpen())
    {
        return false;
    }

    uint32_t peer_id = GetPeerId(session);

    // Check if peer already created
    if (created_peers_.count(peer_id) > 0)
    {
        logger_->debug("DCO: Peer {} already exists, skipping creation", peer_id);
        return true;
    }

    const auto &endpoint = session->GetEndpoint();

    logger_->debug("DCO: Creating peer {} for {}:{}", peer_id, endpoint.addr.to_string(), endpoint.port);

    // Build OVPN_CMD_NEW_PEER message
    // Layout: nlmsghdr | genlmsghdr | OVPN_ATTR_IFINDEX | OVPN_ATTR_NEW_PEER[nested attrs]
    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        char attrs[512];
    } req{};

    req.nlh.nlmsg_type = genl_family_id_;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nlh.nlmsg_seq = 0; // NetlinkHelper will set this
    req.nlh.nlmsg_pid = 0;

    req.genlh.cmd = OVPN_CMD_NEW_PEER;
    req.genlh.version = 0;

    char *buf = req.attrs;
    size_t offset = 0;
    constexpr size_t kAttrsCap = sizeof(req.attrs);

    // OVPN_ATTR_IFINDEX (u32)
    {
        uint32_t ifidx = static_cast<uint32_t>(dco_ifindex_);
        NlaPut(buf, offset, kAttrsCap, OVPN_ATTR_IFINDEX, &ifidx, sizeof(ifidx));
    }

    // OVPN_ATTR_NEW_PEER (nested)
    size_t peer_attr_start = offset;
    struct nlattr *peer_attr = NlaBeginNested(buf, offset, kAttrsCap, OVPN_ATTR_NEW_PEER);
    if (!peer_attr)
    {
        logger_->error("DCO: Netlink attribute buffer overflow in OVPN_CMD_NEW_PEER");
        return false;
    }

    // OVPN_NEW_PEER_ATTR_PEER_ID (u32)
    NlaPut(buf, offset, kAttrsCap, OVPN_NEW_PEER_ATTR_PEER_ID, &peer_id, sizeof(peer_id));

    // OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE (struct sockaddr — v4 or v6)
    {
        if (endpoint.addr.is_v4())
        {
            struct sockaddr_in sa{};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(endpoint.port);
            sa.sin_addr.s_addr = htonl(endpoint.addr.to_v4().to_uint());
            NlaPut(buf, offset, kAttrsCap, OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE, &sa, sizeof(sa));
        }
        else
        {
            struct sockaddr_in6 sa6{};
            sa6.sin6_family = AF_INET6;
            sa6.sin6_port = htons(endpoint.port);
            auto v6bytes = endpoint.addr.to_v6().to_bytes();
            std::memcpy(&sa6.sin6_addr, v6bytes.data(), 16);
            NlaPut(buf, offset, kAttrsCap, OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE, &sa6, sizeof(sa6));
        }
    }

    // OVPN_NEW_PEER_ATTR_SOCKET (u32 - the UDP socket FD)
    {
        uint32_t sockfd = static_cast<uint32_t>(socket_.native_handle());
        NlaPut(buf, offset, kAttrsCap, OVPN_NEW_PEER_ATTR_SOCKET, &sockfd, sizeof(sockfd));
    }

    // OVPN_NEW_PEER_ATTR_IPV4 (u32 - VPN IP if assigned)
    if (auto vpn_ip = session->GetAssignedIpv4())
    {
        uint32_t ip_net = htonl(*vpn_ip);
        NlaPut(buf, offset, kAttrsCap, OVPN_NEW_PEER_ATTR_IPV4, &ip_net, sizeof(ip_net));
    }

    // OVPN_NEW_PEER_ATTR_IPV6 (struct in6_addr - VPN IPv6 if assigned)
    if (auto vpn_ipv6 = session->GetAssignedIpv6())
    {
        NlaPut(buf, offset, kAttrsCap, OVPN_NEW_PEER_ATTR_IPV6, vpn_ipv6->data(), 16);
    }

    // Set nested peer attribute length
    peer_attr->nla_len = static_cast<decltype(peer_attr->nla_len)>(offset - peer_attr_start);

    // Validate no buffer overflow occurred
    if (offset > kAttrsCap)
    {
        logger_->error("DCO: Netlink attribute buffer overflow in RegisterPeer ({} > {})", offset, kAttrsCap);
        return false;
    }

    // Set total message length
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)) + static_cast<decltype(req.nlh.nlmsg_len)>(offset);

    // Send and receive via NetlinkHelper
    std::vector<uint8_t> response;
    if (!netlink_helper_.SendAndReceive(&req.nlh, req.nlh.nlmsg_len, response))
    {
        logger_->error("DCO: Failed to send/receive OVPN_CMD_NEW_PEER");
        return false;
    }

    // Parse response
    struct nlmsghdr *nlh = (struct nlmsghdr *)response.data();
    if (nlh->nlmsg_type == NLMSG_ERROR)
    {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        if (err->error != 0)
        {
            logger_->error("DCO: OVPN_CMD_NEW_PEER failed: {} ({})",
                           std::strerror(-err->error),
                           err->error);
            return false;
        }
    }

    created_peers_.insert(peer_id);
    peer_to_session_[peer_id] = session->GetSessionId();
    logger_->info("DCO: Peer {} created successfully", peer_id);
    return true;
}

void DcoDataChannel::RemoveDcoPeer(ClientSession *session)
{
    if (!dco_initialized_ || !netlink_helper_.IsOpen())
    {
        return;
    }

    uint32_t peer_id = GetPeerId(session);
    logger_->debug("DCO: Removing peer {}", peer_id);

    // Build OVPN_CMD_DEL_PEER message
    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        char attrs[128];
    } req{};

    req.nlh.nlmsg_type = genl_family_id_;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nlh.nlmsg_seq = 0; // NetlinkHelper will set this
    req.nlh.nlmsg_pid = 0;

    req.genlh.cmd = OVPN_CMD_DEL_PEER;
    req.genlh.version = 0;

    char *buf = req.attrs;
    size_t offset = 0;
    constexpr size_t kAttrsCap = sizeof(req.attrs);

    // OVPN_ATTR_IFINDEX
    {
        uint32_t ifidx = static_cast<uint32_t>(dco_ifindex_);
        NlaPut(buf, offset, kAttrsCap, OVPN_ATTR_IFINDEX, &ifidx, sizeof(ifidx));
    }

    // OVPN_ATTR_DEL_PEER (nested)
    size_t del_attr_start = offset;
    struct nlattr *del_attr = NlaBeginNested(buf, offset, kAttrsCap, OVPN_ATTR_DEL_PEER);
    if (!del_attr)
        return;

    // OVPN_DEL_PEER_ATTR_PEER_ID
    NlaPut(buf, offset, kAttrsCap, OVPN_DEL_PEER_ATTR_PEER_ID, &peer_id, sizeof(peer_id));

    del_attr->nla_len = static_cast<decltype(del_attr->nla_len)>(offset - del_attr_start);
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)) + static_cast<decltype(req.nlh.nlmsg_len)>(offset);

    // Send via NetlinkHelper (best effort - don't check response)
    std::vector<uint8_t> response;
    netlink_helper_.SendAndReceive(&req.nlh, req.nlh.nlmsg_len, response);

    created_peers_.erase(peer_id);
    peer_primary_key_.erase(peer_id); // Also clear key tracking
    peer_to_session_.erase(peer_id);  // Also clear reverse mapping
    logger_->debug("DCO: Peer {} removal requested", peer_id);
}

bool DcoDataChannel::SwapKeys(ClientSession *session)
{
    if (!dco_initialized_ || !netlink_helper_.IsOpen())
    {
        logger_->error("DCO: Cannot swap keys - not initialized");
        return false;
    }

    return dco::SwapDcoKeys(dco_ifindex_, genl_family_id_, GetPeerId(session), netlink_helper_, *logger_);
}

bool DcoDataChannel::PushKeysToKernel(ClientSession *session,
                                      const std::vector<uint8_t> &key_material,
                                      openvpn::CipherAlgorithm cipher_algo,
                                      std::uint8_t key_id,
                                      uint8_t key_slot)
{
    if (!dco_initialized_ || !netlink_helper_.IsOpen())
    {
        logger_->error("DCO: Cannot push keys - not initialized");
        return false;
    }

    return dco::PushKeysToKernel(dco_ifindex_, genl_family_id_, GetPeerId(session), key_material, cipher_algo, key_id, key_slot, openvpn::PeerRole::Server, netlink_helper_, *logger_);
}

bool DcoDataChannel::SetPeerKeepalive(ClientSession *session)
{
    if (!dco_initialized_ || !netlink_helper_.IsOpen())
    {
        logger_->error("DCO: Cannot set peer keepalive - not initialized");
        return false;
    }

    if (network_config_.keepalive_interval == 0 && network_config_.keepalive_timeout == 0)
    {
        logger_->debug("DCO: Keepalive disabled (both interval and timeout are 0)");
        return true;
    }

    return dco::SetDcoPeerKeepalive(dco_ifindex_, genl_family_id_, GetPeerId(session), network_config_.keepalive_interval, network_config_.keepalive_timeout, netlink_helper_, *logger_);
}

asio::awaitable<void> DcoDataChannel::SendKeepAlivePing(ClientSession *session)
{
    // In DCO mode the kernel sends PINGs autonomously via the timers
    // configured by SetPeerKeepalive() during key installation.
    // Nothing to do here.
    (void)session;
    co_return;
}

asio::awaitable<void> DcoDataChannel::RunKeepaliveMonitor(DeadPeerCallback on_dead_peer)
{
    // Open a dedicated netlink socket for multicast notifications
    NetlinkHelper mcast_helper;
    mcast_helper.Open(NETLINK_GENERIC);

    // Resolve the multicast group ID for "peers" from the ovpn-dco-v2 family
    uint32_t mcast_group = mcast_helper.ResolveMulticastGroupId(
        OVPN_NL_NAME, OVPN_NL_MULTICAST_GROUP_PEERS);

    if (mcast_group == 0)
    {
        logger_->error("DCO keepalive monitor: failed to resolve multicast group '{}'",
                       OVPN_NL_MULTICAST_GROUP_PEERS);
        co_return;
    }

    if (!mcast_helper.JoinMulticastGroup(mcast_group))
    {
        logger_->error("DCO keepalive monitor: failed to join multicast group {} ({})",
                       mcast_group,
                       std::strerror(errno));
        co_return;
    }

    logger_->info("DCO keepalive monitor started: listening on multicast group '{}' (id={})",
                  OVPN_NL_MULTICAST_GROUP_PEERS,
                  mcast_group);

    // Wrap the netlink fd in an asio stream_descriptor for async reads.
    // dup() so the stream_descriptor doesn't close the helper's fd on destruction.
    int dup_fd = ::dup(mcast_helper.RawFd());
    if (dup_fd < 0)
    {
        logger_->error("DCO keepalive monitor: dup() failed: {}", std::strerror(errno));
        co_return;
    }

    asio::posix::stream_descriptor nl_stream(io_context_, dup_fd);

    std::array<uint8_t, 4096> buf;

    while (running_)
    {
        std::error_code ec;
        auto bytes = co_await nl_stream.async_read_some(
            asio::buffer(buf), asio::redirect_error(asio::use_awaitable, ec));

        if (ec)
        {
            if (ec == asio::error::operation_aborted)
                break;
            logger_->warn("DCO keepalive monitor: read error: {}", ec.message());
            continue;
        }

        if (bytes < sizeof(struct nlmsghdr))
            continue;

        // Parse the generic netlink message
        auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf.data());
        if (!NLMSG_OK(nlh, bytes))
            continue;

        // We only care about messages from the ovpn-dco family
        if (nlh->nlmsg_type != genl_family_id_)
            continue;

        auto *genlh = static_cast<struct genlmsghdr *>(NLMSG_DATA(nlh));
        if (genlh->cmd != OVPN_CMD_DEL_PEER)
            continue;

        // Parse DEL_PEER attributes: walk past the genlmsghdr to find
        // OVPN_ATTR_DEL_PEER (nested) → OVPN_DEL_PEER_ATTR_PEER_ID + REASON
        struct nlattr *attr = reinterpret_cast<struct nlattr *>(
            reinterpret_cast<char *>(genlh) + GENL_HDRLEN);
        int attrlen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

        while (NLA_OK(attr, attrlen))
        {
            if ((attr->nla_type & ~NLA_F_NESTED) == OVPN_ATTR_DEL_PEER)
            {
                // Walk nested attrs
                struct nlattr *nested = reinterpret_cast<struct nlattr *>(NLA_DATA(attr));
                int nested_len = attr->nla_len - NLA_HDRLEN;

                uint32_t dead_peer_id = 0;
                uint8_t reason = 0;
                bool has_peer_id = false;

                while (NLA_OK(nested, nested_len))
                {
                    if (nested->nla_type == OVPN_DEL_PEER_ATTR_PEER_ID)
                    {
                        dead_peer_id = *reinterpret_cast<uint32_t *>(NLA_DATA(nested));
                        has_peer_id = true;
                    }
                    else if (nested->nla_type == OVPN_DEL_PEER_ATTR_REASON)
                    {
                        reason = *reinterpret_cast<uint8_t *>(NLA_DATA(nested));
                    }
                    nested = NLA_NEXT(nested, nested_len);
                }

                if (!has_peer_id)
                    break;

                // Map reason enum to string for logging
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

                logger_->info("DCO: DEL_PEER notification for peer {} (reason={})",
                              dead_peer_id,
                              reason_str);

                // Ignore userspace-initiated deletions (we already cleaned up)
                if (reason == OVPN_DEL_PEER_REASON_USERSPACE || reason == OVPN_DEL_PEER_REASON_TEARDOWN)
                    break;

                // Look up the SessionId for this peer
                auto it = peer_to_session_.find(dead_peer_id);
                if (it != peer_to_session_.end())
                {
                    auto sid = it->second;
                    // Clean up local peer tracking
                    created_peers_.erase(dead_peer_id);
                    peer_primary_key_.erase(dead_peer_id);
                    peer_to_session_.erase(it);

                    on_dead_peer(sid);
                }
                else
                {
                    logger_->warn("DCO: DEL_PEER for unknown peer {}", dead_peer_id);
                }

                break; // Only one DEL_PEER per message
            }
            attr = NLA_NEXT(attr, attrlen);
        }
    }

    logger_->info("DCO keepalive monitor stopped");
}

// ---------------------------------------------------------------------------
// SnapshotStats — aggregate per-peer traffic counters from kernel
// ---------------------------------------------------------------------------

DataPathStats DcoDataChannel::SnapshotStats() const
{
    DataPathStats stats{};

    if (!dco_initialized_ || genl_family_id_ == 0)
    {
        logger_->debug("DCO SnapshotStats: skipped (init={} fam={})",
                       dco_initialized_,
                       genl_family_id_);
        return stats;
    }

    // We need a temporary netlink socket because the member socket may be
    // busy with the multicast monitor.  Generic netlink is cheap to open.
    NetlinkHelper nl;
    nl.Open(NETLINK_GENERIC);

    uint16_t fam = nl.ResolveFamilyId(OVPN_NL_NAME);
    if (fam == 0)
    {
        logger_->warn("DCO SnapshotStats: failed to resolve family ID");
        return stats;
    }

    // Build OVPN_CMD_GET_PEER with NLM_F_DUMP (all peers)
    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        char attrs[64];
    } req{};

    req.nlh.nlmsg_type = fam;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 0;
    req.nlh.nlmsg_pid = 0;

    req.genlh.cmd = OVPN_CMD_GET_PEER;
    req.genlh.version = 0;

    char *buf = req.attrs;
    size_t offset = 0;
    constexpr size_t kAttrsCap = sizeof(req.attrs);

    // OVPN_ATTR_IFINDEX (u32)
    {
        uint32_t ifidx = static_cast<uint32_t>(dco_ifindex_);
        NlaPut(buf, offset, kAttrsCap, OVPN_ATTR_IFINDEX, &ifidx, sizeof(ifidx));
    }

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr))
                        + static_cast<decltype(req.nlh.nlmsg_len)>(offset);

    // Send the dump request
    if (::send(nl.RawFd(), &req, req.nlh.nlmsg_len, 0) < 0)
    {
        logger_->warn("DCO SnapshotStats: send failed ({})", std::strerror(errno));
        return stats;
    }

    // Receive multipart response until NLMSG_DONE
    std::array<char, 16384> rbuf;
    bool done = false;

    while (!done)
    {
        ssize_t len = ::recv(nl.RawFd(), rbuf.data(), rbuf.size(), 0);
        if (len <= 0)
            break;

        for (auto *nlh = reinterpret_cast<struct nlmsghdr *>(rbuf.data());
             NLMSG_OK(nlh, static_cast<unsigned>(len));
             nlh = NLMSG_NEXT(nlh, len))
        {
            if (nlh->nlmsg_type == NLMSG_DONE)
            {
                done = true;
                break;
            }

            if (nlh->nlmsg_type == NLMSG_ERROR)
            {
                auto *err = static_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
                if (err->error != 0)
                    logger_->warn("DCO SnapshotStats: kernel error {}",
                                  std::strerror(-err->error));
                done = true;
                break;
            }

            // Each message: genlmsghdr + OVPN_ATTR_GET_PEER (nested)
            auto *genlh = static_cast<struct genlmsghdr *>(NLMSG_DATA(nlh));
            auto *attr = reinterpret_cast<struct nlattr *>(
                reinterpret_cast<char *>(genlh) + GENL_HDRLEN);
            int attrlen = static_cast<int>(
                nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));

            while (NLA_OK(attr, attrlen))
            {
                if ((attr->nla_type & ~NLA_F_NESTED) == OVPN_ATTR_GET_PEER)
                {
                    // Parse nested peer attributes
                    auto *inner = reinterpret_cast<struct nlattr *>(NLA_DATA(attr));
                    int innerlen = attr->nla_len - NLA_HDRLEN;

                    while (NLA_OK(inner, innerlen))
                    {
                        switch (inner->nla_type)
                        {
                        case OVPN_GET_PEER_RESP_ATTR_LINK_RX_BYTES:
                            stats.bytesReceived += *reinterpret_cast<const uint64_t *>(NLA_DATA(inner));
                            break;
                        case OVPN_GET_PEER_RESP_ATTR_LINK_TX_BYTES:
                            stats.bytesSent += *reinterpret_cast<const uint64_t *>(NLA_DATA(inner));
                            break;
                        case OVPN_GET_PEER_RESP_ATTR_VPN_RX_BYTES:
                            // VPN-level decrypted bytes — informational
                            break;
                        case OVPN_GET_PEER_RESP_ATTR_VPN_TX_BYTES:
                            // VPN-level encrypted bytes — informational
                            break;
                        case OVPN_GET_PEER_RESP_ATTR_VPN_RX_PACKETS:
                            {
                                auto pkts = static_cast<uint64_t>(
                                    *reinterpret_cast<const uint32_t *>(NLA_DATA(inner)));
                                stats.packetsReceived += pkts;
                                stats.packetsDecrypted += pkts; // kernel decrypted them
                                stats.tunWrites += pkts;        // kernel wrote them to TUN
                                break;
                            }
                        case OVPN_GET_PEER_RESP_ATTR_VPN_TX_PACKETS:
                            {
                                auto pkts = static_cast<uint64_t>(
                                    *reinterpret_cast<const uint32_t *>(NLA_DATA(inner)));
                                stats.packetsSent += pkts;
                                stats.packetsEncrypted += pkts; // kernel encrypted them
                                stats.tunReads += pkts;         // kernel read them from TUN
                                break;
                            }
                        default:
                            break;
                        }
                        inner = NLA_NEXT(inner, innerlen);
                    }
                }
                attr = NLA_NEXT(attr, attrlen);
            }
        }
    }

    return stats;
}

} // namespace clv::vpn
