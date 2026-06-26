// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "dco_core.h"

#include "data_path_stats.h"
#include "dco_netlink_ops.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/key_derivation.h"
#include "openvpn/ovpn_dco.h"
#include "transport/transport.h"
#include "util/netlink_helper.h"

#include <atomic>
#include <linux/netlink.h>
#include <numeric_util.h>
#include <optional>
#include <scope_guard.h>
#include <sys/types.h>
#include <unique_fd.h>
#include <util/nla_helpers.h>

#include <arpa/inet.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace clv::vpn {

using clv::netlink::NetlinkHelper;
using clv::netlink::NlaPut;
using clv::netlink::NlaBeginNested;
using clv::netlink::NlaReadScalar;

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

DcoCoreBase::DcoCoreBase(asio::io_context &io_ctx,
                         spdlog::logger &logger,
                         std::string ifname,
                         const std::atomic<bool> &running)
    : io_context_(io_ctx),
      logger_(&logger),
      running_(running),
      dco_ifname_(std::move(ifname))
{
}

DcoCoreBase::~DcoCoreBase() = default;

// ---------------------------------------------------------------------------
// Device lifecycle
// ---------------------------------------------------------------------------

void DcoCoreBase::InitializeDcoDevice(std::uint8_t ovpn_mode)
{
    dco::CreateDcoDevice(dco_ifname_, ovpn_mode, *logger_);

    auto device_guard = scope_fail([this]()
    {
        dco::DestroyDcoDevice(dco_ifindex_, dco_ifname_, *logger_);
    });

    InitializeNetlink();

    logger_->debug("DCO: Device {} created (ifindex={}, family_id={})",
                   dco_ifname_,
                   dco_ifindex_,
                   genl_family_id_);
}

void DcoCoreBase::InitializeNetlink()
{
    // Get interface index
    clv::UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, dco_ifname_.c_str(), IFNAMSIZ - 1);
    if (ioctl(sock.get(), SIOCGIFINDEX, &ifr) < 0)
    {
        throw std::system_error(errno, std::system_category(), "DCO: Failed to get ifindex for " + dco_ifname_);
    }
    dco_ifindex_ = ifr.ifr_ifindex;

    // Open generic netlink socket and resolve ovpn-dco-v2 family
    netlink_helper_.Open();
    genl_family_id_ = netlink_helper_.ResolveFamilyId(OVPN_NL_NAME);
    if (genl_family_id_ == 0)
    {
        throw std::runtime_error(
            "DCO: Failed to resolve generic netlink family '" + std::string(OVPN_NL_NAME) + "'");
    }

    dco_initialized_ = true;
}

void DcoCoreBase::DestroyDcoDevice()
{
    if (dco_initialized_ && dco_ifindex_ >= 0)
    {
        dco::DestroyDcoDevice(dco_ifindex_, dco_ifname_, *logger_);
        dco_ifindex_ = -1;
        dco_initialized_ = false;
    }
}

// ---------------------------------------------------------------------------
// Stats — aggregate per-peer traffic counters from kernel
// ---------------------------------------------------------------------------

DataPathStats DcoCoreBase::SnapshotStatsImpl() const
{
    DataPathStats stats{};

    if (!dco_initialized_ || genl_family_id_ == 0)
    {
        logger_->debug("DCO SnapshotStats: skipped (init={} fam={})",
                       dco_initialized_,
                       genl_family_id_);
        return stats;
    }

    // Open a temporary netlink socket — the member socket may be busy
    // with the multicast keepalive monitor.
    NetlinkHelper nl;
    nl.Open(NETLINK_GENERIC);

    std::uint16_t fam = nl.ResolveFamilyId(OVPN_NL_NAME);
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
    std::size_t offset = 0;
    constexpr std::size_t kAttrsCap = sizeof(req.attrs);

    {
        std::uint32_t ifidx = static_cast<std::uint32_t>(dco_ifindex_);
        if (!NlaPut(buf, offset, kAttrsCap, OVPN_ATTR_IFINDEX, &ifidx, sizeof(ifidx)))
        {
            logger_->warn("DCO SnapshotStats: buffer overflow building request");
            return stats;
        }
    }

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)) + static_cast<decltype(req.nlh.nlmsg_len)>(offset);

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

        auto remaining_opt = clv::checked_cast<int>(len);
        if (!remaining_opt)
        {
            logger_->warn("DCO SnapshotStats: recv length out of range ({})", len);
            break;
        }
        int remaining = *remaining_opt;

        for (auto *nlh = reinterpret_cast<struct nlmsghdr *>(rbuf.data());
             NLMSG_OK(nlh, remaining);
             nlh = NLMSG_NEXT(nlh, remaining))
        {
            if (nlh->nlmsg_type == NLMSG_DONE)
            {
                done = true;
                break;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR)
            {
                if (NLMSG_PAYLOAD(nlh, 0) < static_cast<int>(sizeof(struct nlmsgerr)))
                {
                    logger_->warn("DCO SnapshotStats: malformed NLMSG_ERROR payload");
                    done = true;
                    break;
                }

                auto *err = static_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
                if (err->error != 0)
                    logger_->warn("DCO SnapshotStats: kernel error {}",
                                  std::strerror(-err->error));
                done = true;
                break;
            }

            if (NLMSG_PAYLOAD(nlh, 0) < static_cast<int>(sizeof(struct genlmsghdr)))
            {
                logger_->debug("DCO SnapshotStats: short generic netlink payload");
                continue;
            }

            auto *genlh = static_cast<struct genlmsghdr *>(NLMSG_DATA(nlh));
            auto *attr = reinterpret_cast<struct nlattr *>(
                reinterpret_cast<char *>(genlh) + GENL_HDRLEN);
            int attrlen = NLMSG_PAYLOAD(nlh, sizeof(struct genlmsghdr));

            while (NLA_OK(attr, attrlen))
            {
                if ((attr->nla_type & ~NLA_F_NESTED) == OVPN_ATTR_GET_PEER)
                {
                    auto *inner = reinterpret_cast<struct nlattr *>(NLA_DATA(attr));
                    int innerlen = attr->nla_len - NLA_HDRLEN;
                    bool malformed_peer = false;

                    while (NLA_OK(inner, innerlen))
                    {
                        switch (inner->nla_type)
                        {
                        case OVPN_GET_PEER_RESP_ATTR_LINK_RX_BYTES:
                            {
                                std::uint64_t bytes_rx = 0;
                                if (NlaReadScalar(inner, bytes_rx))
                                    stats.bytesReceived += bytes_rx;
                                else
                                {
                                    logger_->warn("DCO SnapshotStats: malformed RX_BYTES attr payload");
                                    malformed_peer = true;
                                }
                                break;
                            }
                        case OVPN_GET_PEER_RESP_ATTR_LINK_TX_BYTES:
                            {
                                std::uint64_t bytes_tx = 0;
                                if (NlaReadScalar(inner, bytes_tx))
                                    stats.bytesSent += bytes_tx;
                                else
                                {
                                    logger_->warn("DCO SnapshotStats: malformed TX_BYTES attr payload");
                                    malformed_peer = true;
                                }
                                break;
                            }
                        case OVPN_GET_PEER_RESP_ATTR_VPN_RX_PACKETS:
                            {
                                std::uint32_t pkts_raw = 0;
                                if (!NlaReadScalar(inner, pkts_raw))
                                {
                                    logger_->warn("DCO SnapshotStats: malformed VPN_RX_PACKETS attr payload");
                                    malformed_peer = true;
                                    break;
                                }
                                auto pkts = static_cast<std::uint64_t>(pkts_raw);
                                stats.packetsReceived += pkts;
                                stats.packetsDecrypted += pkts;
                                stats.tunWrites += pkts;
                                break;
                            }
                        case OVPN_GET_PEER_RESP_ATTR_VPN_TX_PACKETS:
                            {
                                std::uint32_t pkts_raw = 0;
                                if (!NlaReadScalar(inner, pkts_raw))
                                {
                                    logger_->warn("DCO SnapshotStats: malformed VPN_TX_PACKETS attr payload");
                                    malformed_peer = true;
                                    break;
                                }
                                auto pkts = static_cast<std::uint64_t>(pkts_raw);
                                stats.packetsSent += pkts;
                                stats.packetsEncrypted += pkts;
                                stats.tunReads += pkts;
                                break;
                            }
                        default:
                            break;
                        }

                        if (malformed_peer)
                        {
                            done = true;
                            break;
                        }

                        inner = NLA_NEXT(inner, innerlen);
                    }

                    if (done)
                        break;
                }
                attr = NLA_NEXT(attr, attrlen);
            }

            if (done)
                break;
        }
    }

    return stats;
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

bool DcoCoreBase::PushKeysToKernelImpl(std::uint32_t peer_id,
                                       const std::vector<std::uint8_t> &key_material,
                                       openvpn::CipherAlgorithm cipher,
                                       std::uint8_t key_id,
                                       std::uint8_t key_slot,
                                       openvpn::PeerRole role)
{
    if (!dco_initialized_ || !netlink_helper_.IsOpen())
    {
        logger_->error("DCO: Cannot push keys — not initialized");
        return false;
    }

    return dco::PushKeysToKernel(dco_ifindex_, genl_family_id_, peer_id, key_material, cipher, key_id, key_slot, role, netlink_helper_, *logger_);
}

bool DcoCoreBase::SwapKeysImpl(std::uint32_t peer_id)
{
    if (!dco_initialized_ || !netlink_helper_.IsOpen())
    {
        logger_->error("DCO: Cannot swap keys — not initialized");
        return false;
    }

    return dco::SwapDcoKeys(dco_ifindex_, genl_family_id_, peer_id, netlink_helper_, *logger_);
}

bool DcoCoreBase::SetPeerKeepaliveImpl(std::uint32_t peer_id,
                                       std::uint32_t interval,
                                       std::uint32_t timeout)
{
    if (!dco_initialized_ || !netlink_helper_.IsOpen())
    {
        logger_->error("DCO: Cannot set peer keepalive — not initialized");
        return false;
    }

    return dco::SetDcoPeerKeepalive(dco_ifindex_, genl_family_id_, peer_id, interval, timeout, netlink_helper_, *logger_);
}

// ---------------------------------------------------------------------------
// Peer CRUD
// ---------------------------------------------------------------------------

bool DcoCoreBase::CreatePeerImpl(std::uint32_t peer_id,
                                 const transport::PeerEndpoint &remote,
                                 int socket_fd,
                                 std::optional<std::uint32_t> vpn_ipv4,
                                 const std::uint8_t *vpn_ipv6)
{
    if (!dco_initialized_ || !netlink_helper_.IsOpen())
    {
        logger_->error("DCO: Cannot create peer — not initialized");
        return false;
    }

    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        char attrs[512];
    } req{};

    req.nlh.nlmsg_type = genl_family_id_;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.genlh.cmd = OVPN_CMD_NEW_PEER;
    req.genlh.version = 0;

    char *buf = req.attrs;
    std::size_t offset = 0;
    constexpr std::size_t kCap = sizeof(req.attrs);

    // OVPN_ATTR_IFINDEX
    {
        std::uint32_t ifidx = static_cast<std::uint32_t>(dco_ifindex_);
        if (!NlaPut(buf, offset, kCap, OVPN_ATTR_IFINDEX, &ifidx, sizeof(ifidx)))
        {
            logger_->error("DCO: Buffer overflow in OVPN_CMD_NEW_PEER");
            return false;
        }
    }

    // OVPN_ATTR_NEW_PEER (nested)
    std::size_t peer_start = offset;
    struct nlattr *peer_attr = NlaBeginNested(buf, offset, kCap, OVPN_ATTR_NEW_PEER);
    if (!peer_attr)
    {
        logger_->error("DCO: Buffer overflow in OVPN_CMD_NEW_PEER");
        return false;
    }

    if (!NlaPut(buf, offset, kCap, OVPN_NEW_PEER_ATTR_PEER_ID, &peer_id, sizeof(peer_id)))
    {
        logger_->error("DCO: Buffer overflow in OVPN_CMD_NEW_PEER");
        return false;
    }

    // Remote address (v4 or v6)
    if (remote.addr.is_v4())
    {
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(remote.port);
        sa.sin_addr.s_addr = htonl(remote.addr.to_v4().to_uint());
        if (!NlaPut(buf, offset, kCap, OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE, &sa, sizeof(sa)))
        {
            logger_->error("DCO: Buffer overflow in OVPN_CMD_NEW_PEER");
            return false;
        }
    }
    else
    {
        struct sockaddr_in6 sa6{};
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons(remote.port);
        auto v6bytes = remote.addr.to_v6().to_bytes();
        std::memcpy(&sa6.sin6_addr, v6bytes.data(), 16);
        if (!NlaPut(buf, offset, kCap, OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE, &sa6, sizeof(sa6)))
        {
            logger_->error("DCO: Buffer overflow in OVPN_CMD_NEW_PEER");
            return false;
        }
    }

    // Socket FD
    {
        std::uint32_t sockfd = static_cast<std::uint32_t>(socket_fd);
        if (!NlaPut(buf, offset, kCap, OVPN_NEW_PEER_ATTR_SOCKET, &sockfd, sizeof(sockfd)))
        {
            logger_->error("DCO: Buffer overflow in OVPN_CMD_NEW_PEER");
            return false;
        }
    }

    // Optional VPN IPv4 (network byte order)
    if (vpn_ipv4)
    {
        std::uint32_t ip = *vpn_ipv4;
        if (!NlaPut(buf, offset, kCap, OVPN_NEW_PEER_ATTR_IPV4, &ip, sizeof(ip)))
        {
            logger_->error("DCO: Buffer overflow in OVPN_CMD_NEW_PEER");
            return false;
        }
    }

    // Optional VPN IPv6 (16 bytes, network byte order)
    if (vpn_ipv6)
    {
        if (!NlaPut(buf, offset, kCap, OVPN_NEW_PEER_ATTR_IPV6, vpn_ipv6, 16))
        {
            logger_->error("DCO: Buffer overflow in OVPN_CMD_NEW_PEER");
            return false;
        }
    }

    peer_attr->nla_len = static_cast<decltype(peer_attr->nla_len)>(offset - peer_start);
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)) + static_cast<decltype(req.nlh.nlmsg_len)>(offset);

    std::vector<std::uint8_t> response;
    if (!netlink_helper_.SendAndReceive(&req.nlh, req.nlh.nlmsg_len, response))
    {
        logger_->error("DCO: Failed to send/receive OVPN_CMD_NEW_PEER");
        return false;
    }

    if (!dco::detail::CheckGenlResponse(response, "OVPN_CMD_NEW_PEER", *logger_))
        return false;

    logger_->info("DCO: Peer {} created (remote={}:{})",
                  peer_id,
                  remote.addr.to_string(),
                  remote.port);
    return true;
}

void DcoCoreBase::RemovePeerImpl(std::uint32_t peer_id)
{
    if (!dco_initialized_ || !netlink_helper_.IsOpen())
        return;

    logger_->debug("DCO: Removing peer {}", peer_id);

    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        char attrs[128];
    } req{};

    req.nlh.nlmsg_type = genl_family_id_;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.genlh.cmd = OVPN_CMD_DEL_PEER;
    req.genlh.version = 0;

    char *buf = req.attrs;
    std::size_t offset = 0;
    constexpr std::size_t kCap = sizeof(req.attrs);

    {
        std::uint32_t ifidx = static_cast<std::uint32_t>(dco_ifindex_);
        if (!NlaPut(buf, offset, kCap, OVPN_ATTR_IFINDEX, &ifidx, sizeof(ifidx)))
            return;
    }

    std::size_t del_start = offset;
    struct nlattr *del_attr = NlaBeginNested(buf, offset, kCap, OVPN_ATTR_DEL_PEER);
    if (!del_attr)
        return;

    if (!NlaPut(buf, offset, kCap, OVPN_DEL_PEER_ATTR_PEER_ID, &peer_id, sizeof(peer_id)))
        return;

    del_attr->nla_len = static_cast<decltype(del_attr->nla_len)>(offset - del_start);
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)) + static_cast<decltype(req.nlh.nlmsg_len)>(offset);

    // Best effort — don't check response
    std::vector<std::uint8_t> response;
    netlink_helper_.SendAndReceive(&req.nlh, req.nlh.nlmsg_len, response);

    logger_->debug("DCO: Peer {} removal requested", peer_id);
}

} // namespace clv::vpn
