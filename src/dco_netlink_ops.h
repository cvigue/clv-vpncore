// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_DCO_NETLINK_OPS_H
#define CLV_VPN_DCO_NETLINK_OPS_H

/**
 * @file dco_netlink_ops.h
 * @brief Shared DCO netlink operations used by both VpnClient and DcoDataChannel.
 *
 * Each function builds a single netlink message, sends it via NetlinkHelper or
 * rtnetlink, and parses the kernel ACK.  Parameters are all primitives so there
 * is no coupling to VpnClient/VpnServer/DcoDataChannel types.
 *
 * Covers factoring items F10–F15 from goals-plan.md §6.
 */

#include "openvpn/crypto_algorithms.h"
#include "openvpn/key_derivation.h" // PeerRole
#include "openvpn/ovpn_dco.h"
#include "util/nla_helpers.h"
#include <util/netlink_helper.h>
#include <unique_fd.h>

#include <cstdint>
#include <cstring>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <string>
#include <vector>

#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

namespace clv::vpn::dco {

// ---------------------------------------------------------------------------
// Internal helper: check a generic-netlink ACK response for errors.
// ---------------------------------------------------------------------------
namespace detail {

/** @brief Parse a genl response buffer for NLMSG_ERROR.
 *  @return true if the response indicates success (error == 0 or no error msg).
 */
inline bool CheckGenlResponse(const std::vector<uint8_t> &response,
                              const char *op_name,
                              spdlog::logger &logger)
{
    auto *nlh = reinterpret_cast<const struct nlmsghdr *>(response.data());
    if (nlh->nlmsg_type == NLMSG_ERROR)
    {
        auto *err = reinterpret_cast<const struct nlmsgerr *>(NLMSG_DATA(nlh));
        if (err->error != 0)
        {
            logger.error("DCO: {} failed: {} ({})", op_name, std::strerror(-err->error), err->error);
            return false;
        }
    }
    return true;
}

} // namespace detail

/**
 * @brief Create an ovpn-dco netdevice via RTM_NEWLINK.
 * @param ifname   Desired interface name (e.g. "ovpn0")
 * @param ovpn_mode OVPN_MODE_P2P or OVPN_MODE_MP
 * @param logger   Logger for diagnostics
 * @throws std::runtime_error on buffer overflow or netlink failure
 */
inline void CreateDcoDevice(const std::string &ifname,
                            uint8_t ovpn_mode,
                            spdlog::logger &logger)
{
    logger.debug("DCO: Creating device {} (mode={})", ifname, ovpn_mode == OVPN_MODE_P2P ? "P2P" : "MP");

    auto sock = NetlinkHelper::CreateRtnetlinkSocket();

    struct
    {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
        char buf[256];
    } req{};

    req.nlh.nlmsg_type = RTM_NEWLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    req.nlh.nlmsg_seq = 1;
    req.ifi.ifi_family = AF_UNSPEC;

    char *buf = req.buf;
    size_t remaining = sizeof(req.buf);

    // IFLA_IFNAME
    size_t name_len = ifname.length() + 1;
    size_t name_attr_len = RTA_LENGTH(name_len);
    if (name_attr_len > remaining)
        throw std::runtime_error("DCO: Buffer too small for IFLA_IFNAME");
    auto *rta_name = reinterpret_cast<struct rtattr *>(buf);
    rta_name->rta_type = IFLA_IFNAME;
    rta_name->rta_len = static_cast<unsigned short>(name_attr_len);
    std::memcpy(RTA_DATA(rta_name), ifname.c_str(), name_len);
    buf += RTA_ALIGN(name_attr_len);
    remaining -= RTA_ALIGN(name_attr_len);

    // IFLA_LINKINFO (nested)
    auto *rta_linkinfo = reinterpret_cast<struct rtattr *>(buf);
    rta_linkinfo->rta_type = IFLA_LINKINFO;
    char *linkinfo_start = buf;
    buf += RTA_LENGTH(0);
    remaining -= RTA_LENGTH(0);

    // IFLA_INFO_KIND = "ovpn-dco"
    const char *kind = "ovpn-dco";
    size_t kind_len = std::strlen(kind) + 1;
    size_t kind_attr_len = RTA_LENGTH(kind_len);
    if (kind_attr_len > remaining)
        throw std::runtime_error("DCO: Buffer too small for IFLA_INFO_KIND");
    auto *rta_kind = reinterpret_cast<struct rtattr *>(buf);
    rta_kind->rta_type = IFLA_INFO_KIND;
    rta_kind->rta_len = static_cast<unsigned short>(kind_attr_len);
    std::memcpy(RTA_DATA(rta_kind), kind, kind_len);
    buf += RTA_ALIGN(kind_attr_len);
    remaining -= RTA_ALIGN(kind_attr_len);

    // IFLA_INFO_DATA → IFLA_OVPN_MODE
    auto *rta_infodata = reinterpret_cast<struct rtattr *>(buf);
    rta_infodata->rta_type = IFLA_INFO_DATA;
    char *infodata_start = buf;
    buf += RTA_LENGTH(0);
    remaining -= RTA_LENGTH(0);

    {
        size_t mode_attr_len = RTA_LENGTH(sizeof(uint8_t));
        if (mode_attr_len > remaining)
            throw std::runtime_error("DCO: Buffer too small for IFLA_OVPN_MODE");
        auto *rta_mode = reinterpret_cast<struct rtattr *>(buf);
        rta_mode->rta_type = IFLA_OVPN_MODE;
        rta_mode->rta_len = static_cast<unsigned short>(mode_attr_len);
        *static_cast<uint8_t *>(RTA_DATA(rta_mode)) = ovpn_mode;
        buf += RTA_ALIGN(mode_attr_len);
        remaining -= RTA_ALIGN(mode_attr_len);
    }

    rta_infodata->rta_len = static_cast<unsigned short>(buf - infodata_start);
    rta_linkinfo->rta_len = static_cast<unsigned short>(buf - linkinfo_start);
    req.nlh.nlmsg_len = static_cast<decltype(req.nlh.nlmsg_len)>(buf - reinterpret_cast<char *>(&req));

    NetlinkHelper::SendNetlinkMessage(sock.get(), &req, req.nlh.nlmsg_len, "RTM_NEWLINK");
    NetlinkHelper::ReceiveNetlinkAck(sock.get(), "RTM_NEWLINK");

    logger.info("DCO: Device {} created successfully", ifname);
}

/**
 * @brief Destroy an ovpn-dco netdevice via RTM_DELLINK.
 * @param ifindex  Interface index (from SIOCGIFINDEX).  No-op if < 0.
 * @param ifname   Interface name (for logging only)
 * @param logger   Logger for diagnostics
 */
inline void DestroyDcoDevice(int ifindex,
                             const std::string &ifname,
                             spdlog::logger &logger)
{
    if (ifindex < 0)
        return;

    logger.debug("DCO: Destroying device {} (ifindex={})", ifname, ifindex);

    try
    {
        auto sock = NetlinkHelper::CreateRtnetlinkSocket();

        struct
        {
            struct nlmsghdr nlh;
            struct ifinfomsg ifi;
        } req{};

        req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
        req.nlh.nlmsg_type = RTM_DELLINK;
        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        req.nlh.nlmsg_seq = 1;
        req.ifi.ifi_family = AF_UNSPEC;
        req.ifi.ifi_index = ifindex;

        NetlinkHelper::SendNetlinkMessage(sock.get(), &req, req.nlh.nlmsg_len, "RTM_DELLINK");
        NetlinkHelper::ReceiveNetlinkAck(sock.get(), "RTM_DELLINK");

        logger.info("DCO: Device {} destroyed successfully", ifname);
    }
    catch (const std::exception &e)
    {
        logger.warn("DCO: Failed to destroy device {}: {}", ifname, e.what());
    }
}

/**
 * @brief Push encryption/decryption keys to the DCO kernel module.
 * @param ifindex       Interface index
 * @param family_id     Generic netlink family ID for ovpn-dco
 * @param peer_id       Peer ID in the kernel
 * @param key_material  OpenVPN key2 material (>= 256 bytes)
 * @param cipher_algo   Cipher algorithm
 * @param key_id        Key generation ID (0-7)
 * @param key_slot      OVPN_KEY_SLOT_PRIMARY or OVPN_KEY_SLOT_SECONDARY
 * @param role          PeerRole::Server or PeerRole::Client — determines
 *                      which half of key2 is encrypt vs decrypt
 * @param nl            Open NetlinkHelper for genl messaging
 * @param logger        Logger for diagnostics
 * @return true on success
 */
inline bool PushKeysToKernel(int ifindex,
                             uint16_t family_id,
                             uint32_t peer_id,
                             const std::vector<uint8_t> &key_material,
                             openvpn::CipherAlgorithm cipher_algo,
                             uint8_t key_id,
                             uint8_t key_slot,
                             openvpn::PeerRole role,
                             NetlinkHelper &nl,
                             spdlog::logger &logger)
{
    if (key_material.size() < 256)
    {
        logger.error("DCO: Key material too small ({} bytes, need 256)", key_material.size());
        return false;
    }

    // Determine DCO cipher constant and key size
    uint16_t dco_cipher_alg;
    size_t cipher_key_size;

    switch (cipher_algo)
    {
    case openvpn::CipherAlgorithm::AES_128_GCM:
        dco_cipher_alg = OVPN_CIPHER_ALG_AES_GCM;
        cipher_key_size = 16;
        break;
    case openvpn::CipherAlgorithm::AES_256_GCM:
        dco_cipher_alg = OVPN_CIPHER_ALG_AES_GCM;
        cipher_key_size = 32;
        break;
    case openvpn::CipherAlgorithm::CHACHA20_POLY1305:
        dco_cipher_alg = OVPN_CIPHER_ALG_CHACHA20_POLY1305;
        cipher_key_size = 32;
        break;
    default:
        logger.error("DCO: Unsupported cipher for DCO");
        return false;
    }

    // OpenVPN key2 layout (256 bytes):
    //   offset   0: keys[0] = client→server  (128 bytes)
    //   offset 128: keys[1] = server→client  (128 bytes)
    // Within each 128-byte block: bytes 0-63 cipher key area, byte 64+ nonce tail.
    //
    // Server: encrypt = keys[1] (server→client), decrypt = keys[0] (client→server)
    // Client: encrypt = keys[0] (client→server), decrypt = keys[1] (server→client)
    const uint8_t *encrypt_key;
    const uint8_t *decrypt_key;
    const uint8_t *encrypt_nonce_tail;
    const uint8_t *decrypt_nonce_tail;

    if (role == openvpn::PeerRole::Server)
    {
        encrypt_key = key_material.data() + 128; // server→client
        decrypt_key = key_material.data();       // client→server
    }
    else
    {
        encrypt_key = key_material.data();       // client→server
        decrypt_key = key_material.data() + 128; // server→client
    }
    encrypt_nonce_tail = encrypt_key + 64;
    decrypt_nonce_tail = decrypt_key + 64;

    logger.debug("DCO: Pushing keys (peer={}, cipher={}, key_size={}, key_id={}, slot={})",
                 peer_id,
                 dco_cipher_alg,
                 cipher_key_size,
                 key_id,
                 key_slot == OVPN_KEY_SLOT_PRIMARY ? "PRIMARY" : "SECONDARY");

    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        char attrs[1024];
    } req{};

    req.nlh.nlmsg_type = family_id;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.genlh.cmd = OVPN_CMD_NEW_KEY;
    req.genlh.version = 0;

    char *buf = req.attrs;
    size_t offset = 0;
    constexpr size_t kAttrsCap = sizeof(req.attrs);

    // OVPN_ATTR_IFINDEX
    {
        uint32_t ifidx = static_cast<uint32_t>(ifindex);
        NlaPut(buf, offset, kAttrsCap, OVPN_ATTR_IFINDEX, &ifidx, sizeof(ifidx));
    }

    // OVPN_ATTR_NEW_KEY (nested)
    size_t new_key_start = offset;
    struct nlattr *new_key_attr = NlaBeginNested(buf, offset, kAttrsCap, OVPN_ATTR_NEW_KEY);
    if (!new_key_attr)
    {
        logger.error("DCO: Buffer overflow in OVPN_CMD_NEW_KEY");
        return false;
    }

    NlaPut(buf, offset, kAttrsCap, OVPN_NEW_KEY_ATTR_PEER_ID, &peer_id, sizeof(peer_id));
    NlaPut(buf, offset, kAttrsCap, OVPN_NEW_KEY_ATTR_KEY_SLOT, &key_slot, sizeof(key_slot));
    NlaPut(buf, offset, kAttrsCap, OVPN_NEW_KEY_ATTR_KEY_ID, &key_id, sizeof(key_id));
    NlaPut(buf, offset, kAttrsCap, OVPN_NEW_KEY_ATTR_CIPHER_ALG, &dco_cipher_alg, sizeof(dco_cipher_alg));

    // ENCRYPT_KEY (nested)
    {
        size_t ek_start = offset;
        struct nlattr *ek = NlaBeginNested(buf, offset, kAttrsCap, OVPN_NEW_KEY_ATTR_ENCRYPT_KEY);
        if (!ek)
            return false;
        NlaPut(buf, offset, kAttrsCap, OVPN_KEY_DIR_ATTR_CIPHER_KEY, encrypt_key, cipher_key_size);
        NlaPut(buf, offset, kAttrsCap, OVPN_KEY_DIR_ATTR_NONCE_TAIL, encrypt_nonce_tail, 8);
        ek->nla_len = static_cast<decltype(ek->nla_len)>(offset - ek_start);
    }

    // DECRYPT_KEY (nested)
    {
        size_t dk_start = offset;
        struct nlattr *dk = NlaBeginNested(buf, offset, kAttrsCap, OVPN_NEW_KEY_ATTR_DECRYPT_KEY);
        if (!dk)
            return false;
        NlaPut(buf, offset, kAttrsCap, OVPN_KEY_DIR_ATTR_CIPHER_KEY, decrypt_key, cipher_key_size);
        NlaPut(buf, offset, kAttrsCap, OVPN_KEY_DIR_ATTR_NONCE_TAIL, decrypt_nonce_tail, 8);
        dk->nla_len = static_cast<decltype(dk->nla_len)>(offset - dk_start);
    }

    new_key_attr->nla_len = static_cast<decltype(new_key_attr->nla_len)>(offset - new_key_start);
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)) + static_cast<decltype(req.nlh.nlmsg_len)>(offset);

    std::vector<uint8_t> response;
    if (!nl.SendAndReceive(&req.nlh, req.nlh.nlmsg_len, response))
    {
        logger.error("DCO: Failed to send/receive OVPN_CMD_NEW_KEY");
        return false;
    }

    if (!detail::CheckGenlResponse(response, "OVPN_CMD_NEW_KEY", logger))
        return false;

    logger.info("DCO: Keys pushed successfully (peer={}, key_id={})", peer_id, key_id);
    return true;
}

/**
 * @brief Ask the kernel to swap primary ↔ secondary key slots for a peer.
 * @param ifindex    Interface index
 * @param family_id  Generic netlink family ID
 * @param peer_id    Peer ID
 * @param nl         Open NetlinkHelper
 * @param logger     Logger for diagnostics
 * @return true on success
 */
inline bool SwapDcoKeys(int ifindex,
                        uint16_t family_id,
                        uint32_t peer_id,
                        NetlinkHelper &nl,
                        spdlog::logger &logger)
{
    logger.debug("DCO: Swapping keys for peer {}", peer_id);

    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        char attrs[64];
    } req{};

    req.nlh.nlmsg_type = family_id;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.genlh.cmd = OVPN_CMD_SWAP_KEYS;
    req.genlh.version = 0;

    char *buf = req.attrs;
    size_t offset = 0;
    constexpr size_t kAttrsCap = sizeof(req.attrs);

    {
        uint32_t ifidx = static_cast<uint32_t>(ifindex);
        NlaPut(buf, offset, kAttrsCap, OVPN_ATTR_IFINDEX, &ifidx, sizeof(ifidx));
    }

    size_t swap_start = offset;
    struct nlattr *swap_attr = NlaBeginNested(buf, offset, kAttrsCap, OVPN_ATTR_SWAP_KEYS);
    if (!swap_attr)
        return false;
    NlaPut(buf, offset, kAttrsCap, OVPN_SWAP_KEYS_ATTR_PEER_ID, &peer_id, sizeof(peer_id));
    swap_attr->nla_len = static_cast<decltype(swap_attr->nla_len)>(offset - swap_start);
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)) + static_cast<decltype(req.nlh.nlmsg_len)>(offset);

    std::vector<uint8_t> response;
    if (!nl.SendAndReceive(&req.nlh, req.nlh.nlmsg_len, response))
    {
        logger.error("DCO: Failed to send/receive OVPN_CMD_SWAP_KEYS");
        return false;
    }

    if (!detail::CheckGenlResponse(response, "OVPN_CMD_SWAP_KEYS", logger))
        return false;

    logger.info("DCO: Keys swapped for peer {}", peer_id);
    return true;
}

/**
 * @brief Configure keepalive timers for a DCO peer in the kernel.
 * @param ifindex    Interface index
 * @param family_id  Generic netlink family ID
 * @param peer_id    Peer ID
 * @param interval   Keepalive send interval (seconds)
 * @param timeout    Keepalive receive timeout (seconds)
 * @param nl         Open NetlinkHelper
 * @param logger     Logger for diagnostics
 * @return true on success
 */
inline bool SetDcoPeerKeepalive(int ifindex,
                                uint16_t family_id,
                                uint32_t peer_id,
                                uint32_t interval,
                                uint32_t timeout,
                                NetlinkHelper &nl,
                                spdlog::logger &logger)
{
    logger.debug("DCO: Setting keepalive for peer {} (interval={}s, timeout={}s)",
                 peer_id,
                 interval,
                 timeout);

    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        char attrs[128];
    } req{};

    req.nlh.nlmsg_type = family_id;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.genlh.cmd = OVPN_CMD_SET_PEER;
    req.genlh.version = 0;

    char *buf = req.attrs;
    size_t offset = 0;
    constexpr size_t kAttrsCap = sizeof(req.attrs);

    {
        uint32_t ifidx = static_cast<uint32_t>(ifindex);
        NlaPut(buf, offset, kAttrsCap, OVPN_ATTR_IFINDEX, &ifidx, sizeof(ifidx));
    }

    size_t set_start = offset;
    struct nlattr *set_attr = NlaBeginNested(buf, offset, kAttrsCap, OVPN_ATTR_SET_PEER);
    if (!set_attr)
        return false;
    NlaPut(buf, offset, kAttrsCap, OVPN_SET_PEER_ATTR_PEER_ID, &peer_id, sizeof(peer_id));
    NlaPut(buf, offset, kAttrsCap, OVPN_SET_PEER_ATTR_KEEPALIVE_INTERVAL, &interval, sizeof(interval));
    NlaPut(buf, offset, kAttrsCap, OVPN_SET_PEER_ATTR_KEEPALIVE_TIMEOUT, &timeout, sizeof(timeout));
    set_attr->nla_len = static_cast<decltype(set_attr->nla_len)>(offset - set_start);
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr)) + static_cast<decltype(req.nlh.nlmsg_len)>(offset);

    std::vector<uint8_t> response;
    if (!nl.SendAndReceive(&req.nlh, req.nlh.nlmsg_len, response))
    {
        logger.error("DCO: Failed to send/receive OVPN_CMD_SET_PEER");
        return false;
    }

    if (!detail::CheckGenlResponse(response, "OVPN_CMD_SET_PEER", logger))
        return false;

    logger.info("DCO: Keepalive configured for peer {} (interval={}s, timeout={}s)",
                peer_id,
                interval,
                timeout);
    return true;
}

} // namespace clv::vpn::dco

#endif // CLV_VPN_DCO_NETLINK_OPS_H
