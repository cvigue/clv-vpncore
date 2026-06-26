// SPDX-License-Identifier: (GPL-2.0-only WITH Linux-syscall-note) OR MIT
/*
 * OpenVPN data channel accelerator
 * Copyright (C) 2019-2023 OpenVPN, Inc.
 */

#ifndef OVPN_DCO_H_
#define OVPN_DCO_H_

#include <linux/if_link.h>

#define OVPN_NL_NAME "ovpn-dco-v2"
#define OVPN_NL_MULTICAST_GROUP_PEERS "peers"

// Netlink commands
enum ovpn_nl_commands
{
    OVPN_CMD_UNSPEC = 0,
    OVPN_CMD_NEW_PEER,
    OVPN_CMD_SET_PEER,
    OVPN_CMD_DEL_PEER,
    OVPN_CMD_NEW_KEY,
    OVPN_CMD_SWAP_KEYS,
    OVPN_CMD_DEL_KEY,
    OVPN_CMD_GET_PEER,
};

// Cipher algorithms
enum ovpn_cipher_alg
{
    OVPN_CIPHER_ALG_NONE = 0,
    OVPN_CIPHER_ALG_AES_GCM,
    OVPN_CIPHER_ALG_CHACHA20_POLY1305,
};

// Key slots
enum ovpn_key_slot
{
    OVPN_KEY_SLOT_PRIMARY = 0,
    OVPN_KEY_SLOT_SECONDARY,
};

// Top-level attributes
enum ovpn_netlink_attrs
{
    OVPN_ATTR_UNSPEC = 0,
    OVPN_ATTR_IFINDEX,
    OVPN_ATTR_NEW_PEER,
    OVPN_ATTR_SET_PEER,
    OVPN_ATTR_DEL_PEER,
    OVPN_ATTR_NEW_KEY,
    OVPN_ATTR_SWAP_KEYS,
    OVPN_ATTR_DEL_KEY,
    OVPN_ATTR_GET_PEER,
};

// New peer attributes
enum ovpn_netlink_new_peer_attrs
{
    OVPN_NEW_PEER_ATTR_UNSPEC = 0,
    OVPN_NEW_PEER_ATTR_PEER_ID,
    OVPN_NEW_PEER_ATTR_SOCKADDR_REMOTE,
    OVPN_NEW_PEER_ATTR_SOCKET,
    OVPN_NEW_PEER_ATTR_IPV4,
    OVPN_NEW_PEER_ATTR_IPV6,
    OVPN_NEW_PEER_ATTR_LOCAL_IP,
};

// New key attributes
enum ovpn_netlink_new_key_attrs
{
    OVPN_NEW_KEY_ATTR_UNSPEC = 0,
    OVPN_NEW_KEY_ATTR_PEER_ID,
    OVPN_NEW_KEY_ATTR_KEY_SLOT,
    OVPN_NEW_KEY_ATTR_KEY_ID,
    OVPN_NEW_KEY_ATTR_CIPHER_ALG,
    OVPN_NEW_KEY_ATTR_ENCRYPT_KEY,
    OVPN_NEW_KEY_ATTR_DECRYPT_KEY,
};

// Key direction attributes (nested in ENCRYPT_KEY/DECRYPT_KEY)
enum ovpn_netlink_key_dir_attrs
{
    OVPN_KEY_DIR_ATTR_UNSPEC = 0,
    OVPN_KEY_DIR_ATTR_CIPHER_KEY,
    OVPN_KEY_DIR_ATTR_NONCE_TAIL,
};

// Swap keys attributes
enum ovpn_netlink_swap_keys_attrs
{
    OVPN_SWAP_KEYS_ATTR_UNSPEC = 0,
    OVPN_SWAP_KEYS_ATTR_PEER_ID,
};

// Set peer attributes (keepalive timers)
enum ovpn_netlink_set_peer_attrs
{
    OVPN_SET_PEER_ATTR_UNSPEC = 0,
    OVPN_SET_PEER_ATTR_PEER_ID,
    OVPN_SET_PEER_ATTR_KEEPALIVE_INTERVAL,
    OVPN_SET_PEER_ATTR_KEEPALIVE_TIMEOUT,
};

// Get peer request attributes (for OVPN_CMD_GET_PEER query)
enum ovpn_netlink_get_peer_attrs
{
    OVPN_GET_PEER_ATTR_UNSPEC = 0,
    OVPN_GET_PEER_ATTR_PEER_ID, ///< u32 — filter by peer (omit + NLM_F_DUMP for all)
};

// Get peer response attributes (nested inside OVPN_ATTR_GET_PEER)
enum ovpn_netlink_get_peer_resp_attrs
{
    OVPN_GET_PEER_RESP_ATTR_UNSPEC = 0,
    OVPN_GET_PEER_RESP_ATTR_PEER_ID,            ///< u32
    OVPN_GET_PEER_RESP_ATTR_SOCKADDR_REMOTE,    ///< struct sockaddr_storage
    OVPN_GET_PEER_RESP_ATTR_IPV4,               ///< u32
    OVPN_GET_PEER_RESP_ATTR_IPV6,               ///< struct in6_addr
    OVPN_GET_PEER_RESP_ATTR_LOCAL_IP,           ///< u32
    OVPN_GET_PEER_RESP_ATTR_LOCAL_PORT,         ///< u16
    OVPN_GET_PEER_RESP_ATTR_KEEPALIVE_INTERVAL, ///< u32
    OVPN_GET_PEER_RESP_ATTR_KEEPALIVE_TIMEOUT,  ///< u32
    OVPN_GET_PEER_RESP_ATTR_VPN_RX_BYTES,       ///< u64 — plaintext bytes received (after decrypt)
    OVPN_GET_PEER_RESP_ATTR_VPN_TX_BYTES,       ///< u64 — plaintext bytes sent (before encrypt)
    OVPN_GET_PEER_RESP_ATTR_VPN_RX_PACKETS,     ///< u32 — plaintext packets received
    OVPN_GET_PEER_RESP_ATTR_VPN_TX_PACKETS,     ///< u32 — plaintext packets sent
    OVPN_GET_PEER_RESP_ATTR_LINK_RX_BYTES,      ///< u64 — link-level bytes received
    OVPN_GET_PEER_RESP_ATTR_LINK_TX_BYTES,      ///< u64 — link-level bytes sent
    OVPN_GET_PEER_RESP_ATTR_LINK_RX_PACKETS,    ///< u32 — link-level packets received
    OVPN_GET_PEER_RESP_ATTR_LINK_TX_PACKETS,    ///< u32 — link-level packets sent
};

// Delete peer attributes
enum ovpn_netlink_del_peer_attrs
{
    OVPN_DEL_PEER_ATTR_UNSPEC = 0,
    OVPN_DEL_PEER_ATTR_REASON,
    OVPN_DEL_PEER_ATTR_PEER_ID,
};

// Reasons for peer deletion (kernel → userspace notification)
enum ovpn_del_peer_reason
{
    OVPN_DEL_PEER_REASON_TEARDOWN = 0,
    OVPN_DEL_PEER_REASON_USERSPACE,
    OVPN_DEL_PEER_REASON_EXPIRED,
    OVPN_DEL_PEER_REASON_TRANSPORT_ERROR,
    OVPN_DEL_PEER_REASON_TRANSPORT_DISCONNECT,
};

// Device mode (passed via IFLA_INFO_DATA at device creation).
// These were upstreamed into <linux/if_link.h> in kernel 6.12; only define
// them locally when the build-time probe (CMakeLists.txt) determined they are
// absent from the system headers.  A version-number check would break on
// distros that backport the definitions, hence the probe approach.
#ifndef KERNEL_HEADERS_HAVE_OVPN_IFLA
enum
{
    IFLA_OVPN_UNSPEC = 0,
    IFLA_OVPN_MODE,
};

enum ovpn_mode
{
    OVPN_MODE_P2P = 0,
    OVPN_MODE_MP,
};
#endif

#endif // OVPN_DCO_H_
