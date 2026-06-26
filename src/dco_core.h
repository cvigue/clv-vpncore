// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_DCO_CORE_H
#define CLV_VPN_DCO_CORE_H

/**
 * @file dco_core.h
 * @brief Shared DCO kernel interaction — device lifecycle, key management, peer CRUD, stats.
 *
 * DcoCoreBase holds the netlink state and provides the primitive operations
 * that all DCO channel variants (client P2P, server MP) share.  DcoCore<Derived>
 * is a thin CRTP shell so that mixin subclasses can dispatch downward.
 *
 * All methods are protected; only role-specific mixins (DcoClientDataMixin,
 * DcoServerDataMixin) and the final composed channel classes inherit from this.
 */

#include "data_path_stats.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/key_derivation.h" // PeerRole
#include "transport/transport.h"

#include <not_null.h>
#include <util/netlink_helper.h>

#include <asio/io_context.hpp>

#include <spdlog/logger.h>

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace clv::vpn {

using clv::netlink::NetlinkHelper;

/**
 * @brief Non-template base providing shared DCO netlink operations.
 *
 * Owns the netlink socket, device index and generic-netlink family ID.
 * Subclasses call the protected *Impl methods for all kernel interactions.
 */
class DcoCoreBase
{
  protected:
    DcoCoreBase(asio::io_context &io_ctx,
                spdlog::logger &logger,
                std::string ifname,
                const std::atomic<bool> &running);

    ~DcoCoreBase();

    DcoCoreBase(const DcoCoreBase &) = delete;
    DcoCoreBase &operator=(const DcoCoreBase &) = delete;
    DcoCoreBase(DcoCoreBase &&) = delete;
    DcoCoreBase &operator=(DcoCoreBase &&) = delete;

    // -- Device lifecycle ---------------------------------------------------

    /// Create an ovpn-dco device, resolve interface index and netlink family.
    /// @param ovpn_mode  OVPN_MODE_P2P or OVPN_MODE_MP
    void InitializeDcoDevice(std::uint8_t ovpn_mode);

    /// Resolve interface index and open netlink (without creating the device).
    /// Use when the ovpn-dco device already exists (e.g. server restart).
    void InitializeNetlink();

    /// Destroy the ovpn-dco device and reset state.  Safe to call repeatedly.
    void DestroyDcoDevice();

    // -- Stats --------------------------------------------------------------

    /// Query kernel for aggregate per-peer traffic stats (OVPN_CMD_GET_PEER dump).
    DataPathStats SnapshotStatsImpl() const;

    // -- Key management -----------------------------------------------------

    bool PushKeysToKernelImpl(std::uint32_t peer_id,
                              const std::vector<std::uint8_t> &key_material,
                              openvpn::CipherAlgorithm cipher,
                              std::uint8_t key_id,
                              std::uint8_t key_slot,
                              openvpn::PeerRole role);

    bool SwapKeysImpl(std::uint32_t peer_id);

    bool SetPeerKeepaliveImpl(std::uint32_t peer_id,
                              std::uint32_t interval,
                              std::uint32_t timeout);

    // -- Peer CRUD ----------------------------------------------------------

    /// Create a DCO peer via OVPN_CMD_NEW_PEER.
    /// @param vpn_ipv4  VPN IPv4 in network byte order (nullopt = omit).
    /// @param vpn_ipv6  Pointer to 16-byte IPv6 address (nullptr = omit).
    bool CreatePeerImpl(std::uint32_t peer_id,
                        const transport::PeerEndpoint &remote,
                        int socket_fd,
                        std::optional<std::uint32_t> vpn_ipv4 = {},
                        const std::uint8_t *vpn_ipv6 = nullptr);

    /// Remove a DCO peer via OVPN_CMD_DEL_PEER.  Best-effort.
    void RemovePeerImpl(std::uint32_t peer_id);

    // -- Shared state -------------------------------------------------------

    asio::io_context &io_context_;
    clv::not_null<spdlog::logger *> logger_;
    const std::atomic<bool> &running_;

    bool dco_initialized_ = false;
    int dco_ifindex_ = -1;
    std::string dco_ifname_;
    std::uint16_t genl_family_id_ = 0;
    NetlinkHelper netlink_helper_;
};

/**
 * @brief CRTP shell — adds derived() accessor for mixin dispatch.
 */
template <typename Derived>
class DcoCore : public DcoCoreBase
{
  protected:
    using DcoCoreBase::DcoCoreBase;

    Derived &derived() noexcept
    {
        return static_cast<Derived &>(*this);
    }
    const Derived &derived() const noexcept
    {
        return static_cast<const Derived &>(*this);
    }
};

} // namespace clv::vpn

#endif // CLV_VPN_DCO_CORE_H
