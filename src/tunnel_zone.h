// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TUNNEL_ZONE_H
#define CLV_VPN_TUNNEL_ZONE_H

#include "scoped_c2c_isolation.h"
#include "scoped_masquerade.h"
#include "scoped_proc_toggle.h"
#include "traffic_policy.h"

#include <mutex_type.h>
#include <spdlog/logger.h>

#include <cstddef>
#include <optional>
#include <string>
#include <unordered_map>

namespace clv::vpn {

/**
 * @brief Per-process traffic-policy controller for tunnel attachments.
 *
 * Owns hub/link attachment registry and kernel policy guards (masquerade and
 * intra-pool nft isolation when client_to_client=false). VpnServer::Start
 * calls EnsureTransitRouting() when ZonePolicy::ip_forward is set.
 */
class TunnelZone
{
  public:
    /**
     * @brief Construct a zone with the given traffic policy.
     * @param policy Masquerade, C2C isolation, and forwarding rules
     * @param logger Logger for kernel policy installation events
     * @param install_kernel_policy When false, skip nft/masquerade (testing)
     */
    explicit TunnelZone(ZonePolicy policy,
                        spdlog::logger &logger,
                        bool install_kernel_policy = true);

    TunnelZone(const TunnelZone &) = delete;
    TunnelZone &operator=(const TunnelZone &) = delete;
    TunnelZone(TunnelZone &&) = delete;
    TunnelZone &operator=(TunnelZone &&) = delete;

    /**
     * @brief Register a hub TUN attachment and install per-hub kernel policy.
     * @param spec Hub device name, tunnel pools, and attachment metadata
     */
    void RegisterHubAttachment(HubAttachmentSpec spec);

    /**
     * @brief Remove a hub attachment and tear down its kernel policy guards.
     * @param data_dev Hub TUN device name previously passed to RegisterHubAttachment
     */
    void UnregisterHubAttachment(const std::string &data_dev);

    /**
     * @brief Enable process-level IPv4/IPv6 forwarding per ZonePolicy::ip_forward.
     *
     * Called by VpnServer::Start when transit routing is required.
     */
    void EnsureTransitRouting();

    /**
     * @brief Active zone traffic policy.
     * @return Policy supplied at construction
     */
    ZonePolicy Policy() const noexcept
    {
        return policy_;
    }

    /**
     * @brief Number of registered hub attachments.
     * @return Count of active hub TUN devices
     */
    std::size_t HubAttachmentCount() const;

    /**
     * @brief Whether a hub attachment is registered for the given device.
     * @param data_dev Hub TUN device name
     * @return true if the device is registered
     */
    bool HasHubAttachment(const std::string &data_dev) const;

    /**
     * @brief Look up a registered hub attachment by device name.
     * @param data_dev Hub TUN device name
     * @return Attachment spec, or nullopt if not registered
     */
    std::optional<HubAttachmentSpec> FindHubAttachment(const std::string &data_dev) const;

  private:
    template <typename Guard>
    struct PerFamilyGuards
    {
        std::optional<Guard> v4;
        std::optional<Guard> v6;

        template <typename F>
        void Emplace(const TunnelPool &pool_v4,
                     const std::optional<TunnelPool> &pool_v6,
                     F &&factory)
        {
            v4.emplace(factory(pool_v4));
            if (pool_v6)
                v6.emplace(factory(*pool_v6));
        }
    };

    struct HubAttachmentState
    {
        HubAttachmentSpec spec;
        PerFamilyGuards<ScopedMasquerade> masquerade;
        PerFamilyGuards<ScopedNftIntraPoolDrop> c2c_isolation;
    };

    void InstallHubKernelPolicy(HubAttachmentState &state);

    ZonePolicy policy_;
    spdlog::logger &logger_;
    bool install_kernel_policy_;
    bool transit_routing_engaged_ = false;
    std::optional<ScopedIpForward> ip_forward_guard_;
    std::optional<ScopedIpv6Forward> ip6_forward_guard_;
    clv::UniqueMutexType<std::unordered_map<std::string, HubAttachmentState>> hubs_;
};

} // namespace clv::vpn

#endif // CLV_VPN_TUNNEL_ZONE_H
