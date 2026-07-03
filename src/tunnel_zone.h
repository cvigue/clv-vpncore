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
 * intra-pool nft isolation when client_to_client=false).
 */
class TunnelZone
{
  public:
    explicit TunnelZone(ZonePolicy policy,
                        spdlog::logger &logger,
                        bool install_kernel_policy = true);

    TunnelZone(const TunnelZone &) = delete;
    TunnelZone &operator=(const TunnelZone &) = delete;
    TunnelZone(TunnelZone &&) = delete;
    TunnelZone &operator=(TunnelZone &&) = delete;

    void RegisterHubAttachment(HubAttachmentSpec spec);
    void UnregisterHubAttachment(const std::string &data_dev);

    /** Enable process-level IPv4/IPv6 forwarding per @c ZonePolicy::ip_forward. */
    void EnsureTransitRouting();

    ZonePolicy Policy() const noexcept
    {
        return policy_;
    }

    std::size_t HubAttachmentCount() const;
    bool HasHubAttachment(const std::string &data_dev) const;
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
