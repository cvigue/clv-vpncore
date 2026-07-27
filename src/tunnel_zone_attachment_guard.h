// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TUNNEL_ZONE_ATTACHMENT_GUARD_H
#define CLV_VPN_TUNNEL_ZONE_ATTACHMENT_GUARD_H

/**
 * @file tunnel_zone_attachment_guard.h
 * @brief RAII hub attachment for TunnelZone.
 *
 * Owns RegisterHubAttachment / UnregisterHubAttachment for one data_dev.
 * Server UDP/TCP/DCO channels hold a guard and attach after netdev setup;
 * Release() runs before TUN teardown so nft/masquerade cleanup sees the iface.
 */

#include "traffic_policy.h"
#include "tunnel_zone.h"

#include <optional>
#include <string>
#include <utility>

namespace clv::vpn {

class TunnelZoneAttachmentGuard
{
  public:
    TunnelZoneAttachmentGuard() = default;
    ~TunnelZoneAttachmentGuard()
    {
        Release();
    }

    TunnelZoneAttachmentGuard(const TunnelZoneAttachmentGuard &) = delete;
    TunnelZoneAttachmentGuard &operator=(const TunnelZoneAttachmentGuard &) = delete;
    TunnelZoneAttachmentGuard(TunnelZoneAttachmentGuard &&) = delete;
    TunnelZoneAttachmentGuard &operator=(TunnelZoneAttachmentGuard &&) = delete;

    /**
     * Register @p spec on @p zone (no-op if zone is null).
     * Releases any prior attachment first.
     */
    void Reset(TunnelZone *zone, HubAttachmentSpec spec)
    {
        Release();
        if (!zone)
            return;
        std::string ifname = spec.data_dev;
        zone->RegisterHubAttachment(std::move(spec));
        zone_ = zone;
        ifname_ = std::move(ifname);
    }

    /** Unregister if attached; safe to call repeatedly. */
    void Release() noexcept
    {
        if (!zone_ || !ifname_)
            return;
        zone_->UnregisterHubAttachment(*ifname_);
        zone_ = nullptr;
        ifname_.reset();
    }

    [[nodiscard]] bool attached() const noexcept
    {
        return zone_ != nullptr && ifname_.has_value();
    }

    [[nodiscard]] const std::string &data_dev() const
    {
        return *ifname_;
    }

  private:
    TunnelZone *zone_ = nullptr;
    std::optional<std::string> ifname_;
};

} // namespace clv::vpn

#endif // CLV_VPN_TUNNEL_ZONE_ATTACHMENT_GUARD_H
