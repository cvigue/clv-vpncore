// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include "tunnel_zone.h"
#include "scoped_nft_rule.h"
#include "traffic_policy.h"

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace clv::vpn {

TunnelZone::TunnelZone(ZonePolicy policy,
                       spdlog::logger &logger,
                       bool install_kernel_policy)
    : policy_(policy),
      logger_(logger),
      install_kernel_policy_(install_kernel_policy)
{
}

void TunnelZone::EnsureTransitRouting()
{
    if (!install_kernel_policy_ || !policy_.ip_forward || transit_routing_engaged_)
        return;

    ip_forward_guard_.emplace(logger_);
    ip6_forward_guard_.emplace(logger_);
    transit_routing_engaged_ = true;
    logger_.info("Transit routing enabled (ip_forward per zone policy)");
}

void TunnelZone::InstallHubKernelPolicy(HubAttachmentState &state)
{
    if (!install_kernel_policy_)
        return;

    const auto &spec = state.spec;
    if (spec.masquerade)
    {
        state.masquerade.Emplace(
            spec.pool_v4,
            spec.pool_v6,
            [&](const TunnelPool &pool)
        {
            return ScopedMasquerade(pool.cidr, logger_);
        });
    }

    if (!spec.client_to_client)
    {
        state.c2c_isolation.Emplace(
            spec.pool_v4,
            spec.pool_v6,
            [&](const TunnelPool &pool)
        {
            return ScopedNftIntraPoolDrop(spec.data_dev,
                                          pool.cidr,
                                          pool.bridge_ip,
                                          logger_);
        });
    }
}

void TunnelZone::RegisterHubAttachment(HubAttachmentSpec spec)
{
    if (spec.data_dev.empty())
        throw std::invalid_argument("HubAttachmentSpec.data_dev is required");

    const std::string ifname = spec.data_dev;
    auto reg = hubs_.LockRW();

    if (reg->contains(ifname))
        throw std::invalid_argument("Hub attachment already registered: " + ifname);

    auto [it, inserted] = reg->try_emplace(ifname, HubAttachmentState{std::move(spec), {}, {}});
    if (!inserted)
        throw std::logic_error("Failed to register hub attachment: " + ifname);

    InstallHubKernelPolicy(it->second);
    logger_.info("Registered hub attachment on {}", it->second.spec.data_dev);
}

void TunnelZone::UnregisterHubAttachment(const std::string &data_dev)
{
    auto reg = hubs_.LockRW();
    auto it = reg->find(data_dev);
    if (it == reg->end())
        return;

    logger_.info("Unregistering hub attachment on {}", data_dev);
    reg->erase(it);
}

std::size_t TunnelZone::HubAttachmentCount() const
{
    auto reg = hubs_.LockRO();
    return reg->size();
}

bool TunnelZone::HasHubAttachment(const std::string &data_dev) const
{
    auto reg = hubs_.LockRO();
    return reg->contains(data_dev);
}

std::optional<HubAttachmentSpec> TunnelZone::FindHubAttachment(const std::string &data_dev) const
{
    auto reg = hubs_.LockRO();
    auto it = reg->find(data_dev);
    if (it == reg->end())
        return std::nullopt;
    return it->second.spec;
}

} // namespace clv::vpn
