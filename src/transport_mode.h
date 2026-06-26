// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_MODE_H
#define CLV_VPN_TRANSPORT_MODE_H

#include "dco_utils.h"
#include "openvpn/vpn_config.h"

namespace clv::vpn {

enum class TransportMode
{
    Udp,
    Tcp,
    Dco
};

/// Resolve transport mode from config (works for both client and server roles).
inline TransportMode ResolveTransportMode(const VpnConfig &config)
{
    std::string proto;
    if (config.server)
        proto = config.server->proto;
    else if (config.client)
        proto = config.client->proto;

    if (proto == "tcp")
        return TransportMode::Tcp;
    if (config.performance.enable_dco && dco::IsAvailable())
        return TransportMode::Dco;
    return TransportMode::Udp;
}

inline const char *TransportModeString(TransportMode mode)
{
    switch (mode)
    {
    case TransportMode::Tcp:
        return "TCP (TUN-based)";
    case TransportMode::Dco:
        return "DCO (kernel offload)";
    case TransportMode::Udp:
        return "UDP (TUN-based)";
    }
    return "Unknown";
}

} // namespace clv::vpn

#endif // CLV_VPN_TRANSPORT_MODE_H
