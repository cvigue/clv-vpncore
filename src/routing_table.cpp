// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "routing_table.h"

// Explicit instantiations so the linker sees the symbols exactly once.
template class clv::vpn::RoutingTable<clv::vpn::Ipv4RoutingTraits>;
template class clv::vpn::RoutingTable<clv::vpn::Ipv6RoutingTraits>;
