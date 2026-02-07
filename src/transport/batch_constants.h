// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_BATCH_CONSTANTS_H
#define CLV_VPN_TRANSPORT_BATCH_CONSTANTS_H

#include <cstddef>

namespace clv::vpn::transport {

/**
 * Compile-time upper bound for recvmmsg / sendmmsg metadata arrays.
 * The runtime batch size (from config) must be ≤ this value.
 * RecvBatch/SendBatch allocate ~96 bytes of metadata per slot on the
 * stack (iovec + mmsghdr + sockaddr_in6) — at 4096 that is ~480 KB.
 */
inline constexpr std::size_t kMaxBatchSize = 4096;

/// Default runtime batch size when not specified in config.
inline constexpr std::size_t kDefaultBatchSize = 4096;

/// Maximum UDP datagram size (matches OpenVPN practical limit).
inline constexpr std::size_t kMaxDatagram = 2048;

/// Default packets processed per event-loop yield in the receive loop.
/// A value of 0 disables chunking — the entire batch is processed before yielding.
inline constexpr std::size_t kDefaultProcessQuanta = 128;

} // namespace clv::vpn::transport

#endif // CLV_VPN_TRANSPORT_BATCH_CONSTANTS_H
