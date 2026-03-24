// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_BATCH_CONSTANTS_H
#define CLV_VPN_TRANSPORT_BATCH_CONSTANTS_H

#include <algorithm>
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

/// Compute the effective batch size from a raw config value.
/// Returns the configured value clamped to kMaxBatchSize,
/// or kDefaultBatchSize if the value is 0 or negative.
inline std::size_t EffectiveBatchSize(int configValue)
{
    if (configValue <= 0)
        return kDefaultBatchSize;
    return std::min(static_cast<std::size_t>(configValue), kMaxBatchSize);
}

} // namespace clv::vpn::transport

#endif // CLV_VPN_TRANSPORT_BATCH_CONSTANTS_H
