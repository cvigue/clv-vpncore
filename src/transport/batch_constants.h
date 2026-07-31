// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_BATCH_CONSTANTS_H
#define CLV_VPN_TRANSPORT_BATCH_CONSTANTS_H

#include <algorithm>
#include <cstddef>

namespace clv::vpn::transport {

/**
 * Compile-time upper bound for recvmmsg / sendmmsg metadata arrays.
 * The runtime batch size (from config) must be <= this value.
 * BatchScratchpad holds ~96 bytes of metadata per slot (iovec + mmsghdr +
 * sockaddr_in6) — at 4096 that is ~480 KB, allocated once per scratchpad.
 */
inline constexpr std::size_t kMaxBatchSize = 4096;

/** Default runtime batch size when not specified in config. */
inline constexpr std::size_t kDefaultBatchSize = 4096;

/** TCP SendRaw coalesce / TUN-pending defaults when config uses 0 (= path default). */
inline constexpr std::size_t kDefaultTcpSendBatch = 16;
inline constexpr std::size_t kDefaultTcpSmallPktFlush = 0; // 0 = disabled
inline constexpr std::size_t kDefaultTcpRxProcessBatch = 0; // 0 = no mid-peel count cap

/** Maximum UDP datagram size (matches OpenVPN practical limit). */
inline constexpr std::size_t kMaxDatagram = 2048;

/**
 * Compute the effective batch size from a raw config value.
 * Returns the configured value clamped to kMaxBatchSize,
 * or kDefaultBatchSize if the value is 0 or negative.
 */
inline std::size_t EffectiveBatchSize(int configValue)
{
    if (configValue <= 0)
        return kDefaultBatchSize;
    return std::min(static_cast<std::size_t>(configValue), kMaxBatchSize);
}

/**
 * Map a non-negative config int to a size: @p when_zero if @p config_value <= 0,
 * otherwise the configured value.
 */
inline std::size_t EffectivePositiveCount(int config_value, std::size_t when_zero)
{
    return config_value > 0 ? static_cast<std::size_t>(config_value) : when_zero;
}

} // namespace clv::vpn::transport

#endif // CLV_VPN_TRANSPORT_BATCH_CONSTANTS_H
