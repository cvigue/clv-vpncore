// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_UDP_BATCH_H
#define CLV_VPN_TRANSPORT_UDP_BATCH_H

// _GNU_SOURCE is required for struct mmsghdr used by BatchScratchpad.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "transport/transport.h"
#include "batch_constants.h"

#include <sys/socket.h> // mmsghdr, msghdr
#include <sys/uio.h>    // iovec
#include <netinet/in.h> // sockaddr_in6

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace clv::vpn::transport {

// ---------------------------------------------------------------------------
// BatchScratchpad — one-time allocation for recvmmsg/sendmmsg metadata
// ---------------------------------------------------------------------------

/**
 * @brief Pre-allocated scratch storage for RecvBatch/SendBatch.
 *
 * Holds the iovec, mmsghdr, and sockaddr_in6 arrays that recvmmsg(2) and
 * sendmmsg(2) require. Allocate once (per thread / per coroutine) and pass
 * to every batch call to avoid ~480 KB of per-call stack allocation.
 */
struct BatchScratchpad
{
    std::array<struct iovec, kMaxBatchSize> iovecs{};
    std::array<struct mmsghdr, kMaxBatchSize> msgs{};
    std::array<struct sockaddr_in6, kMaxBatchSize> addrs{};
};

// ---------------------------------------------------------------------------
// Batched receive — zero-copy recvmmsg(2) into caller-provided buffers
// ---------------------------------------------------------------------------

/** @brief Slot for zero-copy batch receive. */
struct IncomingSlot
{
    std::uint8_t *buf;        ///< Writable destination buffer
    std::size_t capacity;     ///< Available bytes in buf
    std::size_t len = 0;      ///< Output: bytes actually received
    PeerEndpoint sender = {}; ///< Output: sender endpoint
};

/**
 * @brief Receive up to @p slots.size() datagrams directly into caller-provided buffers.
 *
 * Each slot provides a pre-allocated buffer (e.g., an arena slot). The kernel
 * writes directly into these buffers via recvmmsg(2) — no intermediate copy.
 * Must be called when the socket is readable (after async_wait). Uses
 * MSG_DONTWAIT so it never blocks.
 *
 * @param fd    The socket file descriptor
 * @param slots Span of IncomingSlot — each must have valid buf/capacity.
 *              On return, len and sender are filled for received datagrams.
 * @param scratch  Pre-allocated scratchpad (reuse across calls).
 * @return      Number of datagrams received (0 on error / EAGAIN)
 */
std::size_t RecvBatch(int fd, std::span<IncomingSlot> slots, BatchScratchpad &scratch);

// ---------------------------------------------------------------------------
// Batched send — sendmmsg(2) wrapper
// ---------------------------------------------------------------------------

/** @brief Entry for batched sending: payload + destination endpoint. */
struct SendEntry
{
    std::span<const std::uint8_t> data; ///< Packet payload (caller retains ownership)
    PeerEndpoint dest;                  ///< Destination endpoint
};

/**
 * @brief Send datagrams via sendmmsg(2).
 *
 * Larger batches are split into chunks of kMaxBatchSize internally.
 *
 * @param fd      The socket file descriptor
 * @param entries Datagrams to send
 * @param scratch  Pre-allocated scratchpad (reuse across calls).
 * @return        Total number of datagrams successfully sent
 */
std::size_t SendBatch(int fd, std::span<const SendEntry> entries, BatchScratchpad &scratch);

} // namespace clv::vpn::transport

#endif // CLV_VPN_TRANSPORT_UDP_BATCH_H
