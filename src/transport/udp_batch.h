// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_UDP_BATCH_H
#define CLV_VPN_TRANSPORT_UDP_BATCH_H

#include "transport/transport.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace clv::vpn::transport {

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
 * @return      Number of datagrams received (0 on error / EAGAIN)
 */
std::size_t RecvBatch(int fd, std::span<IncomingSlot> slots);

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
 * @return        Total number of datagrams successfully sent
 */
std::size_t SendBatch(int fd, std::span<const SendEntry> entries);

} // namespace clv::vpn::transport

#endif // CLV_VPN_TRANSPORT_UDP_BATCH_H
