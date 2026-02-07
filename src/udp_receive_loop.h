// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_UDP_RECEIVE_LOOP_H
#define CLV_VPN_UDP_RECEIVE_LOOP_H

/**
 * @file udp_receive_loop.h
 * @brief Shared UDP receive-loop skeleton for VpnClient and VpnServer.
 *
 * Extracts the common recvmmsg → classify → dispatch → TUN-flush pipeline
 * into a function template parameterised by three callbacks:
 *   - ShouldContinueFn : () → bool  — loop predicate
 *   - DataDispatchFn   : (IncomingSlot&) → std::span<uint8_t>  — fast-path
 *   - ControlDispatchFn: (IncomingSlot&) → void                — slow-path
 *
 * An optional fourth callback (PostRecvFn) fires after each recvmmsg,
 * e.g. for adaptive-affinity bookkeeping on the server.
 */

#include "data_path_stats.h"
#include "openvpn/packet.h"
#include "transport/packet_arena.h"
#include "transport/udp_batch.h"
#include "tun/tun_device.h"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>

#include <exception>
#include <memory>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstddef>
#include <span>
#include <vector>

// Forward-declare to avoid pulling in the full TunDevice header.
namespace clv::vpn::tun {
class TunDevice;
} // namespace clv::vpn::tun

namespace clv::vpn {

/**
 * @brief Shared UDP receive-loop skeleton.
 *
 * Handles arena-slot initialisation, recvmmsg batching, quanta-based
 * chunking, per-packet stats accounting, opcode classification, TUN
 * batch flushing, and inter-chunk yielding.  Callers supply three
 * callbacks that implement the class-specific dispatch logic.
 *
 * @tparam ShouldContinueFn  `() -> bool` — return true while the loop should keep running.
 * @tparam DataDispatchFn    `(transport::IncomingSlot&) -> std::span<std::uint8_t>`
 *                           Called for data-channel packets when tunFd >= 0.
 *                           Return the plaintext IP span to write to TUN,
 *                           or an empty span to skip.
 * @tparam ControlDispatchFn `(transport::IncomingSlot&) -> void`
 *                           Called for control-channel packets (co_spawn, etc.).
 * @tparam PostRecvFn        `(std::size_t count) -> void`  (optional, default no-op)
 *                           Called after each recvmmsg with the datagram count.
 *
 * @param socket         ASIO UDP socket (for async_wait).
 * @param socketFd       Raw fd for recvmmsg(2).
 * @param tunFd          TUN device fd (-1 to skip TUN writes).
 * @param batchSize      Max datagrams per recvmmsg call.
 * @param processQuanta  Chunk size for inter-yield splitting (0 = no yield).
 * @param inboundSlots   Pre-sized slot vector (will be initialised here).
 * @param inboundArena   Arena backing the slot buffers.
 * @param stats          Monotonic counters (single-thread hot-path).
 * @param statsObserver  Windowed histogram tracker.
 * @param tunDevice      TUN device for batch writes (may be nullptr).
 * @param ioCtx          ASIO io_context for co_await post().
 * @param logger         spdlog logger.
 */
template <typename ShouldContinueFn,
          typename DataDispatchFn,
          typename ControlDispatchFn,
          typename PostRecvFn = decltype([](std::size_t) {})>
asio::awaitable<void> UdpReceiveLoopSkeleton(
    asio::ip::udp::socket &socket,
    int socketFd,
    int tunFd,
    std::size_t batchSize,
    std::size_t processQuanta,
    std::vector<transport::IncomingSlot> &inboundSlots,
    transport::PacketArena &inboundArena,
    DataPathStats &stats,
    StatsObserver &statsObserver,
    tun::TunDevice *tunDevice,
    asio::io_context &ioCtx,
    std::shared_ptr<spdlog::logger> logger,
    ShouldContinueFn shouldContinue,
    DataDispatchFn onDataPacket,
    ControlDispatchFn onControlPacket,
    PostRecvFn onPostRecv = {})
{
    // ---- Pre-allocate inbound arena slots ----
    inboundSlots.resize(batchSize);
    for (std::size_t i = 0; i < batchSize; ++i)
    {
        inboundSlots[i].buf = inboundArena.Slot(i);
        inboundSlots[i].capacity = inboundArena.SlotSize();
        inboundSlots[i].len = 0;
    }

    // Pre-allocate iovec array for batch TUN writes
    std::vector<struct iovec> tunIovecs;
    tunIovecs.reserve(batchSize);

    logger->info("UdpReceiveLoop: zero-copy arena (batch_size={}, arena={}KB, tunFd={})",
                 batchSize,
                 inboundArena.TotalSize() / 1024,
                 tunFd);

    while (shouldContinue())
    {
        try
        {
            // Wait for socket readability (ASIO/epoll integration)
            co_await socket.async_wait(
                asio::ip::udp::socket::wait_read,
                asio::use_awaitable);

            for (auto &s : inboundSlots)
                s.len = 0;

            auto count = transport::RecvBatch(
                socketFd,
                std::span<transport::IncomingSlot>(inboundSlots.data(), batchSize));

            if (count == 0)
                continue;

            stats.RecordRecvBatch(count, batchSize);
            statsObserver.RecordRxBatchHistogram(count);
            onPostRecv(count);

            // quanta == 0 → process the full batch in one pass (no yields).
            // quanta  > 0 → chunk + yield to prevent head-of-line blocking.
            const std::size_t quanta = processQuanta;
            const std::size_t effectiveQuanta = (quanta == 0) ? count : quanta;

            for (std::size_t chunk_start = 0; chunk_start < count;
                 chunk_start += effectiveQuanta)
            {
                const std::size_t chunk_end = std::min(chunk_start + effectiveQuanta, count);
                tunIovecs.clear();

                for (std::size_t i = chunk_start; i < chunk_end; ++i)
                {
                    auto &slot = inboundSlots[i];
                    stats.packetsReceived++;
                    stats.bytesReceived += slot.len;

                    if (slot.len == 0)
                        continue;

                    auto opcode = openvpn::GetOpcode(slot.buf[0]);

                    if (openvpn::IsDataPacket(opcode) && tunFd >= 0)
                    {
                        // ---- FAST PATH: caller-supplied data dispatch ----
                        auto ip_data = onDataPacket(slot);
                        if (!ip_data.empty())
                        {
                            tunIovecs.push_back({.iov_base = ip_data.data(),
                                                 .iov_len = ip_data.size()});
                        }
                    }
                    else
                    {
                        // ---- SLOW PATH: caller-supplied control dispatch ----
                        onControlPacket(slot);
                    }
                }

                // Flush this chunk's TUN writes
                if (!tunIovecs.empty() && tunDevice)
                {
                    auto written = tunDevice->WriteBatchRaw(tunIovecs.data(), tunIovecs.size());
                    stats.tunWrites += tunIovecs.size();
                    (void)written;
                }

                // Yield to event loop between chunks
                if (chunk_end < count)
                    co_await asio::post(ioCtx, asio::use_awaitable);
            }
        }
        catch (const std::exception &e)
        {
            if (shouldContinue())
            {
                logger->error("UdpReceiveLoop error: {}", e.what());
            }
        }
    }
}

} // namespace clv::vpn

#endif // CLV_VPN_UDP_RECEIVE_LOOP_H
