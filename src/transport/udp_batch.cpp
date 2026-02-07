// Copyright (c) 2025- Charlie Vigue. All rights reserved.

// _GNU_SOURCE is required for struct mmsghdr, recvmmsg, sendmmsg on glibc.
// Must be defined before ANY includes.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "udp_batch.h"
#include "batch_constants.h"
#include "transport/transport.h"

#include <asio/ip/address_v4.hpp>
#include <asio/ip/address_v6.hpp>

#include <sys/socket.h> // recvmmsg, sendmmsg, mmsghdr, msghdr
#include <sys/uio.h>    // iovec
#include <netinet/in.h> // sockaddr_in, sockaddr_in6, htons, ntohs
#include <arpa/inet.h>  // ntohl, htonl
#include <cerrno>

#include <algorithm>
#include <array>
#include <bits/types/struct_iovec.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace clv::vpn::transport {

// ---------------------------------------------------------------------------
// Helpers — sockaddr_in6 ↔ PeerEndpoint
// ---------------------------------------------------------------------------

namespace {

/// @brief Build a PeerEndpoint from a sockaddr_in6.
/// Normalizes v4-mapped addresses (::ffff:x.x.x.x) to plain IPv4.
PeerEndpoint PeerFromSockaddr6(const struct sockaddr_in6 &sa6)
{
    auto v6 = asio::ip::address_v6(std::to_array(sa6.sin6_addr.s6_addr));
    asio::ip::address addr;
    if (v6.is_v4_mapped())
        addr = asio::ip::make_address_v4(asio::ip::v4_mapped, v6);
    else
        addr = v6;
    return PeerEndpoint{.addr = addr, .port = ntohs(sa6.sin6_port)};
}

/// @brief Fill a sockaddr_in6 from a PeerEndpoint.
/// Wraps IPv4 addresses as v4-mapped IPv6.
void FillSockaddr6(struct sockaddr_in6 &sa6, const PeerEndpoint &ep)
{
    std::memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
    sa6.sin6_port = htons(ep.port);

    asio::ip::address_v6 v6;
    if (ep.addr.is_v4())
        v6 = asio::ip::make_address_v6(asio::ip::v4_mapped, ep.addr.to_v4());
    else
        v6 = ep.addr.to_v6();

    auto bytes = v6.to_bytes();
    std::memcpy(&sa6.sin6_addr, bytes.data(), 16);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// RecvBatch — zero-copy batched receive via recvmmsg(2)
// ---------------------------------------------------------------------------

std::size_t RecvBatch(int fd, std::span<IncomingSlot> slots)
{
    if (slots.empty())
        return 0;

    // Clamp to compile-time array size
    const std::size_t maxMessages = std::min(slots.size(), kMaxBatchSize);

    // Stack-local structures for recvmmsg
    std::array<struct iovec, kMaxBatchSize> iovecs{};
    std::array<struct mmsghdr, kMaxBatchSize> msgs{};
    std::array<struct sockaddr_in6, kMaxBatchSize> addrs{};

    for (std::size_t i = 0; i < maxMessages; ++i)
    {
        iovecs[i].iov_base = slots[i].buf;
        iovecs[i].iov_len = slots[i].capacity;

        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_in6);
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = nullptr;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }

    int n = ::recvmmsg(fd, msgs.data(), static_cast<unsigned int>(maxMessages), MSG_DONTWAIT, nullptr);
    if (n <= 0)
        return 0;

    // Fill output fields in caller's slots
    for (int i = 0; i < n; ++i)
    {
        slots[i].len = static_cast<std::size_t>(msgs[i].msg_len);
        slots[i].sender = PeerFromSockaddr6(addrs[i]);
    }

    return static_cast<std::size_t>(n);
}

// ---------------------------------------------------------------------------
// SendBatch — batched send via sendmmsg(2)
// ---------------------------------------------------------------------------

std::size_t SendBatch(int fd, std::span<const SendEntry> entries)
{
    if (entries.empty())
        return 0;

    std::size_t totalSent = 0;

    // Process in chunks of kMaxBatchSize.
    // sendmmsg(2) may return fewer messages than requested (e.g. the kernel
    // caps a single call at UIO_MAXIOV = 1024), so we retry within a chunk
    // until all messages are sent or an error occurs.
    while (!entries.empty())
    {
        auto chunkSize = std::min(entries.size(), kMaxBatchSize);

        // Stack-local send structures
        std::array<struct iovec, kMaxBatchSize> iovecs{};
        std::array<struct mmsghdr, kMaxBatchSize> msgs{};
        std::array<struct sockaddr_in6, kMaxBatchSize> addrs{};

        for (std::size_t i = 0; i < chunkSize; ++i)
        {
            const auto &entry = entries[i];

            // Fill destination sockaddr_in6 (v4 addresses become v4-mapped)
            FillSockaddr6(addrs[i], entry.dest);

            // const_cast required: sendmmsg iov_base is void* but we only read.
            iovecs[i].iov_base = const_cast<std::uint8_t *>(entry.data.data());
            iovecs[i].iov_len = entry.data.size();

            msgs[i].msg_hdr.msg_name = &addrs[i];
            msgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_in6);
            msgs[i].msg_hdr.msg_iov = &iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_control = nullptr;
            msgs[i].msg_hdr.msg_controllen = 0;
            msgs[i].msg_hdr.msg_flags = 0;
            msgs[i].msg_len = 0;
        }

        // Retry within the chunk to handle partial sendmmsg returns.
        std::size_t offset = 0;
        bool error = false;
        while (offset < chunkSize)
        {
            int n = ::sendmmsg(fd, msgs.data() + offset, static_cast<unsigned int>(chunkSize - offset), 0);
            if (n <= 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    // Socket send buffer full — return what we've sent so far.
                    // Caller should wait for writability before retrying.
                }
                error = true;
                break;
            }
            totalSent += static_cast<std::size_t>(n);
            offset += static_cast<std::size_t>(n);
        }

        if (error)
            break;

        entries = entries.subspan(chunkSize);
    }

    return totalSent;
}

} // namespace clv::vpn::transport
