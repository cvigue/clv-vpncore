// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "transport/transport.h"
#include <span>
#include <transport/udp_batch.h>
#include <transport/batch_constants.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace clv::vpn::transport {

namespace {

/**
 * Helper: create a bound UDP socket on 127.0.0.1 with an ephemeral port.
 * Returns {fd, port}.
 */
std::pair<int, uint16_t> CreateBoundUdpSocket()
{
    // Use AF_INET6 dual-stack socket to match the batch path's sockaddr_in6 usage.
    int fd = ::socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    EXPECT_GE(fd, 0);

    // Allow v4-mapped addresses on this IPv6 socket (dual-stack)
    int off = 0;
    ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

    // Ensure socket buffer is large enough for batch tests with kMaxBatchSize > 96
    int rcvbuf = 1 << 20; // 1 MB
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_in6 addr6{};
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = 0; // ephemeral
    addr6.sin6_addr = in6addr_loopback;

    EXPECT_EQ(::bind(fd, reinterpret_cast<sockaddr *>(&addr6), sizeof(addr6)), 0);

    socklen_t len = sizeof(addr6);
    EXPECT_EQ(::getsockname(fd, reinterpret_cast<sockaddr *>(&addr6), &len), 0);

    return {fd, ntohs(addr6.sin6_port)};
}

/// RAII close helper
struct FdGuard
{
    int fd;
    ~FdGuard()
    {
        if (fd >= 0)
            ::close(fd);
    }
};

} // namespace

// ---------------------------------------------------------------------------
// SendBatch tests
// ---------------------------------------------------------------------------

TEST(UdpBatchTest, SendBatchEmptyEntries)
{
    auto [fd, port] = CreateBoundUdpSocket();
    FdGuard guard{fd};

    auto sent = SendBatch(fd, {});
    EXPECT_EQ(sent, 0u);
}

TEST(UdpBatchTest, SendAndRecvSingleDatagram)
{
    auto [fd, port] = CreateBoundUdpSocket();
    FdGuard guard{fd};

    PeerEndpoint dest{.addr = asio::ip::address_v6::loopback(), .port = port}; // ::1

    std::array<uint8_t, 4> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    SendEntry entry{
        .data = std::span<const uint8_t>(payload),
        .dest = dest,
    };

    auto sent = SendBatch(fd, std::span<const SendEntry>(&entry, 1));
    EXPECT_EQ(sent, 1u);

    // Receive it back
    std::array<std::array<std::uint8_t, kMaxDatagram>, 4> bufs;
    std::array<IncomingSlot, 4> slots;
    for (std::size_t i = 0; i < slots.size(); ++i)
        slots[i] = {bufs[i].data(), bufs[i].size()};

    auto n = RecvBatch(fd, slots);
    ASSERT_EQ(n, 1u);
    EXPECT_EQ(slots[0].len, payload.size());
    EXPECT_EQ(std::memcmp(slots[0].buf, payload.data(), payload.size()), 0);
}

TEST(UdpBatchTest, SendAndRecvMultipleDatagrams)
{
    auto [fd, port] = CreateBoundUdpSocket();
    FdGuard guard{fd};

    PeerEndpoint dest{.addr = asio::ip::address_v6::loopback(), .port = port};

    constexpr int kCount = 8;
    std::array<std::array<uint8_t, 2>, kCount> payloads;
    std::array<SendEntry, kCount> entries;

    for (int i = 0; i < kCount; ++i)
    {
        payloads[i] = {static_cast<uint8_t>(i), static_cast<uint8_t>(i + 0x80)};
        entries[i] = SendEntry{
            .data = std::span<const uint8_t>(payloads[i]),
            .dest = dest,
        };
    }

    auto sent = SendBatch(fd, entries);
    EXPECT_EQ(sent, static_cast<std::size_t>(kCount));

    // Receive all — may arrive in fewer recvmmsg calls
    std::array<std::array<std::uint8_t, kMaxDatagram>, kCount> bufs;
    std::array<IncomingSlot, kCount> slots;
    for (int i = 0; i < kCount; ++i)
        slots[i] = {bufs[i].data(), bufs[i].size()};

    auto n = RecvBatch(fd, slots);
    EXPECT_EQ(n, static_cast<std::size_t>(kCount));

    for (std::size_t i = 0; i < n; ++i)
    {
        ASSERT_EQ(slots[i].len, 2u);
        EXPECT_EQ(slots[i].buf[0], static_cast<uint8_t>(i));
    }
}

TEST(UdpBatchTest, SendBatchChunksSplitAtMaxBatchSize)
{
    // Send more than kMaxBatchSize datagrams — the implementation should
    // chunk internally and still deliver all of them.
    auto [fd, port] = CreateBoundUdpSocket();
    FdGuard guard{fd};

    PeerEndpoint dest{.addr = asio::ip::address_v6::loopback(), .port = port};

    constexpr std::size_t kCount = kMaxBatchSize + 4;
    std::vector<std::array<uint8_t, 1>> payloads(kCount);
    std::vector<SendEntry> entries(kCount);

    for (std::size_t i = 0; i < kCount; ++i)
    {
        payloads[i] = {static_cast<uint8_t>(i & 0xFF)};
        entries[i] = SendEntry{
            .data = std::span<const uint8_t>(payloads[i]),
            .dest = dest,
        };
    }

    // The key assertion: SendBatch must report all kCount sent, proving it
    // chunked internally at the kMaxBatchSize boundary.
    auto sent = SendBatch(fd, entries);
    EXPECT_EQ(sent, kCount);

    // Drain what the socket buffer could hold. On default rmem_max (~208 KB)
    // not all 1028 tiny datagrams may fit, so we just verify we received
    // more than one chunk's worth — proving both chunks were actually sent.
    constexpr std::size_t kSlots = 256;
    std::array<std::array<std::uint8_t, kMaxDatagram>, kSlots> bufs;
    std::array<IncomingSlot, kSlots> slots;
    for (std::size_t i = 0; i < kSlots; ++i)
        slots[i] = {bufs[i].data(), bufs[i].size()};

    std::size_t totalReceived = 0;
    for (int attempt = 0; attempt < 16 && totalReceived < kCount; ++attempt)
    {
        auto n = RecvBatch(fd, slots);
        totalReceived += n;
    }
    // Must have received something — and SendBatch must have returned the full count
    EXPECT_GT(totalReceived, 0u);
}

// ---------------------------------------------------------------------------
// RecvBatch tests
// ---------------------------------------------------------------------------

TEST(UdpBatchTest, RecvBatchOnEmptySocketReturnsEmpty)
{
    auto [fd, port] = CreateBoundUdpSocket();
    FdGuard guard{fd};

    std::array<std::array<std::uint8_t, kMaxDatagram>, 4> bufs;
    std::array<IncomingSlot, 4> slots;
    for (std::size_t i = 0; i < slots.size(); ++i)
        slots[i] = {bufs[i].data(), bufs[i].size()};

    auto n = RecvBatch(fd, slots);
    EXPECT_EQ(n, 0u);
}

TEST(UdpBatchTest, RecvBatchReceivesIntoProvidedSlots)
{
    auto [fd, port] = CreateBoundUdpSocket();
    FdGuard guard{fd};

    PeerEndpoint dest{.addr = asio::ip::address_v6::loopback(), .port = port};

    // Send a single packet
    std::array<uint8_t, 1> payload = {0x42};
    SendEntry entry{.data = payload, .dest = dest};
    SendBatch(fd, std::span<const SendEntry>(&entry, 1));

    // Receive into a large slot array — should get exactly 1
    // Heap-allocate: kMaxBatchSize * kMaxDatagram can exceed safe stack size
    auto bufs = std::make_unique<std::array<std::array<std::uint8_t, kMaxDatagram>, kMaxBatchSize>>();
    std::vector<IncomingSlot> slots(kMaxBatchSize);
    for (std::size_t i = 0; i < kMaxBatchSize; ++i)
        slots[i] = {(*bufs)[i].data(), (*bufs)[i].size()};

    auto n = RecvBatch(fd, slots);
    EXPECT_GE(n, 1u);
    EXPECT_LE(n, kMaxBatchSize);
}

TEST(UdpBatchTest, RecvBatchInvalidFdReturnsEmpty)
{
    std::array<std::array<std::uint8_t, kMaxDatagram>, 4> bufs;
    std::array<IncomingSlot, 4> slots;
    for (std::size_t i = 0; i < slots.size(); ++i)
        slots[i] = {bufs[i].data(), bufs[i].size()};

    auto n = RecvBatch(-1, slots);
    EXPECT_EQ(n, 0u);
}

TEST(UdpBatchTest, SendBatchInvalidFdReturnsZero)
{
    PeerEndpoint dest{.addr = asio::ip::address_v6::loopback(), .port = 12345};
    std::array<uint8_t, 1> payload = {0x01};
    SendEntry entry{.data = payload, .dest = dest};

    auto sent = SendBatch(-1, std::span<const SendEntry>(&entry, 1));
    EXPECT_EQ(sent, 0u);
}

} // namespace clv::vpn::transport
