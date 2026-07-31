// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "transport/transport.h"

#include "openvpn/protocol_constants.h"
#include "socket_utils.h"

#include <asio/buffer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <unistd.h>

#include <util/byte_packer.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace clv::vpn::transport {

// ---------------------------------------------------------------------------
// PeerEndpoint conversions
// ---------------------------------------------------------------------------

PeerEndpoint FromAsioEndpoint(const asio::ip::udp::endpoint &ep)
{
    // On a dual-stack socket ASIO returns v4-mapped v6 for IPv4 peers.
    // Normalise to plain v4 so the rest of the pipeline sees clean addresses.
    auto addr = ep.address();
    if (addr.is_v6())
    {
        auto v6 = addr.to_v6();
        if (v6.is_v4_mapped())
            addr = asio::ip::make_address_v4(asio::ip::v4_mapped, v6);
    }
    return {addr, ep.port()};
}

PeerEndpoint FromAsioEndpoint(const asio::ip::tcp::endpoint &ep)
{
    return {ep.address(), ep.port()};
}

asio::ip::udp::endpoint ToUdpEndpoint(const PeerEndpoint &ep)
{
    // The server socket is dual-stack AF_INET6, so even IPv4 destinations
    // must be presented as v4-mapped IPv6 for sendto() to succeed.
    if (ep.addr.is_v4())
    {
        auto v6 = asio::ip::make_address_v6(asio::ip::v4_mapped, ep.addr.to_v4());
        return {v6, ep.port};
    }
    return {ep.addr, ep.port};
}

asio::ip::tcp::endpoint ToTcpEndpoint(const PeerEndpoint &ep)
{
    return {ep.addr, ep.port};
}

// ---------------------------------------------------------------------------
// UdpTransport
// ---------------------------------------------------------------------------

UdpTransport::UdpTransport(std::shared_ptr<asio::ip::udp::socket> socket,
                           asio::ip::udp::endpoint remoteEndpoint)
    : socket_(std::move(socket)),
      remoteEndpoint_(std::move(remoteEndpoint))
{
}

asio::awaitable<void> UdpTransport::Send(std::span<const std::uint8_t> data)
{
    // Unbatched path — direct single-datagram send
    co_await socket_->async_send_to(
        asio::buffer(data.data(), data.size()),
        remoteEndpoint_,
        asio::use_awaitable);
}

asio::awaitable<std::vector<std::uint8_t>> UdpTransport::Receive()
{
    // Buffer is coroutine-local to avoid per-instance overhead on server side
    std::array<std::uint8_t, openvpn::MAX_UDP_RECEIVE_SIZE> recvBuffer;
    asio::ip::udp::endpoint recvEndpoint;

    auto bytesReceived = co_await socket_->async_receive_from(asio::buffer(recvBuffer),
                                                              recvEndpoint,
                                                              asio::use_awaitable);

    co_return std::vector<std::uint8_t>(recvBuffer.begin(),
                                        recvBuffer.begin() + bytesReceived);
}

PeerEndpoint UdpTransport::GetPeer() const
{
    return FromAsioEndpoint(remoteEndpoint_);
}

void UdpTransport::ApplySocketBuffers(int recv_buf, int send_buf, spdlog::logger &logger)
{
    int fd = socket_->native_handle();
    clv::vpn::ApplySocketBuffer(fd, SO_RCVBUFFORCE, SO_RCVBUF, recv_buf, "SO_RCVBUF", logger);
    clv::vpn::ApplySocketBuffer(fd, SO_SNDBUFFORCE, SO_SNDBUF, send_buf, "SO_SNDBUF", logger);
}

std::pair<int, int> UdpTransport::GetSocketBufferSizes() const
{
    int fd = socket_->native_handle();
    int rcv = 0, snd = 0;
    socklen_t len = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, &len) != 0)
        rcv = -1;
    len = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, &len) != 0)
        snd = -1;
    return {rcv, snd};
}

// ---------------------------------------------------------------------------
// TcpTransport
// ---------------------------------------------------------------------------

TcpTransport::TcpTransport(asio::ip::tcp::socket socket)
    : socket_(std::make_shared<asio::ip::tcp::socket>(std::move(socket))),
      rx_(std::make_shared<RxBuffer>())
{
    rx_->data.resize(kRxSize);
}

asio::awaitable<void> TcpTransport::Send(std::span<const std::uint8_t> data)
{
    if (data.size() > 0xFFFF)
        throw std::overflow_error("TCP frame payload exceeds 65535 bytes");

    // 2-byte big-endian length prefix (OpenVPN TCP framing)
    auto lengthPrefix = clv::netcore::uint_to_bytes(static_cast<std::uint16_t>(data.size()));

    // Gather write: prefix + payload sent atomically
    std::array<asio::const_buffer, 2> bufs = {
        asio::buffer(lengthPrefix),
        asio::buffer(data.data(), data.size())};
    co_await asio::async_write(*socket_, bufs, asio::use_awaitable);
}

asio::awaitable<void> TcpTransport::SendRaw(std::span<const std::uint8_t> framed)
{
    if (framed.empty())
        co_return;
    co_await asio::async_write(*socket_,
                               asio::buffer(framed.data(), framed.size()),
                               asio::use_awaitable);
}

void TcpTransport::CompactRx()
{
    if (rx_->begin == 0)
        return;
    const std::size_t avail = rx_->end - rx_->begin;
    if (avail > 0)
        std::memmove(rx_->data.data(), rx_->data.data() + rx_->begin, avail);
    rx_->begin = 0;
    rx_->end = avail;
}

asio::awaitable<bool> TcpTransport::FillRx()
{
    // Slide any unconsumed tail (usually a partial frame) to the front, then
    // read as much as the kernel will give into the free space.
    CompactRx();
    const std::size_t space = rx_->data.size() - rx_->end;
    if (space == 0)
    {
        // Fixed buffer is full with incomplete data — frame length exceeds
        // remaining capacity (should be impossible: max frame << kRxSize).
        throw std::runtime_error("TCP RX buffer full with incomplete frame");
    }

    const std::size_t n = co_await socket_->async_read_some(
        asio::buffer(rx_->data.data() + rx_->end, space),
        asio::use_awaitable);
    if (n == 0)
        co_return false;
    rx_->end += n;
    co_return true;
}

std::optional<std::span<std::uint8_t>> TcpTransport::TryPeelInPlace()
{
    const std::size_t avail = rx_->end - rx_->begin;
    if (avail < 2)
        return std::nullopt;

    const auto payloadLen = clv::netcore::read_uint<2>(
        std::span<const std::uint8_t>(rx_->data.data() + rx_->begin, 2));

    if (payloadLen == 0)
    {
        rx_->begin += 2;
        return std::span<std::uint8_t>{};
    }

    if (payloadLen > openvpn::MAX_TCP_FRAME_SIZE)
        throw std::runtime_error("TCP frame size " + std::to_string(payloadLen)
                                 + " exceeds maximum "
                                 + std::to_string(openvpn::MAX_TCP_FRAME_SIZE));

    if (avail < 2 + payloadLen)
        return std::nullopt;

    auto *payload = rx_->data.data() + rx_->begin + 2;
    rx_->begin += 2 + payloadLen;
    return std::span<std::uint8_t>(payload, payloadLen);
}

asio::awaitable<std::span<std::uint8_t>> TcpTransport::ReceiveInPlace()
{
    for (;;)
    {
        if (auto frame = TryPeelInPlace())
            co_return *frame;

        if (!co_await FillRx())
            co_return std::span<std::uint8_t>{};
    }
}

asio::awaitable<std::vector<std::uint8_t>> TcpTransport::Receive()
{
    auto frame = co_await ReceiveInPlace();
    co_return std::vector<std::uint8_t>(frame.begin(), frame.end());
}

PeerEndpoint TcpTransport::GetPeer() const
{
    auto ep = socket_->remote_endpoint();
    return {ep.address(), ep.port()};
}

bool TcpTransport::IsOpen() const
{
    return socket_->is_open();
}

void TcpTransport::Close()
{
    if (socket_->is_open())
    {
        asio::error_code ec;
        [[maybe_unused]] auto e1 = socket_->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        [[maybe_unused]] auto e2 = socket_->close(ec);
    }
}

void TcpTransport::ApplySocketBuffers(int recv_buf, int send_buf, spdlog::logger &logger)
{
    int fd = socket_->native_handle();
    clv::vpn::ApplySocketBuffer(fd, SO_RCVBUFFORCE, SO_RCVBUF, recv_buf, "SO_RCVBUF", logger);
    clv::vpn::ApplySocketBuffer(fd, SO_SNDBUFFORCE, SO_SNDBUF, send_buf, "SO_SNDBUF", logger);
}

void AppendLengthPrefixedFrame(std::vector<std::uint8_t> &out,
                               std::span<const std::uint8_t> payload)
{
    if (payload.size() > 0xFFFF)
        throw std::overflow_error("TCP frame payload exceeds 65535 bytes");
    const auto prefix = clv::netcore::uint_to_bytes(static_cast<std::uint16_t>(payload.size()));
    const std::size_t start = out.size();
    out.resize(start + 2 + payload.size());
    out[start] = prefix[0];
    out[start + 1] = prefix[1];
    std::memcpy(out.data() + start + 2, payload.data(), payload.size());
}

std::pair<std::size_t, std::span<std::uint8_t>>
BeginTcpTxFrame(std::vector<std::uint8_t> &out, std::size_t ovpn_cap)
{
    const std::size_t prefix_index = out.size();
    out.resize(prefix_index + 2 + ovpn_cap);
    return {prefix_index,
            std::span<std::uint8_t>(out.data() + prefix_index + 2, ovpn_cap)};
}

void FinishTcpTxFrame(std::vector<std::uint8_t> &out,
                      std::size_t prefix_index,
                      std::size_t wire_len)
{
    if (wire_len > 0xFFFF)
        throw std::overflow_error("TCP frame payload exceeds 65535 bytes");
    if (prefix_index + 2 + wire_len > out.size())
        throw std::logic_error("FinishTcpTxFrame: wire_len exceeds reserved room");
    const auto prefix = clv::netcore::uint_to_bytes(static_cast<std::uint16_t>(wire_len));
    out[prefix_index] = prefix[0];
    out[prefix_index + 1] = prefix[1];
    out.resize(prefix_index + 2 + wire_len);
}

void AbortTcpTxFrame(std::vector<std::uint8_t> &out, std::size_t prefix_index)
{
    out.resize(prefix_index);
}

// ---------------------------------------------------------------------------
// TransportHandle
// ---------------------------------------------------------------------------

asio::awaitable<void> TransportHandle::Send(std::span<const std::uint8_t> data)
{
    return std::visit([data](auto &t)
    { return t.Send(data); },
                      *this);
}

asio::awaitable<void> TransportHandle::SendRaw(std::span<const std::uint8_t> framed)
{
    if (auto *tcp = std::get_if<TcpTransport>(this))
    {
        co_await tcp->SendRaw(framed);
        co_return;
    }
    throw std::logic_error("TransportHandle::SendRaw is TCP-only");
}

asio::awaitable<std::vector<std::uint8_t>> TransportHandle::Receive()
{
    return std::visit([](auto &t)
    { return t.Receive(); },
                      *this);
}

PeerEndpoint TransportHandle::GetPeer() const
{
    return std::visit([](const auto &t)
    { return t.GetPeer(); },
                      *this);
}

} // namespace clv::vpn::transport
