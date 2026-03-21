// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "transport.h"

#include "openvpn/protocol_constants.h"
#include "socket_utils.h"

#include <array>
#include <asio/buffer.hpp>
#include <asio/read.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <unistd.h>
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
    std::array<std::uint8_t, 4096> recvBuffer;
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
    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, &len);
    len = sizeof(int);
    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, &len);
    return {rcv, snd};
}

// ---------------------------------------------------------------------------
// TcpTransport
// ---------------------------------------------------------------------------

TcpTransport::TcpTransport(asio::ip::tcp::socket socket)
    : socket_(std::make_shared<asio::ip::tcp::socket>(std::move(socket)))
{
}

asio::awaitable<void> TcpTransport::Send(std::span<const std::uint8_t> data)
{
    if (data.size() > 0xFFFF)
        throw std::overflow_error("TCP frame payload exceeds 65535 bytes");

    // 2-byte big-endian length prefix (OpenVPN TCP framing)
    auto len = static_cast<std::uint16_t>(data.size());
    std::array<std::uint8_t, 2> lengthPrefix = {
        static_cast<std::uint8_t>((len >> 8) & 0xFF),
        static_cast<std::uint8_t>(len & 0xFF)};

    // Gather write: prefix + payload sent atomically
    std::array<asio::const_buffer, 2> bufs = {
        asio::buffer(lengthPrefix),
        asio::buffer(data.data(), data.size())};
    co_await asio::async_write(*socket_, bufs, asio::use_awaitable);
}

asio::awaitable<std::vector<std::uint8_t>> TcpTransport::Receive()
{
    // Read 2-byte big-endian length prefix
    std::array<std::uint8_t, 2> lengthPrefix{};
    co_await asio::async_read(*socket_, asio::buffer(lengthPrefix), asio::use_awaitable);

    auto payloadLen = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(lengthPrefix[0]) << 8) | lengthPrefix[1]);

    if (payloadLen == 0)
        co_return std::vector<std::uint8_t>{};

    if (payloadLen > openvpn::MAX_TCP_FRAME_SIZE)
        throw std::runtime_error("TCP frame size " + std::to_string(payloadLen)
                                 + " exceeds maximum " + std::to_string(openvpn::MAX_TCP_FRAME_SIZE));

    // Read exact payload
    std::vector<std::uint8_t> payload(payloadLen);
    co_await asio::async_read(*socket_, asio::buffer(payload), asio::use_awaitable);
    co_return payload;
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

// ---------------------------------------------------------------------------
// TransportHandle
// ---------------------------------------------------------------------------

asio::awaitable<void> TransportHandle::Send(std::span<const std::uint8_t> data)
{
    return std::visit([data](auto &t)
    { return t.Send(data); },
                      *this);
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
