// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "listener.h"
#include "socket_utils.h"
#include "transport/transport.h"

#include <asio/buffer.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/use_awaitable.hpp>

#include <cstdint>
#include <memory>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <variant>

namespace clv::vpn::transport {

// ---------------------------------------------------------------------------
// UdpListener
// ---------------------------------------------------------------------------

UdpListener::UdpListener(asio::io_context &ctx, std::uint16_t port)
    : socket_(std::make_shared<asio::ip::udp::socket>(ctx))
{
    // Dual-stack: bind an IPv6 socket that also accepts IPv4 clients.
    // IPv4 peers appear as v4-mapped addresses (::ffff:x.x.x.x) at the
    // kernel level; our batch helpers normalise them back to plain v4.
    socket_->open(asio::ip::udp::v6());
    socket_->set_option(asio::ip::v6_only(false));
    socket_->bind(asio::ip::udp::endpoint(asio::ip::udp::v6(), port));
}

UdpTransport UdpListener::TransportFor(const asio::ip::udp::endpoint &ep)
{
    return UdpTransport(socket_, ep);
}

UdpTransport UdpListener::TransportFor(const PeerEndpoint &ep)
{
    return UdpTransport(socket_, ToUdpEndpoint(ep));
}

void UdpListener::ApplySocketBuffers(int recv_buf, int send_buf, spdlog::logger &logger)
{
    int fd = socket_->native_handle();
    clv::vpn::ApplySocketBuffer(fd, SO_RCVBUFFORCE, SO_RCVBUF, recv_buf, "SO_RCVBUF", logger);
    clv::vpn::ApplySocketBuffer(fd, SO_SNDBUFFORCE, SO_SNDBUF, send_buf, "SO_SNDBUF", logger);
}

std::pair<int, int> UdpListener::GetSocketBufferSizes() const
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
// TcpListener
// ---------------------------------------------------------------------------

TcpListener::TcpListener(asio::io_context &ctx, std::uint16_t port)
    : acceptor_(ctx, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port))
{
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
}

asio::awaitable<TcpTransport> TcpListener::AcceptNext()
{
    auto socket = co_await acceptor_.async_accept(asio::use_awaitable);
    socket.set_option(asio::ip::tcp::no_delay(true));
    co_return TcpTransport(std::move(socket));
}

void TcpListener::Close()
{
    if (acceptor_.is_open())
    {
        asio::error_code ec;
        [[maybe_unused]] auto _ = acceptor_.close(ec);
    }
}

// ---------------------------------------------------------------------------
// ServerListener
// ---------------------------------------------------------------------------

std::uint16_t ServerListener::LocalPort() const
{
    return std::visit([](const auto &l)
    { return l.LocalPort(); },
                      *this);
}

void ServerListener::Close()
{
    std::visit([](auto &l)
    {
        if constexpr (std::is_same_v<std::decay_t<decltype(l)>, UdpListener>)
        {
            auto &sock = l.RawSocket();
            if (sock.is_open())
                sock.close();
        }
        else
        {
            l.Close();
        }
    },
               *this);
}

} // namespace clv::vpn::transport
