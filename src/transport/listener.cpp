// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "transport/listener.h"

#include "socket_utils.h"
#include "transport/transport.h"

#include <asio/buffer.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/address_v6.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/use_awaitable.hpp>

#include <asm-generic/socket.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <memory>
#include <utility>

namespace clv::vpn::transport {

// Compute the bind endpoint from a host string, keeping the socket on AF_INET6
// throughout (required: the batch receive path uses sockaddr_in6 unconditionally).
//   "" / "0.0.0.0" / "::"  -> dual-stack wildcard
//   IPv4 literal           -> v4-mapped bind (::ffff:a.b.c.d), dual-stack
//   IPv6 literal           -> bind to that address, IPv6-only
static asio::ip::udp::endpoint MakeUdpBindEndpoint(const std::string &host,
                                                   std::uint16_t port,
                                                   bool &out_v6only)
{
    if (host.empty() || host == "0.0.0.0" || host == "::")
    {
        out_v6only = false;
        return asio::ip::udp::endpoint(asio::ip::udp::v6(), port);
    }
    auto addr = asio::ip::make_address(host);
    if (addr.is_v4())
    {
        out_v6only = false;
        auto mapped = asio::ip::make_address_v6(asio::ip::v4_mapped, addr.to_v4());
        return asio::ip::udp::endpoint(mapped, port);
    }
    out_v6only = true;
    return asio::ip::udp::endpoint(addr.to_v6(), port);
}

static asio::ip::tcp::endpoint MakeTcpBindEndpoint(const std::string &host,
                                                   std::uint16_t port,
                                                   bool &out_v6only)
{
    if (host.empty() || host == "0.0.0.0" || host == "::")
    {
        out_v6only = false;
        return asio::ip::tcp::endpoint(asio::ip::tcp::v6(), port);
    }
    auto addr = asio::ip::make_address(host);
    if (addr.is_v4())
    {
        out_v6only = false;
        auto mapped = asio::ip::make_address_v6(asio::ip::v4_mapped, addr.to_v4());
        return asio::ip::tcp::endpoint(mapped, port);
    }
    out_v6only = true;
    return asio::ip::tcp::endpoint(addr.to_v6(), port);
}

// ---------------------------------------------------------------------------
// UdpListener
// ---------------------------------------------------------------------------

UdpListener::UdpListener(asio::io_context &ctx, const std::string &host, std::uint16_t port)
    : socket_(std::make_shared<asio::ip::udp::socket>(ctx))
{
    // The batch receive/send path stores peer addresses as sockaddr_in6, so all
    // UDP sockets stay on AF_INET6.  IPv4 peers are handled via v4-mapped
    // addresses; the batch helpers normalise them back to plain v4.
    bool v6only = false;
    auto ep = MakeUdpBindEndpoint(host, port, v6only);
    socket_->open(asio::ip::udp::v6());
    socket_->set_option(asio::ip::v6_only(v6only));
    socket_->bind(ep);
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
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, &len) != 0)
        rcv = -1;
    len = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, &len) != 0)
        snd = -1;
    return {rcv, snd};
}

// ---------------------------------------------------------------------------
// TcpListener
// ---------------------------------------------------------------------------

TcpListener::TcpListener(asio::io_context &ctx, const std::string &host, std::uint16_t port)
    : acceptor_(ctx)
{
    bool v6only = false;
    auto ep = MakeTcpBindEndpoint(host, port, v6only);
    acceptor_.open(asio::ip::tcp::v6());
    acceptor_.set_option(asio::ip::v6_only(v6only));
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();
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

} // namespace clv::vpn::transport
