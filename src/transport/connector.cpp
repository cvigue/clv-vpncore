// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "connector.h"
#include "transport/transport.h"

#include <asio/connect.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/ip/v6_only.hpp>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace clv::vpn::transport {

// ---------------------------------------------------------------------------
// UdpConnector
// ---------------------------------------------------------------------------

UdpConnector::UdpConnector(asio::io_context &ctx)
    : ctx_(ctx)
{
}

UdpTransport UdpConnector::Connect(const std::string &host, std::uint16_t port, bool dco_mode)
{
    asio::ip::udp::resolver resolver(ctx_);
    auto endpoints = resolver.resolve(host, std::to_string(port));

    if (endpoints.empty())
        throw std::runtime_error("Failed to resolve server address: " + host);

    resolvedEndpoint_ = *endpoints.begin();

    auto socket = std::make_shared<asio::ip::udp::socket>(ctx_);

    if (dco_mode && resolvedEndpoint_.address().is_v4())
    {
        // DCO mode with an IPv4 server: open a native AF_INET socket.
        // The ovpn-dco kernel module requires sockaddr_in for IPv4 peers
        // and does not handle v4-mapped IPv6 addresses on AF_INET6 sockets.
        // In DCO mode the kernel handles the data path, so we never use
        // the batch sendmmsg path (which assumes sockaddr_in6).
        socket->open(asio::ip::udp::v4());
    }
    else
    {
        // Default: dual-stack IPv6 so that the raw fd works with both
        // Asio async_send_to and the batch sendmmsg path (sockaddr_in6).
        socket->open(asio::ip::udp::v6());
        socket->set_option(asio::ip::v6_only(false));

        // Convert IPv4 endpoint to v4-mapped IPv6 so Asio send_to matches.
        if (resolvedEndpoint_.address().is_v4())
        {
            auto v6 = asio::ip::make_address_v6(
                asio::ip::v4_mapped, resolvedEndpoint_.address().to_v4());
            resolvedEndpoint_ = asio::ip::udp::endpoint(v6, resolvedEndpoint_.port());
        }
    }

    return UdpTransport(std::move(socket), resolvedEndpoint_);
}

// ---------------------------------------------------------------------------
// TcpConnector
// ---------------------------------------------------------------------------

TcpConnector::TcpConnector(asio::io_context &ctx)
    : ctx_(ctx)
{
}

TcpTransport TcpConnector::Connect(const std::string &host, std::uint16_t port)
{
    asio::ip::tcp::resolver resolver(ctx_);
    auto endpoints = resolver.resolve(host, std::to_string(port));

    if (endpoints.empty())
        throw std::runtime_error("Failed to resolve server address: " + host);

    asio::ip::tcp::socket socket(ctx_);
    asio::connect(socket, endpoints);
    socket.set_option(asio::ip::tcp::no_delay(true));

    return TcpTransport(std::move(socket));
}

} // namespace clv::vpn::transport
