// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_CONNECTOR_H
#define CLV_VPN_TRANSPORT_CONNECTOR_H

#include "transport.h"

#include <asio/io_context.hpp>

#include <cstdint>
#include <string>
#include <type_traits>
#include <variant>

namespace clv::vpn::transport {

// ---------------------------------------------------------------------------
// UdpConnector — resolves host and opens a UDP socket for client use
// ---------------------------------------------------------------------------

/**
 * @brief Client-side UDP connector.
 *
 * Resolves the server hostname and creates a UdpTransport that owns its
 * socket via shared_ptr. The resolution and socket creation are synchronous,
 * matching the existing VpnClient::Connect() pattern (called before io_context.run()).
 */
class UdpConnector
{
  public:
    /// @param ctx ASIO I/O context
    explicit UdpConnector(asio::io_context &ctx);

    /**
     * @brief Resolve server and create a UDP transport.
     * @param host Server hostname or IP address
     * @param port Server port
     * @param dco_mode When true and the server is IPv4, opens a native
     *                 AF_INET socket instead of dual-stack AF_INET6.
     *                 Required because the ovpn-dco kernel module cannot
     *                 handle v4-mapped IPv6 addresses on AF_INET6 sockets.
     * @return UdpTransport owning a socket pointed at the resolved server
     * @throws std::runtime_error on resolution failure
     * @throws asio::system_error on socket failure
     */
    UdpTransport Connect(const std::string &host, std::uint16_t port, bool dco_mode = false);

    /// @brief Get the resolved server endpoint (valid after Connect()).
    const asio::ip::udp::endpoint &ResolvedEndpoint() const
    {
        return resolvedEndpoint_;
    }

  private:
    asio::io_context &ctx_;
    asio::ip::udp::endpoint resolvedEndpoint_;
};

// ---------------------------------------------------------------------------
// TcpConnector — resolves host and establishes a TCP connection
// ---------------------------------------------------------------------------

/**
 * @brief Client-side TCP connector.
 *
 * Resolves the server hostname and establishes a synchronous TCP connection,
 * returning a TcpTransport wrapping the connected socket. Synchronous to
 * match VpnClient::Connect() calling convention.
 */
class TcpConnector
{
  public:
    /// @param ctx ASIO I/O context
    explicit TcpConnector(asio::io_context &ctx);

    /**
     * @brief Resolve server and establish a TCP connection.
     * @param host Server hostname or IP address
     * @param port Server port
     * @return TcpTransport with the connected socket (TCP_NODELAY enabled)
     * @throws std::runtime_error on resolution failure
     * @throws asio::system_error on connection failure
     */
    TcpTransport Connect(const std::string &host, std::uint16_t port);

  private:
    asio::io_context &ctx_;
};

// ---------------------------------------------------------------------------
// ClientConnector — variant combining UDP and TCP connectors
// ---------------------------------------------------------------------------

/**
 * @brief Polymorphic client connector using std::variant.
 *
 * Constructed based on the config "proto" field. Dispatches to the
 * appropriate Connect() method via std::visit.
 *
 * Example:
 * @code
 *   ClientConnector connector = (proto == "tcp")
 *       ? ClientConnector(TcpConnector(ctx))
 *       : ClientConnector(UdpConnector(ctx));
 *   auto transport = connector.Connect(host, port);  // returns TransportHandle
 * @endcode
 */
struct ClientConnector : std::variant<UdpConnector, TcpConnector>
{
    using std::variant<UdpConnector, TcpConnector>::variant;

    /**
     * @brief Connect to server using the appropriate transport.
     * @param host Server hostname or IP address
     * @param port Server port
     * @param dco_mode When true, opens native AF_INET for IPv4 (DCO requirement)
     * @return TransportHandle wrapping either UdpTransport or TcpTransport
     * @throws std::runtime_error on resolution failure
     * @throws asio::system_error on socket/connection failure
     */
    TransportHandle Connect(const std::string &host, std::uint16_t port, bool dco_mode = false)
    {
        return std::visit([&host, port, dco_mode](auto &connector) -> TransportHandle
        {
            if constexpr (std::is_same_v<std::decay_t<decltype(connector)>, UdpConnector>)
                return TransportHandle(connector.Connect(host, port, dco_mode));
            else
                return TransportHandle(connector.Connect(host, port));
        },
                          static_cast<std::variant<UdpConnector, TcpConnector> &>(*this));
    }
};


} // namespace clv::vpn::transport

#endif // CLV_VPN_TRANSPORT_CONNECTOR_H
