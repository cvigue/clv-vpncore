// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_LISTENER_H
#define CLV_VPN_TRANSPORT_LISTENER_H

#include "transport.h"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>

#include <cstdint>
#include <memory>
#include <variant>

namespace clv::vpn::transport {

// ---------------------------------------------------------------------------
// UdpListener — binds a UDP socket and receives datagrams
// ---------------------------------------------------------------------------

/**
 * @brief Server-side UDP listener.
 *
 * Binds a UDP socket on the specified port, receives datagrams via
 * coroutine-based ReceiveNext(), and creates per-client UdpTransport
 * handles for sending replies.
 */
class UdpListener
{
  public:
    /**
     * @brief Bind a UDP socket on the given port.
     * @param ctx ASIO I/O context
     * @param port Port to bind on
     */
    UdpListener(asio::io_context &ctx, std::uint16_t port);

    /**
     * @brief Create a transport handle for sending to a specific ASIO endpoint.
     * @param ep The peer's UDP endpoint
     * @return A UdpTransport sharing this listener's socket
     */
    UdpTransport TransportFor(const asio::ip::udp::endpoint &ep);

    /**
     * @brief Create a transport handle from a PeerEndpoint.
     * @param ep The peer endpoint
     * @return A UdpTransport sharing this listener's socket
     */
    UdpTransport TransportFor(const PeerEndpoint &ep);

    /// @brief Access the raw ASIO socket (e.g., for DcoDataChannel FD extraction).
    asio::ip::udp::socket &RawSocket()
    {
        return *socket_;
    }

    /// @brief Get the local port the listener is bound to.
    std::uint16_t LocalPort() const
    {
        return socket_->local_endpoint().port();
    }

  private:
    std::shared_ptr<asio::ip::udp::socket> socket_;
};

// ---------------------------------------------------------------------------
// TcpListener — accepts TCP connections
// ---------------------------------------------------------------------------

/**
 * @brief Server-side TCP listener (acceptor).
 *
 * Listens on a TCP port and accepts incoming connections. Each accepted
 * connection produces a TcpTransport that the server uses for per-client
 * communication.
 */
class TcpListener
{
  public:
    /**
     * @brief Start listening on the given port.
     * @param ctx ASIO I/O context
     * @param port Port to listen on
     */
    TcpListener(asio::io_context &ctx, std::uint16_t port);

    /**
     * @brief Accept the next incoming connection.
     * @return A TcpTransport wrapping the accepted socket (with TCP_NODELAY set)
     */
    asio::awaitable<TcpTransport> AcceptNext();

    /// @brief Close the acceptor (cancels pending AcceptNext).
    void Close();

    /// @brief Get the local port the listener is bound to.
    std::uint16_t LocalPort() const
    {
        return acceptor_.local_endpoint().port();
    }

  private:
    asio::ip::tcp::acceptor acceptor_;
};

// ---------------------------------------------------------------------------
// ServerListener — variant combining UDP and TCP listeners
// ---------------------------------------------------------------------------

/**
 * @brief Polymorphic server listener using std::variant.
 *
 * Constructed based on the config "proto" field. The server dispatches
 * to the appropriate receive/accept model via std::visit.
 */
struct ServerListener : std::variant<UdpListener, TcpListener>
{
    using std::variant<UdpListener, TcpListener>::variant;

    /// @brief Get the local port the listener is bound to.
    std::uint16_t LocalPort() const;

    /// @brief Close the underlying listener (cancels pending operations).
    void Close();
};

} // namespace clv::vpn::transport

#endif // CLV_VPN_TRANSPORT_LISTENER_H
