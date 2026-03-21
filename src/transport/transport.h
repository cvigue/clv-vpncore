// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_TRANSPORT_H
#define CLV_VPN_TRANSPORT_TRANSPORT_H

#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace clv::vpn::transport {

// ---------------------------------------------------------------------------
// PeerEndpoint — transport-agnostic remote peer identity
// ---------------------------------------------------------------------------

/**
 * @brief Identifies a remote peer by IP address and port.
 *
 * Supports both IPv4 and IPv6 via asio::ip::address.
 *
 * Mirrors ClientSession::Endpoint layout for easy conversion.
 */
struct PeerEndpoint
{
    asio::ip::address addr; ///< IPv4 or IPv6 address
    std::uint16_t port = 0; ///< Port number

    bool operator==(const PeerEndpoint &) const = default;
};

/// @brief Convert ASIO UDP endpoint to PeerEndpoint.
PeerEndpoint FromAsioEndpoint(const asio::ip::udp::endpoint &ep);

/// @brief Convert ASIO TCP endpoint to PeerEndpoint.
PeerEndpoint FromAsioEndpoint(const asio::ip::tcp::endpoint &ep);

/// @brief Convert PeerEndpoint to ASIO UDP endpoint.
asio::ip::udp::endpoint ToUdpEndpoint(const PeerEndpoint &ep);

/// @brief Convert PeerEndpoint to ASIO TCP endpoint.
asio::ip::tcp::endpoint ToTcpEndpoint(const PeerEndpoint &ep);

// ---------------------------------------------------------------------------
// UdpTransport — per-client handle over a (possibly shared) UDP socket
// ---------------------------------------------------------------------------

/**
 * @brief Per-client transport handle for UDP.
 *
 * On the server side, multiple UdpTransport instances share a single socket
 * (owned by UdpListener) and differ only by remote endpoint. On the client
 * side, the transport owns the socket via shared_ptr.
 *
 * Supports Send() for both sides and Receive() for the client side
 * (server-side receiving is done by UdpListener::ReceiveNext()).
 */
class UdpTransport
{
  public:
    /**
     * @brief Construct from a shared socket and remote endpoint.
     * @param socket Shared pointer to the UDP socket (lifetime managed externally or shared)
     * @param remoteEndpoint The remote peer's UDP endpoint
     */
    UdpTransport(std::shared_ptr<asio::ip::udp::socket> socket,
                 asio::ip::udp::endpoint remoteEndpoint);

    /**
     * @brief Send data to the remote peer.
     * @param data Bytes to send
     */
    asio::awaitable<void> Send(std::span<const std::uint8_t> data);

    /**
     * @brief Receive next datagram from the socket.
     *
     * Intended for client-side use where only one remote peer sends data.
     * On the server side, use UdpListener::ReceiveNext() instead.
     * @return Received datagram payload
     */
    asio::awaitable<std::vector<std::uint8_t>> Receive();

    /// @brief Get the remote peer identity.
    PeerEndpoint GetPeer() const;

    /// @brief Access the underlying ASIO socket (e.g., for DcoDataChannel FD extraction).
    asio::ip::udp::socket &RawSocket()
    {
        return *socket_;
    }

    /// @brief Apply SO_RCVBUF/SO_SNDBUF (with FORCE fallback) to the socket.
    void ApplySocketBuffers(int recv_buf, int send_buf, spdlog::logger &logger);

    /// @brief Query actual kernel socket buffer sizes.
    /// @return {recv_buf, send_buf} as reported by getsockopt.
    std::pair<int, int> GetSocketBufferSizes() const;

  private:
    std::shared_ptr<asio::ip::udp::socket> socket_;
    asio::ip::udp::endpoint remoteEndpoint_;
};

// ---------------------------------------------------------------------------
// TcpTransport — owns a connected TCP socket with OpenVPN length-prefix framing
// ---------------------------------------------------------------------------

/**
 * @brief Per-client transport for TCP.
 *
 * Holds a shared pointer to a connected TCP socket and implements OpenVPN's
 * 2-byte big-endian length-prefix framing for message boundaries on the
 * stream. The shared_ptr design mirrors UdpTransport and allows the same
 * socket to be referenced by both the per-client receive loop and the
 * session's send path.
 *
 * ASIO guarantees that one outstanding async_read and one outstanding
 * async_write may coexist on the same socket, so a single receive loop
 * and the send path can operate concurrently. Multiple concurrent writes
 * must be externally serialized (the caller's responsibility).
 */
class TcpTransport
{
  public:
    /**
     * @brief Construct from an already-connected TCP socket.
     * @param socket Connected TCP socket (ownership transferred into shared_ptr)
     */
    explicit TcpTransport(asio::ip::tcp::socket socket);

    /**
     * @brief Send a length-prefixed message to the remote peer.
     * @param data Bytes to send (prefixed with 2-byte big-endian length on the wire)
     * @throws std::overflow_error if data exceeds 65535 bytes
     */
    asio::awaitable<void> Send(std::span<const std::uint8_t> data);

    /**
     * @brief Receive one framed message.
     * @details Reads a 2-byte big-endian length prefix, then reads that many payload bytes.
     * @return Received message payload
     */
    asio::awaitable<std::vector<std::uint8_t>> Receive();

    /// @brief Get the remote peer identity.
    PeerEndpoint GetPeer() const;

    /// @brief Check if the underlying socket is open.
    bool IsOpen() const;

    /// @brief Close the connection gracefully.
    void Close();

  private:
    std::shared_ptr<asio::ip::tcp::socket> socket_;
};

// ---------------------------------------------------------------------------
// TransportHandle — variant dispatch (matches DataChannelStrategy pattern)
// ---------------------------------------------------------------------------

/**
 * @brief Polymorphic transport handle using std::variant.
 *
 * Provides unified Send/Receive/GetPeer dispatched to the underlying
 * UdpTransport or TcpTransport. Follows the project's DataChannelStrategy
 * pattern of variant + visit.
 */
struct TransportHandle : std::variant<UdpTransport, TcpTransport>
{
    using std::variant<UdpTransport, TcpTransport>::variant;

    /// @brief Send data via the underlying transport.
    asio::awaitable<void> Send(std::span<const std::uint8_t> data);

    /// @brief Receive one message via the underlying transport.
    asio::awaitable<std::vector<std::uint8_t>> Receive();

    /// @brief Get the remote peer identity.
    PeerEndpoint GetPeer() const;

    /// @brief Check if the underlying transport is TCP.
    bool IsTcp() const
    {
        return std::holds_alternative<TcpTransport>(*this);
    }

    /// @brief Check if the underlying transport is UDP.
    bool IsUdp() const
    {
        return std::holds_alternative<UdpTransport>(*this);
    }

    /// @brief Whether this transport supports batched I/O (sendmmsg/recvmmsg).
    bool IsBatchingSupported() const { return IsUdp(); }
};

} // namespace clv::vpn::transport

#endif // CLV_VPN_TRANSPORT_TRANSPORT_H
