// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TRANSPORT_TRANSPORT_H
#define CLV_VPN_TRANSPORT_TRANSPORT_H

#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>

#include <spdlog/spdlog.h>

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
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
 * Mirrors Connection::Endpoint layout for easy conversion.
 */
struct PeerEndpoint
{
    asio::ip::address addr; ///< IPv4 or IPv6 address
    std::uint16_t port = 0; ///< Port number

    /** @brief Equality by address and port. */
    bool operator==(const PeerEndpoint &) const = default;
};

/** @brief Convert ASIO UDP endpoint to PeerEndpoint. */
PeerEndpoint FromAsioEndpoint(const asio::ip::udp::endpoint &ep);

/** @brief Convert ASIO TCP endpoint to PeerEndpoint. */
PeerEndpoint FromAsioEndpoint(const asio::ip::tcp::endpoint &ep);

/** @brief Convert PeerEndpoint to ASIO UDP endpoint. */
asio::ip::udp::endpoint ToUdpEndpoint(const PeerEndpoint &ep);

/** @brief Convert PeerEndpoint to ASIO TCP endpoint. */
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

    /** @brief Get the remote peer identity. */
    PeerEndpoint GetPeer() const;

    /** @brief Access the underlying ASIO socket (e.g., for DcoDataChannel FD extraction). */
    asio::ip::udp::socket &RawSocket()
    {
        return *socket_;
    }

    /** @brief Shared ownership handle for the socket (used to form weak_ptr in DCO mixin). */
    std::shared_ptr<asio::ip::udp::socket> SharedSocket()
    {
        return socket_;
    }

    /** @brief Apply SO_RCVBUF/SO_SNDBUF (with FORCE fallback) to the socket. */
    void ApplySocketBuffers(int recv_buf, int send_buf, spdlog::logger &logger);

    /**
     * @brief Query actual kernel socket buffer sizes.
     * @return {recv_buf, send_buf} as reported by getsockopt.
     */
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
 * RX uses a fixed link buffer: `async_read_some` into the free tail (up to
 * whatever the kernel has), then peel complete frames by advancing an offset
 * (no memmove). Before the next fill, any unconsumed tail (partial frame) is
 * slid to the front. Only one Receive() coroutine may run per connection.
 *
 * Prefer ReceiveInPlace() on the data path — the returned span aliases the link
 * buffer and is valid until the next Receive/ReceiveInPlace that fills (compacts).
 * Receive() copies into a heap vector (control / TransportHandle).
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
     * @brief Receive one framed message (heap copy).
     * @details Prefer ReceiveInPlace() on the hot path. This copies the peel into
     *          a new vector for callers that need ownership (e.g. TransportHandle).
     * @return Received message payload (empty on orderly EOF / zero-length frame)
     */
    asio::awaitable<std::vector<std::uint8_t>> Receive();

    /**
     * @brief Receive one framed message without copying.
     * @return Mutable span into the link buffer covering the frame payload.
     *         Valid until the next Receive/ReceiveInPlace that fills (compacts).
     *         Empty on orderly EOF / zero-length frame.
     */
    asio::awaitable<std::span<std::uint8_t>> ReceiveInPlace();

    /**
     * @brief Non-blocking peel of one complete frame already in the link buffer.
     * @return Payload span if a full frame is buffered; empty optional if more
     *         socket data is required (call ReceiveInPlace / Fill). Does not
     *         read from the socket. Span validity same as ReceiveInPlace.
     */
    std::optional<std::span<std::uint8_t>> TryPeelInPlace();

    /**
     * @brief Write raw bytes (already length-prefixed frames) to the socket.
     * @details Used to flush a coalesced TX batch built by the data path.
     */
    asio::awaitable<void> SendRaw(std::span<const std::uint8_t> framed);

    /** @brief Get the remote peer identity. */
    PeerEndpoint GetPeer() const;

    /** @brief Check if the underlying socket is open. */
    bool IsOpen() const;

    /** @brief Close the connection gracefully. */
    void Close();

    /** @brief Apply SO_RCVBUF/SO_SNDBUF (with FORCE fallback) to the socket. */
    void ApplySocketBuffers(int recv_buf, int send_buf, spdlog::logger &logger);

  private:
    struct RxBuffer
    {
        std::vector<std::uint8_t> data;
        std::size_t begin = 0;
        std::size_t end = 0;
    };

    /// Per-connection stream working set; kernel SO_RCVBUF holds the real backlog.
    static constexpr std::size_t kRxSize = 256 * 1024;

    void CompactRx();
    asio::awaitable<bool> FillRx();

    std::shared_ptr<asio::ip::tcp::socket> socket_;
    std::shared_ptr<RxBuffer> rx_;
};

/**
 * @brief Append an OpenVPN TCP length-prefixed frame to @p out.
 * @param out Destination buffer (grows)
 * @param payload Frame payload (not including the 2-byte length)
 */
void AppendLengthPrefixedFrame(std::vector<std::uint8_t> &out,
                               std::span<const std::uint8_t> payload);

/**
 * @brief Grow @p out by (2 + ovpn_cap) and return the OpenVPN-packet region.
 * @details Layout: [2-byte length][ovpn_cap bytes for EncryptPacketInPlace].
 *          After encrypt, call FinishTcpTxFrame with the wire length.
 * @return {prefix_index, span of size ovpn_cap starting after the length prefix}
 */
std::pair<std::size_t, std::span<std::uint8_t>>
BeginTcpTxFrame(std::vector<std::uint8_t> &out, std::size_t ovpn_cap);

/**
 * @brief Write the length prefix and shrink @p out to the finished frame.
 * @param prefix_index Value returned by BeginTcpTxFrame
 * @param wire_len OpenVPN packet length (not including the 2-byte TCP prefix)
 */
void FinishTcpTxFrame(std::vector<std::uint8_t> &out,
                      std::size_t prefix_index,
                      std::size_t wire_len);

/** @brief Abort an unfinished BeginTcpTxFrame (resize back to @p prefix_index). */
void AbortTcpTxFrame(std::vector<std::uint8_t> &out, std::size_t prefix_index);

// ---------------------------------------------------------------------------
// TransportHandle — variant dispatch (matches DataPlane pattern)
// ---------------------------------------------------------------------------

/**
 * @brief Polymorphic transport handle using std::variant.
 *
 * Provides unified Send/Receive/GetPeer dispatched to the underlying
 * UdpTransport or TcpTransport. Follows the project's DataPlane
 * pattern of variant + visit.
 */
struct TransportHandle : std::variant<UdpTransport, TcpTransport>
{
    using std::variant<UdpTransport, TcpTransport>::variant;

    /** @brief Send data via the underlying transport. */
    asio::awaitable<void> Send(std::span<const std::uint8_t> data);

    /**
     * @brief Write a pre-framed byte stream (TCP length-prefixed batch).
     * @details TCP-only; UDP throws. Used to flush coalesced TX batches.
     */
    asio::awaitable<void> SendRaw(std::span<const std::uint8_t> framed);

    /** @brief Receive one message via the underlying transport. */
    asio::awaitable<std::vector<std::uint8_t>> Receive();

    /** @brief Get the remote peer identity. */
    PeerEndpoint GetPeer() const;

    /** @brief Check if the underlying transport is TCP. */
    bool IsTcp() const
    {
        return std::holds_alternative<TcpTransport>(*this);
    }

    /** @brief Check if the underlying transport is UDP. */
    bool IsUdp() const
    {
        return std::holds_alternative<UdpTransport>(*this);
    }

    /** @brief Whether this transport supports batched I/O (sendmmsg/recvmmsg). */
    bool IsBatchingSupported() const
    {
        return IsUdp();
    }
};

} // namespace clv::vpn::transport

// std::hash specialization for PeerEndpoint — enables use as unordered_map key.
/** @brief Hash support for PeerEndpoint as an unordered_map key. */
template <>
struct std::hash<clv::vpn::transport::PeerEndpoint>
{
    /**
     * @brief Hash an endpoint by address bytes and port.
     * @param ep Endpoint to hash
     * @return Combined hash value
     */
    std::size_t operator()(const clv::vpn::transport::PeerEndpoint &ep) const noexcept
    {
        std::size_t h;
        if (ep.addr.is_v4())
        {
            h = std::hash<std::uint32_t>{}(ep.addr.to_v4().to_uint());
        }
        else
        {
            auto bytes = ep.addr.to_v6().to_bytes();
            std::uint64_t lo, hi;
            std::memcpy(&lo, bytes.data(), 8);
            std::memcpy(&hi, bytes.data() + 8, 8);
            h = std::hash<std::uint64_t>{}(lo) ^ (std::hash<std::uint64_t>{}(hi) * 2654435761u);
        }
        h ^= std::hash<std::uint16_t>{}(ep.port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

#endif // CLV_VPN_TRANSPORT_TRANSPORT_H
