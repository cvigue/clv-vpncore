// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CONNECTION_H
#define CLV_VPN_CONNECTION_H

#include "openvpn/control_channel.h"
#include "openvpn/data_channel.h"
#include "openvpn/packet.h"
#include "openvpn/tls_context.h"
#include "openvpn/tls_crypt.h"
#include "transport/transport.h"

#include <asio/steady_timer.hpp>
#include <functional>
#include <not_null.h>
#include <net/ipv6_utils.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <new>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace spdlog {
class logger;
}

namespace clv::vpn {

namespace ipv6 = clv::net::ipv6;

/**
 * @brief Role of a VPN connection (server-side or client-side).
 */
enum class ConnectionRole
{
    Server,
    Client
};

/**
 * @brief Per-connection protocol state for one VPN session.
 *
 * Bundles the control channel, data channel, session identity, key material,
 * and transport handle that together describe a single peer connection.
 * Both VpnServer (via SessionManager) and VpnClient own Connection instances.
 *
 * Role-agnostic: the same type serves server-side and client-side sessions.
 * Role-specific behavior is expressed by the orchestrator (VpnServer/VpnClient)
 * or, in the future, by free lifecycle coroutines.
 */
class Connection
{
  public:
    struct Endpoint
    {
        asio::ip::address addr; ///< Peer's IP address (v4 or v6)
        uint16_t port;          ///< Peer's transport port

        bool operator==(const Endpoint &other) const
        {
            return addr == other.addr && port == other.port;
        }
    };

    /**
     * @brief Create a new connection
     * @param session_id Unique session identifier
     * @param endpoint Remote endpoint (IP and port)
     * @param role Whether this connection is server-side or client-side
     * @param cert_config Optional TLS certificate configuration
     * @param logger Structured logger (must remain valid for connection lifetime)
     */
    Connection(openvpn::SessionId session_id,
               const Endpoint &endpoint,
               ConnectionRole role,
               std::optional<openvpn::TlsCertConfig> cert_config,
               spdlog::logger &logger);

    /**
     * @brief Backward-compatible constructor accepting bool is_server.
     * @param session_id Unique session identifier
     * @param endpoint Remote endpoint (IP and port)
     * @param is_server True → Server role, false → Client role
     * @param cert_config Optional TLS certificate configuration
     * @param logger Structured logger (must remain valid for connection lifetime)
     */
    Connection(openvpn::SessionId session_id,
               const Endpoint &endpoint,
               bool is_server,
               std::optional<openvpn::TlsCertConfig> cert_config,
               spdlog::logger &logger);

    ~Connection() = default;

    // Non-copyable, non-movable (atomic members are not movable)
    Connection(const Connection &) = delete;
    Connection &operator=(const Connection &) = delete;
    Connection(Connection &&) = delete;
    Connection &operator=(Connection &&) = delete;

    // ── Identity ────────────────────────────────────────────────────────

    /**
     * @brief Get the session ID
     */
    openvpn::SessionId GetSessionId() const
    {
        return session_id_;
    }

    /**
     * @brief Get the remote endpoint
     */
    const Endpoint &GetEndpoint() const
    {
        return endpoint_;
    }

    /**
     * @brief Get the connection role
     */
    ConnectionRole GetRole() const
    {
        return role_;
    }

    /**
     * @brief Convenience: true when this is a server-side connection.
     *
     * Matches the `is_server` parameter expected by control_plane_helpers.
     */
    bool IsServer() const
    {
        return role_ == ConnectionRole::Server;
    }

    // ── Protocol Channels ───────────────────────────────────────────────

    /**
     * @brief Access the control channel
     */
    openvpn::ControlChannel &GetControlChannel()
    {
        return control_channel_;
    }
    const openvpn::ControlChannel &GetControlChannel() const
    {
        return control_channel_;
    }

    /**
     * @brief Access the data channel
     */
    openvpn::DataChannel &GetDataChannel()
    {
        return data_channel_;
    }
    const openvpn::DataChannel &GetDataChannel() const
    {
        return data_channel_;
    }

    // ── Activity Tracking ───────────────────────────────────────────────

    /**
     * @brief Get the last activity timestamp (RX side, thread-safe).
     */
    std::chrono::steady_clock::time_point GetLastActivity() const noexcept
    {
        return std::chrono::steady_clock::time_point(
            std::chrono::steady_clock::duration(
                last_activity_ns_.load(std::memory_order_relaxed)));
    }

    /**
     * @brief Update the last activity timestamp (called from RX thread).
     */
    void UpdateLastActivity() noexcept
    {
        last_activity_ns_.store(
            std::chrono::steady_clock::now().time_since_epoch().count(),
            std::memory_order_relaxed);
    }

    /**
     * @brief Get the last outbound traffic timestamp (TX side, thread-safe).
     */
    std::chrono::steady_clock::time_point GetLastOutbound() const noexcept
    {
        return std::chrono::steady_clock::time_point(
            std::chrono::steady_clock::duration(
                last_outbound_ns_.load(std::memory_order_relaxed)));
    }

    /**
     * @brief Update the last outbound traffic timestamp (called from TX thread).
     */
    void UpdateLastOutbound() noexcept
    {
        last_outbound_ns_.store(
            std::chrono::steady_clock::now().time_since_epoch().count(),
            std::memory_order_relaxed);
    }

    // ── Outbound Packet-ID ──────────────────────────────────────────────

    /**
     * @brief Atomically claim the next outbound data-channel packet ID.
     *
     * Called from both the TX hot path (MultiPeerPolicy) and the slow-path
     * control-plane keepalive sender (ServerDataAdapter) so that all encrypted
     * data packets share a single monotonic sequence and the peer's anti-replay
     * window never sees duplicate IDs.
     */
    std::uint32_t GetAndIncrementOutboundPacketId() noexcept
    {
        return outbound_data_packet_id_.fetch_add(1, std::memory_order_relaxed);
    }

    // ── Session State ───────────────────────────────────────────────────

    /**
     * @brief Check if the session is established (handshake complete)
     */
    bool IsEstablished() const
    {
        using State = openvpn::ControlChannel::State;
        return control_channel_.GetState() == State::KeyMaterialReady;
    }

    /**
     * @brief Try to mark the per-session rekey timer as armed.
     * @return true if timer transitioned from disarmed->armed, false if already armed.
     */
    bool TryArmRekeyTimer() noexcept
    {
        if (rekey_timer_armed_)
            return false;

        rekey_timer_armed_ = true;
        return true;
    }

    /**
     * @brief Set whether the per-session rekey timer is currently armed.
     */
    void SetRekeyTimerArmed(bool armed) noexcept
    {
        rekey_timer_armed_ = armed;
    }

    /**
     * @brief Query whether a per-session rekey timer is already armed.
     */
    bool IsRekeyTimerArmed() const noexcept
    {
        return rekey_timer_armed_;
    }

    /**
     * @brief Arm the per-session rekey timer.
     *
     * Creates (or replaces) the timer and sets its expiry.  Called by
     * RekeyLoop before co_await-ing so that StopBase() can cancel it via
     * CancelRekeyTimer() / SessionManager::CancelAllRekeyTimers().
     */
    void ArmRekeyTimer(asio::io_context &ctx, std::chrono::seconds d)
    {
        rekey_timer_.emplace(ctx);
        rekey_timer_->expires_after(d);
    }

    /** @brief Access the armed rekey timer (must call ArmRekeyTimer first). */
    asio::steady_timer &RekeyTimer()
    {
        return *rekey_timer_;
    }

    /**
     * @brief Cancel the rekey timer if one is armed.
     *
     * Idempotent.  Called from SessionManager::CancelAllRekeyTimers during
     * server teardown so every in-flight RekeyLoop wakes up and exits before
     * session state is destroyed.
     */
    void CancelRekeyTimer() noexcept
    {
        if (rekey_timer_)
            rekey_timer_->cancel();
    }

    // ── IP Assignment ───────────────────────────────────────────────────

    /**
     * @brief Set assigned VPN IPv4 address
     * @param ipv4 VPN IPv4 address in host byte order
     */
    void SetAssignedIpv4(uint32_t ipv4)
    {
        assigned_ipv4_ = ipv4;
    }

    /**
     * @brief Get assigned VPN IPv4 address
     * @return IPv4 address in host byte order, or nullopt if not assigned
     */
    std::optional<uint32_t> GetAssignedIpv4() const
    {
        return assigned_ipv4_;
    }

    /**
     * @brief Set assigned VPN IPv6 address
     * @param ipv6 VPN IPv6 address (16 bytes, network byte order)
     */
    void SetAssignedIpv6(const ipv6::Ipv6Address &ipv6)
    {
        assigned_ipv6_ = ipv6;
    }

    /**
     * @brief Get assigned VPN IPv6 address
     * @return IPv6 address, or nullopt if not assigned
     */
    std::optional<ipv6::Ipv6Address> GetAssignedIpv6() const
    {
        return assigned_ipv6_;
    }

    // ── Cipher & Key Material ───────────────────────────────────────────

    /**
     * @brief Get the negotiated cipher suite
     * @return Cipher name or empty if not yet negotiated
     */
    std::string GetCipherSuite() const;

    /**
     * @brief Check if key-method 2 message has been sent to client
     */
    bool HasSentKeyMethod2() const
    {
        return sent_key_method_2_;
    }

    /**
     * @brief Mark key-method 2 message as sent
     */
    void SetSentKeyMethod2(bool sent)
    {
        sent_key_method_2_ = sent;
    }

    /**
     * @brief Check whether TX key activation is pending the client's ACK of KEY_METHOD_2.
     *
     * When true, the server has derived new keys but must not publish them to the
     * TX data path until the client ACKs KEY_METHOD_2 (mirroring OpenVPN's
     * reliable_empty() / S_GENERATED_KEYS invariant).
     */
    bool IsKeysPendingActivation() const
    {
        return keys_pending_activation_;
    }

    /**
     * @brief Set or clear the pending-key-activation flag.
     */
    void SetKeysPendingActivation(bool pending)
    {
        keys_pending_activation_ = pending;
    }

    /**
     * @brief Store the server's random bytes for key derivation
     * @param random 48 bytes of random data
     */
    void SetServerRandom(const std::vector<uint8_t> &random)
    {
        server_random_ = random;
    }

    /**
     * @brief Get the server's random bytes
     */
    const std::vector<uint8_t> &GetServerRandom() const
    {
        return server_random_;
    }

    /**
     * @brief Store the client's random bytes for key derivation
     * @param random 48 bytes of random data from client
     */
    void SetClientRandom(const std::vector<uint8_t> &random)
    {
        client_random_ = random;
    }

    /**
     * @brief Get the client's random bytes
     */
    const std::vector<uint8_t> &GetClientRandom() const
    {
        return client_random_;
    }

    // ── Client Capabilities ─────────────────────────────────────────────

    /**
     * @brief Store the IV_PROTO bitmask advertised by the client in peer-info.
     * @param iv_proto Parsed value of IV_PROTO=N from the client's key-method-2 message.
     */
    void SetClientIvProto(std::uint32_t iv_proto)
    {
        client_iv_proto_ = iv_proto;
    }

    /**
     * @brief Get the IV_PROTO bitmask advertised by the client.
     * @return 0 if the client sent no peer-info or did not include IV_PROTO.
     */
    std::uint32_t GetClientIvProto() const
    {
        return client_iv_proto_;
    }

    // ── Transport ───────────────────────────────────────────────────────

    /**
     * @brief Set the transport handle for this connection
     * @param transport Transport handle (UdpTransport or TcpTransport)
     */
    void SetTransport(transport::TransportHandle transport)
    {
        transport_.emplace(std::move(transport));
    }

    /**
     * @brief Get the transport handle for this connection
     * @return Reference to the transport handle
     * @pre HasTransport() is true
     */
    transport::TransportHandle &GetTransport()
    {
        return *transport_;
    }

    const transport::TransportHandle &GetTransport() const
    {
        return *transport_;
    }

    /**
     * @brief Check if a transport handle has been assigned
     */
    bool HasTransport() const
    {
        return transport_.has_value();
    }

    // ── Per-session TLS-Crypt (V2) ─────────────────────────────────────

    /**
     * @brief Set the per-session TLS-Crypt key derived from a V2 client key (Kc).
     * @param tls_crypt TlsCrypt instance built from the unwrapped Kc.
     */
    void SetSessionTlsCrypt(openvpn::TlsCrypt tls_crypt)
    {
        session_tls_crypt_.emplace(std::move(tls_crypt));
    }

    /**
     * @brief Get the per-session TLS-Crypt key (V2), if set.
     */
    std::optional<openvpn::TlsCrypt> &GetSessionTlsCrypt()
    {
        return session_tls_crypt_;
    }

  private:
    openvpn::SessionId session_id_;
    Endpoint endpoint_;
    ConnectionRole role_;
    openvpn::ControlChannel control_channel_;
    openvpn::DataChannel data_channel_;
    // Cache-line separated atomics: RX writes last_activity_ns_, TX writes last_outbound_ns_.
    // std::atomic<int64_t> gives proper C++ memory-model guarantees (no UB on any arch).
    // Note: hardware_destructive_interference_size is a standard implementation detail, not ABI.
#if defined(__GNUC__) && !defined(__clang__) && (__GNUC__ >= 11)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winterference-size"
#endif
    alignas(std::hardware_destructive_interference_size)
        std::atomic<std::int64_t> last_activity_ns_{
            std::chrono::steady_clock::now().time_since_epoch().count()};
    alignas(std::hardware_destructive_interference_size)
        std::atomic<std::int64_t> last_outbound_ns_{
            std::chrono::steady_clock::now().time_since_epoch().count()};
    // Shared outbound data-channel packet ID: incremented from both the TX hot
    // path and the control-plane keepalive slow path so all encrypted data
    // packets from this session share one monotonic sequence.
    alignas(std::hardware_destructive_interference_size)
        std::atomic<std::uint32_t> outbound_data_packet_id_{1};
#if defined(__GNUC__) && !defined(__clang__) && (__GNUC__ >= 11)
#pragma GCC diagnostic pop
#endif
    std::optional<uint32_t> assigned_ipv4_;               // VPN IPv4 address assigned to this connection
    std::optional<ipv6::Ipv6Address> assigned_ipv6_;      // VPN IPv6 address assigned to this connection
    bool rekey_timer_armed_{false};                       // Server-side rekey timer guard (control thread only)
    std::optional<asio::steady_timer> rekey_timer_;       // Armed rekey timer (present while RekeyLoop is awaiting)
    bool sent_key_method_2_{false};                       // Whether key-method 2 message has been sent
    bool keys_pending_activation_{false};                 // TX keys derived but not yet published (awaiting client ACK)
    std::uint32_t client_iv_proto_{0};                    // IV_PROTO bitmask from client peer-info (0 = unknown)
    std::vector<uint8_t> server_random_;                  // Server's 48-byte random for key derivation
    std::vector<uint8_t> client_random_;                  // Client's 48-byte random for key derivation
    std::optional<transport::TransportHandle> transport_; // Per-session transport handle (UDP or TCP)
    std::optional<openvpn::TlsCrypt> session_tls_crypt_;  // Per-session TlsCrypt from V2 Kc (nullopt for V1)
    clv::not_null<spdlog::logger *> logger_;              // Structured logger (never null)
};

} // namespace clv::vpn

// std::hash specialization for Connection::Endpoint — enables use as
// unordered_map key for O(1) endpoint-based session lookup.
template <>
struct std::hash<clv::vpn::Connection::Endpoint>
{
    std::size_t operator()(const clv::vpn::Connection::Endpoint &ep) const noexcept
    {
        // Hash the address bytes directly.  For v4 the 4-byte representation
        // is fast; for v6 we fold the 16 bytes via two 64-bit loads.
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
        // Combine with port — shift prevents collisions when address low bits
        // and port overlap.
        h ^= std::hash<std::uint16_t>{}(ep.port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

#endif // CLV_VPN_CONNECTION_H
