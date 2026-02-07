// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CLIENT_SESSION_H
#define CLV_VPN_CLIENT_SESSION_H

#include "openvpn/control_channel.h"
#include "openvpn/data_channel.h"
#include "openvpn/packet.h"
#include "openvpn/tls_context.h"
#include "../transport/transport.h"

#include <util/ipv6_utils.h>

#include <not_null.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace spdlog {
class logger;
}

namespace clv::vpn {

/**
 * @brief Represents a single VPN client session
 *
 * Manages the control channel, data channel, and endpoint information for a connected client.
 * Each ClientSession encapsulates the complete state for one client connection.
 */
class ClientSession
{
  public:
    struct Endpoint
    {
        asio::ip::address addr; ///< Client's IP address (v4 or v6)
        uint16_t port;          ///< Client's transport port

        bool operator==(const Endpoint &other) const
        {
            return addr == other.addr && port == other.port;
        }
    };

    /**
     * @brief Create a new client session
     * @param session_id Unique session identifier
     * @param endpoint Remote endpoint (IP and port)
     * @param is_server True if this is server-side, false for client-side
     * @param cert_config Optional TLS certificate configuration
     * @param logger Optional structured logger
     */
    ClientSession(openvpn::SessionId session_id,
                  const Endpoint &endpoint,
                  bool is_server,
                  std::optional<openvpn::TlsCertConfig> cert_config,
                  spdlog::logger &logger);

    ~ClientSession() = default;

    // Non-copyable, movable
    ClientSession(const ClientSession &) = delete;
    ClientSession &operator=(const ClientSession &) = delete;
    ClientSession(ClientSession &&) = default;
    ClientSession &operator=(ClientSession &&) = default;

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

    /**
     * @brief Get the last activity timestamp
     */
    std::chrono::steady_clock::time_point GetLastActivity() const
    {
        return last_activity_;
    }

    /**
     * @brief Update the last activity timestamp (inbound traffic)
     */
    void UpdateLastActivity()
    {
        last_activity_ = std::chrono::steady_clock::now();
    }

    /**
     * @brief Get the last outbound traffic timestamp (data or PING)
     */
    std::chrono::steady_clock::time_point GetLastOutbound() const
    {
        return last_outbound_;
    }

    /**
     * @brief Update the last outbound traffic timestamp
     */
    void UpdateLastOutbound()
    {
        last_outbound_ = std::chrono::steady_clock::now();
    }

    /**
     * @brief Check if the session is established (handshake complete)
     */
    bool IsEstablished() const
    {
        using State = openvpn::ControlChannel::State;
        return control_channel_.GetState() == State::KeyMaterialReady;
    }

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

    /**
     * @brief Set the transport handle for this session
     * @param transport Transport handle (UdpTransport or TcpTransport)
     */
    void SetTransport(transport::TransportHandle transport)
    {
        transport_.emplace(std::move(transport));
    }

    /**
     * @brief Get the transport handle for this session
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

    /**
     * @brief Set whether this client uses compression framing
     *
     * When true, decrypted data packets have a 1-byte compression prefix
     * (e.g. 0xFA = NO_COMPRESS) that must be stripped before writing to TUN,
     * and outgoing packets must have the prefix prepended before encryption.
     */
    void SetUsesCompressionFraming(bool uses)
    {
        uses_compression_framing_ = uses;
    }

    /**
     * @brief Check if this client uses compression framing
     */
    bool UsesCompressionFraming() const
    {
        return uses_compression_framing_;
    }

  private:
    openvpn::SessionId session_id_;
    Endpoint endpoint_;
    openvpn::ControlChannel control_channel_;
    openvpn::DataChannel data_channel_;
    std::chrono::steady_clock::time_point last_activity_{std::chrono::steady_clock::now()};
    std::chrono::steady_clock::time_point last_outbound_{std::chrono::steady_clock::now()};
    std::optional<uint32_t> assigned_ipv4_;               // VPN IPv4 address assigned to this client
    std::optional<ipv6::Ipv6Address> assigned_ipv6_;      // VPN IPv6 address assigned to this client
    bool sent_key_method_2_{false};                       // Whether key-method 2 message has been sent
    std::vector<uint8_t> server_random_;                  // Server's 48-byte random for key derivation
    std::vector<uint8_t> client_random_;                  // Client's 48-byte random for key derivation
    std::optional<transport::TransportHandle> transport_; // Per-session transport handle (UDP or TCP)
    bool uses_compression_framing_{false};                // Client prepends compression byte to data
    clv::not_null<spdlog::logger *> logger_;              // Structured logger (never null)
};

} // namespace clv::vpn

#endif // CLV_VPN_CLIENT_SESSION_H
