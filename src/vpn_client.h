// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_VPN_CLIENT_H
#define CLV_VPN_VPN_CLIENT_H

#include "client_control_adapter.h"
#include "data_path_stats.h"
#include "data_plane.h"
#include "openvpn/vpn_config.h"
#include "transport_types.h"

#include <nlohmann/json_fwd.hpp>

#include <asio/io_context.hpp>

#include <spdlog/fwd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace clv::vpn {

/**
 * @brief Convenience loader — produces a VpnConfig with client role populated.
 */
struct VpnClientConfig
{
    /**
     * @brief Parse client configuration from a JSON object.
     * @param json Parsed configuration document
     * @return VpnConfig with client role fields populated
     * @throws std::exception on parse or validation failure
     */
    static VpnConfig ParseJson(const nlohmann::json &json);

    /**
     * @brief Load client configuration from a JSON file.
     * @param path Path to a JSON configuration file
     * @return VpnConfig with client role fields populated
     * @throws std::exception if the file cannot be read or parsed
     */
    static VpnConfig LoadFromFile(const std::string &path);

    /**
     * @brief Load client configuration from an OpenVPN .ovpn profile.
     * @param path Path to an .ovpn file
     * @return VpnConfig with client role fields populated
     * @throws std::exception if the file cannot be read or parsed
     */
    static VpnConfig LoadFromOvpnFile(const std::string &path);

    /**
     * @brief Load client configuration, auto-detecting JSON vs .ovpn by extension.
     * @param path Path to a JSON or .ovpn configuration file
     * @return VpnConfig with client role fields populated
     * @throws std::exception if the file cannot be read or parsed
     */
    static VpnConfig Load(const std::string &path);
};

// VpnClientState enum and VpnClientStateToString live in client_control_adapter.h.

/**
 * @brief OpenVPN client — thin factory shell.
 *
 * Owns the config and running flag; delegates all protocol work to
 * ClientControlPlane held in @ref data_plane_.
 */
class VpnClient
{
  public:
    /**
     * @brief Construct a client for the given configuration.
     * @param io_context ASIO context used by the control and data planes
     * @param config Client configuration (must include client role)
     */
    VpnClient(asio::io_context &io_context, const VpnConfig &config);

    /** @brief Stop the client and tear down the active transport. */
    ~VpnClient();

    VpnClient(const VpnClient &) = delete;
    VpnClient &operator=(const VpnClient &) = delete;
    VpnClient(VpnClient &&) noexcept = delete;
    VpnClient &operator=(VpnClient &&) noexcept = delete;

    /** @brief Callback invoked on connection state transitions. */
    using StateCallback = std::function<void(VpnClientState, VpnClientState)>;

    /**
     * @brief Register a callback for connection state changes.
     * @param cb Called with (old_state, new_state) on each transition
     */
    void SetStateCallback(StateCallback cb)
    {
        data_plane_.Visit([&](auto &dp)
        { dp.SetStateCallback(std::move(cb)); });
    }

    /** @brief Begin the connection handshake (non-blocking). */
    void Connect();

    /** @brief Tear down the session and return to Disconnected. */
    void Disconnect();

    /**
     * @brief Current connection state.
     * @return State of the control-plane handshake and session
     */
    VpnClientState GetState() const
    {
        VpnClientState s = VpnClientState::Disconnected;
        data_plane_.Visit([&](auto &dp)
        { s = dp.GetState(); });
        return s;
    }

    /**
     * @brief Whether the client has a fully established session.
     * @return true when state is Connected
     */
    bool IsConnected() const
    {
        bool c = false;
        data_plane_.Visit([&](auto &dp)
        { c = dp.IsConnected(); });
        return c;
    }

    /**
     * @brief Assigned tunnel IPv4 address from the server's PUSH reply.
     * @return Dotted-quad string, or empty if not yet assigned
     */
    std::string GetAssignedIp() const
    {
        std::string ip;
        data_plane_.Visit([&](auto &dp)
        { ip = dp.GetAssignedIp(); });
        return ip;
    }

    /**
     * @brief Routes pushed by the server.
     * @return CIDR strings (e.g. "10.0.0.0/8")
     */
    std::vector<std::string> GetRoutes() const
    {
        std::vector<std::string> r;
        data_plane_.Visit([&](auto &dp)
        { r = dp.GetRoutes(); });
        return r;
    }

    /**
     * @brief DNS servers pushed by the server.
     * @return Resolver addresses in dotted-quad or bracketed IPv6 form
     */
    std::vector<std::string> GetDnsServers() const
    {
        std::vector<std::string> d;
        data_plane_.Visit([&](auto &dp)
        { d = dp.GetDnsServers(); });
        return d;
    }

    /**
     * @brief Immutable client configuration.
     * @return Reference to the config supplied at construction
     */
    const VpnConfig &GetConfig() const
    {
        return config_;
    }

    /**
     * @brief Total encrypted bytes sent on the data channel.
     * @return Cumulative TX byte count since connect
     */
    std::uint64_t GetBytesSent() const
    {
        std::uint64_t v = 0;
        data_plane_.Visit([&](auto &dp)
        { v = dp.GetStats().bytesSent; });
        return v;
    }

    /**
     * @brief Total encrypted bytes received on the data channel.
     * @return Cumulative RX byte count since connect
     */
    std::uint64_t GetBytesReceived() const
    {
        std::uint64_t v = 0;
        data_plane_.Visit([&](auto &dp)
        { v = dp.GetStats().bytesReceived; });
        return v;
    }

    /**
     * @brief Time since the session reached Connected.
     * @return Zero when not connected
     */
    std::chrono::seconds GetUptime() const
    {
        std::chrono::seconds u(0);
        data_plane_.Visit([&](auto &dp)
        { u = dp.GetUptime(); });
        return u;
    }

    /**
     * @brief Snapshot of data-path counters and rates.
     * @return Full DataPathStats from the active transport
     */
    DataPathStats GetStats() const
    {
        DataPathStats s{};
        data_plane_.Visit([&](auto &dp)
        { s = dp.GetStats(); });
        return s;
    }

  private:
    using ClientDataPlane = DataPlane<ClientUdpTransport, ClientDcoTransport, ClientTcpTransport>;

    asio::io_context &io_context_;
    VpnConfig config_;
    std::shared_ptr<spdlog::logger> logger_;
    std::atomic<bool> running_{false};

    ClientDataPlane data_plane_;
};

} // namespace clv::vpn

#endif // CLV_VPN_VPN_CLIENT_H
