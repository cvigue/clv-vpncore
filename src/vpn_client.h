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
    static VpnConfig ParseJson(const nlohmann::json &json);
    static VpnConfig LoadFromFile(const std::string &path);
    static VpnConfig LoadFromOvpnFile(const std::string &path);
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
    VpnClient(asio::io_context &io_context, const VpnConfig &config);
    ~VpnClient();

    VpnClient(const VpnClient &) = delete;
    VpnClient &operator=(const VpnClient &) = delete;
    VpnClient(VpnClient &&) noexcept = delete;
    VpnClient &operator=(VpnClient &&) noexcept = delete;

    using StateCallback = std::function<void(VpnClientState, VpnClientState)>;

    void SetStateCallback(StateCallback cb)
    {
        data_plane_.Visit([&](auto &dp)
        { dp.SetStateCallback(std::move(cb)); });
    }

    void Connect();
    void Disconnect();

    VpnClientState GetState() const
    {
        VpnClientState s = VpnClientState::Disconnected;
        data_plane_.Visit([&](auto &dp)
        { s = dp.GetState(); });
        return s;
    }

    bool IsConnected() const
    {
        bool c = false;
        data_plane_.Visit([&](auto &dp)
        { c = dp.IsConnected(); });
        return c;
    }

    std::string GetAssignedIp() const
    {
        std::string ip;
        data_plane_.Visit([&](auto &dp)
        { ip = dp.GetAssignedIp(); });
        return ip;
    }

    std::vector<std::string> GetRoutes() const
    {
        std::vector<std::string> r;
        data_plane_.Visit([&](auto &dp)
        { r = dp.GetRoutes(); });
        return r;
    }

    std::vector<std::string> GetDnsServers() const
    {
        std::vector<std::string> d;
        data_plane_.Visit([&](auto &dp)
        { d = dp.GetDnsServers(); });
        return d;
    }

    const VpnConfig &GetConfig() const
    {
        return config_;
    }

    std::uint64_t GetBytesSent() const
    {
        std::uint64_t v = 0;
        data_plane_.Visit([&](auto &dp)
        { v = dp.GetStats().bytesSent; });
        return v;
    }

    std::uint64_t GetBytesReceived() const
    {
        std::uint64_t v = 0;
        data_plane_.Visit([&](auto &dp)
        { v = dp.GetStats().bytesReceived; });
        return v;
    }

    std::chrono::seconds GetUptime() const
    {
        std::chrono::seconds u(0);
        data_plane_.Visit([&](auto &dp)
        { u = dp.GetUptime(); });
        return u;
    }

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
