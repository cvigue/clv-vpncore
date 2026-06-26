// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_VPN_CLIENT_H
#define CLV_VPN_VPN_CLIENT_H

#include "client_control_adapter.h"
#include "client_data_adapter.h"
#include "client_dco_channel.h"
#include "client_tcp_channel.h"
#include "client_udp_channel.h"
#include "data_path_stats.h"
#include "openvpn/vpn_config.h"
#include "data_transport.h"

#include <nlohmann/json_fwd.hpp>

#include <asio/io_context.hpp>

#include <spdlog/fwd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
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
 * DataTransport instantiated with either UDP or DCO channel.
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
        WithDataTransport([&](auto &dp)
        { dp.SetStateCallback(std::move(cb)); });
    }

    void Connect();
    void Disconnect();

    VpnClientState GetState() const
    {
        VpnClientState s = VpnClientState::Disconnected;
        WithDataTransport([&](auto &dp)
        { s = dp.GetState(); });
        return s;
    }

    bool IsConnected() const
    {
        bool c = false;
        WithDataTransport([&](auto &dp)
        { c = dp.IsConnected(); });
        return c;
    }

    std::string GetAssignedIp() const
    {
        std::string ip;
        WithDataTransport([&](auto &dp)
        { ip = dp.GetAssignedIp(); });
        return ip;
    }

    std::vector<std::string> GetRoutes() const
    {
        std::vector<std::string> r;
        WithDataTransport([&](auto &dp)
        { r = dp.GetRoutes(); });
        return r;
    }

    std::vector<std::string> GetDnsServers() const
    {
        std::vector<std::string> d;
        WithDataTransport([&](auto &dp)
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
        WithDataTransport([&](auto &dp)
        { v = dp.GetStats().bytesSent; });
        return v;
    }

    std::uint64_t GetBytesReceived() const
    {
        std::uint64_t v = 0;
        WithDataTransport([&](auto &dp)
        { v = dp.GetStats().bytesReceived; });
        return v;
    }

    std::chrono::seconds GetUptime() const
    {
        std::chrono::seconds u(0);
        WithDataTransport([&](auto &dp)
        { u = dp.GetUptime(); });
        return u;
    }

    DataPathStats GetStats() const
    {
        DataPathStats s{};
        WithDataTransport([&](auto &dp)
        { s = dp.GetStats(); });
        return s;
    }

  private:
    using ClientUdpTransport = DataTransport<ClientUdpChannel,
                                             ClientDataAdapter,
                                             ClientControlAdapter>;
    using ClientDcoTransport = DataTransport<ClientDcoChannel,
                                             ClientDataAdapter,
                                             ClientControlAdapter>;
    using ClientTcpTransport = DataTransport<ClientTcpChannel,
                                             ClientDataAdapter,
                                             ClientControlAdapter>;
    using DataTransportVariant = std::variant<std::monostate, ClientUdpTransport, ClientDcoTransport, ClientTcpTransport>;

    template <typename F>
    void WithDataTransport(F &&f)
    {
        std::visit([&](auto &dp)
        {
            if constexpr (!std::is_same_v<std::decay_t<decltype(dp)>, std::monostate>)
                f(dp);
        },
                   data_transport_);
    }

    template <typename F>
    void WithDataTransport(F &&f) const
    {
        std::visit([&](auto &dp)
        {
            if constexpr (!std::is_same_v<std::decay_t<decltype(dp)>, std::monostate>)
                f(dp);
        },
                   data_transport_);
    }

    asio::io_context &io_context_;
    VpnConfig config_;
    std::shared_ptr<spdlog::logger> logger_;
    std::atomic<bool> running_{false};

    DataTransportVariant data_transport_;
};

} // namespace clv::vpn

#endif // CLV_VPN_VPN_CLIENT_H
