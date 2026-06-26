// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_VPN_SERVER_H
#define CLV_VPN_VPN_SERVER_H

#include "cpu_affinity.h"
#include "log_subsystems.h"
#include "openvpn/dco_data_channel.h"
#include "openvpn/tcp_data_channel.h"
#include "openvpn/udp_data_channel.h"
#include "openvpn/vpn_config.h"
#include "scoped_masquerade.h"
#include "server_tcp_control_adapter.h"
#include "server_udp_control_adapter.h"
#include "server_dco_control_adapter.h"
#include "server_data_adapter.h"
#include "data_transport.h"

#include <asio/io_context.hpp>

#include <spdlog/spdlog.h>

#include <atomic>
#include <memory>
#include <optional>
#include <type_traits>
#include <variant>

namespace clv::vpn {

/**
 * @brief Thin factory shell around a fully composed DataTransport.
 *
 * Owns configuration, loggers, masquerade guards, and the running flag.
 * All control-plane intelligence lives in DataTransport ControlAdapterT template
 * argument.
 */
class VpnServer
{
  public:
    VpnServer(asio::io_context &io_context, const VpnConfig &config);
    ~VpnServer();

    VpnServer(const VpnServer &) = delete;
    VpnServer &operator=(const VpnServer &) = delete;
    VpnServer(VpnServer &&) noexcept = delete;
    VpnServer &operator=(VpnServer &&) noexcept = delete;

    void Start();
    void Stop();

    bool IsRunning() const
    {
        return running_;
    }
    const VpnConfig &GetConfig() const
    {
        return config_;
    }

  private:
    using ServerUdpTransport = DataTransport<UdpDataChannel,
                                             ServerDataAdapter,
                                             ServerUdpControlAdapter>;
    using ServerDcoTransport = DataTransport<DcoDataChannel,
                                             ServerDataAdapter,
                                             ServerDcoControlAdapter>;
    using ServerTcpTransport = DataTransport<TcpDataChannel,
                                             ServerDataAdapter,
                                             ServerTcpControlAdapter>;
    using DataTransportVariant = std::variant<std::monostate, ServerUdpTransport, ServerDcoTransport, ServerTcpTransport>;

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
    logging::SubsystemLoggerManager logger_manager_;
    std::shared_ptr<spdlog::logger> logger_;
    std::atomic<bool> running_ = false;

    DataTransportVariant data_transport_;

    std::optional<ScopedMasquerade> masquerade_guard_;
    std::optional<ScopedMasquerade> masquerade6_guard_;
};

} // namespace clv::vpn

#endif // CLV_VPN_VPN_SERVER_H
