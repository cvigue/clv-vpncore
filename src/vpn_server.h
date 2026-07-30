// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_VPN_SERVER_H
#define CLV_VPN_VPN_SERVER_H

#include "cpu_affinity.h"
#include "data_plane.h"
#include "log_subsystems.h"
#include "openvpn/vpn_config.h"
#include "server_dco_control_adapter.h"
#include "server_tcp_control_adapter.h"
#include "server_udp_control_adapter.h"
#include "tunnel_zone.h"

#include <asio/io_context.hpp>

#include <spdlog/spdlog.h>

#include <atomic>
#include <memory>

namespace clv::vpn {

/**
 * @brief Thin factory shell around a server transport leaf.
 *
 * Owns configuration, loggers, the running flag, and a reference to the process
 * TunnelZone (kernel policy is installed on hub attachment registration;
 * Start() engages transit routing when zone policy requests ip_forward).
 * Protocol + channel live in ServerUdp/Dco/TcpTransport. Active engine is held
 * in @ref data_plane_.
 */
class VpnServer
{
  public:
    /**
     * @brief Construct a server for the given configuration and tunnel zone.
     * @param io_context ASIO context used by listeners and control planes
     * @param config Server configuration (must include server role)
     * @param zone Process-wide tunnel zone for hub attachment and routing policy
     */
    VpnServer(asio::io_context &io_context, const VpnConfig &config, TunnelZone &zone);

    /** @brief Stop the server and tear down listeners and sessions. */
    ~VpnServer();

    VpnServer(const VpnServer &) = delete;
    VpnServer &operator=(const VpnServer &) = delete;
    VpnServer(VpnServer &&) noexcept = delete;
    VpnServer &operator=(VpnServer &&) noexcept = delete;

    /**
     * @brief Start listeners and engage zone transit routing when configured.
     *
     * Idempotent while already running.
     */
    void Start();

    /**
     * @brief Stop listeners, drain sessions, and disengage transit routing.
     *
     * Safe to call when not running.
     */
    void Stop();

    /**
     * @brief Whether Start() has been called and Stop() has not.
     * @return Current running flag
     */
    bool IsRunning() const
    {
        return running_;
    }

    /**
     * @brief Immutable server configuration.
     * @return Reference to the config supplied at construction
     */
    const VpnConfig &GetConfig() const
    {
        return config_;
    }

  private:
    using ServerDataPlane = DataPlane<ServerUdpTransport, ServerDcoTransport, ServerTcpTransport>;

    asio::io_context &io_context_;
    VpnConfig config_;
    TunnelZone &zone_;
    logging::SubsystemLoggerManager logger_manager_;
    std::shared_ptr<spdlog::logger> logger_;
    std::atomic<bool> running_ = false;

    ServerDataPlane data_plane_;
};

} // namespace clv::vpn

#endif // CLV_VPN_VPN_SERVER_H
