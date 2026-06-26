// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "vpn_server.h"

#include "cpu_affinity.h"
#include "log_subsystems.h"
#include "transport_mode.h"
#include "openvpn/vpn_config.h"
#include "server_control_base.h"
#include "transport/batch_constants.h"

#include <ci_string.h>

#include <exception>
#include <spdlog/sinks/stdout_color_sinks-inl.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <cstdlib>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <utility>

namespace clv::vpn {

namespace {

/// Parse a log level string: spdlog names or numeric "0"–"6".
spdlog::level::level_enum ParseLogLevel(const std::string &str)
{
    if (str.empty())
    {
        std::fprintf(stderr, "VpnServer: empty log level string\n");
        throw std::invalid_argument("empty log level");
    }

    if (!str.empty() && str.find_first_not_of("0123456789") == std::string::npos)
    {
        int n = 0;
        try
        {
            n = std::stoi(str);
        }
        catch (const std::exception &)
        {
            std::fprintf(stderr, "VpnServer: invalid numeric log level '%s'\n", str.c_str());
            throw std::invalid_argument("invalid numeric log level: " + str);
        }

        if (n >= 0 && n <= static_cast<int>(spdlog::level::off))
            return static_cast<spdlog::level::level_enum>(n);

        std::fprintf(stderr, "VpnServer: numeric log level out of range '%s'\n", str.c_str());
        throw std::out_of_range("numeric log level out of range: " + str);
    }

    clv::ci_string_view level_name{str};
    if (level_name == clv::ci_string_view{"trace"})
        return spdlog::level::trace;
    if (level_name == clv::ci_string_view{"debug"})
        return spdlog::level::debug;
    if (level_name == clv::ci_string_view{"info"})
        return spdlog::level::info;
    if (level_name == clv::ci_string_view{"warn"} || level_name == clv::ci_string_view{"warning"})
        return spdlog::level::warn;
    if (level_name == clv::ci_string_view{"error"} || level_name == clv::ci_string_view{"err"})
        return spdlog::level::err;
    if (level_name == clv::ci_string_view{"critical"})
        return spdlog::level::critical;
    if (level_name == clv::ci_string_view{"off"})
        return spdlog::level::off;

    std::fprintf(stderr, "VpnServer: invalid named log level '%s'\n", str.c_str());
    throw std::invalid_argument("invalid named log level: " + str);
}

} // namespace

VpnServer::VpnServer(asio::io_context &io_context, const VpnConfig &config)
    : io_context_(io_context),
      config_(config),
      logger_(spdlog::stdout_color_mt("vpn_server"))
{
    // Set log level from config (env var VPN_LOG_LEVEL overrides)
    auto env_level = std::getenv("VPN_LOG_LEVEL");
    spdlog::level::level_enum log_level;
    if (env_level)
        log_level = ParseLogLevel(env_level);
    else
        log_level = ParseLogLevel(config_.logging.verbosity);

    logger_->set_level(log_level);
    logger_manager_.SetDefaultLevel(log_level);

    VpnConfigParser::ValidateServer(config_, logger_);

    for (const auto &[name, level_str] : config_.logging.subsystem_levels)
    {
        auto subsys = logging::SubsystemFromString(name);
        std::string env_key = "SPDLOG_LEVEL_vpn_" + name;
        if (!std::getenv(env_key.c_str()))
            logger_manager_.SetSubsystemLevel(subsys, ParseLogLevel(level_str));
    }

    auto mode = ResolveTransportMode(config_);

    ServerControlConfig ctrl_cfg{
        .io_context = io_context_,
        .config = config_,
        .logger_manager = logger_manager_,
        .logger = logger_,
        .running = running_,
    };

    logger_->info("Data channel mode: {}", TransportModeString(mode));

    switch (mode)
    {
    case TransportMode::Tcp:
        data_transport_.emplace<ServerTcpTransport>(std::move(ctrl_cfg));
        break;
    case TransportMode::Dco:
        data_transport_.emplace<ServerDcoTransport>(std::move(ctrl_cfg));
        break;
    case TransportMode::Udp:
        data_transport_.emplace<ServerUdpTransport>(std::move(ctrl_cfg));
        break;
    }
}

VpnServer::~VpnServer()
{
    Stop();
}

void VpnServer::Start()
{
    if (running_)
        throw std::logic_error("Server already running");

    logger_->info("Starting VPN server on {}:{}", config_.server->host, config_.server->port);
    logger_->info("  cipher={} tun_mtu={} proto={}",
                  config_.server->cipher,
                  config_.server->tun_mtu,
                  config_.server->proto);
    logger_->info("  dco={} socket_recv_buf={} socket_send_buf={} batch_size={} stats_interval={}s cpu_affinity={}",
                  config_.performance.enable_dco,
                  config_.performance.socket_recv_buffer,
                  config_.performance.socket_send_buffer,
                  transport::EffectiveBatchSize(config_.performance.batch_size),
                  config_.performance.stats_interval_seconds,
                  AffinityModeString(config_.process.cpu_affinity));

    // Masquerade (RAII — reverted on Stop/destruction)
    masquerade_guard_.emplace(config_.server->network, *logger_);
    if (!config_.server->network_v6.empty())
        masquerade6_guard_.emplace(config_.server->network_v6, *logger_);

    running_ = true;

    WithDataTransport([](auto &dp)
    { dp.Start(); });

    logger_->info("VPN server started successfully");
    logger_->info("Waiting for client connections...");
}

void VpnServer::Stop()
{
    if (!running_)
        return;

    logger_->info("Stopping VPN server...");
    running_ = false;

    WithDataTransport([](auto &dp)
    { dp.Stop(); });

    masquerade6_guard_.reset();
    masquerade_guard_.reset();

    logger_->info("VPN server stopped");
}

} // namespace clv::vpn
