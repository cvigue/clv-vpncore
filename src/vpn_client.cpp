// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "vpn_client.h"

#include "client_control_adapter.h"
#include "nlohmann/json_fwd.hpp"
#include "openvpn/ovpn_config_parser.h"
#include "openvpn/vpn_config.h"
#include "transport_mode.h"
#include "transport/batch_constants.h"

#include <exception>
#include <nlohmann/json.hpp>

#include <spdlog/sinks/stdout_color_sinks.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <filesystem>
#include <string>
#include <utility>
#include <variant>

namespace clv::vpn {

// ============================================================================
// VpnClientConfig Convenience Loaders
// ============================================================================

VpnConfig VpnClientConfig::ParseJson(const nlohmann::json &json)
{
    return VpnConfigParser::ParseJson(json);
}

VpnConfig VpnClientConfig::LoadFromFile(const std::string &path)
{
    return VpnConfigParser::ParseFile(path);
}

VpnConfig VpnClientConfig::LoadFromOvpnFile(const std::string &path)
{
    auto ovpn = OvpnConfigParser::ParseFile(path);
    OvpnConfigParser::Validate(ovpn);

    VpnConfig config;

    // Client role
    VpnConfig::ClientConfig cli;
    cli.server_host = ovpn.remote.host;
    cli.server_port = ovpn.remote.port;
    // Normalise address-family suffixes from .ovpn files: udp6/tcp6 encode an
    // IPv6-only preference; store that as the ipv6_only flag and collapse proto
    // to the bare transport name so the rest of the stack sees only "udp"/"tcp".
    if (ovpn.remote.proto == "udp6")
    {
        cli.proto = "udp";
        cli.ipv6_only = true;
    }
    else if (ovpn.remote.proto == "tcp6")
    {
        cli.proto = "tcp";
        cli.ipv6_only = true;
    }
    else
    {
        cli.proto = ovpn.remote.proto;
    }
    cli.keepalive_interval = ovpn.keepalive_interval;
    cli.keepalive_timeout = ovpn.keepalive_timeout;
    cli.dev_name = ""; // auto
    cli.reconnect_delay_seconds = ovpn.connect_retry_delay;
    cli.max_reconnect_attempts = ovpn.connect_retry_max;

    // Client identity — inline PEM from the .ovpn
    if (std::holds_alternative<std::string>(ovpn.client_cert))
        cli.cert_pem = std::get<std::string>(ovpn.client_cert);
    if (std::holds_alternative<std::string>(ovpn.client_key))
        cli.key_pem = std::get<std::string>(ovpn.client_key);

    config.client = std::move(cli);

    // Client crypto from .ovpn
    config.client->cipher = ovpn.cipher;
    config.client->auth = ovpn.auth;
    config.client->data_ciphers = ovpn.data_ciphers;

    if (std::holds_alternative<std::string>(ovpn.ca_cert))
        config.client->ca_cert_pem = std::get<std::string>(ovpn.ca_cert);

    if (std::holds_alternative<std::string>(ovpn.tls_crypt))
        config.client->tls_crypt_key_pem = std::get<std::string>(ovpn.tls_crypt);
    else if (std::holds_alternative<std::string>(ovpn.tls_auth))
        config.client->tls_crypt_key_pem = std::get<std::string>(ovpn.tls_auth);

    // Performance
    constexpr int kDefaultSocketBuf = 4 * 1024 * 1024;
    config.performance.socket_send_buffer = ovpn.sndbuf > 0 ? ovpn.sndbuf : kDefaultSocketBuf;
    config.performance.socket_recv_buffer = ovpn.rcvbuf > 0 ? ovpn.rcvbuf : kDefaultSocketBuf;
    config.performance.enable_dco = !ovpn.disable_dco;

    if (ovpn.stats_interval >= 0)
        config.performance.stats_interval_seconds = ovpn.stats_interval;

    // Logging
    config.logging.verbosity = std::to_string(ovpn.verbosity);

    return config;
}

VpnConfig VpnClientConfig::Load(const std::string &path)
{
    std::filesystem::path p(path);
    auto ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    if (ext == ".ovpn")
        return LoadFromOvpnFile(path);
    else
        return LoadFromFile(path);
}

// ============================================================================
// State Helpers
// ============================================================================

const char *VpnClientStateToString(VpnClientState state)
{
    switch (state)
    {
    case VpnClientState::Disconnected:
        return "Disconnected";
    case VpnClientState::Connecting:
        return "Connecting";
    case VpnClientState::TlsHandshake:
        return "TlsHandshake";
    case VpnClientState::Authenticating:
        return "Authenticating";
    case VpnClientState::Connected:
        return "Connected";
    case VpnClientState::Reconnecting:
        return "Reconnecting";
    case VpnClientState::Error:
        return "Error";
    default:
        return "Unknown";
    }
}

// ============================================================================
// VpnClient Implementation (thin factory shell)
// ============================================================================

static std::atomic<int> next_client_logger_index_{0};

VpnClient::VpnClient(asio::io_context &io_context, const VpnConfig &config)
    : io_context_(io_context),
      config_(config),
      logger_(spdlog::stdout_color_mt(
          [&]
{
    int idx = next_client_logger_index_++;
    return idx == 0 ? std::string("vpn_client")
                    : "vpn_client." + std::to_string(idx + 1);
}()))
{
    // Set log level from config
    auto log_level = spdlog::level::from_str(config_.logging.verbosity);
    if (log_level == spdlog::level::off && config_.logging.verbosity != "off")
    {
        try
        {
            int v = std::stoi(config_.logging.verbosity);
            log_level = static_cast<spdlog::level::level_enum>(
                std::max(0, static_cast<int>(spdlog::level::off) - v));
        }
        catch (...)
        {
        }
    }
    logger_->set_level(log_level);

    VpnConfigParser::ValidateClient(config_, logger_);

    auto mode = ResolveTransportMode(config_);
    logger_->info("Client data channel mode: {}", TransportModeString(mode));

    switch (mode)
    {
    case TransportMode::Tcp:
        data_transport_.emplace<ClientTcpTransport>(ClientControlConfig{io_context_, config_, *logger_, running_});
        break;
    case TransportMode::Dco:
        try
        {
            data_transport_.emplace<ClientDcoTransport>(ClientControlConfig{io_context_, config_, *logger_, running_});
        }
        catch (const std::exception &e)
        {
            logger_->warn("DCO initialization failed ({}), falling back to UDP", e.what());
            data_transport_.emplace<ClientUdpTransport>(ClientControlConfig{io_context_, config_, *logger_, running_});
        }
        break;
    case TransportMode::Udp:
        data_transport_.emplace<ClientUdpTransport>(ClientControlConfig{io_context_, config_, *logger_, running_});
        break;
    }

    logger_->info("VPN client initialized (batch_size={}, stats_interval={}s)",
                  transport::EffectiveBatchSize(config_.performance.batch_size),
                  config_.performance.stats_interval_seconds);
}

VpnClient::~VpnClient()
{
    if (running_)
        Disconnect();
}

void VpnClient::Connect()
{
    WithDataTransport([](auto &dp)
    { dp.Connect(); });
}

void VpnClient::Disconnect()
{
    WithDataTransport([](auto &dp)
    { dp.Disconnect(); });
}

} // namespace clv::vpn
