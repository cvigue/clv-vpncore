// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "vpn_config.h"
#include "nlohmann/json_fwd.hpp"
#include "transport/batch_constants.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <string>
#include <vector>

namespace clv::vpn {

OpenVpnConfig OpenVpnConfigParser::ParseFile(const std::filesystem::path &filepath)
{
    if (!std::filesystem::exists(filepath))
    {
        throw std::runtime_error("OpenVpnConfigParser: Config file not found: " + filepath.string());
    }

    std::ifstream file(filepath);
    if (!file.is_open())
    {
        throw std::runtime_error("OpenVpnConfigParser: Cannot open config file: " + filepath.string());
    }

    nlohmann::json json;
    try
    {
        file >> json;
    }
    catch (const nlohmann::json::parse_error &e)
    {
        throw std::runtime_error("OpenVpnConfigParser: JSON parse error in " + filepath.string() + ": " + e.what());
    }

    return ParseJson(json);
}

OpenVpnConfig OpenVpnConfigParser::ParseString(const std::string &jsonString)
{
    nlohmann::json json;
    try
    {
        json = nlohmann::json::parse(jsonString);
    }
    catch (const nlohmann::json::parse_error &e)
    {
        throw std::runtime_error("OpenVpnConfigParser: JSON parse error: " + std::string(e.what()));
    }

    return ParseJson(json);
}

OpenVpnConfig OpenVpnConfigParser::ParseJson(const nlohmann::json &json)
{
    OpenVpnConfig config;

    if (!json.is_object())
    {
        throw std::runtime_error("OpenVpnConfigParser: Root JSON must be an object");
    }

    // Parse each section
    if (json.contains("server"))
    {
        config.server = ParseServerSettings(json["server"]);
    }
    if (json.contains("crypto"))
    {
        config.crypto = ParseCryptoSettings(json["crypto"]);
    }
    if (json.contains("network"))
    {
        config.network = ParseNetworkSettings(json["network"]);
    }
    if (json.contains("auth"))
    {
        config.auth = ParseAuthSettings(json["auth"]);
    }
    if (json.contains("performance"))
    {
        config.performance = ParsePerformanceSettings(json["performance"]);
    }
    if (json.contains("logging"))
    {
        config.logging = ParseLoggingSettings(json["logging"]);
    }

    return config;
}

void OpenVpnConfigParser::Validate(const OpenVpnConfig &config, std::shared_ptr<spdlog::logger> logger)
{
    // Validate server settings
    if (config.server.port == 0)
    {
        throw std::runtime_error("OpenVpnConfig: Invalid port number");
    }
    if (config.server.proto != "udp" && config.server.proto != "tcp")
    {
        throw std::runtime_error("OpenVpnConfig: Protocol must be 'udp' or 'tcp'");
    }
    if (config.server.proto == "tcp" && config.performance.enable_dco)
    {
        throw std::runtime_error("OpenVpnConfig: DCO (Data Channel Offload) is not supported with TCP transport. "
                                 "Set enable_dco=false or use proto=udp.");
    }
    if (config.server.dev != "tun" && config.server.dev != "tap")
    {
        throw std::runtime_error("OpenVpnConfig: Device must be 'tun' or 'tap'");
    }

    // Validate crypto settings
    if (config.crypto.ca_cert.empty())
    {
        throw std::runtime_error("OpenVpnConfig: CA certificate path is required");
    }
    if (config.crypto.server_cert.empty())
    {
        throw std::runtime_error("OpenVpnConfig: Server certificate path is required");
    }
    if (config.crypto.server_key.empty())
    {
        throw std::runtime_error("OpenVpnConfig: Server key path is required");
    }

    // Validate network settings
    if (config.network.server_network.empty())
    {
        throw std::runtime_error("OpenVpnConfig: Server network is required");
    }

    // Check file existence for certificates
    std::vector<std::filesystem::path> cert_files = {
        config.crypto.ca_cert,
        config.crypto.server_cert,
        config.crypto.server_key};

    if (!config.crypto.dh_params.empty())
    {
        cert_files.push_back(config.crypto.dh_params);
    }

    for (const auto &cert_file : cert_files)
    {
        if (!std::filesystem::exists(cert_file))
        {
            if (logger)
                logger->warn("Certificate file not found: {}", cert_file.string());
        }
    }
}

OpenVpnConfig::ServerSettings OpenVpnConfigParser::ParseServerSettings(const nlohmann::json &json)
{
    OpenVpnConfig::ServerSettings settings;

    if (json.contains("host"))
        settings.host = json["host"];
    if (json.contains("port"))
        settings.port = json["port"];
    if (json.contains("proto"))
        settings.proto = json["proto"];
    if (json.contains("dev"))
        settings.dev = json["dev"];
    if (json.contains("dev_node"))
        settings.dev_node = json["dev_node"];
    if (json.contains("keepalive") && json["keepalive"].is_array() && json["keepalive"].size() == 2)
    {
        settings.keepalive = {json["keepalive"][0], json["keepalive"][1]};
    }

    return settings;
}

OpenVpnConfig::CryptoSettings OpenVpnConfigParser::ParseCryptoSettings(const nlohmann::json &json)
{
    OpenVpnConfig::CryptoSettings settings;

    if (json.contains("ca_cert"))
        settings.ca_cert = json["ca_cert"].get<std::string>();
    if (json.contains("server_cert"))
        settings.server_cert = json["server_cert"].get<std::string>();
    if (json.contains("server_key"))
        settings.server_key = json["server_key"].get<std::string>();
    if (json.contains("dh_params"))
        settings.dh_params = json["dh_params"].get<std::string>();
    if (json.contains("cipher"))
        settings.cipher = json["cipher"];
    if (json.contains("auth"))
        settings.auth = json["auth"];
    if (json.contains("tls_cipher"))
        settings.tls_cipher = json["tls_cipher"];
    if (json.contains("keysize"))
        settings.keysize = json["keysize"];
    if (json.contains("tls_crypt_key"))
        settings.tls_crypt_key = json["tls_crypt_key"].get<std::string>();

    return settings;
}

OpenVpnConfig::NetworkSettings OpenVpnConfigParser::ParseNetworkSettings(const nlohmann::json &json)
{
    OpenVpnConfig::NetworkSettings settings;

    if (json.contains("server_network"))
        settings.server_network = json["server_network"];
    if (json.contains("server_network_v6"))
        settings.server_network_v6 = json["server_network_v6"];
    if (json.contains("server_bridge"))
        settings.server_bridge = json["server_bridge"];

    if (json.contains("client_dns") && json["client_dns"].is_array())
    {
        settings.client_dns.clear();
        for (const auto &dns : json["client_dns"])
        {
            settings.client_dns.push_back(dns);
        }
    }

    if (json.contains("routes") && json["routes"].is_array())
    {
        settings.routes.clear();
        for (const auto &route : json["routes"])
        {
            settings.routes.push_back(route);
        }
    }

    if (json.contains("routes_v6") && json["routes_v6"].is_array())
    {
        settings.routes_v6.clear();
        for (const auto &route : json["routes_v6"])
        {
            settings.routes_v6.push_back(route);
        }
    }

    if (json.contains("push_routes"))
        settings.push_routes = json["push_routes"];
    if (json.contains("tun_mtu"))
        settings.tun_mtu = json["tun_mtu"];
    if (json.contains("tun_txqueuelen"))
        settings.tun_txqueuelen = json["tun_txqueuelen"];

    // Validate ranges
    settings.tun_mtu = std::clamp(settings.tun_mtu, 576, 9000);
    if (settings.tun_txqueuelen < 0)
        settings.tun_txqueuelen = 0;

    return settings;
}

OpenVpnConfig::AuthSettings OpenVpnConfigParser::ParseAuthSettings(const nlohmann::json &json)
{
    OpenVpnConfig::AuthSettings settings;

    if (json.contains("client_cert_required"))
        settings.client_cert_required = json["client_cert_required"];
    if (json.contains("username_password"))
        settings.username_password = json["username_password"];
    if (json.contains("crl_verify"))
        settings.crl_verify = json["crl_verify"];
    if (json.contains("crl_file"))
        settings.crl_file = json["crl_file"].get<std::string>();

    return settings;
}

OpenVpnConfig::PerformanceSettings OpenVpnConfigParser::ParsePerformanceSettings(const nlohmann::json &json)
{
    OpenVpnConfig::PerformanceSettings settings;

    if (json.contains("max_clients"))
        settings.max_clients = json["max_clients"];

    if (json.contains("ping_timer_remote"))
        settings.ping_timer_remote = json["ping_timer_remote"];
    if (json.contains("renegotiate_seconds"))
        settings.renegotiate_seconds = json["renegotiate_seconds"];
    if (json.contains("enable_dco"))
        settings.enable_dco = json["enable_dco"];
    if (json.contains("stats_interval_seconds"))
        settings.stats_interval_seconds = json["stats_interval_seconds"];
    if (json.contains("socket_recv_buffer"))
        settings.socket_recv_buffer = json["socket_recv_buffer"];
    if (json.contains("socket_send_buffer"))
        settings.socket_send_buffer = json["socket_send_buffer"];
    if (json.contains("batch_size"))
        settings.batch_size = json["batch_size"];
    if (json.contains("process_quanta"))
        settings.process_quanta = json["process_quanta"];
    if (json.contains("lame_duck_seconds"))
        settings.lame_duck_seconds = json["lame_duck_seconds"];

    if (json.contains("cpu_affinity"))
    {
        auto &val = json["cpu_affinity"];
        if (val.is_string())
        {
            auto s = val.get<std::string>();
            if (s == "off")
                settings.cpu_affinity = -1; // kAffinityOff
            else if (s == "auto")
                settings.cpu_affinity = -2; // kAffinityAuto
            else if (s == "adaptive")
                settings.cpu_affinity = -3; // kAffinityAdaptive
        }
        else if (val.is_number_integer())
            settings.cpu_affinity = val.get<int>();
        else if (val.is_object())
        {
            // Object form: {"mode": "adaptive", "probe_interval": 10, ...}
            if (val.contains("mode"))
            {
                auto m = val["mode"].get<std::string>();
                if (m == "off")
                    settings.cpu_affinity = -1;
                else if (m == "auto")
                    settings.cpu_affinity = -2;
                else if (m == "adaptive")
                    settings.cpu_affinity = -3;
            }
            if (val.contains("probe_interval"))
                settings.adaptive_probe_interval = val["probe_interval"];
            if (val.contains("probe_duration"))
                settings.adaptive_probe_duration = val["probe_duration"];
            if (val.contains("baseline_windows"))
                settings.adaptive_baseline_windows = val["baseline_windows"];
            if (val.contains("ema_alpha"))
                settings.adaptive_ema_alpha = val["ema_alpha"];
            if (val.contains("throughput_threshold"))
                settings.adaptive_throughput_threshold = val["throughput_threshold"];
            if (val.contains("window_seconds"))
                settings.adaptive_window_seconds = val["window_seconds"];
        }
        // else: leave at default -1 (off)
    }

    // Validate ranges — negative values clamp to 0 (meaning "use default")
    if (settings.socket_recv_buffer < 0)
        settings.socket_recv_buffer = 0;
    if (settings.socket_send_buffer < 0)
        settings.socket_send_buffer = 0;
    settings.batch_size = std::clamp(settings.batch_size, 0, static_cast<int>(transport::kMaxBatchSize));
    if (settings.process_quanta < 0)
        settings.process_quanta = 0;

    return settings;
}

OpenVpnConfig::LoggingSettings OpenVpnConfigParser::ParseLoggingSettings(const nlohmann::json &json)
{
    OpenVpnConfig::LoggingSettings settings;

    if (json.contains("verbosity"))
    {
        auto &v = json["verbosity"];
        if (v.is_string())
            settings.verbosity = v.get<std::string>();
        else if (v.is_number_integer())
            settings.verbosity = std::to_string(v.get<int>());
    }

    if (json.contains("subsystems") && json["subsystems"].is_object())
    {
        for (auto &[key, val] : json["subsystems"].items())
        {
            if (val.is_string())
                settings.subsystem_levels[key] = val.get<std::string>();
            else if (val.is_number_integer())
                settings.subsystem_levels[key] = std::to_string(val.get<int>());
        }
    }

    return settings;
}

} // namespace clv::vpn