// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "openvpn/vpn_config.h"

#include "openvpn/crypto_algorithms.h"
#include "transport/batch_constants.h"

#include <config_io.h>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <parse_intake.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace clv::vpn {

namespace {

constexpr std::int64_t kIntMax = std::numeric_limits<int>::max();

[[nodiscard]] std::int64_t GetBoundedInt(const nlohmann::json &json,
                                         const char *key,
                                         std::int64_t min_value,
                                         std::int64_t max_value)
{
    return clv::RequireJsonIntOrThrow<std::int64_t>(
        json,
        key,
        min_value,
        max_value,
        {.source = "VpnConfigParser", .field = key},
        [](const std::string &msg)
    { return std::runtime_error(msg); });
}

} // namespace

VpnConfig VpnConfigParser::ParseFile(const std::filesystem::path &filepath)
{
    return ParseJson(config::ParseJsonObjectFile(filepath, "VpnConfigParser"));
}

VpnConfig VpnConfigParser::ParseString(const std::string &jsonString)
{
    return ParseJson(config::ParseJsonString(jsonString, "VpnConfigParser"));
}

VpnConfig VpnConfigParser::ParseJson(const nlohmann::json &json)
{
    VpnConfig config;

    if (!json.is_object())
    {
        throw std::runtime_error("VpnConfigParser: Root JSON must be an object");
    }

    // ---- Parse sections ----
    if (json.contains("server") && json["server"].is_object())
    {
        config.server = ParseServerConfig(json["server"]);
    }
    if (json.contains("client") && json["client"].is_object())
    {
        config.client = ParseClientConfig(json["client"]);
    }
    if (json.contains("process"))
    {
        config.process = ParseProcessConfig(json["process"]);
    }
    if (json.contains("performance"))
    {
        config.performance = ParsePerformanceConfig(json["performance"]);
    }
    if (json.contains("logging"))
    {
        config.logging = ParseLoggingConfig(json["logging"]);
    }

    return config;
}

void VpnConfigParser::ValidateServer(const VpnConfig &config, std::shared_ptr<spdlog::logger> logger)
{
    if (!config.server)
    {
        throw std::runtime_error("VpnConfig: No server role configured");
    }
    const auto &srv = *config.server;

    if (srv.port == 0)
    {
        throw std::runtime_error("VpnConfig: Invalid port number");
    }
    if (srv.proto != "udp" && srv.proto != "tcp")
    {
        throw std::runtime_error("VpnConfig: Protocol must be 'udp' or 'tcp'");
    }
    if (srv.proto == "tcp" && config.performance.enable_dco)
    {
        throw std::runtime_error("VpnConfig: DCO (Data Channel Offload) is not supported with TCP transport. "
                                 "Set enable_dco=false or use proto=udp.");
    }
    if (srv.dev != "tun" && srv.dev != "tap")
    {
        throw std::runtime_error("VpnConfig: Device must be 'tun' or 'tap'");
    }

    // Validate crypto settings
    if (srv.ca_cert.empty())
    {
        throw std::runtime_error("VpnConfig: CA certificate is required");
    }
    if (srv.cert.empty())
    {
        throw std::runtime_error("VpnConfig: Server certificate path is required");
    }
    if (srv.key.empty())
    {
        throw std::runtime_error("VpnConfig: Server key path is required");
    }

    // Validate network settings
    if (srv.network.empty())
    {
        throw std::runtime_error("VpnConfig: Server network is required");
    }

    // Check file existence for certificates
    std::vector<std::filesystem::path> cert_files;
    cert_files.push_back(srv.ca_cert);
    cert_files.push_back(srv.cert);
    cert_files.push_back(srv.key);

    if (!srv.dh_params.empty())
    {
        cert_files.push_back(srv.dh_params);
    }

    for (const auto &cert_file : cert_files)
    {
        if (!std::filesystem::exists(cert_file))
        {
            if (logger)
                logger->warn("Certificate file not found: {}", cert_file.string());
        }
    }

#ifndef _WIN32
    // Warn if private key files are readable by group or others
    for (const auto &key_file : {srv.key, srv.tls_crypt_key, srv.tls_crypt_v2_key})
    {
        if (key_file.empty())
            continue;
        struct stat st;
        if (::stat(key_file.c_str(), &st) == 0)
        {
            if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH))
            {
                if (logger)
                    logger->warn("Key file '{}' has insecure permissions (readable by group or others)",
                                 key_file.string());
            }
        }
    }
#endif
}

void VpnConfigParser::ValidateClient(const VpnConfig &config, std::shared_ptr<spdlog::logger> logger)
{
    if (!config.client)
    {
        throw std::runtime_error("VpnConfig: No client role configured");
    }
    const auto &cli = *config.client;

    if (cli.server_host.empty())
    {
        throw std::runtime_error("VpnConfig: Client server_host is required");
    }
    if (cli.server_port == 0)
    {
        throw std::runtime_error("VpnConfig: Client server_port must be non-zero");
    }

    try
    {
        auto resolved = openvpn::ResolveDataCipherPolicy(cli.data_ciphers, cli.allow_deprecated_data_ciphers);
        if (!resolved.deprecated_ciphers.empty() && logger)
        {
            for (const auto &cipher : resolved.deprecated_ciphers)
                logger->warn("Deprecated data-cipher '{}' enabled by explicit operator policy", cipher);
        }
    }
    catch (const std::invalid_argument &e)
    {
        throw std::runtime_error(std::string("VpnConfig: Invalid client data-ciphers policy: ") + e.what());
    }

#ifndef _WIN32
    // Warn if private key files are readable by group or others
    for (const auto &key_file : {cli.key, cli.tls_crypt_key, cli.tls_crypt_v2_key})
    {
        if (key_file.empty())
            continue;
        struct stat st;
        if (::stat(key_file.c_str(), &st) == 0)
        {
            if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH))
            {
                if (logger)
                    logger->warn("Key file '{}' has insecure permissions (readable by group or others)",
                                 key_file.string());
            }
        }
    }
#endif
}

// ============================================================================
// Section parsers
// ============================================================================

VpnConfig::ServerConfig VpnConfigParser::ParseServerConfig(const nlohmann::json &json)
{
    VpnConfig::ServerConfig s;

    // Listen settings
    if (json.contains("host"))
        s.host = json["host"];
    if (json.contains("port"))
        s.port = static_cast<uint16_t>(GetBoundedInt(json, "port", 1, 65535));
    if (json.contains("proto"))
        s.proto = json["proto"];
    if (json.contains("dev"))
        s.dev = json["dev"];
    if (json.contains("dev_node"))
        s.dev_node = json["dev_node"];
    if (json.contains("keepalive") && json["keepalive"].is_array() && json["keepalive"].size() == 2)
    {
        const auto &ka = json["keepalive"];
        if (!ka[0].is_number_integer() || !ka[1].is_number_integer())
            throw std::runtime_error("VpnConfigParser: 'keepalive' entries must be integers");
        s.keepalive = {std::clamp<std::int64_t>(ka[0].get<std::int64_t>(), 0, kIntMax),
                       std::clamp<std::int64_t>(ka[1].get<std::int64_t>(), 0, kIntMax)};
    }

    // Crypto
    if (json.contains("cipher"))
        s.cipher = json["cipher"];
    if (json.contains("auth"))
        s.auth = json["auth"];
    if (json.contains("tls_cipher"))
        s.tls_cipher = json["tls_cipher"];
    if (json.contains("keysize"))
        s.keysize = static_cast<size_t>(GetBoundedInt(json, "keysize", 128, 4096));
    if (json.contains("ca_cert"))
        s.ca_cert = json["ca_cert"].get<std::string>();
    if (json.contains("tls_crypt_key"))
        s.tls_crypt_key = json["tls_crypt_key"].get<std::string>();
    if (json.contains("tls_crypt_v2_key"))
        s.tls_crypt_v2_key = json["tls_crypt_v2_key"].get<std::string>();

    // Server identity
    if (json.contains("cert"))
        s.cert = json["cert"].get<std::string>();
    if (json.contains("key"))
        s.key = json["key"].get<std::string>();
    if (json.contains("dh_params"))
        s.dh_params = json["dh_params"].get<std::string>();

    // Network
    if (json.contains("network"))
        s.network = json["network"];
    if (json.contains("network_v6"))
        s.network_v6 = json["network_v6"];
    if (json.contains("bridge_ip"))
        s.bridge_ip = json["bridge_ip"];
    if (json.contains("client_dns") && json["client_dns"].is_array())
    {
        s.client_dns.clear();
        for (const auto &dns : json["client_dns"])
            s.client_dns.push_back(dns);
    }
    if (json.contains("client_dns_search_domains") && json["client_dns_search_domains"].is_array())
    {
        s.client_dns_search_domains.clear();
        for (const auto &d : json["client_dns_search_domains"])
            s.client_dns_search_domains.push_back(d);
    }
    if (json.contains("routes") && json["routes"].is_array())
    {
        s.routes.clear();
        for (const auto &route : json["routes"])
            s.routes.push_back(route);
    }
    if (json.contains("routes_v6") && json["routes_v6"].is_array())
    {
        s.routes_v6.clear();
        for (const auto &route : json["routes_v6"])
            s.routes_v6.push_back(route);
    }
    if (json.contains("push_routes"))
        s.push_routes = json["push_routes"];
    if (json.contains("client_to_client"))
        s.client_to_client = json["client_to_client"];
    if (json.contains("tun_mtu"))
        s.tun_mtu = static_cast<int>(GetBoundedInt(json, "tun_mtu", std::numeric_limits<int>::min(), kIntMax));
    if (json.contains("tun_txqueuelen"))
        s.tun_txqueuelen = static_cast<int>(
            GetBoundedInt(json, "tun_txqueuelen", std::numeric_limits<int>::min(), kIntMax));

    // Validate ranges
    s.tun_mtu = std::clamp(s.tun_mtu, 576, 9000);
    if (s.tun_txqueuelen < 0)
        s.tun_txqueuelen = 0;

    // Auth
    if (json.contains("client_cert_required"))
        s.client_cert_required = json["client_cert_required"];
    if (json.contains("username_password"))
        s.username_password = json["username_password"];
    if (json.contains("crl_verify"))
        s.crl_verify = json["crl_verify"];
    if (json.contains("crl_file"))
        s.crl_file = json["crl_file"].get<std::string>();

    // Server-specific tuning
    if (json.contains("max_clients"))
        s.max_clients = static_cast<size_t>(GetBoundedInt(json, "max_clients", 1, 65536));
    if (json.contains("ping_timer_remote"))
        s.ping_timer_remote = static_cast<int>(GetBoundedInt(json, "ping_timer_remote", 0, kIntMax));
    if (json.contains("renegotiate_seconds"))
        s.renegotiate_seconds = static_cast<int>(
            GetBoundedInt(json, "renegotiate_seconds", std::numeric_limits<int>::min(), kIntMax));

    if (s.renegotiate_seconds < 0)
        s.renegotiate_seconds = 0;
    if (s.renegotiate_seconds > 0 && s.renegotiate_seconds < VpnConfig::ServerConfig::kMinRenegotiateSeconds)
    {
        s.renegotiate_seconds = VpnConfig::ServerConfig::kMinRenegotiateSeconds;
    }

    if (json.contains("psid_cookie"))
        s.psid_cookie = json["psid_cookie"].get<bool>();
    if (json.contains("handshake_window"))
        s.handshake_window = static_cast<int>(GetBoundedInt(json, "handshake_window", 1, 86400));
    if (json.contains("tls_crypt_v2_cookie_mode"))
    {
        s.tls_crypt_v2_cookie_mode = json["tls_crypt_v2_cookie_mode"].get<std::string>();
        if (s.tls_crypt_v2_cookie_mode != "force-cookie"
            && s.tls_crypt_v2_cookie_mode != "allow-noncookie")
        {
            throw std::runtime_error(
                "VpnConfigParser: tls_crypt_v2_cookie_mode must be "
                "'force-cookie' or 'allow-noncookie'");
        }
    }

    return s;
}

VpnConfig::ClientConfig VpnConfigParser::ParseClientConfig(const nlohmann::json &json)
{
    VpnConfig::ClientConfig c;

    if (json.contains("server_host"))
        c.server_host = json["server_host"];
    if (json.contains("server_port"))
        c.server_port = static_cast<uint16_t>(GetBoundedInt(json, "server_port", 1, 65535));
    if (json.contains("proto"))
        c.proto = json["proto"];
    else if (json.contains("protocol"))
        c.proto = json["protocol"];

    // Normalise legacy address-family suffixes: udp6 / tcp6 are not valid JSON
    // config values; reject them with a clear error so the operator knows to
    // update the file.  They are still accepted from .ovpn files (where they
    // carry interop meaning) and are normalised there before reaching here.
    if (c.proto == "udp6" || c.proto == "tcp6")
        throw std::runtime_error(
            "VpnConfig: proto '" + c.proto + "' is not valid in JSON config. "
                                             "Use proto=\"udp\" (or \"tcp\") - the server address determines IPv6 behaviour.");
    if (c.proto != "udp" && c.proto != "tcp")
        throw std::runtime_error("VpnConfig: client proto must be 'udp' or 'tcp'");

    // Crypto
    if (json.contains("cipher"))
        c.cipher = json["cipher"];
    if (json.contains("auth"))
        c.auth = json["auth"];
    if (json.contains("data_ciphers") && json["data_ciphers"].is_array())
    {
        c.data_ciphers.clear();
        for (const auto &entry : json["data_ciphers"])
            c.data_ciphers.push_back(entry.get<std::string>());
    }
    if (json.contains("allow_deprecated_data_ciphers"))
        c.allow_deprecated_data_ciphers = json["allow_deprecated_data_ciphers"];
    if (json.contains("ca_cert"))
        c.ca_cert = json["ca_cert"].get<std::string>();
    if (json.contains("ca_cert_pem"))
        c.ca_cert_pem = json["ca_cert_pem"];
    if (json.contains("tls_crypt_key"))
        c.tls_crypt_key = json["tls_crypt_key"].get<std::string>();
    if (json.contains("tls_crypt_key_pem"))
        c.tls_crypt_key_pem = json["tls_crypt_key_pem"];
    if (json.contains("tls_crypt_v2_key"))
        c.tls_crypt_v2_key = json["tls_crypt_v2_key"].get<std::string>();
    if (json.contains("tls_crypt_v2_key_pem"))
        c.tls_crypt_v2_key_pem = json["tls_crypt_v2_key_pem"];

    // Client identity
    if (json.contains("cert"))
        c.cert = json["cert"].get<std::string>();
    if (json.contains("cert_pem"))
        c.cert_pem = json["cert_pem"];
    if (json.contains("key"))
        c.key = json["key"].get<std::string>();
    if (json.contains("key_pem"))
        c.key_pem = json["key_pem"];

    // TUN
    if (json.contains("dev_name"))
        c.dev_name = json["dev_name"];

    // Reconnection
    if (json.contains("reconnect_delay_seconds"))
        c.reconnect_delay_seconds = static_cast<int>(
            GetBoundedInt(json, "reconnect_delay_seconds", 0, kIntMax));
    if (json.contains("max_reconnect_attempts"))
        c.max_reconnect_attempts = static_cast<int>(
            GetBoundedInt(json, "max_reconnect_attempts", 0, kIntMax));

    // Keepalive
    if (json.contains("keepalive") && json["keepalive"].is_array() && json["keepalive"].size() >= 2)
    {
        const auto &ka = json["keepalive"];
        if (!ka[0].is_number_integer() || !ka[1].is_number_integer())
            throw std::runtime_error("VpnConfigParser: 'keepalive' entries must be integers");
        c.keepalive_interval = static_cast<int>(std::clamp<std::int64_t>(ka[0].get<std::int64_t>(), 0, kIntMax));
        c.keepalive_timeout = static_cast<int>(std::clamp<std::int64_t>(ka[1].get<std::int64_t>(), 0, kIntMax));
    }
    if (json.contains("keepalive_interval"))
        c.keepalive_interval = static_cast<int>(GetBoundedInt(json, "keepalive_interval", 0, kIntMax));
    if (json.contains("keepalive_timeout"))
        c.keepalive_timeout = static_cast<int>(GetBoundedInt(json, "keepalive_timeout", 0, kIntMax));

    // Renegotiation
    if (json.contains("renegotiate_seconds"))
        c.renegotiate_seconds = static_cast<int>(GetBoundedInt(json, "renegotiate_seconds", 0, kIntMax));

    return c;
}

VpnConfig::ProcessConfig VpnConfigParser::ParseProcessConfig(const nlohmann::json &json)
{
    VpnConfig::ProcessConfig proc;

    clv::ParseAffinityField(json, "cpu_affinity", proc.cpu_affinity);

    if (json.contains("transit_routing"))
        proc.transit_routing = json["transit_routing"].get<bool>();

    return proc;
}

VpnConfig::PerformanceConfig VpnConfigParser::ParsePerformanceConfig(const nlohmann::json &json)
{
    VpnConfig::PerformanceConfig p;

    constexpr auto kFullIntRange = std::numeric_limits<int>::min();
    auto read_int = [&json](const char *key, int &out)
    {
        if (json.contains(key))
            out = static_cast<int>(GetBoundedInt(json, key, kFullIntRange, kIntMax));
    };

    if (json.contains("enable_dco"))
        p.enable_dco = json["enable_dco"];
    read_int("stats_interval_seconds", p.stats_interval_seconds);
    read_int("socket_recv_buffer", p.socket_recv_buffer);
    read_int("socket_send_buffer", p.socket_send_buffer);
    read_int("batch_size", p.batch_size);
    read_int("tx_drain_depth", p.tx_drain_depth);
    read_int("tx_send_batch", p.tx_send_batch);
    read_int("tx_small_pkt_flush", p.tx_small_pkt_flush);
    read_int("max_recv", p.max_recv);
    read_int("rx_process_batch", p.rx_process_batch);

    clv::ParseAffinityField(json, "rx_thread_affinity", p.rx_thread_affinity);
    clv::ParseAffinityField(json, "tx_thread_affinity", p.tx_thread_affinity);

    // Validate ranges
    if (p.socket_recv_buffer < 0)
        p.socket_recv_buffer = 0;
    if (p.socket_send_buffer < 0)
        p.socket_send_buffer = 0;
    p.batch_size = std::clamp(p.batch_size, 0, static_cast<int>(transport::kMaxBatchSize));
    if (p.tx_drain_depth < 1)
        p.tx_drain_depth = 1;
    if (p.tx_send_batch < 0)
        p.tx_send_batch = 0;
    if (p.tx_small_pkt_flush < 0)
        p.tx_small_pkt_flush = 0;
    if (p.max_recv < 0)
        p.max_recv = 0;
    if (p.rx_process_batch < 0)
        p.rx_process_batch = 0;
    return p;
}

VpnConfig::LoggingConfig VpnConfigParser::ParseLoggingConfig(const nlohmann::json &json)
{
    VpnConfig::LoggingConfig l;

    if (json.contains("verbosity"))
    {
        auto &v = json["verbosity"];
        if (v.is_string())
            l.verbosity = v.get<std::string>();
        else if (v.is_number_integer())
            l.verbosity = std::to_string(v.get<int>());
    }

    if (json.contains("subsystems") && json["subsystems"].is_object())
    {
        for (auto &[key, val] : json["subsystems"].items())
        {
            if (val.is_string())
                l.subsystem_levels[key] = val.get<std::string>();
            else if (val.is_number_integer())
                l.subsystem_levels[key] = std::to_string(val.get<int>());
        }
    }

    return l;
}

} // namespace clv::vpn