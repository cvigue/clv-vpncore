// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_CONFIG_H
#define CLV_VPN_CONFIG_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <filesystem>
#include <optional>

#include <nlohmann/json.hpp>

#include <memory>

namespace spdlog {
class logger;
}

namespace clv::vpn {

/**
    @brief Unified VPN configuration
    @details Single configuration type for both server and client roles.
    Shared settings (performance, logging) live at the top level.
    Role-specific settings (including crypto) live in optional ServerConfig / ClientConfig sections.
*/
struct VpnConfig
{
    // ---- Server role (present only when running as server) ----
    struct ServerConfig
    {
        // Listen settings
        std::string host = "0.0.0.0";
        uint16_t port = 1194;
        std::string proto = "udp";                 // "udp" or "tcp"
        std::string dev = "tun";                   // "tun" or "tap"
        std::string dev_node = "/dev/net/tun";     // Linux TUN/TAP device
        std::pair<int, int> keepalive = {10, 120}; ///< {ping_interval, ping_restart_timeout}

        // Crypto
        std::string cipher = "AES-256-GCM";
        std::string auth = "SHA256";
        std::string tls_cipher = "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384";
        size_t keysize = 256;
        std::filesystem::path ca_cert;
        std::filesystem::path tls_crypt_key;

        // Server identity certificates
        std::filesystem::path cert;
        std::filesystem::path key;
        std::filesystem::path dh_params;

        // Network topology
        std::string network = "10.8.0.0/24"; ///< IPv4 pool CIDR
        std::string network_v6;              ///< IPv6 pool CIDR (empty = disabled)
        std::string bridge_ip = "10.8.0.1";  ///< Server IP on VPN bridge
        std::vector<std::string> client_dns = {"8.8.8.8", "8.8.4.4"};
        std::vector<std::string> routes;
        std::vector<std::string> routes_v6;
        bool push_routes = true;
        bool client_to_client = false; ///< Push tunnel subnet route so clients can reach each other
        int tun_mtu = 1500;            ///< TUN device MTU
        int tun_txqueuelen = 0;        ///< TUN TX queue length (0 = OS default)

        // Authentication
        bool client_cert_required = true;
        bool username_password = false;
        bool crl_verify = false;
        std::filesystem::path crl_file;

        // Server-specific tuning
        size_t max_clients = 100;
        int ping_timer_remote = 60;
        int renegotiate_seconds = 3600;
        int lame_duck_seconds = 0; ///< Lame duck key TTL after renegotiation (0 = no expiry)
    };
    std::optional<ServerConfig> server;

    // ---- Client role (present only when running as client) ----
    struct ClientConfig
    {
        // Server to connect to
        std::string server_host;
        uint16_t server_port = 1194;
        std::string protocol = "udp"; ///< "udp", "udp6", or "tcp"

        // Crypto
        std::string cipher = "AES-256-GCM";
        std::string auth = "SHA256";
        std::filesystem::path ca_cert;
        std::string ca_cert_pem; ///< Inline PEM alternative
        std::filesystem::path tls_crypt_key;
        std::string tls_crypt_key_pem; ///< Inline PEM alternative

        // Client identity certificates
        std::filesystem::path cert;
        std::string cert_pem; ///< Inline PEM alternative
        std::filesystem::path key;
        std::string key_pem; ///< Inline PEM alternative

        // TUN device
        std::string dev_name; ///< TUN device name (empty = auto)

        // Reconnection
        int reconnect_delay_seconds = 5;
        int max_reconnect_attempts = 10;

        // Keepalive
        int keepalive_interval = 10; ///< Send PING every N seconds (0 = disabled)
        int keepalive_timeout = 60;  ///< Peer considered dead after N seconds
    };
    std::optional<ClientConfig> client;

    // ---- Process-global settings ----
    struct ProcessConfig
    {
        int cpu_affinity = -1;                        ///< CPU pinning: -1=off, -2=auto, >=0=core
        std::optional<bool> transit_routing = std::nullopt; ///< IP forwarding: nullopt=auto (on for server, off for client-only), true/false=explicit
    } process;

    // ---- Shared performance settings ----
    struct PerformanceConfig
    {
        bool enable_dco = true;         ///< Use Data Channel Offload if available
        int stats_interval_seconds = 0; ///< Data path stats logging interval (0 = disabled)
        int socket_recv_buffer = 0;     ///< SO_RCVBUF size in bytes (0 = OS default)
        int socket_send_buffer = 0;     ///< SO_SNDBUF size in bytes (0 = OS default)
        int batch_size = 0;             ///< recvmmsg/sendmmsg/TUN batch depth (0 = default)
        int process_quanta = 0;         ///< Max packets per event-loop yield (0 = no chunking)
    } performance;

    // ---- Shared logging settings ----
    struct LoggingConfig
    {
        std::string verbosity = "info"; ///< spdlog level name or numeric (0=trace..6=off)
        /** Per-subsystem level overrides. Key = subsystem name, value = spdlog level. */
        std::unordered_map<std::string, std::string> subsystem_levels;
    } logging;

    // ---- Convenience queries ----
    bool HasServerRole() const
    {
        return server.has_value();
    }
    bool HasClientRole() const
    {
        return client.has_value();
    }
};

// Backward-compat alias (transitional — prefer VpnConfig directly)
using OpenVpnConfig = VpnConfig;

/**
    @brief VPN configuration parser
    @details Parses JSON configuration files into VpnConfig structures.
    Validates configuration and provides sensible defaults.
*/
class VpnConfigParser
{
  public:
    static VpnConfig ParseFile(const std::filesystem::path &filepath);
    static VpnConfig ParseString(const std::string &jsonString);
    static VpnConfig ParseJson(const nlohmann::json &json);

    /** Validate server-role config for required fields and consistency. */
    static void ValidateServer(const VpnConfig &config, std::shared_ptr<spdlog::logger> logger = nullptr);

    /** Validate client-role config for required fields. */
    static void ValidateClient(const VpnConfig &config, std::shared_ptr<spdlog::logger> logger = nullptr);

  private:
    static VpnConfig::ServerConfig ParseServerConfig(const nlohmann::json &json);
    static VpnConfig::ClientConfig ParseClientConfig(const nlohmann::json &json);
    static VpnConfig::ProcessConfig ParseProcessConfig(const nlohmann::json &json);
    static VpnConfig::PerformanceConfig ParsePerformanceConfig(const nlohmann::json &json);
    static VpnConfig::LoggingConfig ParseLoggingConfig(const nlohmann::json &json);
};

// Backward-compat alias
using OpenVpnConfigParser = VpnConfigParser;

} // namespace clv::vpn

#endif // CLV_VPN_CONFIG_H