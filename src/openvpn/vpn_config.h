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

#include <nlohmann/json.hpp>
#include "nlohmann/json_fwd.hpp"

#include <memory>

namespace spdlog {
class logger;
}

namespace clv::vpn {

/**
    @brief OpenVPN server configuration structure
    @details Contains all configuration options for an OpenVPN server instance.
    Supports modern OpenVPN features while excluding deprecated legacy options.
*/
struct OpenVpnConfig
{
    // Server settings
    struct ServerSettings
    {
        std::string host = "0.0.0.0";
        uint16_t port = 1194;
        std::string proto = "udp";                 // "udp" or "tcp"
        std::string dev = "tun";                   // "tun" or "tap"
        std::string dev_node = "/dev/net/tun";     // Linux TUN/TAP device
        std::pair<int, int> keepalive = {10, 120}; ///< {ping_interval_seconds, ping_restart_timeout_seconds}
    } server;

    // Crypto settings
    struct CryptoSettings
    {
        std::filesystem::path ca_cert;
        std::filesystem::path server_cert;
        std::filesystem::path server_key;
        std::filesystem::path dh_params;
        std::string cipher = "AES-256-GCM";
        std::string auth = "SHA256";
        std::string tls_cipher = "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384";
        size_t keysize = 256;
        std::filesystem::path tls_crypt_key; ///< Optional TLS-Crypt key file
    } crypto;

    // Network settings
    struct NetworkSettings
    {
        std::string server_network = "10.8.0.0/24";
        std::string server_network_v6; ///< IPv6 pool CIDR (e.g. "fd00::/112"), empty = disabled
        std::string server_bridge = "10.8.0.1";
        std::vector<std::string> client_dns = {"8.8.8.8", "8.8.4.4"};
        std::vector<std::string> routes;
        std::vector<std::string> routes_v6; ///< IPv6 routes to push (e.g. "fd01::/64")
        bool push_routes = true;
        int tun_mtu = 1500;     ///< TUN device MTU (default 1500)
        int tun_txqueuelen = 0; ///< TUN TX queue length (0 = OS default, typically 500)
    } network;

    // Authentication settings
    struct AuthSettings
    {
        bool client_cert_required = true;
        bool username_password = false;
        bool crl_verify = false;
        std::filesystem::path crl_file;
    } auth;

    // Performance settings
    struct PerformanceSettings
    {
        size_t max_clients = 100;
        int ping_timer_remote = 60;
        int renegotiate_seconds = 3600;
        bool enable_dco = true;         // Use Data Channel Offload (kernel mode) if available
        int stats_interval_seconds = 0; ///< Data path stats logging interval (0 = disabled)
        int socket_recv_buffer = 0;     ///< SO_RCVBUF size in bytes (0 = OS default)
        int socket_send_buffer = 0;     ///< SO_SNDBUF size in bytes (0 = OS default)
        int batch_size = 0;             ///< recvmmsg/sendmmsg/TUN batch depth (0 = default 4096)
        int process_quanta = 0;         ///< Max packets processed between event-loop yields (0 = no chunking)
        int lame_duck_seconds = 0;      ///< Lame duck key TTL after renegotiation (0 = no expiry, lives until next rekey)
        int cpu_affinity = -1;          ///< CPU pinning: -1=off, -2=auto, -3=adaptive, >=0=explicit core

        // Adaptive affinity tunables (only used when cpu_affinity == -3)
        int adaptive_probe_interval = 10;            ///< Stats windows between probes
        int adaptive_probe_duration = 2;             ///< Stats windows to stay unpinned during probe
        int adaptive_baseline_windows = 5;           ///< Windows to seed the initial EMA
        double adaptive_ema_alpha = 0.3;             ///< EMA smoothing factor
        double adaptive_throughput_threshold = 0.75; ///< Probe if throughput < this × EMA
        double adaptive_window_seconds = 5.0;        ///< Sampling window duration (seconds)
    } performance;

    // Logging settings
    struct LoggingSettings
    {
        std::string verbosity = "info"; ///< spdlog level name or numeric (0=trace..6=off)
        /// Per-subsystem level overrides.  Key = subsystem name
        /// ("keepalive","sessions","control","dataio","routing","general"),
        /// value = spdlog level name or numeric string.
        std::unordered_map<std::string, std::string> subsystem_levels;
    } logging;
};

/**
    @brief OpenVPN configuration parser
    @details Parses JSON configuration files into OpenVpnConfig structures.
    Validates configuration and provides sensible defaults.
*/
class OpenVpnConfigParser
{
  public:
    /**
        @brief Parse OpenVPN configuration from JSON file
        @param filepath Path to the JSON configuration file
        @return OpenVpnConfig Parsed configuration
        @throws std::runtime_error if file cannot be read or parsed
    */
    static OpenVpnConfig ParseFile(const std::filesystem::path &filepath);

    /**
        @brief Parse OpenVPN configuration from JSON string
        @param jsonString JSON string containing configuration
        @return OpenVpnConfig Parsed configuration
        @throws std::runtime_error if JSON is malformed
    */
    static OpenVpnConfig ParseString(const std::string &jsonString);

    /**
        @brief Parse OpenVPN configuration from JSON object
        @param json JSON object containing configuration
        @return OpenVpnConfig Parsed configuration
        @throws std::runtime_error if JSON is malformed
    */
    static OpenVpnConfig ParseJson(const nlohmann::json &json);

    /**
        @brief Validate configuration for required fields and consistency
        @param config Configuration to validate
        @param logger Optional logger for warnings
        @throws std::runtime_error if configuration is invalid
    */
    static void Validate(const OpenVpnConfig &config, std::shared_ptr<spdlog::logger> logger = nullptr);

  private:
    /**
        @brief Parse server settings from JSON
        @param json JSON object containing server configuration
        @return ServerSettings Parsed server settings
    */
    static OpenVpnConfig::ServerSettings ParseServerSettings(const nlohmann::json &json);

    /**
        @brief Parse crypto settings from JSON
        @param json JSON object containing crypto configuration
        @return CryptoSettings Parsed crypto settings
    */
    static OpenVpnConfig::CryptoSettings ParseCryptoSettings(const nlohmann::json &json);

    /**
        @brief Parse network settings from JSON
        @param json JSON object containing network configuration
        @return NetworkSettings Parsed network settings
    */
    static OpenVpnConfig::NetworkSettings ParseNetworkSettings(const nlohmann::json &json);

    /**
        @brief Parse auth settings from JSON
        @param json JSON object containing auth configuration
        @return AuthSettings Parsed auth settings
    */
    static OpenVpnConfig::AuthSettings ParseAuthSettings(const nlohmann::json &json);

    /**
        @brief Parse performance settings from JSON
        @param json JSON object containing performance configuration
        @return PerformanceSettings Parsed performance settings
    */
    static OpenVpnConfig::PerformanceSettings ParsePerformanceSettings(const nlohmann::json &json);

    /**
        @brief Parse logging settings from JSON
        @param json JSON object containing logging configuration
        @return LoggingSettings Parsed logging settings
    */
    static OpenVpnConfig::LoggingSettings ParseLoggingSettings(const nlohmann::json &json);
};

} // namespace clv::vpn

#endif // CLV_VPN_CONFIG_H