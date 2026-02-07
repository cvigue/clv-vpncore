// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_OPENVPN_CONFIG_EXCHANGE_H
#define CLV_VPN_OPENVPN_CONFIG_EXCHANGE_H

#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace clv::vpn::openvpn {

/**
 * @brief Configuration option types from config/push directives
 */
enum class ConfigOptionType
{
    CIPHER,           ///< cipher <algo> - Data channel cipher algorithm
    AUTH,             ///< auth <algo> - Data channel HMAC algorithm
    COMPRESS,         ///< compress <mode> - Compression algorithm (lz4, stub, etc)
    FRAGMENT,         ///< fragment <size> - Fragment packets larger than size
    MSSFIX,           ///< mssfix <size> - Adjust TCP MSS
    PUSH_RESET,       ///< push-reset - Clear previous push options
    ROUTE,            ///< route <net> <gw> <metric> - Add route to client routing table
    ROUTE_IPV6,       ///< route-ipv6 <net/mask> <gw> <metric> - IPv6 route
    DHCP_OPTION,      ///< dhcp-option <type> <value> - DHCP option to set
    REDIRECT_GATEWAY, ///< redirect-gateway <flags> - Redirect default gateway through VPN
    TOPOLOGY,         ///< topology <mode> - Network topology (subnet, p2p, net30)
    IFCONFIG,         ///< ifconfig <local> <remote> - Interface configuration (P2P)
    IFCONFIG_IPV6,    ///< ifconfig-ipv6 <local> <prefix> - IPv6 interface config
    REGISTER_DNS,     ///< register-dns - Register DNS settings (Windows)
    INACTIVE,         ///< inactive <timeout> - Inactive timeout in seconds
    RENEG_BYTES,      ///< reneg-bytes <bytes> - Renegotiate after N bytes
    RENEG_PACKETS,    ///< reneg-packets <packets> - Renegotiate after N packets
    RENEG_SEC,        ///< reneg-sec <seconds> - Renegotiate after N seconds
    ROUTE_GATEWAY,    ///< route-gateway <ip> - Default gateway for routes
    PEER_ID,          ///< peer-id <id> - Server-assigned peer identifier for DATA_V2
    PING,             ///< ping <seconds> - Keepalive ping interval
    PING_RESTART,     ///< ping-restart <seconds> - Restart if no ping response
    TUN_MTU,          ///< tun-mtu <size> - TUN device MTU
    UNKNOWN           ///< Unknown option (pass-through for future extensions)
};

/**
 * @brief Single configuration option
 *
 * Represents one push/config directive, typically received as:
 * "cipher AES-256-GCM" -> type=CIPHER, args=["AES-256-GCM"]
 */
struct ConfigOption
{
    /// Type of configuration option
    ConfigOptionType type = ConfigOptionType::UNKNOWN;

    /// Option arguments (e.g., ["AES-256-GCM"] for cipher)
    std::vector<std::string> args;

    /// Raw unparsed option string (for UNKNOWN types)
    std::string raw;

    /// Whether this option should be applied
    bool enabled = true;
};

/**
 * @brief Configuration state for negotiated connection
 *
 * Accumulated from:
 * - Server's push directives (via --push)
 * - Client's config directives
 * - Negotiated defaults
 *
 * Applied after control channel establishes key material.
 */
struct NegotiatedConfig
{
    /// Data channel cipher algorithm (e.g., "AES-256-GCM")
    std::string cipher;

    /// Data channel HMAC algorithm (e.g., "SHA256")
    std::string auth;

    /// Compression algorithm ("lz4", "stub-v2", "none")
    std::string compress;

    /// Maximum fragment size (0 = disabled)
    std::uint16_t fragment_size = 0;

    /// MSS fix size (0 = disabled)
    std::uint16_t mssfix = 0;

    /// Routes to add on client (network, gateway, metric)
    std::vector<std::tuple<std::string, std::string, int>> routes;

    /// IPv6 routes (network/mask, gateway, metric)
    std::vector<std::tuple<std::string, std::string, int>> routes_ipv6;

    /// DHCP options (type, value pairs)
    std::vector<std::pair<std::string, std::string>> dhcp_options;

    /// Redirect gateway flags
    std::string redirect_gateway;

    /// Route gateway IP (from route-gateway directive)
    std::string route_gateway;

    /// Network topology (subnet, p2p, net30)
    std::string topology;

    /// Interface local and remote IPs (P2P mode)
    std::pair<std::string, std::string> ifconfig;

    /// IPv6 interface config (local, prefix)
    std::pair<std::string, int> ifconfig_ipv6;

    /// Inactive timeout in seconds (0 = disabled)
    std::uint32_t inactive_timeout = 0;

    /// Renegotiate after N bytes (0 = disabled)
    std::uint64_t reneg_bytes = 0;

    /// Renegotiate after N packets (0 = disabled)
    std::uint64_t reneg_packets = 0;

    /// Renegotiate after N seconds (0 = disabled, default 3600)
    std::uint32_t reneg_sec = 3600;

    /// Register DNS on Windows
    bool register_dns = false;

    /// Server-assigned peer ID for DATA_V2 packets (-1 = not assigned)
    std::int32_t peer_id = -1;

    /// Keepalive ping interval in seconds (0 = disabled)
    std::uint32_t ping_interval = 0;

    /// Ping restart timeout in seconds (0 = disabled)
    std::uint32_t ping_restart = 0;

    /// TUN MTU (0 = use default)
    std::uint16_t tun_mtu = 0;
};

/**
 * @brief Configuration exchange negotiation state machine
 *
 * Manages the exchange of configuration options between client and server
 * after the control channel TLS handshake completes.
 *
 * Flow:
 * 1. Control channel reaches KeyMaterialReady state
 * 2. Server sends PUSH_REPLY with configuration options
 * 3. Client acknowledges PUSH_REPLY
 * 4. Both sides apply negotiated configuration
 * 5. Control channel transitions to Active
 */
class ConfigExchange
{
  public:
    /// Maximum number of configuration options to accept
    static constexpr int MAX_CONFIG_OPTIONS = 128;

    /// Maximum length of a single option string
    static constexpr int MAX_OPTION_LENGTH = 512;

    /// Timeout waiting for PUSH_REPLY (milliseconds)
    static constexpr int PUSH_REPLY_TIMEOUT = 5000;

    ConfigExchange() = default;
    ~ConfigExchange() = default;

    // Non-copyable
    ConfigExchange(const ConfigExchange &) = delete;
    ConfigExchange &operator=(const ConfigExchange &) = delete;

    // Non-movable
    ConfigExchange(ConfigExchange &&) = delete;
    ConfigExchange &operator=(ConfigExchange &&) = delete;

    /**
     * @brief Start client-initiated configuration exchange
     *
     * Client sends PUSH_REQUEST to server, waits for PUSH_REPLY.
     * Should be called when control channel reaches KeyMaterialReady.
     *
     * @return true if push request prepared successfully
     */
    bool StartPushRequest();

    /**
     * @brief Process received configuration options from server
     *
     * Server sends options via control channel message containing:
     * "PUSH_REPLY,cipher AES-256-GCM,auth SHA256,route 10.8.0.0 255.255.255.0"
     *
     * @param options_str Comma-separated option string from server
     * @return true if options parsed successfully
     */
    bool ProcessPushReply(const std::string &options_str);

    /**
     * @brief Add a local configuration option
     *
     * Client-side configuration that should be negotiated or acknowledged.
     * Typically set from config file or command line.
     *
     * @param option Configuration option to add
     */
    void AddLocalOption(const ConfigOption &option);

    /**
     * @brief Get negotiated configuration
     *
     * Returns the merged configuration after both client and server
     * options have been processed. Only valid after successful push.
     *
     * @return Reference to negotiated configuration (const)
     */
    const NegotiatedConfig &GetNegotiatedConfig() const
    {
        return negotiated_config_;
    }

    /**
     * @brief Check if configuration exchange is complete
     */
    bool IsConfigured() const
    {
        return configured_;
    }

    /**
     * @brief Check if waiting for server's PUSH_REPLY
     */
    bool IsPushPending() const
    {
        return push_pending_;
    }

    /**
     * @brief Get received configuration options
     */
    const std::vector<ConfigOption> &GetReceivedOptions() const
    {
        return received_options_;
    }

    /**
     * @brief Build PUSH_REPLY packet with IPv4 configuration
     *
     * Constructs a PUSH_REPLY string containing IPv4 interface configuration.
     * Format: "PUSH_REPLY,ifconfig <local> <remote>,route-gateway <gw>,...options"
     *
     * @param client_ipv4 Allocated client IPv4 address (host byte order)
     * @param server_ipv4 Server IPv4 address for P2P (host byte order)
     * @param extra_options Additional options to include (cipher, auth, routes, etc.)
     * @return PUSH_REPLY string ready to send to client
     */
    static std::string BuildPushReplyWithIpv4(uint32_t client_ipv4,
                                              uint32_t server_ipv4,
                                              const std::vector<std::string> &extra_options = {});

    /**
     * @brief Get local configuration options
     */
    const std::vector<ConfigOption> &GetLocalOptions() const
    {
        return local_options_;
    }

    /**
     * @brief Reset configuration state (for renegotiation)
     */
    void Reset();

  private:
    /// Whether configuration is complete and applied
    bool configured_ = false;

    /// Whether waiting for server's PUSH_REPLY
    bool push_pending_ = false;

    /// Server-provided configuration options
    std::vector<ConfigOption> received_options_;

    /// Client-provided configuration options
    std::vector<ConfigOption> local_options_;

    /// Merged negotiated configuration
    NegotiatedConfig negotiated_config_;

    /**
     * Parse a single option string into ConfigOption
     * @param option_str Format: "cipher AES-256-GCM" or "route 10.8.0.0 255.255.255.0"
     */
    std::optional<ConfigOption> ParseOption(const std::string &option_str);

    /// Apply a configuration option to negotiated_config_
    bool ApplyOption(const ConfigOption &option);

    /// Merge server and client options according to priority rules
    bool MergeOptions();

    /// Validate cipher/auth combination for compatibility
    bool ValidateAlgorithms(bool strict = true);
};

/**
 * @brief Build key-method 2 message for post-TLS-handshake key exchange
 *
 * After TLS handshake completes, both sides exchange key-method 2 messages.
 * This message contains:
 * - A literal 0x00 byte (key_method 2 marker)
 * - 48 bytes of random data (used for key derivation)
 * - Options string with local settings
 * - Username/password (server side sends empty)
 *
 * @param random_data 48 bytes of random for key derivation (or nullopt to generate)
 * @param options_string Local options (e.g., "V4,dev-type tun,link-mtu 1500,...")
 * @param username Optional username (usually empty for server)
 * @param password Optional password (usually empty for server)
 * @return Serialized key-method 2 message
 */
std::vector<std::uint8_t> BuildKeyMethod2Message(
    const std::vector<std::uint8_t> &random_data,
    const std::string &options_string,
    const std::string &username = "",
    const std::string &password = "");

/**
 * @brief Parse key-method 2 message from peer
 *
 * @param data Raw key-method 2 message
 * @param is_from_server true if parsing server message (64 bytes random),
 *                       false if parsing client message (112 bytes random)
 * @return tuple of (random_data, options_string, username, password) or nullopt on error
 */
std::optional<std::tuple<std::vector<std::uint8_t>, std::string, std::string, std::string>>
ParseKeyMethod2Message(const std::vector<std::uint8_t> &data, bool is_from_server = false);

} // namespace clv::vpn::openvpn

#endif // CLV_VPN_OPENVPN_CONFIG_EXCHANGE_H
