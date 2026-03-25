// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_OVPN_CONFIG_PARSER_H
#define CLV_OVPN_CONFIG_PARSER_H

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace clv::vpn {

/**
 * @brief Client-focused OpenVPN configuration
 * @details Represents configuration for OpenVPN client connections,
 * optimized for peer-to-peer and client-server scenarios. Parsed from
 * standard .ovpn files.
 */
struct ClientConnectionConfig
{
    /**
     * @brief Remote server connection endpoint
     */
    struct RemoteServer
    {
        std::string host;
        uint16_t port = 1194;
        std::string proto = "udp"; // "udp" or "tcp"
    };

    /** Remote server endpoint */
    RemoteServer remote;

    /** Device type ("tun" or "tap") */
    std::string dev = "tun";

    /** Device node path (Linux-specific) */
    std::string dev_node = "/dev/net/tun";

    /** Cipher algorithm (e.g., "AES-256-GCM") */
    std::string cipher;

    /** Authentication algorithm (e.g., "SHA256") */
    std::string auth;

    /** TLS cipher suite */
    std::string tls_cipher;

    /** Connection behavior flags */
    bool persist_key = true;
    bool persist_tun = true;
    bool nobind = true;
    bool resolv_retry_infinite = true;

    /** Keepalive settings (interval, timeout in seconds) */
    int keepalive_interval = 0;
    int keepalive_timeout = 0;

    /** Renegotiation settings */
    int reneg_seconds = 0;

    /** Compression algorithm ("lz4-v2", "lz4", "comp-lzo", "") */
    std::string compression;

    /** Logging verbosity (0-11) */
    int verbosity = 3;

    /**
     * @brief Certificate/key content
     * @details Each field can be:
     * - std::monostate: not provided
     * - std::string: PEM content (loaded from inline or external file during parsing)
     *
     * External file references are resolved during parsing. For future key providers
     * (TPM, FIDO, HSM), the variant would be populated via custom mechanisms.
     */
    std::variant<std::monostate, std::string> ca_cert;
    std::variant<std::monostate, std::string> client_cert;
    std::variant<std::monostate, std::string> client_key;
    std::variant<std::monostate, std::string> tls_auth;
    std::variant<std::monostate, std::string> tls_crypt; ///< tls-crypt key content (inline or loaded from file)

    /** Routes to be added */
    std::vector<std::string> routes;

    /** DNS servers */
    std::vector<std::string> dns_servers;

    /** DNS domain */
    std::string dns_domain;

    /** Whether running in client mode */
    bool client_mode = true;

    /** Connection timeout (seconds) */
    int connect_timeout = 120;

    /** Connection retry settings */
    int connect_retry_max = 0; // 0 = infinite
    int connect_retry_delay = 5;

    /** DCO control (OpenVPN 2.6+ enables DCO by default; disable-dco opts out) */
    bool disable_dco = false;

    /** Socket buffer sizes (OpenVPN sndbuf/rcvbuf directives, 0 = not set) */
    int sndbuf = 0;
    int rcvbuf = 0;

    /** Non-standard: process-quanta <N> (number of packets per batch chunk, 0 = no chunking, -1 = not set) */
    int process_quanta = -1;

    /** Non-standard: stats-interval <seconds> (periodic stats log, 0 = disabled, -1 = not set) */
    int stats_interval = -1;
};

/**
 * @brief Parser for OpenVPN .ovpn configuration files
 * @details Parses standard OpenVPN client configuration files into
 * ClientConnectionConfig structures. Supports inline certificates,
 * external file references, and standard OpenVPN directives.
 *
 * Example usage:
 * @code
 * auto config = OvpnConfigParser::ParseFile("client.ovpn");
 * std::cout << "Remote: " << config.remote.host << ":"
 *           << config.remote.port << std::endl;
 * @endcode
 */
class OvpnConfigParser
{
  public:
    /**
     * @brief Parse .ovpn configuration file
     * @param filepath Path to .ovpn file
     * @return Parsed client connection configuration
     * @throws std::runtime_error if file cannot be read or parsed
     */
    static ClientConnectionConfig ParseFile(const std::filesystem::path &filepath);

    /**
     * @brief Parse .ovpn configuration from string
     * @param content Raw .ovpn file content
     * @return Parsed client connection configuration
     * @throws std::runtime_error if content is malformed
     */
    static ClientConnectionConfig ParseString(const std::string &content);

    /**
     * @brief Validate parsed configuration
     * @param config Configuration to validate
     * @throws std::runtime_error if validation fails
     */
    static void Validate(const ClientConnectionConfig &config);

  private:
    /**
     * @brief Parse .ovpn content into configuration structure
     * @param content Raw .ovpn file content
     * @return Parsed configuration
     */
    static ClientConnectionConfig ParseContent(const std::string &content);

    /**
     * @brief Parse inline certificate/key block
     * @param content Full file content
     * @param tag Tag name (e.g., "ca", "cert", "key")
     * @param start_pos Position to start searching from
     * @return Extracted block content and updated position
     */
    static std::pair<std::string, size_t> ParseInlineBlock(
        const std::string &content,
        const std::string &tag,
        size_t start_pos);

    /**
     * @brief Parse a single directive line
     * @param line Directive line (trimmed)
     * @param config Configuration being built
     */
    static void ParseDirective(const std::string &line, ClientConnectionConfig &config);

    /**
     * @brief Tokenize a directive line into keyword and arguments
     * @param line Directive line
     * @return Vector of tokens (keyword and arguments)
     */
    static std::vector<std::string> Tokenize(const std::string &line);

    /**
     * @brief Trim whitespace from string
     * @param str String to trim
     * @return Trimmed string
     */
    static std::string Trim(const std::string &str);

    /**
     * @brief Convert string to lowercase
     * @param str String to convert
     * @return Lowercase string
     */
    static std::string ToLower(const std::string &str);

    /**
     * @brief Check if line is a comment or empty
     * @param line Line to check
     * @return True if line should be skipped
     */
    static bool IsCommentOrEmpty(const std::string &line);

    /**
     * @brief Read file contents into string
     * @param file_path Path to file
     * @param file_type Description of file type (for error messages)
     * @return File contents as string
     * @throws std::runtime_error if file cannot be read
     */
    static std::string ReadFile(const std::filesystem::path &file_path, const std::string &file_type);
};

} // namespace clv::vpn

#endif // CLV_OVPN_CONFIG_PARSER_H
