// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_CLIENT_CONFIG_GENERATOR_H
#define CLV_CLIENT_CONFIG_GENERATOR_H

#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include "vpn_config.h"

namespace clv::vpn {

/**
 * @brief Options for client configuration generation
 * @details Controls how the .ovpn file is generated including certificate
 * embedding, routing, and client-specific overrides.
 */
struct ClientOptions
{
    /// Client identifier (used in comments/logs)
    std::string client_name;

    /**
     * Embed certificates inline using <ca>, <cert>, <key> tags
     * If false, generates separate file references
     */
    bool embed_certificates = true;

    /// Include tls-auth directive and key material
    bool include_tls_auth = false;

    /// Path to client certificate (if different from auto-generated)
    std::optional<std::filesystem::path> client_cert;

    /// Path to client private key
    std::optional<std::filesystem::path> client_key;

    /// Path to TLS-auth key file (ta.key)
    std::optional<std::filesystem::path> tls_auth_key;

    /// Additional routes to push to this specific client
    std::vector<std::string> extra_routes;

    /// Custom DNS servers for this client (overrides server defaults)
    std::vector<std::string> custom_dns;

    /// Remote server hostname/IP (overrides server config if set)
    std::optional<std::string> remote_host;

    /// Enable LZO compression
    bool enable_compression = false;

    /// Client verbosity level (0-11)
    int verbosity = 3;
};

/**
 * @brief Generates OpenVPN client configuration files (.ovpn)
 * @details Creates client configuration files from server config that are
 * compatible with standard OpenVPN clients. Supports certificate embedding,
 * TLS-auth, custom routes, and client-specific overrides.
 *
 * Example usage:
 * @code
 * OpenVpnConfig server_config = LoadServerConfig("server.json");
 * ClientOptions opts;
 * opts.client_name = "alice";
 * opts.client_cert = "certs/alice.crt";
 * opts.client_key = "certs/alice.key";
 *
 * ClientConfigGenerator generator;
 * std::string ovpn = generator.GenerateConfig(server_config, opts);
 * generator.WriteToFile(ovpn, "alice.ovpn");
 * @endcode
 */
class ClientConfigGenerator
{
  public:
    /**
     * @brief Generate complete .ovpn configuration file content
     * @param server_config Server configuration to derive client settings from
     * @param client_opts Client-specific options and overrides
     * @return Complete .ovpn file content as string
     * @throws std::runtime_error if required certificate files are missing
     */
    std::string GenerateConfig(
        const OpenVpnConfig &server_config,
        const ClientOptions &client_opts) const;

    /**
     * @brief Write configuration content to file
     * @param ovpn_content The .ovpn file content
     * @param output_path Path where the file should be written
     * @throws std::runtime_error if file cannot be written
     */
    void WriteToFile(
        const std::string &ovpn_content,
        const std::filesystem::path &output_path) const;

    /**
     * @brief Generate config and write in one step
     * @param server_config Server configuration
     * @param client_opts Client options
     * @param output_path Output file path
     */
    void GenerateAndWrite(
        const OpenVpnConfig &server_config,
        const ClientOptions &client_opts,
        const std::filesystem::path &output_path) const;

    /**
     * @brief Validate that all required files exist
     * @param server_config Server config with certificate paths
     * @param client_opts Client options with certificate paths
     * @return Empty string if valid, error message otherwise
     */
    std::string ValidateFiles(
        const OpenVpnConfig &server_config,
        const ClientOptions &client_opts) const;

  private:
    /**
     * @brief Build the remote directive line
     * @param server Server settings from config
     * @param client_opts Client options (may override hostname)
     * @return "remote hostname port [proto]"
     */
    std::string BuildRemoteDirective(
        const VpnConfig::ServerConfig &server,
        const ClientOptions &client_opts) const;

    /**
     * @brief Build crypto-related directives
     * @param crypto Crypto settings from server config
     * @param client_opts Client options
     * @return Multi-line crypto directives (cipher, auth, tls-cipher)
     */
    std::string BuildCryptoDirectives(
        const VpnConfig::ServerConfig &server,
        const ClientOptions &client_opts) const;

    /**
     * @brief Build network directives (routes, DNS)
     * @param network Network settings from server config
     * @param client_opts Client options (may override DNS/routes)
     * @return Multi-line network directives
     */
    std::string BuildNetworkDirectives(
        const VpnConfig::ServerConfig &server,
        const ClientOptions &client_opts) const;

    /**
     * @brief Read and embed certificate/key file content
     * @param file_path Path to certificate or key file
     * @param tag_name Tag name (e.g., "ca", "cert", "key", "tls-auth")
     * @return Formatted <tag>content</tag> block
     * @throws std::runtime_error if file cannot be read
     */
    std::string EmbedCertificate(
        const std::filesystem::path &file_path,
        const std::string &tag_name) const;

    /**
     * @brief Generate external file reference directive
     * @param directive Directive name (e.g., "ca", "cert", "key")
     * @param file_path Path to external file
     * @return Single line directive
     */
    std::string ExternalFileReference(
        const std::string &directive,
        const std::filesystem::path &file_path) const;

    /**
     * @brief Read file content as string
     * @param file_path Path to file
     * @return File content
     * @throws std::runtime_error if file cannot be read
     */
    std::string ReadFile(const std::filesystem::path &file_path) const;
};

} // namespace clv::vpn

#endif // CLV_CLIENT_CONFIG_GENERATOR_H
