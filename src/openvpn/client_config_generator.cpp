// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "client_config_generator.h"
#include "vpn_config.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace clv::vpn {

std::string ClientConfigGenerator::GenerateConfig(const OpenVpnConfig &server_config,
                                                  const ClientOptions &client_opts) const
{
    // Validate required files exist
    std::string validation_error = ValidateFiles(server_config, client_opts);
    if (!validation_error.empty())
    {
        throw std::runtime_error("Configuration validation failed: " + validation_error);
    }

    std::ostringstream config;

    // Header comment
    config << "# OpenVPN Client Configuration\n";
    config << "# Generated for: " << client_opts.client_name << "\n";
    config << "# Date: " << __DATE__ << "\n";
    config << "\n";

    // Basic client directives
    config << "client\n";
    config << "dev " << server_config.server.dev << "\n";
    config << "proto " << server_config.server.proto << "\n";

    // Remote directive
    config << BuildRemoteDirective(server_config.server, client_opts) << "\n";

    // Connection behavior
    config << "resolv-retry infinite\n";
    config << "nobind\n";
    config << "persist-key\n";
    config << "persist-tun\n";

    // Crypto directives
    config << BuildCryptoDirectives(server_config.crypto, client_opts);

    // Compression (if enabled)
    if (client_opts.enable_compression)
    {
        config << "comp-lzo\n";
    }

    // Verbosity
    config << "verb " << client_opts.verbosity << "\n";
    config << "\n";

    // Network directives (routes, DNS)
    config << BuildNetworkDirectives(server_config.network, client_opts);

    // Certificate/key material
    if (client_opts.embed_certificates)
    {
        // Embed CA certificate
        config << EmbedCertificate(server_config.crypto.ca_cert, "ca");

        // Embed client certificate if provided
        if (client_opts.client_cert)
        {
            config << EmbedCertificate(*client_opts.client_cert, "cert");
        }

        // Embed client key if provided
        if (client_opts.client_key)
        {
            config << EmbedCertificate(*client_opts.client_key, "key");
        }

        // Embed TLS-auth key if provided
        if (client_opts.include_tls_auth && client_opts.tls_auth_key)
        {
            config << EmbedCertificate(*client_opts.tls_auth_key, "tls-auth");
        }
    }
    else
    {
        // External file references
        config << ExternalFileReference("ca", server_config.crypto.ca_cert);

        if (client_opts.client_cert)
        {
            config << ExternalFileReference("cert", *client_opts.client_cert);
        }

        if (client_opts.client_key)
        {
            config << ExternalFileReference("key", *client_opts.client_key);
        }

        if (client_opts.include_tls_auth && client_opts.tls_auth_key)
        {
            config << "tls-auth " << client_opts.tls_auth_key->string() << " 1\n";
        }
    }

    return config.str();
}

void ClientConfigGenerator::WriteToFile(const std::string &ovpn_content,
                                        const std::filesystem::path &output_path) const
{
    std::ofstream out_file(output_path);
    if (!out_file)
    {
        throw std::runtime_error("Failed to open output file: " + output_path.string());
    }

    out_file << ovpn_content;
    out_file.close();

    if (!out_file)
    {
        throw std::runtime_error("Failed to write output file: " + output_path.string());
    }
}

void ClientConfigGenerator::GenerateAndWrite(const OpenVpnConfig &server_config,
                                             const ClientOptions &client_opts,
                                             const std::filesystem::path &output_path) const
{
    std::string config = GenerateConfig(server_config, client_opts);
    WriteToFile(config, output_path);
}

std::string ClientConfigGenerator::ValidateFiles(const OpenVpnConfig &server_config,
                                                 const ClientOptions &client_opts) const
{
    std::vector<std::string> missing_files;

    // Check CA certificate
    if (!std::filesystem::exists(server_config.crypto.ca_cert))
    {
        missing_files.push_back("CA certificate: " + server_config.crypto.ca_cert.string());
    }

    // Check client certificate if provided
    if (client_opts.client_cert && !std::filesystem::exists(*client_opts.client_cert))
    {
        missing_files.push_back("Client certificate: " + client_opts.client_cert->string());
    }

    // Check client key if provided
    if (client_opts.client_key && !std::filesystem::exists(*client_opts.client_key))
    {
        missing_files.push_back("Client key: " + client_opts.client_key->string());
    }

    // Check TLS-auth key if enabled
    if (client_opts.include_tls_auth && client_opts.tls_auth_key && !std::filesystem::exists(*client_opts.tls_auth_key))
    {
        missing_files.push_back("TLS-auth key: " + client_opts.tls_auth_key->string());
    }

    if (missing_files.empty())
    {
        return "";
    }

    std::ostringstream error;
    error << "Missing required files:\n";
    for (const auto &file : missing_files)
    {
        error << "  - " << file << "\n";
    }
    return error.str();
}

std::string ClientConfigGenerator::BuildRemoteDirective(const OpenVpnConfig::ServerSettings &server,
                                                        const ClientOptions &client_opts) const
{
    std::ostringstream remote;

    // Use custom host if provided, otherwise use server host
    std::string host = client_opts.remote_host.value_or(server.host);

    remote << "remote " << host << " " << server.port;

    // Add protocol if TCP (UDP is default)
    if (server.proto == "tcp")
    {
        remote << " tcp";
    }

    return remote.str();
}

std::string ClientConfigGenerator::BuildCryptoDirectives(const OpenVpnConfig::CryptoSettings &crypto,
                                                         const ClientOptions &client_opts) const
{
    std::ostringstream directives;

    directives << "cipher " << crypto.cipher << "\n";
    directives << "auth " << crypto.auth << "\n";

    // TLS cipher if specified
    if (!crypto.tls_cipher.empty())
    {
        directives << "tls-cipher " << crypto.tls_cipher << "\n";
    }

    // Key size (if non-default)
    if (crypto.keysize != 256)
    {
        directives << "keysize " << crypto.keysize << "\n";
    }

    directives << "\n";
    return directives.str();
}

std::string ClientConfigGenerator::BuildNetworkDirectives(const OpenVpnConfig::NetworkSettings &network,
                                                          const ClientOptions &client_opts) const
{
    std::ostringstream directives;

    // DNS servers - use custom if provided, otherwise server defaults
    const auto &dns_servers = client_opts.custom_dns.empty()
                                  ? network.client_dns
                                  : client_opts.custom_dns;

    for (const auto &dns : dns_servers)
    {
        directives << "dhcp-option DNS " << dns << "\n";
    }

    // Routes from server config
    if (network.push_routes)
    {
        for (const auto &route : network.routes)
        {
            directives << "route " << route << "\n";
        }
    }

    // Additional client-specific routes
    for (const auto &route : client_opts.extra_routes)
    {
        directives << "route " << route << "\n";
    }

    if (!dns_servers.empty() || !network.routes.empty() || !client_opts.extra_routes.empty())
    {
        directives << "\n";
    }

    return directives.str();
}

std::string ClientConfigGenerator::EmbedCertificate(const std::filesystem::path &file_path,
                                                    const std::string &tag_name) const
{
    std::string content = ReadFile(file_path);

    std::ostringstream embedded;
    embedded << "<" << tag_name << ">\n";
    embedded << content;

    // Ensure content ends with newline
    if (!content.empty() && content.back() != '\n')
    {
        embedded << "\n";
    }

    embedded << "</" << tag_name << ">\n";

    return embedded.str();
}

std::string ClientConfigGenerator::ExternalFileReference(const std::string &directive,
                                                         const std::filesystem::path &file_path) const
{
    return directive + " " + file_path.string() + "\n";
}

std::string ClientConfigGenerator::ReadFile(const std::filesystem::path &file_path) const
{
    std::ifstream file(file_path);
    if (!file)
    {
        throw std::runtime_error("Failed to open file: " + file_path.string());
    }

    std::ostringstream content;
    content << file.rdbuf();

    if (file.bad())
    {
        throw std::runtime_error("Error reading file: " + file_path.string());
    }

    return content.str();
}

} // namespace clv::vpn
