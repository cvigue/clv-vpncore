// Copyright (c) 2023- Charlie Vigue. All rights reserved.

/**
 * @file ovpn_parser_demo.cpp
 * @brief Demonstration of parsing .ovpn configuration files
 * @details Shows how to use OvpnConfigParser to read and validate
 * OpenVPN client configuration files.
 */

#include "openvpn/ovpn_config_parser.h"
#include <iostream>
#include <filesystem>

using namespace clv::vpn;
namespace fs = std::filesystem;

void PrintConfig(const ClientConnectionConfig &config)
{
    std::cout << "=== OpenVPN Client Configuration ===\n";
    std::cout << "Remote: " << config.remote.host << ":" << config.remote.port << "\n";
    std::cout << "Protocol: " << config.remote.proto << "\n";
    std::cout << "Device: " << config.dev << "\n";

    if (!config.cipher.empty())
        std::cout << "Cipher: " << config.cipher << "\n";
    if (!config.auth.empty())
        std::cout << "Auth: " << config.auth << "\n";
    if (!config.compression.empty())
        std::cout << "Compression: " << config.compression << "\n";

    std::cout << "Client Mode: " << (config.client_mode ? "Yes" : "No") << "\n";
    std::cout << "Persist Key: " << (config.persist_key ? "Yes" : "No") << "\n";
    std::cout << "Persist TUN: " << (config.persist_tun ? "Yes" : "No") << "\n";
    std::cout << "No Bind: " << (config.nobind ? "Yes" : "No") << "\n";

    if (config.keepalive_interval > 0)
        std::cout << "Keepalive: " << config.keepalive_interval << "s / "
                  << config.keepalive_timeout << "s\n";

    std::cout << "Verbosity: " << config.verbosity << "\n";

    // Certificate info
    if (std::holds_alternative<std::string>(config.ca_cert))
        std::cout << "CA Certificate: Loaded (" << std::get<std::string>(config.ca_cert).length() << " bytes)\n";
    else
        std::cout << "CA Certificate: Not provided\n";

    if (std::holds_alternative<std::string>(config.client_cert))
        std::cout << "Client Certificate: Loaded (" << std::get<std::string>(config.client_cert).length() << " bytes)\n";
    else
        std::cout << "Client Certificate: Not provided\n";

    if (std::holds_alternative<std::string>(config.client_key))
        std::cout << "Client Key: Loaded (" << std::get<std::string>(config.client_key).length() << " bytes)\n";
    else
        std::cout << "Client Key: Not provided\n";

    // Routes
    if (!config.routes.empty())
    {
        std::cout << "Routes:\n";
        for (const auto &route : config.routes)
        {
            std::cout << "  - " << route << "\n";
        }
    }

    // DNS
    if (!config.dns_servers.empty())
    {
        std::cout << "DNS Servers:\n";
        for (const auto &dns : config.dns_servers)
        {
            std::cout << "  - " << dns << "\n";
        }
    }

    if (!config.dns_domain.empty())
        std::cout << "DNS Domain: " << config.dns_domain << "\n";

    std::cout << "====================================\n";
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <config.ovpn>\n";
        std::cerr << "\nExample:\n";
        std::cerr << "  " << argv[0] << " client.ovpn\n\n";
        return 1;
    }

    fs::path config_path(argv[1]);

    try
    {
        std::cout << "Parsing: " << config_path << "\n\n";

        // Parse the .ovpn file
        ClientConnectionConfig config = OvpnConfigParser::ParseFile(config_path);

        // Display the parsed configuration
        PrintConfig(config);

        std::cout << "\n✓ Configuration parsed and validated successfully!\n";

        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
