// Copyright (c) 2025- Charlie Vigue. All rights reserved.

/**
 * @file simple_vpn_server.cpp
 * @brief Simple OpenVPN server demo
 *
 * Demonstrates VPN server functionality with basic configuration.
 * Accepts connections from standard OpenVPN clients.
 *
 * Usage:
 *   sudo ./simple_vpn_server [config.json]
 *
 * Note: Requires root/CAP_NET_ADMIN for TUN device creation.
 */

#include "vpn_server.h"
#include "openvpn/vpn_config.h"

#include "asan_notify.h"

#include <asio.hpp>
#include <asio/io_context.hpp>
#include <asio/signal_set.hpp>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <unistd.h>

int main(int argc, char *argv[])
{
    // Announce ASAN only if compiled with AddressSanitizer
    clv_announce_asan();

    try
    {
        // Check for root privileges
        if (geteuid() != 0)
        {
            std::cerr << "Error: This program requires root privileges for TUN device creation.\n";
            std::cerr << "Please run with sudo.\n";
            return 1;
        }

        // Parse config file path
        std::filesystem::path config_path;
        if (argc > 1)
        {
            config_path = argv[1];
        }
        else
        {
            // Look for default config (relative to CWD = project root)
            config_path = "configs/server_config.json";
        }

        if (!std::filesystem::exists(config_path))
        {
            std::cerr << "Error: Config file not found: " << config_path << "\n";
            std::cerr << "Usage: " << argv[0] << " [config.json]\n";
            return 1;
        }

        std::cout << "Loading configuration from: " << config_path << "\n";

        // Parse configuration
        auto config = clv::vpn::OpenVpnConfigParser::ParseFile(config_path);

        // Create ASIO context
        asio::io_context io_context;

        // Create server
        auto server = std::make_unique<clv::vpn::VpnServer>(io_context, config);

        // Catch SIGINT/SIGTERM on the io_context thread — no globals, no races.
        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](const asio::error_code &ec, int signum)
        {
            if (ec)
                return; // cancelled
            std::cout << "\nReceived signal " << signum << ", shutting down...\n";
            server->Stop();
            io_context.stop();
        });

        // Start server
        server->Start();

        // Run event loop
        std::cout << "\n=== OpenVPN Server Running ===\n";
        std::cout << "Press Ctrl+C to stop\n\n";

        io_context.run();

        std::cout << "\nServer stopped gracefully\n";
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}
