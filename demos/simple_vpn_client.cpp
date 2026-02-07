// Copyright (c) 2025- Charlie Vigue. All rights reserved.

/**
 * @file simple_vpn_client.cpp
 * @brief Simple OpenVPN client demo
 *
 * Usage: simple_vpn_client <config.json | config.ovpn>
 *
 * Connects to an OpenVPN server and establishes a VPN tunnel.
 * Accepts both JSON (.json) and OpenVPN (.ovpn) configuration files.
 */

#include "asan_notify.h"
#include "vpn_client.h"

#include <asio.hpp>
#include <asio/signal_set.hpp>
#include <csignal>
#include <exception>
#include <spdlog/spdlog.h>
#include <iostream>
#include <string>

int main(int argc, char *argv[])
{
    // Announce ASAN only if compiled with AddressSanitizer
    clv_announce_asan();


    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <config.json | config.ovpn>\n";
        std::cerr << "\nExample:\n";
        std::cerr << "  " << argv[0] << " client_config.json\n";
        std::cerr << "  " << argv[0] << " test_client.ovpn\n";
        return 1;
    }

    std::string config_path = argv[1];

    try
    {
        // Load configuration (auto-detects .ovpn vs .json by extension)
        auto config = clv::vpn::VpnClientConfig::Load(config_path);

        std::cout << "Loaded configuration from: " << config_path << "\n";
        std::cout << "Connecting to: " << config.server_host << ":" << config.server_port << "\n";

        // Create I/O context
        asio::io_context io_context;

        // Create client
        clv::vpn::VpnClient client(io_context, config);

        // Catch SIGINT/SIGTERM on the io_context thread — no globals, no races.
        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](const asio::error_code &ec, int signum)
        {
            if (ec)
                return; // cancelled
            std::cout << "\nReceived signal " << signum << ", disconnecting...\n";
            client.Disconnect();
        });

        // Announce state transitions
        client.SetStateCallback([&](auto /*old_state*/, auto new_state)
        {
            if (new_state == clv::vpn::VpnClientState::Connected)
            {
                std::cout << "\n=== VPN Connected ===\n";
                std::cout << "  Assigned IP: " << client.GetAssignedIp() << "\n";
                std::cout << "  Press Ctrl+C to disconnect\n\n";
            }
        });

        // Connect
        client.Connect();

        std::cout << "\n=== OpenVPN Client Running ===\n";
        std::cout << "Press Ctrl+C to disconnect\n\n";

        // Run I/O context
        io_context.run();

        // Print statistics
        if (client.IsConnected())
        {
            std::cout << "\nConnection Statistics:\n";
            std::cout << "  Assigned IP: " << client.GetAssignedIp() << "\n";
            std::cout << "  Uptime: " << client.GetUptime().count() << " seconds\n";
            std::cout << "  Bytes sent: " << client.GetBytesSent() << "\n";
            std::cout << "  Bytes received: " << client.GetBytesReceived() << "\n";
        }

        std::cout << "Client stopped\n";
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
