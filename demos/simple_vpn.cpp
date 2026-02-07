// Copyright (c) 2025- Charlie Vigue. All rights reserved.

/**
 * @file simple_vpn.cpp
 * @brief Unified VPN demo — runs as server, client, or both depending on config.
 *
 * Usage: simple_vpn <config.json | config.ovpn>
 *
 * If the argument is a .ovpn file, runs in client-only mode using that file.
 * Otherwise, expects a JSON config with top-level "server" and/or "client"
 * role sections. Each role section can be:
 *   - An inline object with the full role-specific config, OR
 *   - A string path (or object with a "$ref" key) referencing an external JSON file.
 *
 * Examples:
 * @code
 *   // Inline server + client
 *   {
 *     "server": { ... server fields ... },
 *     "client": { ... client fields ... }
 *   }
 *
 *   // Referential — point to existing config files
 *   {
 *     "server": { "$ref": "server_config.json" },
 *     "client": { "$ref": "client_config.json" }
 *   }
 *
 *   // Shorthand referential
 *   {
 *     "server": "server_config.json",
 *     "client": "client_config.json"
 *   }
 *
 *   // Client from .ovpn profile
 *   {
 *     "client": "my_profile.ovpn"
 *   }
 *
 *   // Server-only
 *   {
 *     "server": { ... }
 *   }
 * @endcode
 *
 * Phase 1 implementation: composes existing VpnServer and VpnClient on a
 * shared io_context. Each role gets its own TUN device. No deep library
 * refactoring required.
 */

#include "asan_notify.h"
#include "nlohmann/json_fwd.hpp"
#include "openvpn/vpn_config.h"
#include "vpn_client.h"
#include "vpn_server.h"

#include <asio.hpp>
#include <asio/signal_set.hpp>
#include <nlohmann/json.hpp>

#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {

/// @brief Check if a path has .ovpn extension (case-insensitive).
bool IsOvpnFile(const std::filesystem::path &path)
{
    auto ext = path.extension().string();
    return ext == ".ovpn" || ext == ".OVPN";
}

// ---------------------------------------------------------------------------
// Resolve a role section: inline object, "$ref" object, or bare string path.
// Returns the resolved JSON object ready for the role's parser.
// ---------------------------------------------------------------------------
nlohmann::json ResolveRoleConfig(const nlohmann::json &value,
                                 const std::filesystem::path &base_dir)
{
    // Bare string → treat as file path
    if (value.is_string())
    {
        auto path = base_dir / value.get<std::string>();
        std::ifstream file(path);
        if (!file.is_open())
            throw std::runtime_error("Cannot open referenced config: " + path.string());
        nlohmann::json j;
        file >> j;
        return j;
    }

    // Object with "$ref" key → load that file
    if (value.is_object() && value.contains("$ref"))
    {
        auto ref = value["$ref"].get<std::string>();
        auto path = base_dir / ref;
        std::ifstream file(path);
        if (!file.is_open())
            throw std::runtime_error("Cannot open $ref config: " + path.string());
        nlohmann::json j;
        file >> j;
        return j;
    }

    // Already an inline object
    return value;
}

} // namespace

int main(int argc, char *argv[])
{
    clv_announce_asan();

    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <config.json | config.ovpn>\n"
                  << "\nIf the argument is a .ovpn file, runs as client using that profile.\n"
                  << "Otherwise, the JSON config may contain \"server\" and/or \"client\" sections.\n"
                  << "Each section can be an inline config object, a \"$ref\" to an external\n"
                  << "file (.json or .ovpn), or a bare string path to an external file.\n";
        return 1;
    }

    try
    {
        // ---- Load top-level config ----
        std::filesystem::path config_path(argv[1]);
        if (!std::filesystem::exists(config_path))
        {
            std::cerr << "Error: Config file not found: " << config_path << "\n";
            return 1;
        }

        // ---- Top-level .ovpn shortcut: client-only mode ----
        if (IsOvpnFile(config_path))
        {
            asio::io_context io_context;
            auto client_config = clv::vpn::VpnClientConfig::LoadFromOvpnFile(config_path.string());
            auto client = std::make_unique<clv::vpn::VpnClient>(io_context, client_config);

            std::cout << "[client] Loaded .ovpn profile: " << config_path.filename() << "\n"
                      << "[client] Target: " << client_config.server_host << ":"
                      << client_config.server_port << " (" << client_config.protocol << ")\n";

            client->SetStateCallback([&](auto /*old*/, auto new_state)
            {
                if (new_state == clv::vpn::VpnClientState::Connected)
                {
                    std::cout << "\n[client] === VPN Connected ===\n"
                              << "  Assigned IP: " << client->GetAssignedIp() << "\n\n";
                }
            });

            asio::signal_set signals(io_context, SIGINT, SIGTERM);
            signals.async_wait([&](const asio::error_code &ec, int signum)
            {
                if (ec)
                    return;
                std::cout << "\nReceived signal " << signum << ", disconnecting...\n";
                client->Disconnect();
            });

            client->Connect();
            std::cout << "\n=== simple_vpn running (client) ===\nPress Ctrl+C to stop\n\n";
            io_context.run();

            if (client->IsConnected())
            {
                std::cout << "\n[client] Statistics:\n"
                          << "  Assigned IP: " << client->GetAssignedIp() << "\n"
                          << "  Uptime: " << client->GetUptime().count() << " seconds\n"
                          << "  Bytes sent: " << client->GetBytesSent() << "\n"
                          << "  Bytes received: " << client->GetBytesReceived() << "\n";
            }
            std::cout << "simple_vpn stopped\n";
            return 0;
        }

        // ---- JSON config path ----

        std::ifstream config_file(config_path);
        if (!config_file.is_open())
        {
            std::cerr << "Error: Cannot open config file: " << config_path << "\n";
            return 1;
        }

        nlohmann::json root;
        config_file >> root;
        config_file.close();

        auto base_dir = std::filesystem::absolute(config_path).parent_path();

        bool has_server = root.contains("server");
        bool has_client = root.contains("client");

        if (!has_server && !has_client)
        {
            std::cerr << "Error: Config must contain at least one of \"server\" or \"client\".\n";
            return 1;
        }

        // ---- Privilege check (only for server role) ----
        if (has_server && geteuid() != 0)
        {
            std::cerr << "Error: Server role requires root privileges (TUN device creation).\n"
                      << "Please run with sudo.\n";
            return 1;
        }

        // ---- Create shared I/O context ----
        asio::io_context io_context;

        // ---- Instantiate server (if configured) ----
        std::unique_ptr<clv::vpn::VpnServer> server;
        if (has_server)
        {
            auto server_json = ResolveRoleConfig(root["server"], base_dir);
            auto server_config = clv::vpn::OpenVpnConfigParser::ParseJson(server_json);
            server = std::make_unique<clv::vpn::VpnServer>(io_context, server_config);

            std::cout << "[server] Loaded config — listening on :"
                      << server_config.server.port << " ("
                      << server_config.server.proto << ")\n";
        }

        // ---- Instantiate client (if configured) ----
        std::unique_ptr<clv::vpn::VpnClient> client;
        if (has_client)
        {
            const auto &client_value = root["client"];

            // Resolve the referenced path (string or $ref) to check for .ovpn
            std::string ref_path;
            if (client_value.is_string())
                ref_path = client_value.get<std::string>();
            else if (client_value.is_object() && client_value.contains("$ref"))
                ref_path = client_value["$ref"].get<std::string>();

            clv::vpn::VpnClientConfig client_config;
            if (!ref_path.empty() && IsOvpnFile(ref_path))
            {
                // .ovpn reference — use the dedicated parser
                auto ovpn_path = base_dir / ref_path;
                client_config = clv::vpn::VpnClientConfig::LoadFromOvpnFile(ovpn_path.string());
            }
            else
            {
                // Inline JSON or JSON file reference
                auto client_json = ResolveRoleConfig(client_value, base_dir);
                client_config = clv::vpn::VpnClientConfig::ParseJson(client_json);
            }

            client = std::make_unique<clv::vpn::VpnClient>(io_context, client_config);

            std::cout << "[client] Loaded config — target "
                      << client_config.server_host << ":"
                      << client_config.server_port << " ("
                      << client_config.protocol << ")\n";

            // Announce state transitions
            client->SetStateCallback([&](auto /*old*/, auto new_state)
            {
                if (new_state == clv::vpn::VpnClientState::Connected)
                {
                    std::cout << "\n[client] === VPN Connected ===\n"
                              << "  Assigned IP: " << client->GetAssignedIp() << "\n\n";
                }
            });
        }

        // ---- Signal handling ----
        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](const asio::error_code &ec, int signum)
        {
            if (ec)
                return;
            std::cout << "\nReceived signal " << signum << ", shutting down...\n";
            if (client)
                client->Disconnect();
            if (server)
            {
                server->Stop();
                io_context.stop();
            }
            if (!server)
                io_context.stop();
        });

        // ---- Start roles ----
        if (server)
            server->Start();
        if (client)
            client->Connect();

        // ---- Announce ----
        std::cout << "\n=== simple_vpn running";
        if (server && client)
            std::cout << " (server + client)";
        else if (server)
            std::cout << " (server)";
        else
            std::cout << " (client)";
        std::cout << " ===\nPress Ctrl+C to stop\n\n";

        // ---- Run event loop ----
        io_context.run();

        // ---- Post-run stats ----
        if (client && client->IsConnected())
        {
            std::cout << "\n[client] Statistics:\n"
                      << "  Assigned IP: " << client->GetAssignedIp() << "\n"
                      << "  Uptime: " << client->GetUptime().count() << " seconds\n"
                      << "  Bytes sent: " << client->GetBytesSent() << "\n"
                      << "  Bytes received: " << client->GetBytesReceived() << "\n";
        }

        std::cout << "simple_vpn stopped\n";
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}
