// Copyright (c) 2025- Charlie Vigue. All rights reserved.

/**
 * @file simple_vpn.cpp
 * @brief Unified VPN demo — runs as server, client, or both depending on config.
 *
 * Usage: simple_vpn <config.json | config.ovpn>
 *
 * If the argument is a .ovpn file, runs in client-only mode using that file.
 * Otherwise, expects a JSON config with top-level "server" and/or "client"
 * (or "clients" for multiple outbound connections) role sections. Each role
 * section can be:
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
 *
 *   // Multiple outbound clients
 *   {
 *     "server": { "$ref": "server_config.json" },
 *     "clients": [
 *       { "$ref": "client_config_site_a.json" },
 *       { "$ref": "client_config_site_b.json" }
 *     ]
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
#include <vector>

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

// ---------------------------------------------------------------------------
// Create a VpnServer from a role config section.
// ---------------------------------------------------------------------------
std::unique_ptr<clv::vpn::VpnServer> CreateServer(const nlohmann::json &role_value,
                                                  const std::filesystem::path &base_dir,
                                                  asio::io_context &io_context)
{
    auto server_json = ResolveRoleConfig(role_value, base_dir);
    auto config = clv::vpn::OpenVpnConfigParser::ParseJson(server_json);
    auto server = std::make_unique<clv::vpn::VpnServer>(io_context, config);

    std::cout << "[server] Loaded config — listening on :"
              << config.server.port << " (" << config.server.proto << ")\n";
    return server;
}

// ---------------------------------------------------------------------------
// Create a VpnClient from a role config section (JSON or .ovpn reference).
// ---------------------------------------------------------------------------
std::unique_ptr<clv::vpn::VpnClient> CreateClient(const nlohmann::json &role_value,
                                                  const std::filesystem::path &base_dir,
                                                  asio::io_context &io_context)
{
    std::string ref_path;
    if (role_value.is_string())
        ref_path = role_value.get<std::string>();
    else if (role_value.is_object() && role_value.contains("$ref"))
        ref_path = role_value["$ref"].get<std::string>();

    clv::vpn::VpnClientConfig config;
    if (!ref_path.empty() && IsOvpnFile(ref_path))
    {
        auto ovpn_path = base_dir / ref_path;
        config = clv::vpn::VpnClientConfig::LoadFromOvpnFile(ovpn_path.string());
    }
    else
    {
        auto client_json = ResolveRoleConfig(role_value, base_dir);
        config = clv::vpn::VpnClientConfig::ParseJson(client_json);
    }

    auto client = std::make_unique<clv::vpn::VpnClient>(io_context, config);

    std::cout << "[client] Loaded config — target "
              << config.server_host << ":" << config.server_port
              << " (" << config.protocol << ")\n";

    auto *client_ptr = client.get();
    client->SetStateCallback([client_ptr](auto /*old*/, auto new_state)
    {
        if (new_state == clv::vpn::VpnClientState::Connected)
        {
            std::cout << "\n[client] === VPN Connected ===\n"
                      << "  Assigned IP: " << client_ptr->GetAssignedIp() << "\n\n";
        }
    });

    return client;
}

// ---------------------------------------------------------------------------
// Print post-run stats for a connected client.
// ---------------------------------------------------------------------------
void PrintClientStats(const clv::vpn::VpnClient &client)
{
    if (!client.IsConnected())
        return;
    std::cout << "\n[client] Statistics:\n"
              << "  Assigned IP: " << client.GetAssignedIp() << "\n"
              << "  Uptime: " << client.GetUptime().count() << " seconds\n"
              << "  Bytes sent: " << client.GetBytesSent() << "\n"
              << "  Bytes received: " << client.GetBytesReceived() << "\n";
}

} // namespace

int main(int argc, char *argv[])
{
    clv_announce_asan();

    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <config.json | config.ovpn>\n"
                  << "\nIf the argument is a .ovpn file, runs as client using that profile.\n"
                  << "Otherwise, the JSON config may contain \"server\" and/or \"client\"\n"
                  << "(or \"clients\" for multiple outbound connections) sections.\n"
                  << "Each section can be an inline config object, a \"$ref\" to an external\n"
                  << "file (.json or .ovpn), or a bare string path to an external file.\n";
        return 1;
    }

    try
    {
        // ---- Load top-level config (JSON or .ovpn) ----
        std::filesystem::path config_path(argv[1]);
        if (!std::filesystem::exists(config_path))
        {
            std::cerr << "Error: Config file not found: " << config_path << "\n";
            return 1;
        }

        nlohmann::json root;
        std::filesystem::path base_dir;

        if (IsOvpnFile(config_path))
        {
            // .ovpn file → synthesize a JSON root that the unified path handles.
            // Use the filename only; base_dir provides the directory component.
            auto abs_path = std::filesystem::absolute(config_path);
            root = nlohmann::json{{"client", abs_path.filename().string()}};
            base_dir = abs_path.parent_path();
        }
        else
        {
            std::ifstream config_file(config_path);
            if (!config_file.is_open())
            {
                std::cerr << "Error: Cannot open config file: " << config_path << "\n";
                return 1;
            }
            config_file >> root;
            config_file.close();
            base_dir = std::filesystem::absolute(config_path).parent_path();
        }

        bool has_server = root.contains("server");
        bool has_clients = root.contains("clients") || root.contains("client");

        if (!has_server && !has_clients)
        {
            std::cerr << "Error: Config must contain at least one of "
                         "\"server\", \"client\", or \"clients\".\n";
            return 1;
        }

        // Normalize client config(s) into an array.
        nlohmann::json client_configs = nlohmann::json::array();
        if (root.contains("clients") && root["clients"].is_array())
            client_configs = root["clients"];
        else if (root.contains("client"))
            client_configs.push_back(root["client"]);

        // ---- Privilege check (only for server role) ----
        if (has_server && geteuid() != 0)
        {
            std::cerr << "Error: Server role requires root privileges (TUN device creation).\n"
                      << "Please run with sudo.\n";
            return 1;
        }

        // ---- Create shared I/O context ----
        asio::io_context io_context;

        // ---- Instantiate roles ----
        std::unique_ptr<clv::vpn::VpnServer> server;
        if (has_server)
            server = CreateServer(root["server"], base_dir, io_context);

        std::vector<std::unique_ptr<clv::vpn::VpnClient>> clients;
        for (const auto &client_cfg : client_configs)
            clients.push_back(CreateClient(client_cfg, base_dir, io_context));

        // ---- Signal handling ----
        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](const asio::error_code &ec, int signum)
        {
            if (ec)
                return;
            std::cout << "\nReceived signal " << signum << ", shutting down...\n";
            for (auto &c : clients)
                c->Disconnect();
            if (server)
                server->Stop();
            io_context.stop();
        });

        // ---- Start roles ----
        if (server)
            server->Start();
        for (auto &c : clients)
            c->Connect();

        // ---- Announce ----
        std::cout << "\n=== simple_vpn running (";
        if (server)
            std::cout << "server";
        if (server && !clients.empty())
            std::cout << " + ";
        if (!clients.empty())
        {
            std::cout << clients.size() << " client";
            if (clients.size() > 1)
                std::cout << "s";
        }
        std::cout << ") ===\nPress Ctrl+C to stop\n\n";

        // ---- Run event loop ----
        io_context.run();

        // ---- Post-run stats ----
        for (const auto &c : clients)
            PrintClientStats(*c);

        std::cout << "simple_vpn stopped\n";
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}
