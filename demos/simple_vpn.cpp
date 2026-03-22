// Copyright (c) 2025- Charlie Vigue. All rights reserved.

/**
 * @file simple_vpn.cpp
 * @brief Unified VPN node — runs 0‑1 server instances and 0‑N clients
 *
 * Usage: simple_vpn <config.json>
 *
 * The config file is standard VpnConfig JSON with an optional "clients" array.
 * Each clients entry can be:
 *   - An inline object (client fields; inherits root performance/logging)
 *   - A string path to a .json or .ovpn file (self-contained)
 *
 * Requires root/CAP_NET_ADMIN when a server section is present.
 */

#include "vpn_server.h"
#include "vpn_client.h"
#include "openvpn/vpn_config.h"
#include "asan_notify.h"

#include <asio.hpp>
#include <asio/signal_set.hpp>
#include <exception>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>

namespace vpn = clv::vpn;
using json = nlohmann::json;

/// Build a VpnConfig for an inline client object, inheriting root-level
/// performance and logging settings (with per-client overrides).
static vpn::VpnConfig BuildInlineClientConfig(const json &entry,
                                              const json &root)
{
    // Separate client fields from per-client section overrides
    json client_fields = entry;
    json perf_override;
    json log_override;

    if (client_fields.contains("performance"))
    {
        perf_override = client_fields["performance"];
        client_fields.erase("performance");
    }
    if (client_fields.contains("logging"))
    {
        log_override = client_fields["logging"];
        client_fields.erase("logging");
    }

    // Assemble a synthetic full-config JSON for the unified parser
    json synthetic;
    synthetic["client"] = client_fields;

    // Inherit root performance/logging, then layer per-client overrides
    if (root.contains("performance"))
        synthetic["performance"] = root["performance"];
    if (!perf_override.is_null())
        synthetic["performance"].update(perf_override);

    if (root.contains("logging"))
        synthetic["logging"] = root["logging"];
    if (!log_override.is_null())
        synthetic["logging"].update(log_override);

    return vpn::VpnConfigParser::ParseJson(synthetic);
}

int main(int argc, char *argv[])
{
    clv_announce_asan();

    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <config.json>\n"
                  << "\nRuns 0-1 VPN server instances and 0-N VPN clients.\n";
        return 1;
    }

    try
    {
        const std::filesystem::path config_path = argv[1];
        std::ifstream file(config_path);
        if (!file)
        {
            std::cerr << "Error: Cannot open " << config_path << "\n";
            return 1;
        }

        const json root = json::parse(file);

        // ── Parse base config (server + process + performance + logging) ──
        auto base_config = vpn::VpnConfigParser::ParseJson(root);

        if (base_config.HasServerRole() && geteuid() != 0)
        {
            std::cerr << "Error: Server mode requires root (TUN device creation).\n";
            return 1;
        }

        // ── Prepare I/O ──
        asio::io_context io_context;

        // ── Server (optional) ──
        std::unique_ptr<vpn::VpnServer> server;
        if (base_config.HasServerRole())
        {
            server = std::make_unique<vpn::VpnServer>(io_context, base_config);
        }

        // ── Clients (optional) ──
        std::vector<std::unique_ptr<vpn::VpnClient>> clients;

        if (root.contains("clients") && root["clients"].is_array())
        {
            for (const auto &entry : root["clients"])
            {
                vpn::VpnConfig client_config;

                if (entry.is_string())
                {
                    // External file — self-contained (.json or .ovpn)
                    client_config = vpn::VpnClientConfig::Load(
                        entry.get<std::string>());
                }
                else if (entry.is_object())
                {
                    // Inline object — inherits root performance/logging
                    client_config = BuildInlineClientConfig(entry, root);
                }
                else
                {
                    std::cerr << "Warning: Skipping invalid clients entry\n";
                    continue;
                }

                auto idx = clients.size() + 1;
                auto &client = clients.emplace_back(
                    std::make_unique<vpn::VpnClient>(io_context, client_config));

                client->SetStateCallback(
                    [idx](auto /*old*/, auto new_state)
                {
                    if (new_state == vpn::VpnClientState::Connected)
                        std::cout << "Client " << idx << " connected\n";
                    else if (new_state == vpn::VpnClientState::Error)
                        std::cerr << "Client " << idx << " error\n";
                });
            }
        }
        else if (base_config.HasClientRole())
        {
            // Single "client" section — use base_config directly
            auto &client = clients.emplace_back(
                std::make_unique<vpn::VpnClient>(io_context, base_config));

            client->SetStateCallback(
                [](auto /*old*/, auto new_state)
            {
                if (new_state == vpn::VpnClientState::Connected)
                    std::cout << "Client connected\n";
                else if (new_state == vpn::VpnClientState::Error)
                    std::cerr << "Client error\n";
            });
        }

        if (!server && clients.empty())
        {
            std::cerr << "Error: Config contains no server section and no clients array.\n";
            return 1;
        }

        // ── Signal handling ──
        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait(
            [&](const asio::error_code &ec, int signum)
        {
            if (ec)
                return;
            std::cout << "\nSignal " << signum << " — shutting down...\n";
            for (auto &c : clients)
                c->Disconnect();
            if (server)
                server->Stop();
        });

        // ── Start ──
        if (server)
        {
            server->Start();
            std::cout << "Server listening on "
                      << base_config.server->host << ":"
                      << base_config.server->port << "\n";
        }
        for (auto &c : clients)
            c->Connect();

        if (server && !clients.empty())
            std::cout << "\n=== VPN Node (server + "
                      << clients.size() << " client(s)) ===\n";
        else if (server)
            std::cout << "\n=== VPN Server ===\n";
        else
            std::cout << "\n=== VPN Client(s) (" << clients.size() << ") ===\n";

        std::cout << "Press Ctrl+C to stop\n\n";

        io_context.run();

        std::cout << "\nStopped\n";
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal: " << e.what() << "\n";
        return 1;
    }
}
