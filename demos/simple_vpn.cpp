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

#include "nlohmann/json_fwd.hpp"
#include "vpn_server.h"
#include "vpn_client.h"
#include "openvpn/vpn_config.h"
#include "scoped_proc_toggle.h"
#include "asan_notify.h"

#include <asio.hpp>
#include <exception>
#include <nlohmann/json.hpp>
#include <optional>
#include <spdlog/spdlog.h>

#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <signal.h>
#include <string>
#include <thread>
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

        // ── Block signals before spawning any threads ──
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);
        pthread_sigmask(SIG_BLOCK, &mask, nullptr);

        // ── Per-role reactor + thread ──
        struct Role
        {
            asio::io_context ctx;
            std::jthread thread;
        };
        std::vector<std::unique_ptr<Role>> roles;

        // ── Server (optional) ──
        std::unique_ptr<vpn::VpnServer> server;
        if (base_config.HasServerRole())
        {
            auto &role = roles.emplace_back(std::make_unique<Role>());
            server = std::make_unique<vpn::VpnServer>(role->ctx, base_config);
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

                auto &role = roles.emplace_back(std::make_unique<Role>());
                auto idx = clients.size() + 1;
                auto &client = clients.emplace_back(
                    std::make_unique<vpn::VpnClient>(role->ctx, client_config));

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
            auto &role = roles.emplace_back(std::make_unique<Role>());
            auto &client = clients.emplace_back(
                std::make_unique<vpn::VpnClient>(role->ctx, base_config));

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

        // ── IP forwarding (process-level, RAII) ──
        // Default: on for server role, off for client-only.
        // Explicit "transit_routing" in process config overrides.
        bool enable_forward = base_config.process.transit_routing.value_or(
            base_config.HasServerRole());

        std::optional<clv::vpn::ScopedIpForward> ip_fwd_guard;
        std::optional<clv::vpn::ScopedIpv6Forward> ip6_fwd_guard;
        if (enable_forward)
        {
            auto &proc_logger = *spdlog::default_logger();
            ip_fwd_guard.emplace(proc_logger);
            ip6_fwd_guard.emplace(proc_logger);
        }

        // ── Start roles and spawn threads ──
        if (server)
        {
            server->Start();
            std::cout << "Server listening on "
                      << base_config.server->host << ":"
                      << base_config.server->port << "\n";
        }
        for (auto &c : clients)
            c->Connect();

        for (auto &role : roles)
            role->thread = std::jthread([&role]
            { role->ctx.run(); });

        if (server && !clients.empty())
            std::cout << "\n=== VPN Node (server + "
                      << clients.size() << " client(s)) ===\n";
        else if (server)
            std::cout << "\n=== VPN Server ===\n";
        else
            std::cout << "\n=== VPN Client(s) (" << clients.size() << ") ===\n";

        std::cout << "Press Ctrl+C to stop\n\n";

        // ── Supervisor: park until signal ──
        int sig = 0;
        sigwait(&mask, &sig);
        std::cout << "\nSignal " << sig << " — shutting down...\n";

        // ── Ordered teardown: clients first, then server ──
        for (auto &c : clients)
            c->Disconnect();
        if (server)
            server->Stop();

        // Stop all reactors — unblocks ctx.run() in each thread
        for (auto &role : roles)
            role->ctx.stop();

        // ~jthread joins automatically when roles vector is cleared
        roles.clear();
        clients.clear();
        server.reset();

        std::cout << "Stopped\n";
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal: " << e.what() << "\n";
        return 1;
    }
}
