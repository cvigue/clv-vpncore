// Copyright (c) 2025- Charlie Vigue. All rights reserved.

/**
 * @file generate_client_config.cpp
 * @brief CLI tool for generating OpenVPN client configuration files
 * @details Command-line utility to generate .ovpn files from server configuration
 */

#include "openvpn/client_config_generator.h"
#include "openvpn/vpn_config.h"
#include <iostream>
#include <string>
#include <cstring>

using namespace clv::vpn;

/**
 * @brief Print usage information
 */
void PrintUsage(const char *program_name)
{
    std::cout << "OpenVPN Client Configuration Generator\n";
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n";
    std::cout << "Required:\n";
    std::cout << "  --server-config FILE    Path to server configuration JSON file\n";
    std::cout << "  --client-name NAME      Name/identifier for this client\n";
    std::cout << "  --output FILE           Output .ovpn file path\n\n";
    std::cout << "Client Certificates:\n";
    std::cout << "  --client-cert FILE      Path to client certificate (.crt)\n";
    std::cout << "  --client-key FILE       Path to client private key (.key)\n\n";
    std::cout << "Options:\n";
    std::cout << "  --remote HOST           Override server hostname/IP\n";
    std::cout << "  --external-certs        Use external cert files (don't embed)\n";
    std::cout << "  --tls-auth FILE         Enable tls-auth with key file\n";
    std::cout << "  --compression           Enable LZO compression\n";
    std::cout << "  --verbosity LEVEL       Set verbosity (0-11, default: 3)\n";
    std::cout << "  --dns SERVER            Add custom DNS server (can be repeated)\n";
    std::cout << "  --route ROUTE           Add extra route (can be repeated)\n";
    std::cout << "  --help                  Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  # Basic client config with embedded certificates\n";
    std::cout << "  " << program_name << " \\\n";
    std::cout << "    --server-config server.json \\\n";
    std::cout << "    --client-name alice \\\n";
    std::cout << "    --client-cert certs/alice.crt \\\n";
    std::cout << "    --client-key certs/alice.key \\\n";
    std::cout << "    --output alice.ovpn\n\n";
    std::cout << "  # With custom DNS and TLS-auth\n";
    std::cout << "  " << program_name << " \\\n";
    std::cout << "    --server-config server.json \\\n";
    std::cout << "    --client-name bob \\\n";
    std::cout << "    --client-cert certs/bob.crt \\\n";
    std::cout << "    --client-key certs/bob.key \\\n";
    std::cout << "    --tls-auth certs/ta.key \\\n";
    std::cout << "    --dns 1.1.1.1 \\\n";
    std::cout << "    --dns 1.0.0.1 \\\n";
    std::cout << "    --output bob.ovpn\n\n";
}

/**
 * @brief Parse command line arguments
 */
struct CommandLineArgs
{
    std::string server_config_path;
    std::string client_name;
    std::string output_path;
    std::optional<std::string> client_cert;
    std::optional<std::string> client_key;
    std::optional<std::string> remote_host;
    std::optional<std::string> tls_auth_key;
    std::vector<std::string> custom_dns;
    std::vector<std::string> extra_routes;
    bool embed_certificates = true;
    bool enable_compression = false;
    int verbosity = 3;

    bool Validate() const
    {
        if (server_config_path.empty())
        {
            std::cerr << "Error: --server-config is required\n";
            return false;
        }
        if (client_name.empty())
        {
            std::cerr << "Error: --client-name is required\n";
            return false;
        }
        if (output_path.empty())
        {
            std::cerr << "Error: --output is required\n";
            return false;
        }
        return true;
    }
};

/**
 * @brief Parse command line arguments
 */
CommandLineArgs ParseArgs(int argc, char *argv[])
{
    CommandLineArgs args;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h")
        {
            PrintUsage(argv[0]);
            std::exit(0);
        }
        else if (arg == "--server-config" && i + 1 < argc)
        {
            args.server_config_path = argv[++i];
        }
        else if (arg == "--client-name" && i + 1 < argc)
        {
            args.client_name = argv[++i];
        }
        else if (arg == "--output" && i + 1 < argc)
        {
            args.output_path = argv[++i];
        }
        else if (arg == "--client-cert" && i + 1 < argc)
        {
            args.client_cert = argv[++i];
        }
        else if (arg == "--client-key" && i + 1 < argc)
        {
            args.client_key = argv[++i];
        }
        else if (arg == "--remote" && i + 1 < argc)
        {
            args.remote_host = argv[++i];
        }
        else if (arg == "--tls-auth" && i + 1 < argc)
        {
            args.tls_auth_key = argv[++i];
        }
        else if (arg == "--dns" && i + 1 < argc)
        {
            args.custom_dns.push_back(argv[++i]);
        }
        else if (arg == "--route" && i + 1 < argc)
        {
            args.extra_routes.push_back(argv[++i]);
        }
        else if (arg == "--external-certs")
        {
            args.embed_certificates = false;
        }
        else if (arg == "--compression")
        {
            args.enable_compression = true;
        }
        else if (arg == "--verbosity" && i + 1 < argc)
        {
            args.verbosity = std::stoi(argv[++i]);
        }
        else
        {
            std::cerr << "Error: Unknown argument: " << arg << "\n";
            PrintUsage(argv[0]);
            std::exit(1);
        }
    }

    return args;
}

/**
 * @brief Main entry point
 */
int main(int argc, char *argv[])
{
    try
    {
        // Parse command line arguments
        if (argc < 2)
        {
            PrintUsage(argv[0]);
            return 1;
        }

        CommandLineArgs args = ParseArgs(argc, argv);

        if (!args.Validate())
        {
            std::cerr << "\nUse --help for usage information\n";
            return 1;
        }

        // Load server configuration
        std::cout << "Loading server config: " << args.server_config_path << "\n";
        OpenVpnConfig server_config = OpenVpnConfigParser::ParseFile(args.server_config_path);

        // Build client options
        ClientOptions client_opts;
        client_opts.client_name = args.client_name;
        client_opts.embed_certificates = args.embed_certificates;
        client_opts.enable_compression = args.enable_compression;
        client_opts.verbosity = args.verbosity;

        if (args.client_cert)
        {
            client_opts.client_cert = *args.client_cert;
        }
        if (args.client_key)
        {
            client_opts.client_key = *args.client_key;
        }
        if (args.remote_host)
        {
            client_opts.remote_host = *args.remote_host;
        }
        if (args.tls_auth_key)
        {
            client_opts.include_tls_auth = true;
            client_opts.tls_auth_key = *args.tls_auth_key;
        }

        client_opts.custom_dns = args.custom_dns;
        client_opts.extra_routes = args.extra_routes;

        // Generate configuration
        std::cout << "Generating client config for: " << args.client_name << "\n";
        ClientConfigGenerator generator;

        // Validate files before generation
        std::string validation_error = generator.ValidateFiles(server_config, client_opts);
        if (!validation_error.empty())
        {
            std::cerr << "Validation failed:\n"
                      << validation_error;
            return 1;
        }

        // Generate and write
        generator.GenerateAndWrite(server_config, client_opts, args.output_path);

        std::cout << "Success! Client configuration written to: " << args.output_path << "\n";

        // Print summary
        std::cout << "\nConfiguration Summary:\n";
        std::cout << "  Remote: " << server_config.server->host << ":"
                  << server_config.server->port << "\n";
        std::cout << "  Protocol: " << server_config.server->proto << "\n";
        std::cout << "  Cipher: " << server_config.server->cipher << "\n";
        std::cout << "  Auth: " << server_config.server->auth << "\n";
        std::cout << "  Certificates: "
                  << (args.embed_certificates ? "embedded" : "external") << "\n";

        if (client_opts.include_tls_auth)
        {
            std::cout << "  TLS-auth: enabled\n";
        }

        if (!client_opts.custom_dns.empty())
        {
            std::cout << "  Custom DNS: ";
            for (size_t i = 0; i < client_opts.custom_dns.size(); ++i)
            {
                if (i > 0)
                    std::cout << ", ";
                std::cout << client_opts.custom_dns[i];
            }
            std::cout << "\n";
        }

        if (!client_opts.extra_routes.empty())
        {
            std::cout << "  Extra routes: " << client_opts.extra_routes.size() << "\n";
        }

        std::cout << "\nTo connect:\n";
        std::cout << "  openvpn --config " << args.output_path << "\n";

        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
