// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "ovpn_config_parser.h"
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace clv::vpn {

ClientConnectionConfig OvpnConfigParser::ParseFile(const std::filesystem::path &filepath)
{
    if (!std::filesystem::exists(filepath))
    {
        throw std::runtime_error("OvpnConfigParser: Config file not found: " + filepath.string());
    }

    std::ifstream file(filepath);
    if (!file.is_open())
    {
        throw std::runtime_error("OvpnConfigParser: Cannot open config file: " + filepath.string());
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return ParseString(buffer.str());
}

ClientConnectionConfig OvpnConfigParser::ParseString(const std::string &content)
{
    ClientConnectionConfig config = ParseContent(content);
    Validate(config);
    return config;
}

ClientConnectionConfig OvpnConfigParser::ParseContent(const std::string &content)
{
    ClientConnectionConfig config;
    std::istringstream stream(content);
    std::string line;
    size_t line_number = 0;

    // First pass: Extract inline blocks
    std::string remaining_content = content;

    // Extract <ca> block
    if (remaining_content.find("<ca>") != std::string::npos)
    {
        auto [ca_content, end_pos] = ParseInlineBlock(remaining_content, "ca", 0);
        config.ca_cert = ca_content;
    }

    // Extract <cert> block
    if (remaining_content.find("<cert>") != std::string::npos)
    {
        auto [cert_content, end_pos] = ParseInlineBlock(remaining_content, "cert", 0);
        config.client_cert = cert_content;
    }

    // Extract <key> block
    if (remaining_content.find("<key>") != std::string::npos)
    {
        auto [key_content, end_pos] = ParseInlineBlock(remaining_content, "key", 0);
        config.client_key = key_content;
    }

    // Extract <tls-auth> block
    if (remaining_content.find("<tls-auth>") != std::string::npos)
    {
        auto [tls_content, end_pos] = ParseInlineBlock(remaining_content, "tls-auth", 0);
        config.tls_auth = tls_content;
    }

    // Extract <tls-crypt> block
    if (remaining_content.find("<tls-crypt>") != std::string::npos)
    {
        auto [tls_content, end_pos] = ParseInlineBlock(remaining_content, "tls-crypt", 0);
        config.tls_crypt = tls_content;
    }

    // Second pass: Parse directive lines
    stream.clear();
    stream.seekg(0);

    while (std::getline(stream, line))
    {
        line_number++;
        line = Trim(line);

        if (IsCommentOrEmpty(line))
        {
            continue;
        }

        // Skip inline block markers (already processed)
        if (line.find('<') == 0)
        {
            // Skip until closing tag
            std::string tag = line.substr(1, line.find('>') - 1);
            std::string closing_tag = "</" + tag + ">";
            while (std::getline(stream, line))
            {
                if (Trim(line).find(closing_tag) != std::string::npos)
                {
                    break;
                }
            }
            continue;
        }

        try
        {
            ParseDirective(line, config);
        }
        catch (const std::exception &e)
        {
            throw std::runtime_error("OvpnConfigParser: Error at line " + std::to_string(line_number) + ": " + e.what());
        }
    }

    return config;
}

std::pair<std::string, size_t> OvpnConfigParser::ParseInlineBlock(
    const std::string &content,
    const std::string &tag,
    size_t start_pos)
{
    std::string open_tag = "<" + tag + ">";
    std::string close_tag = "</" + tag + ">";

    size_t open_pos = content.find(open_tag, start_pos);
    if (open_pos == std::string::npos)
    {
        return {"", std::string::npos};
    }

    size_t content_start = open_pos + open_tag.length();
    size_t close_pos = content.find(close_tag, content_start);

    if (close_pos == std::string::npos)
    {
        throw std::runtime_error("OvpnConfigParser: Missing closing tag </" + tag + ">");
    }

    std::string block_content = content.substr(content_start, close_pos - content_start);
    return {Trim(block_content), close_pos + close_tag.length()};
}

void OvpnConfigParser::ParseDirective(const std::string &line, ClientConnectionConfig &config)
{
    std::vector<std::string> tokens = Tokenize(line);
    if (tokens.empty())
    {
        return;
    }

    std::string keyword = ToLower(tokens[0]);

    // Remote directive: remote <host> [port] [proto]
    if (keyword == "remote")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("remote directive requires at least hostname");
        }
        config.remote.host = tokens[1];
        if (tokens.size() > 2)
        {
            config.remote.port = static_cast<uint16_t>(std::stoi(tokens[2]));
        }
        if (tokens.size() > 3)
        {
            config.remote.proto = ToLower(tokens[3]);
        }
    }
    // Proto directive: proto <udp|tcp>
    else if (keyword == "proto")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("proto directive requires protocol argument");
        }
        config.remote.proto = ToLower(tokens[1]);
    }
    // Device directive: dev <tun|tap>
    else if (keyword == "dev")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("dev directive requires device type");
        }
        config.dev = ToLower(tokens[1]);
    }
    // Device node: dev-node <path>
    else if (keyword == "dev-node")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("dev-node directive requires path");
        }
        config.dev_node = tokens[1];
    }
    // Cipher directive: cipher <algorithm>
    else if (keyword == "cipher")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("cipher directive requires algorithm");
        }
        config.cipher = tokens[1];
    }
    // Auth directive: auth <algorithm>
    else if (keyword == "auth")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("auth directive requires algorithm");
        }
        config.auth = tokens[1];
    }
    // TLS cipher: tls-cipher <cipher-suite>
    else if (keyword == "tls-cipher")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("tls-cipher directive requires cipher suite");
        }
        config.tls_cipher = tokens[1];
    }
    // Client mode
    else if (keyword == "client")
    {
        config.client_mode = true;
    }
    // Connection behavior flags
    else if (keyword == "nobind")
    {
        config.nobind = true;
    }
    else if (keyword == "persist-key")
    {
        config.persist_key = true;
    }
    else if (keyword == "persist-tun")
    {
        config.persist_tun = true;
    }
    else if (keyword == "resolv-retry")
    {
        if (tokens.size() > 1 && ToLower(tokens[1]) == "infinite")
        {
            config.resolv_retry_infinite = true;
        }
    }
    // Keepalive: keepalive <interval> <timeout>
    else if (keyword == "keepalive")
    {
        if (tokens.size() < 3)
        {
            throw std::runtime_error("keepalive directive requires interval and timeout");
        }
        config.keepalive_interval = std::stoi(tokens[1]);
        config.keepalive_timeout = std::stoi(tokens[2]);
    }
    // Renegotiation: reneg-sec <seconds>
    else if (keyword == "reneg-sec")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("reneg-sec directive requires seconds");
        }
        config.reneg_seconds = std::stoi(tokens[1]);
    }
    // Compression directives
    else if (keyword == "compress" || keyword == "comp-lzo")
    {
        if (keyword == "comp-lzo")
        {
            config.compression = "comp-lzo";
        }
        else if (tokens.size() > 1)
        {
            config.compression = tokens[1]; // e.g., "lz4-v2"
        }
    }
    // Verbosity: verb <level>
    else if (keyword == "verb")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("verb directive requires level");
        }
        config.verbosity = std::stoi(tokens[1]);
    }
    // DCO control
    else if (keyword == "disable-dco")
    {
        config.disable_dco = true;
    }
    // Socket buffer sizes: sndbuf <bytes> / rcvbuf <bytes>
    else if (keyword == "sndbuf")
    {
        if (tokens.size() >= 2)
            config.sndbuf = std::stoi(tokens[1]);
    }
    else if (keyword == "rcvbuf")
    {
        if (tokens.size() >= 2)
            config.rcvbuf = std::stoi(tokens[1]);
    }
    // Non-standard: process-quanta <N> (batch processing chunk size, 0 = no chunking)
    else if (keyword == "process-quanta")
    {
        if (tokens.size() >= 2)
            config.process_quanta = std::stoi(tokens[1]);
    }
    // Non-standard: stats-interval <seconds>
    else if (keyword == "stats-interval")
    {
        if (tokens.size() >= 2)
            config.stats_interval = std::stoi(tokens[1]);
    }
    // External certificate files
    else if (keyword == "ca")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("ca directive requires file path");
        }
        config.ca_cert = ReadFile(tokens[1], "ca");
    }
    else if (keyword == "cert")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("cert directive requires file path");
        }
        config.client_cert = ReadFile(tokens[1], "cert");
    }
    else if (keyword == "key")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("key directive requires file path");
        }
        config.client_key = ReadFile(tokens[1], "key");
    }
    else if (keyword == "tls-auth")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("tls-auth directive requires file path");
        }
        config.tls_auth = ReadFile(tokens[1], "tls-auth");
    }
    else if (keyword == "tls-crypt")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("tls-crypt directive requires file path");
        }
        config.tls_crypt = ReadFile(tokens[1], "tls-crypt");
    }
    // Route: route <network> <netmask> [gateway]
    else if (keyword == "route")
    {
        if (tokens.size() < 3)
        {
            throw std::runtime_error("route directive requires network and netmask");
        }
        std::string route_str = tokens[1] + " " + tokens[2];
        if (tokens.size() > 3)
        {
            route_str += " " + tokens[3];
        }
        config.routes.push_back(route_str);
    }
    // DHCP options (DNS, domain, etc.)
    else if (keyword == "dhcp-option")
    {
        if (tokens.size() < 3)
        {
            // Some dhcp-option may have different formats, skip for now
            return;
        }
        std::string option_type = tokens[1];
        if (option_type == "DNS")
        {
            config.dns_servers.push_back(tokens[2]);
        }
        else if (option_type == "DOMAIN")
        {
            config.dns_domain = tokens[2];
        }
    }
    // Connect timeout
    else if (keyword == "connect-timeout")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("connect-timeout directive requires seconds");
        }
        config.connect_timeout = std::stoi(tokens[1]);
    }
    // Connect retry
    else if (keyword == "connect-retry")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("connect-retry directive requires delay");
        }
        config.connect_retry_delay = std::stoi(tokens[1]);
    }
    else if (keyword == "connect-retry-max")
    {
        if (tokens.size() < 2)
        {
            throw std::runtime_error("connect-retry-max directive requires max attempts");
        }
        config.connect_retry_max = std::stoi(tokens[1]);
    }
    // Ignore unknown directives (for forward compatibility)
}

void OvpnConfigParser::Validate(const ClientConnectionConfig &config)
{
    // Validate remote host
    if (config.remote.host.empty())
    {
        throw std::runtime_error("OvpnConfigParser: remote host is required");
    }

    // Validate protocol
    if (config.remote.proto != "udp" && config.remote.proto != "tcp")
    {
        throw std::runtime_error("OvpnConfigParser: protocol must be 'udp' or 'tcp'");
    }

    // Validate device type
    if (config.dev != "tun" && config.dev != "tap")
    {
        throw std::runtime_error("OvpnConfigParser: device must be 'tun' or 'tap'");
    }

    // Validate that we have CA certificate (inline or external)
    if (std::holds_alternative<std::monostate>(config.ca_cert))
    {
        throw std::runtime_error("OvpnConfigParser: CA certificate is required (inline or file)");
    }

    // Validate port range
    if (config.remote.port == 0 || config.remote.port > 65535)
    {
        throw std::runtime_error("OvpnConfigParser: invalid port number");
    }
}

std::vector<std::string> OvpnConfigParser::Tokenize(const std::string &line)
{
    std::vector<std::string> tokens;
    std::istringstream stream(line);
    std::string token;

    while (stream >> token)
    {
        tokens.push_back(token);
    }

    return tokens;
}

std::string OvpnConfigParser::Trim(const std::string &str)
{
    size_t start = 0;
    size_t end = str.length();

    while (start < end && std::isspace(static_cast<unsigned char>(str[start])))
    {
        start++;
    }

    while (end > start && std::isspace(static_cast<unsigned char>(str[end - 1])))
    {
        end--;
    }

    return str.substr(start, end - start);
}

std::string OvpnConfigParser::ToLower(const std::string &str)
{
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c)
    { return std::tolower(c); });
    return result;
}

bool OvpnConfigParser::IsCommentOrEmpty(const std::string &line)
{
    if (line.empty())
    {
        return true;
    }

    char first = line[0];
    return (first == '#' || first == ';');
}

std::string OvpnConfigParser::ReadFile(const std::filesystem::path &file_path, const std::string &file_type)
{
    if (!std::filesystem::exists(file_path))
    {
        throw std::runtime_error(file_type + " file not found: " + file_path.string());
    }

    std::ifstream file(file_path);
    if (!file.is_open())
    {
        throw std::runtime_error("Cannot open " + file_type + " file: " + file_path.string());
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

} // namespace clv::vpn
