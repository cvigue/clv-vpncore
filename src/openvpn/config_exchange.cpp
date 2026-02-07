// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "config_exchange.h"
#include "crypto_algorithms.h"
#include "protocol_constants.h"
#include "util/byte_packer.h"
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <span>
#include <sstream>
#include <cctype>
#include <string>
#include <tuple>
#include <vector>

namespace clv::vpn::openvpn {

bool ConfigExchange::StartPushRequest()
{
    if (configured_)
        return false; // Already configured

    push_pending_ = true;
    return true;
}

bool ConfigExchange::ProcessPushReply(const std::string &options_str)
{
    if (configured_)
        return false; // Already configured

    // Reset configuration state before applying new options
    negotiated_config_ = NegotiatedConfig();
    received_options_.clear();

    // Parse comma-separated options: "option1 val1,option2 val2,..."
    std::istringstream stream(options_str);
    std::string token;

    while (std::getline(stream, token, ','))
    {
        // Trim whitespace
        token.erase(0, token.find_first_not_of(" \t\r\n"));
        token.erase(token.find_last_not_of(" \t\r\n") + 1);

        if (token.empty())
            continue;

        if (token.length() > MAX_OPTION_LENGTH)
            return false; // Option too long

        auto option = ParseOption(token);
        if (!option)
            return false; // Parse error

        if (!ApplyOption(*option))
            return false; // Application error

        received_options_.push_back(*option);

        if (received_options_.size() > MAX_CONFIG_OPTIONS)
            return false; // Too many options
    }

    // Validate cipher/auth compatibility
    if (!ValidateAlgorithms())
        return false;

    push_pending_ = false;
    configured_ = true;
    return true;
}

void ConfigExchange::AddLocalOption(const ConfigOption &option)
{
    if (local_options_.size() < MAX_CONFIG_OPTIONS)
    {
        local_options_.push_back(option);
    }
}

void ConfigExchange::Reset()
{
    configured_ = false;
    push_pending_ = false;
    received_options_.clear();
    local_options_.clear();
    negotiated_config_ = NegotiatedConfig();
}

std::optional<ConfigOption> ConfigExchange::ParseOption(const std::string &option_str)
{
    ConfigOption option;
    option.raw = option_str;

    std::istringstream stream(option_str);
    std::string key;

    if (!(stream >> key))
        return std::nullopt; // Empty option

    // Determine option type and parse arguments
    // This is a huge list of conditionals and I could make it better with a map if it really gets
    // out of hand later. For now this is fine.
    if (key == "cipher")
    {
        option.type = ConfigOptionType::CIPHER;
        std::string algo;
        if (stream >> algo)
            option.args.push_back(algo);
    }
    else if (key == "auth")
    {
        option.type = ConfigOptionType::AUTH;
        std::string algo;
        if (stream >> algo)
            option.args.push_back(algo);
    }
    else if (key == "compress")
    {
        option.type = ConfigOptionType::COMPRESS;
        std::string algo;
        if (stream >> algo)
            option.args.push_back(algo);
    }
    else if (key == "fragment")
    {
        option.type = ConfigOptionType::FRAGMENT;
        std::string size_str;
        if (stream >> size_str)
            option.args.push_back(size_str);
    }
    else if (key == "mssfix")
    {
        option.type = ConfigOptionType::MSSFIX;
        std::string size_str;
        if (stream >> size_str)
            option.args.push_back(size_str);
    }
    else if (key == "push-reset")
    {
        option.type = ConfigOptionType::PUSH_RESET;
    }
    else if (key == "route")
    {
        option.type = ConfigOptionType::ROUTE;
        std::string tok;
        while (stream >> tok)
            option.args.push_back(tok);
    }
    else if (key == "route-ipv6")
    {
        option.type = ConfigOptionType::ROUTE_IPV6;
        std::string tok;
        while (stream >> tok)
            option.args.push_back(tok);
    }
    else if (key == "route-gateway")
    {
        option.type = ConfigOptionType::ROUTE_GATEWAY;
        std::string gw;
        if (stream >> gw)
            option.args.push_back(gw);
    }
    else if (key == "dhcp-option")
    {
        option.type = ConfigOptionType::DHCP_OPTION;
        std::string type_str, value;
        if (stream >> type_str)
        {
            option.args.push_back(type_str);
            if (std::getline(stream, value))
            {
                // Trim leading space from getline
                if (!value.empty() && value[0] == ' ')
                    value.erase(0, 1);
                option.args.push_back(value);
            }
        }
    }
    else if (key == "redirect-gateway")
    {
        option.type = ConfigOptionType::REDIRECT_GATEWAY;
        std::string flags;
        if (std::getline(stream, flags))
        {
            if (!flags.empty() && flags[0] == ' ')
                flags.erase(0, 1);
            option.args.push_back(flags);
        }
    }
    else if (key == "topology")
    {
        option.type = ConfigOptionType::TOPOLOGY;
        std::string mode;
        if (stream >> mode)
            option.args.push_back(mode);
    }
    else if (key == "ifconfig")
    {
        option.type = ConfigOptionType::IFCONFIG;
        std::string local, remote;
        if (stream >> local >> remote)
            option.args = {local, remote};
    }
    else if (key == "ifconfig-ipv6")
    {
        option.type = ConfigOptionType::IFCONFIG_IPV6;
        std::string local, prefix;
        if (stream >> local >> prefix)
            option.args = {local, prefix};
    }
    else if (key == "register-dns")
    {
        option.type = ConfigOptionType::REGISTER_DNS;
    }
    else if (key == "inactive")
    {
        option.type = ConfigOptionType::INACTIVE;
        std::string timeout;
        if (stream >> timeout)
            option.args.push_back(timeout);
    }
    else if (key == "reneg-bytes")
    {
        option.type = ConfigOptionType::RENEG_BYTES;
        std::string bytes;
        if (stream >> bytes)
            option.args.push_back(bytes);
    }
    else if (key == "reneg-packets")
    {
        option.type = ConfigOptionType::RENEG_PACKETS;
        std::string packets;
        if (stream >> packets)
            option.args.push_back(packets);
    }
    else if (key == "reneg-sec")
    {
        option.type = ConfigOptionType::RENEG_SEC;
        std::string seconds;
        if (stream >> seconds)
            option.args.push_back(seconds);
    }
    else if (key == "peer-id")
    {
        option.type = ConfigOptionType::PEER_ID;
        std::string id;
        if (stream >> id)
            option.args.push_back(id);
    }
    else if (key == "ping")
    {
        option.type = ConfigOptionType::PING;
        std::string seconds;
        if (stream >> seconds)
            option.args.push_back(seconds);
    }
    else if (key == "ping-restart")
    {
        option.type = ConfigOptionType::PING_RESTART;
        std::string seconds;
        if (stream >> seconds)
            option.args.push_back(seconds);
    }
    else if (key == "tun-mtu")
    {
        option.type = ConfigOptionType::TUN_MTU;
        std::string mtu;
        if (stream >> mtu)
            option.args.push_back(mtu);
    }
    else
    {
        option.type = ConfigOptionType::UNKNOWN;
    }

    return option;
}

bool ConfigExchange::ApplyOption(const ConfigOption &option)
{
    if (!option.enabled)
        return true; // Disabled options are silently skipped

    // Again monster switch statement; fix later if it gets worse. For now it's manageable.
    switch (option.type)
    {
    case ConfigOptionType::CIPHER:
        if (option.args.size() >= 1)
            negotiated_config_.cipher = option.args[0];
        return !option.args.empty();

    case ConfigOptionType::AUTH:
        if (option.args.size() >= 1)
            negotiated_config_.auth = option.args[0];
        return !option.args.empty();

    case ConfigOptionType::COMPRESS:
        if (option.args.size() >= 1)
            negotiated_config_.compress = option.args[0];
        return !option.args.empty();

    case ConfigOptionType::FRAGMENT:
        if (option.args.size() >= 1)
        {
            try
            {
                negotiated_config_.fragment_size = static_cast<std::uint16_t>(std::stoul(option.args[0]));
            }
            catch (...)
            {
                return false;
            }
        }
        return !option.args.empty();

    case ConfigOptionType::MSSFIX:
        if (option.args.size() >= 1)
        {
            try
            {
                negotiated_config_.mssfix = static_cast<std::uint16_t>(std::stoul(option.args[0]));
            }
            catch (...)
            {
                return false;
            }
        }
        return !option.args.empty();

    case ConfigOptionType::PUSH_RESET:
        // Clear all previously received options
        negotiated_config_ = NegotiatedConfig();
        return true;

    case ConfigOptionType::ROUTE:
        if (option.args.size() >= 1)
        {
            std::string net = option.args[0];
            std::string mask_or_gw = (option.args.size() >= 2) ? option.args[1] : "";
            int metric = 0;
            if (option.args.size() >= 3)
            {
                try
                {
                    metric = std::stoi(option.args[2]);
                }
                catch (...)
                { /* ignore bad metric */
                }
            }
            negotiated_config_.routes.push_back({net, mask_or_gw, metric});
        }
        return option.args.size() >= 1;

    case ConfigOptionType::ROUTE_IPV6:
        if (option.args.size() >= 1)
        {
            std::string net = option.args[0];
            std::string gw = (option.args.size() >= 2) ? option.args[1] : "";
            int metric = 0;
            if (option.args.size() >= 3)
            {
                try
                {
                    metric = std::stoi(option.args[2]);
                }
                catch (...)
                { /* ignore bad metric */
                }
            }
            negotiated_config_.routes_ipv6.push_back({net, gw, metric});
        }
        return option.args.size() >= 1;

    case ConfigOptionType::DHCP_OPTION:
        if (option.args.size() >= 2)
        {
            negotiated_config_.dhcp_options.push_back({option.args[0], option.args[1]});
        }
        return option.args.size() >= 2;

    case ConfigOptionType::ROUTE_GATEWAY:
        if (option.args.size() >= 1)
            negotiated_config_.route_gateway = option.args[0];
        return !option.args.empty();

    case ConfigOptionType::REDIRECT_GATEWAY:
        if (option.args.size() >= 1)
            negotiated_config_.redirect_gateway = option.args[0];
        return !option.args.empty();

    case ConfigOptionType::TOPOLOGY:
        if (option.args.size() >= 1)
            negotiated_config_.topology = option.args[0];
        return !option.args.empty();

    case ConfigOptionType::IFCONFIG:
        if (option.args.size() >= 2)
        {
            negotiated_config_.ifconfig = {option.args[0], option.args[1]};
        }
        return option.args.size() >= 2;

    case ConfigOptionType::IFCONFIG_IPV6:
        if (option.args.size() >= 1)
        {
            try
            {
                // Format: "addr/prefix [gateway]"
                // args[0] = "fd00::65/112", args[1] = "fd00::1" (gateway, ignored here)
                auto &addr_prefix = option.args[0];
                auto slash = addr_prefix.find('/');
                if (slash != std::string::npos)
                {
                    std::string addr = addr_prefix.substr(0, slash);
                    int prefix = std::stoi(addr_prefix.substr(slash + 1));
                    negotiated_config_.ifconfig_ipv6 = {addr, prefix};
                }
                else
                {
                    // No prefix in addr, try args[1] as prefix
                    if (option.args.size() >= 2)
                    {
                        int prefix = std::stoi(option.args[1]);
                        negotiated_config_.ifconfig_ipv6 = {addr_prefix, prefix};
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            catch (...)
            {
                return false;
            }
        }
        return option.args.size() >= 1;

    case ConfigOptionType::REGISTER_DNS:
        negotiated_config_.register_dns = true;
        return true;

    case ConfigOptionType::INACTIVE:
        if (option.args.size() >= 1)
        {
            try
            {
                negotiated_config_.inactive_timeout = static_cast<std::uint32_t>(std::stoul(option.args[0]));
            }
            catch (...)
            {
                return false;
            }
        }
        return !option.args.empty();

    case ConfigOptionType::RENEG_BYTES:
        if (option.args.size() >= 1)
        {
            try
            {
                negotiated_config_.reneg_bytes = std::stoull(option.args[0]);
            }
            catch (...)
            {
                return false;
            }
        }
        return !option.args.empty();

    case ConfigOptionType::RENEG_PACKETS:
        if (option.args.size() >= 1)
        {
            try
            {
                negotiated_config_.reneg_packets = std::stoull(option.args[0]);
            }
            catch (...)
            {
                return false;
            }
        }
        return !option.args.empty();

    case ConfigOptionType::RENEG_SEC:
        if (option.args.size() >= 1)
        {
            try
            {
                negotiated_config_.reneg_sec = static_cast<std::uint32_t>(std::stoul(option.args[0]));
            }
            catch (...)
            {
                return false;
            }
        }
        return !option.args.empty();

    case ConfigOptionType::UNKNOWN:
        // Unknown options are accepted but not applied
        return true;

    case ConfigOptionType::PEER_ID:
        if (option.args.size() >= 1)
        {
            try
            {
                negotiated_config_.peer_id = static_cast<std::int32_t>(std::stol(option.args[0]));
            }
            catch (...)
            {
                return false;
            }
        }
        return !option.args.empty();

    case ConfigOptionType::PING:
        if (option.args.size() >= 1)
        {
            try
            {
                negotiated_config_.ping_interval = static_cast<std::uint32_t>(std::stoul(option.args[0]));
            }
            catch (...)
            {
                return false;
            }
        }
        return !option.args.empty();

    case ConfigOptionType::PING_RESTART:
        if (option.args.size() >= 1)
        {
            try
            {
                negotiated_config_.ping_restart = static_cast<std::uint32_t>(std::stoul(option.args[0]));
            }
            catch (...)
            {
                return false;
            }
        }
        return !option.args.empty();

    case ConfigOptionType::TUN_MTU:
        if (option.args.size() >= 1)
        {
            try
            {
                negotiated_config_.tun_mtu = static_cast<std::uint16_t>(std::stoul(option.args[0]));
            }
            catch (...)
            {
                return false;
            }
        }
        return !option.args.empty();
    }

    return true;
}

bool ConfigExchange::MergeOptions()
{
    // Simple merge: received options override local options
    // In a full implementation, we'd have more complex priority rules

    for (const auto &opt : received_options_)
    {
        if (!ApplyOption(opt))
            return false;
    }

    return true;
}

bool ConfigExchange::ValidateAlgorithms(bool strict)
{
    // Use centralized crypto registry for validation
    return ValidateAlgorithmCombination(negotiated_config_.cipher,
                                        negotiated_config_.auth,
                                        strict);
}

std::string ConfigExchange::BuildPushReplyWithIpv4(std::uint32_t client_ipv4,
                                                   std::uint32_t server_ipv4,
                                                   const std::vector<std::string> &extra_options)
{
    // Convert uint32_t IPv4 addresses to dotted-decimal format
    auto ipv4_to_string = [](std::uint32_t ip) -> std::string
    {
        return std::to_string((ip >> 24) & 0xFF) + "." + std::to_string((ip >> 16) & 0xFF) + "." + std::to_string((ip >> 8) & 0xFF) + "." + std::to_string(ip & 0xFF);
    };

    std::string client_ip_str = ipv4_to_string(client_ipv4);
    std::string server_ip_str = ipv4_to_string(server_ipv4);

    // Build PUSH_REPLY with required OpenVPN options
    // Format: PUSH_REPLY,<option1>,<option2>,...
    std::string push_reply = "PUSH_REPLY,";

    // Add ifconfig option: assigns IP to TUN interface
    // Format: ifconfig <client_ip> <server_ip>
    push_reply += "ifconfig " + client_ip_str + " " + server_ip_str;

    // Add route-gateway option: specifies default gateway
    push_reply += ",route-gateway " + server_ip_str;

    // Add extra options if provided (cipher, auth, routes, etc.)
    for (const auto &opt : extra_options)
    {
        if (!opt.empty())
        {
            push_reply += "," + opt;
        }
    }

    return push_reply;
}

std::vector<std::uint8_t> BuildKeyMethod2Message(
    const std::vector<std::uint8_t> &random_data,
    const std::string &options_string,
    const std::string &username,
    const std::string &password)
{
    std::vector<std::uint8_t> result;

    // Key method 2 format (from OpenVPN source ssl.c key_method_2_write):
    // [4 bytes: uint32 literal 0 - header]
    // [1 byte: KEY_METHOD_2 = 0x02]
    // [key source material: server sends random1(32) + random2(32) = 64 bytes]
    //                       client sends pre_master(48) + random1(32) + random2(32) = 112 bytes
    // [options_string_length: 2 bytes big-endian]
    // [options_string: null-terminated]
    // [username_length: 2 bytes big-endian]
    // [username: null-terminated]
    // [password_length: 2 bytes big-endian]
    // [password: null-terminated]
    // [peer_info_length: 2 bytes big-endian] (optional for server)
    // [peer_info: null-terminated] (optional for server)

    // 4-byte header (uint32 = 0) + Key method byte (KEY_METHOD_2 = 2)
    auto header = netcore::multi_uint_to_bytes(std::uint32_t{0}, std::uint8_t{0x02});
    result.insert(result.end(), header.begin(), header.end());

    // Random data - use as-is (caller provides correct size: 64 for server, 112 for client)
    result.insert(result.end(), random_data.begin(), random_data.end());

    // Length-prefixed null-terminated strings
    netcore::append_length_prefixed_string(result, options_string);
    netcore::append_length_prefixed_string(result, username);
    netcore::append_length_prefixed_string(result, password);

    return result;
}

std::optional<std::tuple<std::vector<std::uint8_t>, std::string, std::string, std::string>>
ParseKeyMethod2Message(const std::vector<std::uint8_t> &data, bool is_from_server)
{
    // Key method 2 format:
    // [4 bytes: uint32 header = 0]
    // [1 byte: KEY_METHOD_2 = 0x02]
    // [key source: server sends random1(32) + random2(32) = 64 bytes
    //              client sends pre_master(48) + random1(32) + random2(32) = 112 bytes]
    // [options_string_length: 2 bytes big-endian]
    // [options_string: null-terminated]
    // [username_length: 2 bytes big-endian]
    // [username: null-terminated]
    // [password_length: 2 bytes big-endian]
    // [password: null-terminated]
    // [peer_info_length: 2 bytes big-endian] (optional)
    // [peer_info: null-terminated] (optional)

    // Sizes defined in protocol_constants.h

    size_t key_source_size = is_from_server ? SERVER_KEY_SOURCE_SIZE : CLIENT_KEY_SOURCE_SIZE;

    // Minimum: 4 (header) + 1 (method) + key_source_size + 2 (options_len)
    if (data.size() < 4 + 1 + key_source_size + 2)
    {
        return std::nullopt;
    }

    size_t pos = 0;

    // Skip 4-byte header (should be 0)
    pos += 4;

    // Check key method byte (should be 2)
    if (data[pos] != 0x02)
    {
        return std::nullopt;
    }
    pos++;

    // Extract random data (64 bytes for server, 112 bytes for client)
    std::vector<std::uint8_t> random_data(data.begin() + pos, data.begin() + pos + key_source_size);
    pos += key_source_size;

    // Extract length-prefixed null-terminated strings
    std::span<const std::uint8_t> data_span(data);
    auto options_string = netcore::read_length_prefixed_string(data_span, pos);
    if (!options_string)
        return std::nullopt;

    auto username = netcore::read_length_prefixed_string(data_span, pos);
    auto password = netcore::read_length_prefixed_string(data_span, pos);

    return std::make_tuple(random_data,
                           *options_string,
                           username.value_or(""),
                           password.value_or(""));
}

} // namespace clv::vpn::openvpn
