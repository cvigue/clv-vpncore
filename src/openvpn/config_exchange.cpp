// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "config_exchange.h"
#include "crypto_algorithms.h"
#include "protocol_constants.h"
#include "util/byte_packer.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <vector>

namespace clv::vpn::openvpn {

// ============================================================================
// Table-driven option helpers
// ============================================================================

// --- String helpers: store args[0] into a std::string member ----------------
template <std::string NegotiatedConfig::*Field>
void ApplyString(NegotiatedConfig &c, const std::vector<std::string> &args)
{
    if (args.empty())
        throw ConfigParseError("missing argument for string option");
    c.*Field = args[0];
}

template <std::string NegotiatedConfig::*Field, char const *Keyword>
std::string EmitString(const NegotiatedConfig &c)
{
    if ((c.*Field).empty())
        return {};
    return std::string(",") + Keyword + ' ' + c.*Field;
}

// --- Unsigned integer helpers -----------------------------------------------
template <auto Field, typename Raw = unsigned long>
void ApplyUint(NegotiatedConfig &c, const std::vector<std::string> &args)
{
    if (args.empty())
        throw ConfigParseError("missing argument for integer option");
    try
    {
        c.*Field = static_cast<std::remove_reference_t<decltype(c.*Field)>>(std::stoul(args[0]));
    }
    catch (const std::exception &)
    {
        throw ConfigParseError("invalid integer value '" + args[0] + "'");
    }
}

template <auto Field>
void ApplyUint64(NegotiatedConfig &c, const std::vector<std::string> &args)
{
    if (args.empty())
        throw ConfigParseError("missing argument for integer option");
    try
    {
        c.*Field = std::stoull(args[0]);
    }
    catch (const std::exception &)
    {
        throw ConfigParseError("invalid integer value '" + args[0] + "'");
    }
}

template <auto Field>
void ApplyInt32(NegotiatedConfig &c, const std::vector<std::string> &args)
{
    if (args.empty())
        throw ConfigParseError("missing argument for integer option");
    try
    {
        c.*Field = static_cast<std::int32_t>(std::stol(args[0]));
    }
    catch (const std::exception &)
    {
        throw ConfigParseError("invalid integer value '" + args[0] + "'");
    }
}

template <auto Field, char const *Keyword>
std::string EmitUint(const NegotiatedConfig &c)
{
    if (c.*Field <= 0)
        return {};
    return std::string(",") + Keyword + ' ' + std::to_string(c.*Field);
}

template <auto Field, char const *Keyword>
std::string EmitInt32(const NegotiatedConfig &c)
{
    if (c.*Field < 0)
        return {};
    return std::string(",") + Keyword + ' ' + std::to_string(c.*Field);
}

// --- Flag helpers -----------------------------------------------------------
template <bool NegotiatedConfig::*Field>
void ApplyFlag(NegotiatedConfig &c, const std::vector<std::string> & /*args*/)
{
    c.*Field = true;
}

template <bool NegotiatedConfig::*Field, char const *Keyword>
std::string EmitFlag(const NegotiatedConfig &c)
{
    if (!(c.*Field))
        return {};
    return std::string(",") + Keyword;
}

// --- Route helpers (vector of tuples) ----------------------------------------

// Apply route: args = [net, mask_or_gw?, metric?]
template <auto Field>
void ApplyRoute(NegotiatedConfig &c, const std::vector<std::string> &args)
{
    if (args.empty())
        throw ConfigParseError("missing network for route option");
    std::string net = args[0];
    std::string mask_or_gw = (args.size() >= 2) ? args[1] : "";
    int metric = 0;
    if (args.size() >= 3)
    {
        try
        {
            metric = std::stoi(args[2]);
        }
        catch (...)
        { /* bad metric → 0 */
        }
    }
    (c.*Field).push_back({net, mask_or_gw, metric});
}

template <auto Field, char const *Keyword>
std::string EmitRoutes(const NegotiatedConfig &c)
{
    std::string result;
    for (const auto &[net, mask, metric] : c.*Field)
    {
        result += ',';
        result += Keyword;
        result += ' ';
        result += net;
        if (!mask.empty())
        {
            result += ' ';
            result += mask;
        }
        if (metric != 0)
        {
            result += ' ';
            result += std::to_string(metric);
        }
    }
    return result;
}

// --- Custom apply/emit for types that don't fit templates -------------------

void ApplyPushReset(NegotiatedConfig &c, const std::vector<std::string> & /*args*/)
{
    c = NegotiatedConfig();
}
std::string EmitNoop(const NegotiatedConfig &)
{
    return {};
}

// ifconfig: pair of strings
void ApplyIfconfig(NegotiatedConfig &c, const std::vector<std::string> &args)
{
    if (args.size() < 2)
        throw ConfigParseError("ifconfig requires local and remote addresses");
    c.ifconfig = {args[0], args[1]};
}
std::string EmitIfconfig(const NegotiatedConfig &c)
{
    if (c.ifconfig.first.empty() || c.ifconfig.second.empty())
        return {};
    return ",ifconfig " + c.ifconfig.first + ' ' + c.ifconfig.second;
}

// ifconfig-ipv6: "addr/prefix gateway" — complex slash-split parsing
void ApplyIfconfigIpv6(NegotiatedConfig &c, const std::vector<std::string> &args)
{
    if (args.empty())
        throw ConfigParseError("ifconfig-ipv6 requires address/prefix");
    try
    {
        auto &addr_prefix = args[0];
        auto slash = addr_prefix.find('/');
        if (slash != std::string::npos)
        {
            std::string addr = addr_prefix.substr(0, slash);
            int prefix = std::stoi(addr_prefix.substr(slash + 1));
            c.ifconfig_ipv6 = {addr, prefix};
        }
        else if (args.size() >= 2)
        {
            int prefix = std::stoi(args[1]);
            c.ifconfig_ipv6 = {addr_prefix, prefix};
        }
        else
        {
            throw ConfigParseError("ifconfig-ipv6 requires address/prefix");
        }
    }
    catch (const ConfigParseError &)
    {
        throw;
    }
    catch (const std::exception &)
    {
        throw ConfigParseError("invalid ifconfig-ipv6 value '" + args[0] + "'");
    }
}
std::string EmitIfconfigIpv6(const NegotiatedConfig &c)
{
    if (c.ifconfig_ipv6.first.empty() || c.ifconfig_ipv6.second <= 0)
        return {};
    return ",ifconfig-ipv6 " + c.ifconfig_ipv6.first + '/' + std::to_string(c.ifconfig_ipv6.second);
}

// dhcp-option: first arg is type, remaining args joined as value
void ApplyDhcpOption(NegotiatedConfig &c, const std::vector<std::string> &args)
{
    if (args.size() < 2)
        throw ConfigParseError("dhcp-option requires type and value");
    std::string value = args[1];
    for (std::size_t i = 2; i < args.size(); ++i)
    {
        value += ' ';
        value += args[i];
    }
    c.dhcp_options.push_back({args[0], value});
}
std::string EmitDhcpOptions(const NegotiatedConfig &c)
{
    std::string result;
    for (const auto &[type, value] : c.dhcp_options)
    {
        result += ",dhcp-option ";
        result += type;
        result += ' ';
        result += value;
    }
    return result;
}

// reneg-sec: special default (3600) — only emit if non-default and > 0
std::string EmitRenegSec(const NegotiatedConfig &c)
{
    if (c.reneg_sec == 3600 || c.reneg_sec <= 0)
        return {};
    return ",reneg-sec " + std::to_string(c.reneg_sec);
}

// ============================================================================
// Keyword string constants (needed for template NTTP)
// ============================================================================
// NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays)
inline constexpr char kCipher[] = "cipher";
inline constexpr char kAuth[] = "auth";
inline constexpr char kCompress[] = "compress";
inline constexpr char kFragment[] = "fragment";
inline constexpr char kMssfix[] = "mssfix";
inline constexpr char kTopology[] = "topology";
inline constexpr char kRouteGateway[] = "route-gateway";
inline constexpr char kRedirectGateway[] = "redirect-gateway";
inline constexpr char kInactive[] = "inactive";
inline constexpr char kRenegBytes[] = "reneg-bytes";
inline constexpr char kRenegPackets[] = "reneg-packets";
inline constexpr char kRenegSec[] = "reneg-sec";
inline constexpr char kPeerId[] = "peer-id";
inline constexpr char kPing[] = "ping";
inline constexpr char kPingRestart[] = "ping-restart";
inline constexpr char kTunMtu[] = "tun-mtu";
inline constexpr char kRoute[] = "route";
inline constexpr char kRouteIpv6[] = "route-ipv6";
inline constexpr char kRegisterDns[] = "register-dns";
// NOLINTEND(cppcoreguidelines-avoid-c-arrays)

// ============================================================================
// The option table
// ============================================================================

static constexpr auto kOptionTable = std::to_array<OptionSpec>({
    // --- String options (single arg) ---
    {"cipher", ConfigOptionType::CIPHER, ArgMode::SINGLE, ApplyString<&NegotiatedConfig::cipher>, EmitString<&NegotiatedConfig::cipher, kCipher>},
    {"auth", ConfigOptionType::AUTH, ArgMode::SINGLE, ApplyString<&NegotiatedConfig::auth>, EmitString<&NegotiatedConfig::auth, kAuth>},
    {"compress", ConfigOptionType::COMPRESS, ArgMode::SINGLE, ApplyString<&NegotiatedConfig::compress>, EmitString<&NegotiatedConfig::compress, kCompress>},
    {"topology", ConfigOptionType::TOPOLOGY, ArgMode::SINGLE, ApplyString<&NegotiatedConfig::topology>, EmitString<&NegotiatedConfig::topology, kTopology>},
    {"route-gateway", ConfigOptionType::ROUTE_GATEWAY, ArgMode::SINGLE, ApplyString<&NegotiatedConfig::route_gateway>, EmitString<&NegotiatedConfig::route_gateway, kRouteGateway>},
    {"redirect-gateway", ConfigOptionType::REDIRECT_GATEWAY, ArgMode::REST, ApplyString<&NegotiatedConfig::redirect_gateway>, EmitString<&NegotiatedConfig::redirect_gateway, kRedirectGateway>},

    // --- Unsigned integer options ---
    {"fragment", ConfigOptionType::FRAGMENT, ArgMode::SINGLE, ApplyUint<&NegotiatedConfig::fragment_size>, EmitUint<&NegotiatedConfig::fragment_size, kFragment>},
    {"mssfix", ConfigOptionType::MSSFIX, ArgMode::SINGLE, ApplyUint<&NegotiatedConfig::mssfix>, EmitUint<&NegotiatedConfig::mssfix, kMssfix>},
    {"tun-mtu", ConfigOptionType::TUN_MTU, ArgMode::SINGLE, ApplyUint<&NegotiatedConfig::tun_mtu>, EmitUint<&NegotiatedConfig::tun_mtu, kTunMtu>},
    {"inactive", ConfigOptionType::INACTIVE, ArgMode::SINGLE, ApplyUint<&NegotiatedConfig::inactive_timeout>, EmitUint<&NegotiatedConfig::inactive_timeout, kInactive>},
    {"ping", ConfigOptionType::PING, ArgMode::SINGLE, ApplyUint<&NegotiatedConfig::ping_interval>, EmitUint<&NegotiatedConfig::ping_interval, kPing>},
    {"ping-restart", ConfigOptionType::PING_RESTART, ArgMode::SINGLE, ApplyUint<&NegotiatedConfig::ping_restart>, EmitUint<&NegotiatedConfig::ping_restart, kPingRestart>},
    {"reneg-sec", ConfigOptionType::RENEG_SEC, ArgMode::SINGLE, ApplyUint<&NegotiatedConfig::reneg_sec>, EmitRenegSec},
    {"peer-id", ConfigOptionType::PEER_ID, ArgMode::SINGLE, ApplyInt32<&NegotiatedConfig::peer_id>, EmitInt32<&NegotiatedConfig::peer_id, kPeerId>},

    // --- Uint64 options ---
    {"reneg-bytes", ConfigOptionType::RENEG_BYTES, ArgMode::SINGLE, ApplyUint64<&NegotiatedConfig::reneg_bytes>, EmitUint<&NegotiatedConfig::reneg_bytes, kRenegBytes>},
    {"reneg-packets", ConfigOptionType::RENEG_PACKETS, ArgMode::SINGLE, ApplyUint64<&NegotiatedConfig::reneg_packets>, EmitUint<&NegotiatedConfig::reneg_packets, kRenegPackets>},

    // --- Flag options ---
    {"register-dns", ConfigOptionType::REGISTER_DNS, ArgMode::NONE, ApplyFlag<&NegotiatedConfig::register_dns>, EmitFlag<&NegotiatedConfig::register_dns, kRegisterDns>},

    // --- Route vectors ---
    {"route", ConfigOptionType::ROUTE, ArgMode::ALL, ApplyRoute<&NegotiatedConfig::routes>, EmitRoutes<&NegotiatedConfig::routes, kRoute>},
    {"route-ipv6", ConfigOptionType::ROUTE_IPV6, ArgMode::ALL, ApplyRoute<&NegotiatedConfig::routes_ipv6>, EmitRoutes<&NegotiatedConfig::routes_ipv6, kRouteIpv6>},

    // --- Custom handlers ---
    {"push-reset", ConfigOptionType::PUSH_RESET, ArgMode::NONE, ApplyPushReset, EmitNoop},
    {"ifconfig", ConfigOptionType::IFCONFIG, ArgMode::PAIR, ApplyIfconfig, EmitIfconfig},
    {"ifconfig-ipv6", ConfigOptionType::IFCONFIG_IPV6, ArgMode::PAIR, ApplyIfconfigIpv6, EmitIfconfigIpv6},
    {"dhcp-option", ConfigOptionType::DHCP_OPTION, ArgMode::ALL, ApplyDhcpOption, EmitDhcpOptions},
});

std::span<const OptionSpec> GetOptionTable()
{
    return kOptionTable;
}

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

    try
    {
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
                throw ConfigParseError("option exceeds maximum length: " + token.substr(0, 40) + "...");

            auto option = ParseOption(token);
            if (!option)
                throw ConfigParseError("failed to parse option: " + token);

            ApplyOption(*option);

            received_options_.push_back(*option);

            if (received_options_.size() > MAX_CONFIG_OPTIONS)
                throw ConfigParseError("too many options (limit " + std::to_string(MAX_CONFIG_OPTIONS) + ")");
        }

        // Validate cipher/auth compatibility
        if (!ValidateAlgorithms())
            throw ConfigParseError("invalid cipher/auth combination: " + negotiated_config_.cipher + "/" + negotiated_config_.auth);
    }
    catch (const ConfigParseError &e)
    {
        std::cerr << "PUSH_REPLY rejected: " << e.what() << '\n';
        negotiated_config_ = NegotiatedConfig();
        received_options_.clear();
        return false;
    }

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

    // Look up keyword in the option table
    auto table = GetOptionTable();
    auto it = std::find_if(table.begin(), table.end(), [&key](const OptionSpec &spec)
    { return spec.keyword == key; });

    if (it != table.end())
    {
        option.type = it->type;
        switch (it->arg_mode)
        {
        case ArgMode::SINGLE:
            {
                std::string tok;
                if (stream >> tok)
                    option.args.push_back(tok);
                break;
            }
        case ArgMode::PAIR:
            {
                std::string a, b;
                if (stream >> a)
                    option.args.push_back(a);
                if (stream >> b)
                    option.args.push_back(b);
                break;
            }
        case ArgMode::ALL:
            {
                std::string tok;
                while (stream >> tok)
                    option.args.push_back(tok);
                break;
            }
        case ArgMode::REST:
            {
                std::string rest;
                if (std::getline(stream, rest))
                {
                    if (!rest.empty() && rest[0] == ' ')
                        rest.erase(0, 1);
                    if (!rest.empty())
                        option.args.push_back(rest);
                }
                break;
            }
        case ArgMode::NONE:
            break;
        }
    }
    else
    {
        option.type = ConfigOptionType::UNKNOWN;
    }

    return option;
}

void ConfigExchange::ApplyOption(const ConfigOption &option)
{
    if (!option.enabled)
        return;

    if (option.type == ConfigOptionType::UNKNOWN)
        return;

    auto table = GetOptionTable();
    auto it = std::find_if(table.begin(), table.end(), [&option](const OptionSpec &spec)
    { return spec.type == option.type; });

    if (it != table.end())
        it->apply(negotiated_config_, option.args);
}

void ConfigExchange::MergeOptions()
{
    for (const auto &opt : received_options_)
        ApplyOption(opt);
}

bool ConfigExchange::ValidateAlgorithms(bool strict)
{
    // Use centralized crypto registry for validation
    return ValidateAlgorithmCombination(negotiated_config_.cipher,
                                        negotiated_config_.auth,
                                        strict);
}

std::string ConfigExchange::Serialize(const NegotiatedConfig &config)
{
    std::string result = "PUSH_REPLY";

    for (const auto &spec : GetOptionTable())
        result += spec.emit(config);

    return result;
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
