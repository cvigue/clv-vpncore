// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "openvpn/ovpn_config_parser.h"

#include <ci_string.h>
#include <config_io.h>
#include <parse_intake.h>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace clv::vpn {

namespace {

constexpr int kIntMax = std::numeric_limits<int>::max();

[[nodiscard]] int ParseIntToken(const std::string &token,
                                const char *directive,
                                int min_value,
                                int max_value)
{
    return clv::ParseBoundedOrThrow<int>(
        token,
        min_value,
        max_value,
        {.source = "OvpnConfigParser", .field = directive},
        [](const std::string &msg)
    { return std::runtime_error(msg); });
}

[[nodiscard]] std::string TrimString(const std::string &str)
{
    std::size_t start = 0;
    std::size_t end = str.length();

    while (start < end && std::isspace(static_cast<unsigned char>(str[start])))
        ++start;
    while (end > start && std::isspace(static_cast<unsigned char>(str[end - 1])))
        --end;

    return str.substr(start, end - start);
}

[[nodiscard]] std::string ReadOvpnSidecarFile(const std::string &path, const std::string &file_type)
{
    return config::ReadTextFile(path, OvpnConfigParser::kMaxInlineBlockBytes, file_type);
}

[[nodiscard]] std::vector<std::string> SplitColonList(const std::string &value)
{
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= value.size())
    {
        const std::size_t pos = value.find(':', start);
        std::string token = (pos == std::string::npos) ? value.substr(start) : value.substr(start, pos - start);
        token = TrimString(token);
        if (!token.empty())
            parts.push_back(token);
        if (pos == std::string::npos)
            break;
        start = pos + 1;
    }
    return parts;
}

void RequireArgCount(const std::vector<std::string> &tokens,
                     std::size_t min_count,
                     const char *message)
{
    if (tokens.size() < min_count)
        throw std::runtime_error(message);
}

void ApplyRemote(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "remote directive requires at least hostname");
    config.remote.host = tokens[1];
    if (tokens.size() > 2)
        config.remote.port = static_cast<std::uint16_t>(ParseIntToken(tokens[2], "remote port", 1, 65535));
    if (tokens.size() > 3)
    {
        clv::ci_string_view proto(tokens[3]);
        if (proto == "udp")
            config.remote.proto = "udp";
        else if (proto == "tcp")
            config.remote.proto = "tcp";
        else
            config.remote.proto = tokens[3];
    }
}

void ApplyProto(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "proto directive requires protocol argument");
    clv::ci_string_view proto(tokens[1]);
    if (proto == "udp")
        config.remote.proto = "udp";
    else if (proto == "tcp")
        config.remote.proto = "tcp";
    else
        config.remote.proto = tokens[1];
}

void ApplyDev(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "dev directive requires device type");
    clv::ci_string_view dev(tokens[1]);
    if (dev == "tun")
        config.dev = "tun";
    else if (dev == "tap")
        config.dev = "tap";
    else
        config.dev = tokens[1];
}

void ApplyDevNode(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "dev-node directive requires path");
    config.dev_node = tokens[1];
}

void ApplyCipher(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "cipher directive requires algorithm");
    config.cipher = tokens[1];
}

void ApplyDataCiphers(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "data-ciphers directive requires at least one cipher");
    config.data_ciphers = SplitColonList(tokens[1]);
    if (config.data_ciphers.empty())
        throw std::runtime_error("data-ciphers directive resolved to an empty list");
}

void ApplyAuth(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "auth directive requires algorithm");
    config.auth = tokens[1];
}

void ApplyTlsCipher(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "tls-cipher directive requires cipher suite");
    config.tls_cipher = tokens[1];
}

void ApplyClient(ClientConnectionConfig &config, const std::vector<std::string> & /*tokens*/)
{
    config.client_mode = true;
}

void ApplyNobind(ClientConnectionConfig &config, const std::vector<std::string> & /*tokens*/)
{
    config.nobind = true;
}

void ApplyPersistKey(ClientConnectionConfig &config, const std::vector<std::string> & /*tokens*/)
{
    config.persist_key = true;
}

void ApplyPersistTun(ClientConnectionConfig &config, const std::vector<std::string> & /*tokens*/)
{
    config.persist_tun = true;
}

void ApplyResolvRetry(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    if (tokens.size() > 1 && clv::ci_string_view(tokens[1]) == "infinite")
        config.resolv_retry_infinite = true;
}

void ApplyKeepalive(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 3, "keepalive directive requires interval and timeout");
    config.keepalive_interval = ParseIntToken(tokens[1], "keepalive interval", 0, kIntMax);
    config.keepalive_timeout = ParseIntToken(tokens[2], "keepalive timeout", 0, kIntMax);
}

void ApplyRenegSec(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "reneg-sec directive requires seconds");
    config.reneg_seconds = ParseIntToken(tokens[1], "reneg-sec", 0, kIntMax);
}

void ApplyCompress(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    if (tokens.size() > 1)
        config.compression = tokens[1];
}

void ApplyCompLzo(ClientConnectionConfig &config, const std::vector<std::string> & /*tokens*/)
{
    config.compression = "comp-lzo";
}

void ApplyVerb(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "verb directive requires level");
    config.verbosity = ParseIntToken(tokens[1], "verb", 0, 11);
}

void ApplyDisableDco(ClientConnectionConfig &config, const std::vector<std::string> & /*tokens*/)
{
    config.disable_dco = true;
}

void ApplySndbuf(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    if (tokens.size() >= 2)
        config.sndbuf = ParseIntToken(tokens[1], "sndbuf", 0, kIntMax);
}

void ApplyRcvbuf(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    if (tokens.size() >= 2)
        config.rcvbuf = ParseIntToken(tokens[1], "rcvbuf", 0, kIntMax);
}

void ApplyStatsInterval(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    if (tokens.size() >= 2)
        config.stats_interval = ParseIntToken(tokens[1], "stats-interval", 0, kIntMax);
}

void ApplyCa(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "ca directive requires file path");
    config.ca_cert = ReadOvpnSidecarFile(tokens[1], "ca");
}

void ApplyCert(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "cert directive requires file path");
    config.client_cert = ReadOvpnSidecarFile(tokens[1], "cert");
}

void ApplyKey(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "key directive requires file path");
    config.client_key = ReadOvpnSidecarFile(tokens[1], "key");
}

void ApplyTlsAuth(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "tls-auth directive requires file path");
    config.tls_auth = ReadOvpnSidecarFile(tokens[1], "tls-auth");
}

void ApplyTlsCrypt(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "tls-crypt directive requires file path");
    config.tls_crypt = ReadOvpnSidecarFile(tokens[1], "tls-crypt");
}

void ApplyRoute(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 3, "route directive requires network and netmask");
    std::string route_str = tokens[1] + " " + tokens[2];
    if (tokens.size() > 3)
        route_str += " " + tokens[3];
    config.routes.push_back(route_str);
}

void ApplyDhcpOption(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    if (tokens.size() < 3)
        return;
    const std::string &option_type = tokens[1];
    if (option_type == "DNS")
        config.dns_servers.push_back(tokens[2]);
    else if (option_type == "DOMAIN")
        config.dns_domain = tokens[2];
}

void ApplyConnectTimeout(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "connect-timeout directive requires seconds");
    config.connect_timeout = ParseIntToken(tokens[1], "connect-timeout", 0, kIntMax);
}

void ApplyConnectRetry(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "connect-retry directive requires delay");
    config.connect_retry_delay = ParseIntToken(tokens[1], "connect-retry", 0, kIntMax);
}

void ApplyConnectRetryMax(ClientConnectionConfig &config, const std::vector<std::string> &tokens)
{
    RequireArgCount(tokens, 2, "connect-retry-max directive requires max attempts");
    config.connect_retry_max = ParseIntToken(tokens[1], "connect-retry-max", 0, kIntMax);
}

using OvpnApplyFn = void (*)(ClientConnectionConfig &, const std::vector<std::string> &);

struct OvpnDirectiveSpec
{
    const char *keyword;
    OvpnApplyFn apply;
};

// NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays)
constexpr OvpnDirectiveSpec kOvpnDirectives[] = {
    {"remote", ApplyRemote},
    {"proto", ApplyProto},
    {"dev", ApplyDev},
    {"dev-node", ApplyDevNode},
    {"cipher", ApplyCipher},
    {"data-ciphers", ApplyDataCiphers},
    {"ncp-ciphers", ApplyDataCiphers},
    {"auth", ApplyAuth},
    {"tls-cipher", ApplyTlsCipher},
    {"client", ApplyClient},
    {"nobind", ApplyNobind},
    {"persist-key", ApplyPersistKey},
    {"persist-tun", ApplyPersistTun},
    {"resolv-retry", ApplyResolvRetry},
    {"keepalive", ApplyKeepalive},
    {"reneg-sec", ApplyRenegSec},
    {"compress", ApplyCompress},
    {"comp-lzo", ApplyCompLzo},
    {"verb", ApplyVerb},
    {"disable-dco", ApplyDisableDco},
    {"sndbuf", ApplySndbuf},
    {"rcvbuf", ApplyRcvbuf},
    {"stats-interval", ApplyStatsInterval},
    {"ca", ApplyCa},
    {"cert", ApplyCert},
    {"key", ApplyKey},
    {"tls-auth", ApplyTlsAuth},
    {"tls-crypt", ApplyTlsCrypt},
    {"route", ApplyRoute},
    {"dhcp-option", ApplyDhcpOption},
    {"connect-timeout", ApplyConnectTimeout},
    {"connect-retry", ApplyConnectRetry},
    {"connect-retry-max", ApplyConnectRetryMax},
};
// NOLINTEND(cppcoreguidelines-avoid-c-arrays)

const OvpnDirectiveSpec *LookupDirective(clv::ci_string_view keyword)
{
    for (const auto &spec : kOvpnDirectives)
    {
        if (keyword == spec.keyword)
            return &spec;
    }
    return nullptr;
}

} // namespace

ClientConnectionConfig OvpnConfigParser::ParseFile(const std::filesystem::path &filepath)
{
    return ParseString(config::ReadTextFile(filepath, kMaxConfigBytes, "OvpnConfigParser"));
}

ClientConnectionConfig OvpnConfigParser::ParseString(const std::string &content)
{
    if (content.size() > kMaxConfigBytes)
    {
        throw std::runtime_error("OvpnConfigParser: Config string too large");
    }
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

    const size_t block_len = close_pos - content_start;
    if (block_len > kMaxInlineBlockBytes)
    {
        throw std::runtime_error("OvpnConfigParser: Inline <" + tag + "> block too large");
    }

    std::string block_content = content.substr(content_start, block_len);
    return {Trim(block_content), close_pos + close_tag.length()};
}

void OvpnConfigParser::ParseDirective(const std::string &line, ClientConnectionConfig &config)
{
    const std::vector<std::string> tokens = Tokenize(line);
    if (tokens.empty())
        return;

    const clv::ci_string_view keyword(tokens[0]);
    if (const OvpnDirectiveSpec *spec = LookupDirective(keyword))
        spec->apply(config, tokens);
}

void OvpnConfigParser::Validate(const ClientConnectionConfig &config)
{
    // Validate remote host
    if (config.remote.host.empty())
    {
        throw std::runtime_error("OvpnConfigParser: remote host is required");
    }

    // Validate protocol - accept the udp6/tcp6 variants from real .ovpn files
    if (config.remote.proto != "udp" && config.remote.proto != "tcp"
        && config.remote.proto != "udp6" && config.remote.proto != "tcp6")
    {
        throw std::runtime_error("OvpnConfigParser: protocol must be 'udp', 'tcp', 'udp6', or 'tcp6'");
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
    if (config.remote.port == 0)
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
    return config::ReadTextFile(file_path, kMaxInlineBlockBytes, file_type);
}

} // namespace clv::vpn
