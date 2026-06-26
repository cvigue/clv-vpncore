// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/config_exchange.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace clv::vpn::openvpn::test {

class ConfigExchangeTest : public ::testing::Test
{
  protected:
    ConfigExchange exchange_;
};

// ============================================================================
// Push Request Tests
// ============================================================================

TEST_F(ConfigExchangeTest, StartPushRequestSucceeds)
{
    EXPECT_TRUE(exchange_.StartPushRequest());
    EXPECT_TRUE(exchange_.IsPushPending());
    EXPECT_FALSE(exchange_.IsConfigured());
}

TEST_F(ConfigExchangeTest, StartPushRequestFailsWhenAlreadyConfigured)
{
    exchange_.ProcessPushReply("cipher AES-256-GCM");
    EXPECT_TRUE(exchange_.IsConfigured());

    EXPECT_FALSE(exchange_.StartPushRequest());
}

// ============================================================================
// Cipher/Auth Parsing Tests
// ============================================================================

TEST_F(ConfigExchangeTest, ParseCipherOption)
{
    exchange_.ProcessPushReply("cipher AES-256-GCM");
    EXPECT_EQ("AES-256-GCM", exchange_.GetNegotiatedConfig().cipher);
}

TEST_F(ConfigExchangeTest, ParseAuthOption)
{
    exchange_.ProcessPushReply("auth SHA256");
    EXPECT_EQ("SHA256", exchange_.GetNegotiatedConfig().auth);
}

TEST_F(ConfigExchangeTest, RejectCompressOption)
{
    EXPECT_THROW(exchange_.ProcessPushReply("compress lz4"), ConfigParseError);
}

TEST_F(ConfigExchangeTest, ParseMultipleCipherAuthOptions)
{
    exchange_.ProcessPushReply("cipher AES-128-GCM,auth SHA512");

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ("AES-128-GCM", config.cipher);
    EXPECT_EQ("SHA512", config.auth);
}

// ============================================================================
// Numeric Option Parsing Tests
// ============================================================================

TEST_F(ConfigExchangeTest, ParseFragmentOption)
{
    exchange_.ProcessPushReply("fragment 1500");
    EXPECT_EQ(1500, exchange_.GetNegotiatedConfig().fragment_size);
}

TEST_F(ConfigExchangeTest, ParseMssfixOption)
{
    exchange_.ProcessPushReply("mssfix 1450");
    EXPECT_EQ(1450, exchange_.GetNegotiatedConfig().mssfix);
}

TEST_F(ConfigExchangeTest, ParseInactiveOption)
{
    exchange_.ProcessPushReply("inactive 600");
    EXPECT_EQ(600, exchange_.GetNegotiatedConfig().inactive_timeout);
}

TEST_F(ConfigExchangeTest, ParseRenegBytesOption)
{
    exchange_.ProcessPushReply("reneg-bytes 1000000");
    EXPECT_EQ(1000000, exchange_.GetNegotiatedConfig().reneg_bytes);
}

TEST_F(ConfigExchangeTest, ParseRenegPacketsOption)
{
    exchange_.ProcessPushReply("reneg-packets 100000");
    EXPECT_EQ(100000, exchange_.GetNegotiatedConfig().reneg_packets);
}

TEST_F(ConfigExchangeTest, ParseRenegSecOption)
{
    exchange_.ProcessPushReply("reneg-sec 7200");
    EXPECT_EQ(7200, exchange_.GetNegotiatedConfig().reneg_sec);
}

// ============================================================================
// Route Parsing Tests
// ============================================================================

TEST_F(ConfigExchangeTest, ParseRouteOption)
{
    exchange_.ProcessPushReply("route 10.8.0.0 255.255.255.0 0");

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ(1, config.routes.size());
    EXPECT_EQ("10.8.0.0", std::get<0>(config.routes[0]));
    EXPECT_EQ("255.255.255.0", std::get<1>(config.routes[0]));
    EXPECT_EQ(0, std::get<2>(config.routes[0]));
}

TEST_F(ConfigExchangeTest, ParseMultipleRoutes)
{
    exchange_.ProcessPushReply("route 10.8.0.0 255.255.255.0 0,route 192.168.1.0 255.255.255.0 1");

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ(2, config.routes.size());
    EXPECT_EQ("10.8.0.0", std::get<0>(config.routes[0]));
    EXPECT_EQ("192.168.1.0", std::get<0>(config.routes[1]));
}

TEST_F(ConfigExchangeTest, ParseRouteIpv6Option)
{
    exchange_.ProcessPushReply("route-ipv6 2001:db8::/32 ::1 0");

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ(1, config.routes_ipv6.size());
    EXPECT_EQ("2001:db8::/32", std::get<0>(config.routes_ipv6[0]));
}

// ============================================================================
// Network Config Tests
// ============================================================================

TEST_F(ConfigExchangeTest, ParseTopologyOption)
{
    exchange_.ProcessPushReply("topology subnet");
    EXPECT_EQ("subnet", exchange_.GetNegotiatedConfig().topology);
}

TEST_F(ConfigExchangeTest, ParseIfconfigOption)
{
    exchange_.ProcessPushReply("ifconfig 10.8.0.6 10.8.0.5");

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ("10.8.0.6", config.ifconfig.first);
    EXPECT_EQ("10.8.0.5", config.ifconfig.second);
}

TEST_F(ConfigExchangeTest, ParseIfconfigIpv6Option)
{
    exchange_.ProcessPushReply("ifconfig-ipv6 fd00::1000 64");

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ("fd00::1000", config.ifconfig_ipv6.first);
    EXPECT_EQ(64, config.ifconfig_ipv6.second);
}

TEST_F(ConfigExchangeTest, ParseRedirectGatewayOption)
{
    exchange_.ProcessPushReply("redirect-gateway def1 bypass-dhcp");
    EXPECT_FALSE(exchange_.GetNegotiatedConfig().redirect_gateway.empty());
}

// ============================================================================
// Special Option Tests
// ============================================================================

TEST_F(ConfigExchangeTest, ParseRegisterDnsOption)
{
    exchange_.ProcessPushReply("register-dns");
    EXPECT_TRUE(exchange_.GetNegotiatedConfig().register_dns);
}

TEST_F(ConfigExchangeTest, ParseDhcpOptionDns)
{
    exchange_.ProcessPushReply("dhcp-option DNS 8.8.8.8");

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ(1, config.dhcp_options.size());
    EXPECT_EQ("DNS", config.dhcp_options[0].first);
    EXPECT_EQ("8.8.8.8", config.dhcp_options[0].second);
}

TEST_F(ConfigExchangeTest, ParseDhcpOptionDomain)
{
    exchange_.ProcessPushReply("dhcp-option DOMAIN example.com");

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ(1, config.dhcp_options.size());
    EXPECT_EQ("DOMAIN", config.dhcp_options[0].first);
    EXPECT_EQ("example.com", config.dhcp_options[0].second);
}

TEST_F(ConfigExchangeTest, ParseMultipleDhcpOptions)
{
    exchange_.ProcessPushReply("dhcp-option DNS 8.8.8.8,dhcp-option DNS 8.8.4.4");

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ(2, config.dhcp_options.size());
    EXPECT_EQ("DNS", config.dhcp_options[0].first);
    EXPECT_EQ("DNS", config.dhcp_options[1].first);
}

// ============================================================================
// Complex Configuration Tests
// ============================================================================

TEST_F(ConfigExchangeTest, ParseCompleteServerConfig)
{
    std::string config = "cipher AES-256-GCM,"
                         "auth SHA256,"
                         "topology subnet,"
                         "route 10.8.0.0 255.255.255.0 0,"
                         "ifconfig 10.8.0.6 10.8.0.5,"
                         "dhcp-option DNS 8.8.8.8,"
                         "dhcp-option DOMAIN example.com,"
                         "register-dns";

    exchange_.ProcessPushReply(config);
    EXPECT_TRUE(exchange_.IsConfigured());

    auto &cfg = exchange_.GetNegotiatedConfig();
    EXPECT_EQ("AES-256-GCM", cfg.cipher);
    EXPECT_EQ("SHA256", cfg.auth);
    EXPECT_EQ("subnet", cfg.topology);
    EXPECT_EQ(1, cfg.routes.size());
    EXPECT_EQ("10.8.0.6", cfg.ifconfig.first);
    EXPECT_EQ(2, cfg.dhcp_options.size());
    EXPECT_TRUE(cfg.register_dns);
}

TEST_F(ConfigExchangeTest, PushResetClearsOptions)
{
    exchange_.ProcessPushReply("cipher AES-256-GCM");
    EXPECT_EQ("AES-256-GCM", exchange_.GetNegotiatedConfig().cipher);

    exchange_.Reset();

    EXPECT_FALSE(exchange_.IsConfigured());
    EXPECT_TRUE(exchange_.StartPushRequest());

    exchange_.ProcessPushReply("push-reset,cipher AES-128-GCM");
    EXPECT_EQ("AES-128-GCM", exchange_.GetNegotiatedConfig().cipher);
}

// ============================================================================
// Validation Tests
// ============================================================================

TEST_F(ConfigExchangeTest, RejectsInvalidCipher)
{
    EXPECT_THROW(exchange_.ProcessPushReply("cipher INVALID-CIPHER"), ConfigParseError);
}

TEST_F(ConfigExchangeTest, RejectsInvalidAuth)
{
    EXPECT_THROW(exchange_.ProcessPushReply("cipher AES-256-GCM,auth INVALID-AUTH"), ConfigParseError);
}

TEST_F(ConfigExchangeTest, RejectsInvalidFragmentSize)
{
    EXPECT_THROW(exchange_.ProcessPushReply("fragment not-a-number"), ConfigParseError);
}

TEST_F(ConfigExchangeTest, AcceptsRouteWithInvalidMetric)
{
    // Invalid metric is silently ignored (defaults to 0)
    exchange_.ProcessPushReply("route 10.8.0.0 255.255.255.0 invalid");
    const auto &config = exchange_.GetNegotiatedConfig();
    ASSERT_EQ(config.routes.size(), 1u);
    EXPECT_EQ(std::get<0>(config.routes[0]), "10.8.0.0");
    EXPECT_EQ(std::get<2>(config.routes[0]), 0); // bad metric -> 0
}

TEST_F(ConfigExchangeTest, AcceptsRouteWithNetworkOnly)
{
    // route with only network and no mask/gw/metric is valid
    exchange_.ProcessPushReply("route 10.8.0.0");
    const auto &config = exchange_.GetNegotiatedConfig();
    ASSERT_EQ(config.routes.size(), 1u);
    EXPECT_EQ(std::get<0>(config.routes[0]), "10.8.0.0");
}

TEST_F(ConfigExchangeTest, RejectsOptionTooLong)
{
    std::string long_option("cipher " + std::string(600, 'A'));
    EXPECT_THROW(exchange_.ProcessPushReply(long_option), ConfigParseError);
}

TEST_F(ConfigExchangeTest, RejectsTooManyOptions)
{
    std::string many_options;
    for (int i = 0; i < 150; ++i)
    {
        if (i > 0)
            many_options += ",";
        many_options += "dhcp-option DNS 8.8.8.8";
    }
    EXPECT_THROW(exchange_.ProcessPushReply(many_options), ConfigParseError);
}

// ============================================================================
// State Management Tests
// ============================================================================

TEST_F(ConfigExchangeTest, ResetClearsConfiguredState)
{
    exchange_.ProcessPushReply("cipher AES-256-GCM");
    EXPECT_TRUE(exchange_.IsConfigured());

    exchange_.Reset();
    EXPECT_FALSE(exchange_.IsConfigured());
    EXPECT_FALSE(exchange_.IsPushPending());
}

TEST_F(ConfigExchangeTest, GetReceivedOptionsAfterProcessing)
{
    exchange_.ProcessPushReply("cipher AES-256-GCM,auth SHA256");

    auto &options = exchange_.GetReceivedOptions();
    EXPECT_GE(options.size(), 2);
}

TEST_F(ConfigExchangeTest, AddLocalOptions)
{
    ConfigOption opt;
    opt.type = ConfigOptionType::CIPHER;
    opt.args = {"AES-128-GCM"};

    exchange_.AddLocalOption(opt);

    auto &local = exchange_.GetLocalOptions();
    EXPECT_EQ(1, local.size());
    EXPECT_EQ(ConfigOptionType::CIPHER, local[0].type);
}

// ============================================================================
// Edge Cases Tests
// ============================================================================

TEST_F(ConfigExchangeTest, HandlesEmptyOptions)
{
    exchange_.ProcessPushReply("");
    EXPECT_TRUE(exchange_.IsConfigured());
}

TEST_F(ConfigExchangeTest, HandlesWhitespaceInOptions)
{
    exchange_.ProcessPushReply("  cipher   AES-256-GCM  ");
    EXPECT_EQ("AES-256-GCM", exchange_.GetNegotiatedConfig().cipher);
}

TEST_F(ConfigExchangeTest, HandlesTrailingCommas)
{
    exchange_.ProcessPushReply("cipher AES-256-GCM,");
    EXPECT_EQ("AES-256-GCM", exchange_.GetNegotiatedConfig().cipher);
}

TEST_F(ConfigExchangeTest, UnknownOptionsAccepted)
{
    exchange_.ProcessPushReply("unknown-option value");
    EXPECT_TRUE(exchange_.IsConfigured());
}

TEST_F(ConfigExchangeTest, MixValidAndUnknownOptions)
{
    exchange_.ProcessPushReply("cipher AES-256-GCM,unknown-feature value");
    EXPECT_EQ("AES-256-GCM", exchange_.GetNegotiatedConfig().cipher);
    EXPECT_TRUE(exchange_.IsConfigured());
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(ConfigExchangeTest, FullClientServerFlow)
{
    // Client requests configuration
    EXPECT_TRUE(exchange_.StartPushRequest());
    EXPECT_TRUE(exchange_.IsPushPending());

    // Server responds with configuration
    std::string server_config = "cipher AES-256-GCM,"
                                "auth SHA256,"
                                "topology subnet,"
                                "route 10.8.0.0 255.255.255.0 0,"
                                "ifconfig 10.8.0.6 10.8.0.5";

    exchange_.ProcessPushReply(server_config);
    EXPECT_FALSE(exchange_.IsPushPending());
    EXPECT_TRUE(exchange_.IsConfigured());

    // Verify all options applied
    auto &cfg = exchange_.GetNegotiatedConfig();
    EXPECT_EQ("AES-256-GCM", cfg.cipher);
    EXPECT_EQ("SHA256", cfg.auth);
    EXPECT_EQ("subnet", cfg.topology);
}

TEST_F(ConfigExchangeTest, RenegotiationFlow)
{
    // Initial configuration
    exchange_.ProcessPushReply("cipher AES-256-GCM,reneg-sec 3600");
    EXPECT_EQ(3600, exchange_.GetNegotiatedConfig().reneg_sec);

    // Renegotiate with new config
    exchange_.Reset();
    exchange_.ProcessPushReply("cipher AES-128-GCM,reneg-sec 7200");
    EXPECT_EQ("AES-128-GCM", exchange_.GetNegotiatedConfig().cipher);
    EXPECT_EQ(7200, exchange_.GetNegotiatedConfig().reneg_sec);
}

// ============================================================================
// Serialize Tests
// ============================================================================

TEST_F(ConfigExchangeTest, SerializeBasicIpv4Config)
{
    NegotiatedConfig config;
    config.ifconfig = {"10.8.0.2", "10.8.0.1"};
    config.route_gateway = "10.8.0.1";
    config.cipher = "AES-256-GCM";

    std::string reply = ConfigExchange::Serialize(config);

    EXPECT_NE(reply.find("PUSH_REPLY,"), std::string::npos);
    EXPECT_NE(reply.find("ifconfig 10.8.0.2 10.8.0.1"), std::string::npos);
    EXPECT_NE(reply.find("route-gateway 10.8.0.1"), std::string::npos);
    EXPECT_NE(reply.find("cipher AES-256-GCM"), std::string::npos);
}

TEST_F(ConfigExchangeTest, SerializeRoundTripAllFields)
{
    NegotiatedConfig original;
    original.ifconfig = {"10.8.0.6", "10.8.0.5"};
    original.ifconfig_ipv6 = {"fd00::6/64 fd00::1", 0};
    original.topology = "net30";
    original.route_gateway = "10.8.0.5";
    original.routes = {{"192.168.50.0", "255.255.255.0", 0}, {"10.0.0.0", "255.0.0.0", 0}};
    original.routes_ipv6 = {{"fd01::/64", "", 0}};
    original.cipher = "AES-256-GCM";
    original.auth = "SHA256";
    original.tun_mtu = 1500;
    original.ping_interval = 10;
    original.ping_restart = 60;
    original.peer_id = 42;

    std::string serialized = ConfigExchange::Serialize(original);

    // Strip "PUSH_REPLY," prefix before feeding to ProcessPushReply
    ASSERT_TRUE(serialized.starts_with("PUSH_REPLY,"));
    std::string options = serialized.substr(std::string("PUSH_REPLY,").size());

    ConfigExchange rx;
    rx.ProcessPushReply(options);

    auto &parsed = rx.GetNegotiatedConfig();
    EXPECT_EQ(parsed.ifconfig.first, original.ifconfig.first);
    EXPECT_EQ(parsed.ifconfig.second, original.ifconfig.second);
    EXPECT_EQ(parsed.topology, original.topology);
    EXPECT_EQ(parsed.cipher, original.cipher);
    EXPECT_EQ(parsed.auth, original.auth);
    EXPECT_EQ(parsed.tun_mtu, original.tun_mtu);
    EXPECT_EQ(parsed.ping_interval, original.ping_interval);
    EXPECT_EQ(parsed.ping_restart, original.ping_restart);
    EXPECT_EQ(parsed.peer_id, original.peer_id);
    ASSERT_EQ(parsed.routes.size(), 2u);
    EXPECT_EQ(std::get<0>(parsed.routes[0]), "192.168.50.0");
    EXPECT_EQ(std::get<1>(parsed.routes[0]), "255.255.255.0");
    EXPECT_EQ(std::get<0>(parsed.routes[1]), "10.0.0.0");
    EXPECT_EQ(std::get<1>(parsed.routes[1]), "255.0.0.0");
    ASSERT_EQ(parsed.routes_ipv6.size(), 1u);
    EXPECT_EQ(std::get<0>(parsed.routes_ipv6[0]), "fd01::/64");
}

TEST_F(ConfigExchangeTest, SerializeMinimalConfig)
{
    // Only the fields that Serialize always emits
    NegotiatedConfig config;
    config.cipher = "AES-128-GCM";
    config.ping_interval = 5;
    config.ping_restart = 30;

    std::string reply = ConfigExchange::Serialize(config);

    EXPECT_NE(reply.find("PUSH_REPLY"), std::string::npos);
    EXPECT_NE(reply.find("cipher AES-128-GCM"), std::string::npos);
    EXPECT_NE(reply.find("ping 5"), std::string::npos);
    EXPECT_NE(reply.find("ping-restart 30"), std::string::npos);
    // Should NOT contain ifconfig since it was empty
    EXPECT_EQ(reply.find("ifconfig"), std::string::npos);
}

TEST_F(ConfigExchangeTest, SerializeWithIpv6Route)
{
    NegotiatedConfig config;
    config.cipher = "AES-256-GCM";
    config.routes_ipv6 = {{"2001:db8::/32", "", 0}};

    std::string reply = ConfigExchange::Serialize(config);
    EXPECT_NE(reply.find("route-ipv6 2001:db8::/32"), std::string::npos);
}

// ============================================================================
// Template error paths — missing/invalid arguments (previously dead)
// ============================================================================

TEST_F(ConfigExchangeTest, RejectsMissingArgumentForStringOption)
{
    // "cipher" alone — ApplyString throws ConfigParseError("missing argument for string option")
    EXPECT_THROW(exchange_.ProcessPushReply("cipher"), ConfigParseError);
}

TEST_F(ConfigExchangeTest, RejectsMissingArgumentForIntegerOption)
{
    // "fragment" alone — ApplyUint throws ConfigParseError("missing argument for integer option")
    EXPECT_THROW(exchange_.ProcessPushReply("fragment"), ConfigParseError);
}

TEST_F(ConfigExchangeTest, RejectsMissingArgumentForRenegBytes)
{
    // "reneg-bytes" alone — ApplyUint64 throws
    EXPECT_THROW(exchange_.ProcessPushReply("reneg-bytes"), ConfigParseError);
}

TEST_F(ConfigExchangeTest, RejectsMissingArgumentForPeerId)
{
    // "peer-id" alone — ApplyInt32 throws
    EXPECT_THROW(exchange_.ProcessPushReply("peer-id"), ConfigParseError);
}

TEST_F(ConfigExchangeTest, RejectsMissingSecondArgForIfconfig)
{
    // ifconfig with only one address — ApplyIfconfig throws
    EXPECT_THROW(exchange_.ProcessPushReply("ifconfig 10.0.0.1"), ConfigParseError);
}

TEST_F(ConfigExchangeTest, RejectsMissingArgsForDhcpOption)
{
    // dhcp-option with only a type but no value — ApplyDhcpOption throws
    EXPECT_THROW(exchange_.ProcessPushReply("dhcp-option DNS"), ConfigParseError);
}

TEST_F(ConfigExchangeTest, RejectsMissingArgForIfconfigIpv6)
{
    // ifconfig-ipv6 with no args — ApplyIfconfigIpv6 throws
    EXPECT_THROW(exchange_.ProcessPushReply("ifconfig-ipv6"), ConfigParseError);
}

TEST_F(ConfigExchangeTest, RejectsInvalidIntegerForPeerId)
{
    // "peer-id notanumber" — stol throws caught by ApplyInt32 → ConfigParseError
    EXPECT_THROW(exchange_.ProcessPushReply("peer-id notanumber"), ConfigParseError);
}

TEST_F(ConfigExchangeTest, RejectsInvalidIntegerForRenegBytes)
{
    // "reneg-bytes notanumber" — stoull throws caught by ApplyUint64 → ConfigParseError
    EXPECT_THROW(exchange_.ProcessPushReply("reneg-bytes notanumber"), ConfigParseError);
}

// ============================================================================
// DNS option parsing tests
//
// TODO: expand coverage once the official clv client ships --dns support.
// Missing cases to add at that time:
//   - GetDnsServers() structured path via a live pushed PUSH_REPLY (requires
//     a mock/stub ClientControlAdapter to drive ProcessPushReply end-to-end)
//   - Server PUSH_REPLY conditional path: IV_PROTO_DNS_OPTION_V2 set → dns
//     server entries emitted; bit clear → dhcp-option DNS emitted instead
//   - Port-qualified addresses ("8.8.8.8:5353") preserved through round-trip
//   - Multiple search-domain accumulation across separate push lines
//   - Priority ordering preserved after multiple server entries
// ============================================================================

TEST_F(ConfigExchangeTest, ParseDnsServerAddress)
{
    exchange_.ProcessPushReply("dns server 0 address 8.8.8.8");
    const auto &cfg = exchange_.GetNegotiatedConfig();
    ASSERT_EQ(1u, cfg.dns_servers.size());
    EXPECT_EQ(0, cfg.dns_servers[0].priority);
    ASSERT_EQ(1u, cfg.dns_servers[0].addresses.size());
    EXPECT_EQ("8.8.8.8", cfg.dns_servers[0].addresses[0]);
    EXPECT_TRUE(cfg.dns_servers[0].resolve_domains.empty());
}

TEST_F(ConfigExchangeTest, ParseDnsServerMultipleAddresses)
{
    // Two address lines for the same priority accumulate in one DnsServerEntry
    exchange_.ProcessPushReply("dns server 0 address 8.8.8.8,dns server 0 address 8.8.4.4");
    const auto &cfg = exchange_.GetNegotiatedConfig();
    ASSERT_EQ(1u, cfg.dns_servers.size());
    EXPECT_EQ(0, cfg.dns_servers[0].priority);
    ASSERT_EQ(2u, cfg.dns_servers[0].addresses.size());
    EXPECT_EQ("8.8.8.8", cfg.dns_servers[0].addresses[0]);
    EXPECT_EQ("8.8.4.4", cfg.dns_servers[0].addresses[1]);
}

TEST_F(ConfigExchangeTest, ParseDnsServerMultiplePriorities)
{
    // Different priorities produce separate DnsServerEntry objects
    exchange_.ProcessPushReply("dns server 0 address 8.8.8.8,dns server 1 address 1.1.1.1");
    const auto &cfg = exchange_.GetNegotiatedConfig();
    ASSERT_EQ(2u, cfg.dns_servers.size());
    EXPECT_EQ(0, cfg.dns_servers[0].priority);
    EXPECT_EQ("8.8.8.8", cfg.dns_servers[0].addresses[0]);
    EXPECT_EQ(1, cfg.dns_servers[1].priority);
    EXPECT_EQ("1.1.1.1", cfg.dns_servers[1].addresses[0]);
}

TEST_F(ConfigExchangeTest, ParseDnsServerResolveDomains)
{
    exchange_.ProcessPushReply("dns server 0 resolve-domains corp.internal example.com");
    const auto &cfg = exchange_.GetNegotiatedConfig();
    ASSERT_EQ(1u, cfg.dns_servers.size());
    EXPECT_EQ(0, cfg.dns_servers[0].priority);
    EXPECT_TRUE(cfg.dns_servers[0].addresses.empty());
    ASSERT_EQ(2u, cfg.dns_servers[0].resolve_domains.size());
    EXPECT_EQ("corp.internal", cfg.dns_servers[0].resolve_domains[0]);
    EXPECT_EQ("example.com", cfg.dns_servers[0].resolve_domains[1]);
}

TEST_F(ConfigExchangeTest, ParseDnsServerAddressAndResolveDomainsSamePriority)
{
    // address and resolve-domains on same priority entry accumulate
    exchange_.ProcessPushReply(
        "dns server 0 address 10.0.0.1,dns server 0 resolve-domains corp.internal");
    const auto &cfg = exchange_.GetNegotiatedConfig();
    ASSERT_EQ(1u, cfg.dns_servers.size());
    ASSERT_EQ(1u, cfg.dns_servers[0].addresses.size());
    ASSERT_EQ(1u, cfg.dns_servers[0].resolve_domains.size());
    EXPECT_EQ("10.0.0.1", cfg.dns_servers[0].addresses[0]);
    EXPECT_EQ("corp.internal", cfg.dns_servers[0].resolve_domains[0]);
}

TEST_F(ConfigExchangeTest, ParseDnsSearchDomains)
{
    exchange_.ProcessPushReply("dns search-domains example.com corp.internal");
    const auto &cfg = exchange_.GetNegotiatedConfig();
    ASSERT_EQ(2u, cfg.dns_search_domains.size());
    EXPECT_EQ("example.com", cfg.dns_search_domains[0]);
    EXPECT_EQ("corp.internal", cfg.dns_search_domains[1]);
}

TEST_F(ConfigExchangeTest, ParseDnsSearchSingleDomain)
{
    exchange_.ProcessPushReply("dns search-domains example.com");
    const auto &cfg = exchange_.GetNegotiatedConfig();
    ASSERT_EQ(1u, cfg.dns_search_domains.size());
    EXPECT_EQ("example.com", cfg.dns_search_domains[0]);
}

TEST_F(ConfigExchangeTest, ParseDnsUnknownFieldKeyIgnored)
{
    // Unknown field key within "dns server N <key>" is logged and no entry created.
    exchange_.ProcessPushReply("dns server 0 future-option foo bar");
    EXPECT_TRUE(exchange_.GetNegotiatedConfig().dns_servers.empty());
}

TEST_F(ConfigExchangeTest, ParseDnsUnknownTopLevelSubcommandIgnored)
{
    // Unknown top-level dns sub-command is logged and state is not modified.
    exchange_.ProcessPushReply("dns future-feature foo");
    EXPECT_TRUE(exchange_.GetNegotiatedConfig().dns_servers.empty());
    EXPECT_TRUE(exchange_.GetNegotiatedConfig().dns_search_domains.empty());
}

TEST_F(ConfigExchangeTest, ParseDnsCoexistsWithDhcpOption)
{
    // Both structured dns and legacy dhcp-option DNS can coexist
    exchange_.ProcessPushReply(
        "dns server 0 address 8.8.8.8,dhcp-option DNS 1.1.1.1");
    const auto &cfg = exchange_.GetNegotiatedConfig();
    ASSERT_EQ(1u, cfg.dns_servers.size());
    EXPECT_EQ("8.8.8.8", cfg.dns_servers[0].addresses[0]);
    ASSERT_EQ(1u, cfg.dhcp_options.size());
    EXPECT_EQ("DNS", cfg.dhcp_options[0].first);
    EXPECT_EQ("1.1.1.1", cfg.dhcp_options[0].second);
}

TEST_F(ConfigExchangeTest, SerializeDnsServersRoundTrip)
{
    NegotiatedConfig original;
    original.cipher = "AES-256-GCM";
    original.ping_interval = 10;
    original.ping_restart = 60;
    DnsServerEntry entry;
    entry.priority = 0;
    entry.addresses = {"8.8.8.8", "8.8.4.4"};
    original.dns_servers.push_back(entry);
    original.dns_search_domains = {"example.com"};

    std::string serialized = ConfigExchange::Serialize(original);

    EXPECT_NE(serialized.find("dns server 0 address 8.8.8.8"), std::string::npos);
    EXPECT_NE(serialized.find("dns server 0 address 8.8.4.4"), std::string::npos);
    EXPECT_NE(serialized.find("dns search-domains example.com"), std::string::npos);

    // Strip PUSH_REPLY, prefix and re-parse
    ASSERT_TRUE(serialized.starts_with("PUSH_REPLY,"));
    std::string options = serialized.substr(std::string("PUSH_REPLY,").size());
    ConfigExchange rx;
    rx.ProcessPushReply(options);

    const auto &parsed = rx.GetNegotiatedConfig();
    ASSERT_EQ(1u, parsed.dns_servers.size());
    EXPECT_EQ(0, parsed.dns_servers[0].priority);
    ASSERT_EQ(2u, parsed.dns_servers[0].addresses.size());
    EXPECT_EQ("8.8.8.8", parsed.dns_servers[0].addresses[0]);
    EXPECT_EQ("8.8.4.4", parsed.dns_servers[0].addresses[1]);
    ASSERT_EQ(1u, parsed.dns_search_domains.size());
    EXPECT_EQ("example.com", parsed.dns_search_domains[0]);
}

TEST_F(ConfigExchangeTest, SerializeDnsResolveDomainRoundTrip)
{
    NegotiatedConfig original;
    original.cipher = "AES-256-GCM";
    original.ping_interval = 10;
    original.ping_restart = 60;
    DnsServerEntry entry;
    entry.priority = 2;
    entry.addresses = {"10.0.0.53"};
    entry.resolve_domains = {"corp.internal", "dev.local"};
    original.dns_servers.push_back(entry);

    std::string serialized = ConfigExchange::Serialize(original);

    EXPECT_NE(serialized.find("dns server 2 address 10.0.0.53"), std::string::npos);
    EXPECT_NE(serialized.find("dns server 2 resolve-domains corp.internal dev.local"), std::string::npos);

    ASSERT_TRUE(serialized.starts_with("PUSH_REPLY,"));
    std::string options = serialized.substr(std::string("PUSH_REPLY,").size());
    ConfigExchange rx;
    rx.ProcessPushReply(options);

    const auto &parsed = rx.GetNegotiatedConfig();
    ASSERT_EQ(1u, parsed.dns_servers.size());
    EXPECT_EQ(2, parsed.dns_servers[0].priority);
    ASSERT_EQ(2u, parsed.dns_servers[0].resolve_domains.size());
    EXPECT_EQ("corp.internal", parsed.dns_servers[0].resolve_domains[0]);
    EXPECT_EQ("dev.local", parsed.dns_servers[0].resolve_domains[1]);
}

// ============================================================================
// ParseClientIvProto tests (free function)
// ============================================================================

TEST(ParseClientIvProtoTest, PresentValue)
{
    EXPECT_EQ(2054u, ParseClientIvProto("IV_VER=1.0\nIV_PROTO=2054\n"));
}

TEST(ParseClientIvProtoTest, AbsentKey)
{
    EXPECT_EQ(0u, ParseClientIvProto("IV_VER=1.0\nIV_PLAT=linux\n"));
}

TEST(ParseClientIvProtoTest, EmptyString)
{
    EXPECT_EQ(0u, ParseClientIvProto(""));
}

TEST(ParseClientIvProtoTest, MalformedValue)
{
    EXPECT_EQ(0u, ParseClientIvProto("IV_PROTO=notanumber\n"));
}

TEST(ParseClientIvProtoTest, ZeroValue)
{
    EXPECT_EQ(0u, ParseClientIvProto("IV_PROTO=0\n"));
}

TEST(ParseClientIvProtoTest, MultilineNoTrailingNewline)
{
    EXPECT_EQ(6u, ParseClientIvProto("IV_VER=1.0\nIV_PROTO=6"));
}

// ============================================================================
// BuildKeyMethod2Message / ParseKeyMethod2Message peer_info round-trip tests
// ============================================================================

TEST(KeyMethod2Test, RoundTripWithPeerInfo)
{
    std::vector<std::uint8_t> random(112, 0xAB);
    std::string options = "V4,dev-type tun,link-mtu 1549";
    std::string peer_info = "IV_VER=1.0\nIV_PROTO=2054\nIV_PLAT=linux\n";

    auto msg = BuildKeyMethod2Message(random, options, "", "", peer_info);

    auto result = ParseKeyMethod2Message(msg, /*is_from_server=*/false);
    ASSERT_TRUE(result.has_value());

    const auto &[parsed_random, parsed_options, parsed_user, parsed_pass, parsed_peer_info] = *result;
    EXPECT_EQ(random, parsed_random);
    EXPECT_EQ(options, parsed_options);
    EXPECT_EQ("", parsed_user);
    EXPECT_EQ("", parsed_pass);
    EXPECT_EQ(peer_info, parsed_peer_info);
}

TEST(KeyMethod2Test, RoundTripEmptyPeerInfo)
{
    std::vector<std::uint8_t> random(112, 0x12);
    std::string options = "V4,dev-type tun,link-mtu 1549";

    auto msg = BuildKeyMethod2Message(random, options);

    auto result = ParseKeyMethod2Message(msg, /*is_from_server=*/false);
    ASSERT_TRUE(result.has_value());

    const auto &[parsed_random, parsed_options, parsed_user, parsed_pass, parsed_peer_info] = *result;
    EXPECT_EQ(options, parsed_options);
    EXPECT_EQ("", parsed_peer_info);
}

TEST(KeyMethod2Test, PeerInfoCarriesIvProto)
{
    std::vector<std::uint8_t> random(112, 0x00);
    std::string peer_info = "IV_PROTO=2054\nIV_VER=1.0\n";

    auto msg = BuildKeyMethod2Message(random, "V4,dev-type tun,link-mtu 1549", "", "", peer_info);
    auto result = ParseKeyMethod2Message(msg, /*is_from_server=*/false);
    ASSERT_TRUE(result.has_value());

    const auto &[r, opts, u, p, pi] = *result;
    EXPECT_EQ(2054u, ParseClientIvProto(pi));
}

} // namespace clv::vpn::openvpn::test
