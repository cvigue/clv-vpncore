// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/config_exchange.h"
#include <cstdint>
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
    EXPECT_TRUE(exchange_.ProcessPushReply("cipher AES-256-GCM"));
    EXPECT_EQ("AES-256-GCM", exchange_.GetNegotiatedConfig().cipher);
}

TEST_F(ConfigExchangeTest, ParseAuthOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("auth SHA256"));
    EXPECT_EQ("SHA256", exchange_.GetNegotiatedConfig().auth);
}

TEST_F(ConfigExchangeTest, ParseCompressOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("compress lz4"));
    EXPECT_EQ("lz4", exchange_.GetNegotiatedConfig().compress);
}

TEST_F(ConfigExchangeTest, ParseMultipleCipherAuthOptions)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("cipher AES-128-GCM,auth SHA512"));

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ("AES-128-GCM", config.cipher);
    EXPECT_EQ("SHA512", config.auth);
}

// ============================================================================
// Numeric Option Parsing Tests
// ============================================================================

TEST_F(ConfigExchangeTest, ParseFragmentOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("fragment 1500"));
    EXPECT_EQ(1500, exchange_.GetNegotiatedConfig().fragment_size);
}

TEST_F(ConfigExchangeTest, ParseMssfixOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("mssfix 1450"));
    EXPECT_EQ(1450, exchange_.GetNegotiatedConfig().mssfix);
}

TEST_F(ConfigExchangeTest, ParseInactiveOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("inactive 600"));
    EXPECT_EQ(600, exchange_.GetNegotiatedConfig().inactive_timeout);
}

TEST_F(ConfigExchangeTest, ParseRenegBytesOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("reneg-bytes 1000000"));
    EXPECT_EQ(1000000, exchange_.GetNegotiatedConfig().reneg_bytes);
}

TEST_F(ConfigExchangeTest, ParseRenegPacketsOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("reneg-packets 100000"));
    EXPECT_EQ(100000, exchange_.GetNegotiatedConfig().reneg_packets);
}

TEST_F(ConfigExchangeTest, ParseRenegSecOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("reneg-sec 7200"));
    EXPECT_EQ(7200, exchange_.GetNegotiatedConfig().reneg_sec);
}

// ============================================================================
// Route Parsing Tests
// ============================================================================

TEST_F(ConfigExchangeTest, ParseRouteOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("route 10.8.0.0 255.255.255.0 0"));

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ(1, config.routes.size());
    EXPECT_EQ("10.8.0.0", std::get<0>(config.routes[0]));
    EXPECT_EQ("255.255.255.0", std::get<1>(config.routes[0]));
    EXPECT_EQ(0, std::get<2>(config.routes[0]));
}

TEST_F(ConfigExchangeTest, ParseMultipleRoutes)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("route 10.8.0.0 255.255.255.0 0,route 192.168.1.0 255.255.255.0 1"));

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ(2, config.routes.size());
    EXPECT_EQ("10.8.0.0", std::get<0>(config.routes[0]));
    EXPECT_EQ("192.168.1.0", std::get<0>(config.routes[1]));
}

TEST_F(ConfigExchangeTest, ParseRouteIpv6Option)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("route-ipv6 2001:db8::/32 ::1 0"));

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ(1, config.routes_ipv6.size());
    EXPECT_EQ("2001:db8::/32", std::get<0>(config.routes_ipv6[0]));
}

// ============================================================================
// Network Config Tests
// ============================================================================

TEST_F(ConfigExchangeTest, ParseTopologyOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("topology subnet"));
    EXPECT_EQ("subnet", exchange_.GetNegotiatedConfig().topology);
}

TEST_F(ConfigExchangeTest, ParseIfconfigOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("ifconfig 10.8.0.6 10.8.0.5"));

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ("10.8.0.6", config.ifconfig.first);
    EXPECT_EQ("10.8.0.5", config.ifconfig.second);
}

TEST_F(ConfigExchangeTest, ParseIfconfigIpv6Option)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("ifconfig-ipv6 fd00::1000 64"));

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ("fd00::1000", config.ifconfig_ipv6.first);
    EXPECT_EQ(64, config.ifconfig_ipv6.second);
}

TEST_F(ConfigExchangeTest, ParseRedirectGatewayOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("redirect-gateway def1 bypass-dhcp"));
    EXPECT_FALSE(exchange_.GetNegotiatedConfig().redirect_gateway.empty());
}

// ============================================================================
// Special Option Tests
// ============================================================================

TEST_F(ConfigExchangeTest, ParseRegisterDnsOption)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("register-dns"));
    EXPECT_TRUE(exchange_.GetNegotiatedConfig().register_dns);
}

TEST_F(ConfigExchangeTest, ParseDhcpOptionDns)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("dhcp-option DNS 8.8.8.8"));

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ(1, config.dhcp_options.size());
    EXPECT_EQ("DNS", config.dhcp_options[0].first);
    EXPECT_EQ("8.8.8.8", config.dhcp_options[0].second);
}

TEST_F(ConfigExchangeTest, ParseDhcpOptionDomain)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("dhcp-option DOMAIN example.com"));

    auto &config = exchange_.GetNegotiatedConfig();
    EXPECT_EQ(1, config.dhcp_options.size());
    EXPECT_EQ("DOMAIN", config.dhcp_options[0].first);
    EXPECT_EQ("example.com", config.dhcp_options[0].second);
}

TEST_F(ConfigExchangeTest, ParseMultipleDhcpOptions)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("dhcp-option DNS 8.8.8.8,dhcp-option DNS 8.8.4.4"));

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
                         "compress lz4-v2,"
                         "topology subnet,"
                         "route 10.8.0.0 255.255.255.0 0,"
                         "ifconfig 10.8.0.6 10.8.0.5,"
                         "dhcp-option DNS 8.8.8.8,"
                         "dhcp-option DOMAIN example.com,"
                         "register-dns";

    EXPECT_TRUE(exchange_.ProcessPushReply(config));
    EXPECT_TRUE(exchange_.IsConfigured());

    auto &cfg = exchange_.GetNegotiatedConfig();
    EXPECT_EQ("AES-256-GCM", cfg.cipher);
    EXPECT_EQ("SHA256", cfg.auth);
    EXPECT_EQ("lz4-v2", cfg.compress);
    EXPECT_EQ("subnet", cfg.topology);
    EXPECT_EQ(1, cfg.routes.size());
    EXPECT_EQ("10.8.0.6", cfg.ifconfig.first);
    EXPECT_EQ(2, cfg.dhcp_options.size());
    EXPECT_TRUE(cfg.register_dns);
}

TEST_F(ConfigExchangeTest, PushResetClearsOptions)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("cipher AES-256-GCM"));
    EXPECT_EQ("AES-256-GCM", exchange_.GetNegotiatedConfig().cipher);

    exchange_.Reset();

    EXPECT_FALSE(exchange_.IsConfigured());
    EXPECT_TRUE(exchange_.StartPushRequest());

    EXPECT_TRUE(exchange_.ProcessPushReply("push-reset,cipher AES-128-GCM"));
    EXPECT_EQ("AES-128-GCM", exchange_.GetNegotiatedConfig().cipher);
}

// ============================================================================
// Validation Tests
// ============================================================================

TEST_F(ConfigExchangeTest, RejectsInvalidCipher)
{
    EXPECT_FALSE(exchange_.ProcessPushReply("cipher INVALID-CIPHER"));
}

TEST_F(ConfigExchangeTest, RejectsInvalidAuth)
{
    EXPECT_FALSE(exchange_.ProcessPushReply("cipher AES-256-GCM,auth INVALID-AUTH"));
}

TEST_F(ConfigExchangeTest, RejectsInvalidFragmentSize)
{
    EXPECT_FALSE(exchange_.ProcessPushReply("fragment not-a-number"));
}

TEST_F(ConfigExchangeTest, AcceptsRouteWithInvalidMetric)
{
    // Invalid metric is silently ignored (defaults to 0)
    EXPECT_TRUE(exchange_.ProcessPushReply("route 10.8.0.0 255.255.255.0 invalid"));
    const auto &config = exchange_.GetNegotiatedConfig();
    ASSERT_EQ(config.routes.size(), 1u);
    EXPECT_EQ(std::get<0>(config.routes[0]), "10.8.0.0");
    EXPECT_EQ(std::get<2>(config.routes[0]), 0); // bad metric -> 0
}

TEST_F(ConfigExchangeTest, AcceptsRouteWithNetworkOnly)
{
    // route with only network and no mask/gw/metric is valid
    EXPECT_TRUE(exchange_.ProcessPushReply("route 10.8.0.0"));
    const auto &config = exchange_.GetNegotiatedConfig();
    ASSERT_EQ(config.routes.size(), 1u);
    EXPECT_EQ(std::get<0>(config.routes[0]), "10.8.0.0");
}

TEST_F(ConfigExchangeTest, RejectsOptionTooLong)
{
    std::string long_option("cipher " + std::string(600, 'A'));
    EXPECT_FALSE(exchange_.ProcessPushReply(long_option));
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
    EXPECT_FALSE(exchange_.ProcessPushReply(many_options));
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
    EXPECT_TRUE(exchange_.ProcessPushReply(""));
    EXPECT_TRUE(exchange_.IsConfigured());
}

TEST_F(ConfigExchangeTest, HandlesWhitespaceInOptions)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("  cipher   AES-256-GCM  "));
    EXPECT_EQ("AES-256-GCM", exchange_.GetNegotiatedConfig().cipher);
}

TEST_F(ConfigExchangeTest, HandlesTrailingCommas)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("cipher AES-256-GCM,"));
    EXPECT_EQ("AES-256-GCM", exchange_.GetNegotiatedConfig().cipher);
}

TEST_F(ConfigExchangeTest, UnknownOptionsAccepted)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("unknown-option value"));
    EXPECT_TRUE(exchange_.IsConfigured());
}

TEST_F(ConfigExchangeTest, MixValidAndUnknownOptions)
{
    EXPECT_TRUE(exchange_.ProcessPushReply("cipher AES-256-GCM,unknown-feature value"));
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

    EXPECT_TRUE(exchange_.ProcessPushReply(server_config));
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
    EXPECT_TRUE(exchange_.ProcessPushReply("cipher AES-256-GCM,reneg-sec 3600"));
    EXPECT_EQ(3600, exchange_.GetNegotiatedConfig().reneg_sec);

    // Renegotiate with new config
    exchange_.Reset();
    EXPECT_TRUE(exchange_.ProcessPushReply("cipher AES-128-GCM,reneg-sec 7200"));
    EXPECT_EQ("AES-128-GCM", exchange_.GetNegotiatedConfig().cipher);
    EXPECT_EQ(7200, exchange_.GetNegotiatedConfig().reneg_sec);
}

// ============================================================================
// IPv4 Configuration Tests
// ============================================================================

TEST_F(ConfigExchangeTest, BuildPushReplyWithBasicIpv4Config)
{
    // Test IPv4 address: 10.8.0.2 (client)
    // Server address: 10.8.0.1 (gateway)
    std::uint32_t client_ipv4 = (10 << 24) | (8 << 16) | (0 << 8) | 2;
    std::uint32_t server_ipv4 = (10 << 24) | (8 << 16) | (0 << 8) | 1;

    std::string push_reply = ConfigExchange::BuildPushReplyWithIpv4(client_ipv4, server_ipv4);

    EXPECT_NE(push_reply.find("PUSH_REPLY,"), std::string::npos);
    EXPECT_NE(push_reply.find("ifconfig 10.8.0.2 10.8.0.1"), std::string::npos);
    EXPECT_NE(push_reply.find("route-gateway 10.8.0.1"), std::string::npos);
}

TEST_F(ConfigExchangeTest, BuildPushReplyWithExtraOptions)
{
    std::uint32_t client_ipv4 = (192 << 24) | (168 << 16) | (1 << 8) | 100;
    std::uint32_t server_ipv4 = (192 << 24) | (168 << 16) | (1 << 8) | 1;

    std::vector<std::string> extra_opts = {"cipher AES-256-GCM", "auth SHA256", "route 10.0.0.0 255.255.255.0"};

    std::string push_reply = ConfigExchange::BuildPushReplyWithIpv4(client_ipv4, server_ipv4, extra_opts);

    EXPECT_NE(push_reply.find("ifconfig 192.168.1.100 192.168.1.1"), std::string::npos);
    EXPECT_NE(push_reply.find("cipher AES-256-GCM"), std::string::npos);
    EXPECT_NE(push_reply.find("auth SHA256"), std::string::npos);
    EXPECT_NE(push_reply.find("route 10.0.0.0 255.255.255.0"), std::string::npos);
}

TEST_F(ConfigExchangeTest, BuildPushReplyAddressFormatting)
{
    // Test various IPv4 addresses to ensure proper formatting
    // 172.16.0.50
    std::uint32_t client_ipv4 = (172 << 24) | (16 << 16) | (0 << 8) | 50;
    std::uint32_t server_ipv4 = (172 << 24) | (16 << 16) | (0 << 8) | 1;

    std::string push_reply = ConfigExchange::BuildPushReplyWithIpv4(client_ipv4, server_ipv4);

    EXPECT_NE(push_reply.find("ifconfig 172.16.0.50 172.16.0.1"), std::string::npos);
}

} // namespace clv::vpn::openvpn::test
