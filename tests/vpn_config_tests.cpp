// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include "openvpn/vpn_config.h"
#include "transport/batch_constants.h"
#include <filesystem>
#include <fstream>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>
#include <sstream>
#include <string>

namespace clv::vpn {

class VpnConfigTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Per-test unique directory under the build tree (no /tmp, no parallel collisions)
        const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
        std::string unique_name = std::string("vpn_config_test_") + info->name();
        temp_dir = std::filesystem::path(TEST_TMP_DIR) / unique_name;
        std::filesystem::create_directories(temp_dir);
    }

    void TearDown() override
    {
        // Clean up temporary files
        std::filesystem::remove_all(temp_dir);
    }

    std::filesystem::path temp_dir;
};

TEST_F(VpnConfigTest, ParseValidJsonString)
{
    std::string json_str = R"(
    {
        "server": {
            "host": "0.0.0.0",
            "port": 1194,
            "proto": "udp",
            "dev": "tun",
            "cert": "/etc/ssl/server.crt",
            "key": "/etc/ssl/server.key",
            "network": "10.8.0.0 255.255.255.0",
            "ca_cert": "/etc/ssl/ca.crt",
            "cipher": "AES-256-GCM"
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    EXPECT_EQ(config.server->host, "0.0.0.0");
    EXPECT_EQ(config.server->port, 1194);
    EXPECT_EQ(config.server->proto, "udp");
    EXPECT_EQ(config.server->dev, "tun");
    EXPECT_EQ(config.server->cert, "/etc/ssl/server.crt");
    EXPECT_EQ(config.server->ca_cert, "/etc/ssl/ca.crt");
    EXPECT_EQ(config.server->cipher, "AES-256-GCM");
    EXPECT_EQ(config.server->network, "10.8.0.0 255.255.255.0");
}

TEST_F(VpnConfigTest, ParseValidJsonFile)
{
    std::string json_content = R"(
    {
        "server": {
            "port": 443,
            "proto": "tcp",
            "dev": "tap",
            "cert": "/path/to/server.crt",
            "key": "/path/to/server.key",
            "network": "192.168.1.0 255.255.255.0",
            "client_dns": ["8.8.8.8", "8.8.4.4"],
            "client_cert_required": true,
            "max_clients": 100,
            "keepalive": [10, 120],
            "ca_cert": "/path/to/ca.crt"
        },
        "logging": {
            "verbosity": "debug"
        }
    })";

    auto config_file = temp_dir / "test_config.json";
    std::ofstream file(config_file);
    file << json_content;
    file.close();

    OpenVpnConfig config = OpenVpnConfigParser::ParseFile(config_file);

    EXPECT_EQ(config.server->port, 443);
    EXPECT_EQ(config.server->proto, "tcp");
    EXPECT_EQ(config.server->dev, "tap");
    EXPECT_EQ(config.server->ca_cert, "/path/to/ca.crt");
    EXPECT_EQ(config.server->network, "192.168.1.0 255.255.255.0");
    EXPECT_EQ(config.server->client_dns.size(), 2);
    EXPECT_EQ(config.server->client_dns[0], "8.8.8.8");
    EXPECT_EQ(config.server->client_dns[1], "8.8.4.4");
    EXPECT_TRUE(config.server->client_cert_required);
    EXPECT_EQ(config.server->max_clients, 100);
    EXPECT_EQ(config.server->keepalive.first, 10);
    EXPECT_EQ(config.server->keepalive.second, 120);
    EXPECT_EQ(config.logging.verbosity, "debug");
}

TEST_F(VpnConfigTest, ParseInvalidJson)
{
    std::string invalid_json = "{ invalid json }";

    EXPECT_THROW(OpenVpnConfigParser::ParseString(invalid_json), std::runtime_error);
}

TEST_F(VpnConfigTest, ParseNonObjectRoot)
{
    std::string json_str = "[1, 2, 3]";

    EXPECT_THROW(OpenVpnConfigParser::ParseString(json_str), std::runtime_error);
}

TEST_F(VpnConfigTest, ValidateMissingRequiredFields)
{
    OpenVpnConfig config;

    // Missing server role entirely
    EXPECT_THROW(OpenVpnConfigParser::ValidateServer(config), std::runtime_error);

    config.server.emplace();
    config.server->proto = "invalid";
    EXPECT_THROW(OpenVpnConfigParser::ValidateServer(config), std::runtime_error);

    config.server->proto = "udp";
    config.server->dev = "invalid";
    EXPECT_THROW(OpenVpnConfigParser::ValidateServer(config), std::runtime_error);

    config.server->dev = "tun";
    // Missing required ca_cert field
    EXPECT_THROW(OpenVpnConfigParser::ValidateServer(config), std::runtime_error);
}

TEST_F(VpnConfigTest, ParseEmptySections)
{
    std::string json_str = R"(
    {
        "server": {},
        "performance": {},
        "logging": {}
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    // Should have default values
    EXPECT_EQ(config.server->port, 1194); // Default port
    EXPECT_TRUE(config.server->ca_cert.empty());
}

TEST_F(VpnConfigTest, ClampRenegotiateSecondsToMinimum)
{
    std::string json_str = R"(
    {
        "server": {
            "ca_cert": "/ca.crt",
            "renegotiate_seconds": 5
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    EXPECT_EQ(config.server->renegotiate_seconds,
              OpenVpnConfig::ServerConfig::kMinRenegotiateSeconds);
}

TEST_F(VpnConfigTest, KeepRenegotiateSecondsDisabledAtZero)
{
    std::string json_str = R"(
    {
        "server": {
            "ca_cert": "/ca.crt",
            "renegotiate_seconds": 0
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    EXPECT_EQ(config.server->renegotiate_seconds, 0);
}

TEST_F(VpnConfigTest, ParseRoutesAndPushRoutes)
{
    std::string json_str = R"(
    {
        "server": {
            "port": 1194,
            "proto": "udp",
            "dev": "tun",
            "cert": "/server.crt",
            "key": "/server.key",
            "network": "10.0.0.0 255.255.255.0",
            "routes": ["192.168.1.0 255.255.255.0", "10.10.0.0 255.255.0.0"],
            "push_routes": true,
            "ca_cert": "/ca.crt"
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    EXPECT_EQ(config.server->routes.size(), 2);
    EXPECT_EQ(config.server->routes[0], "192.168.1.0 255.255.255.0");
    EXPECT_EQ(config.server->routes[1], "10.10.0.0 255.255.0.0");
    EXPECT_TRUE(config.server->push_routes);
}

TEST_F(VpnConfigTest, ParseRoutesV6)
{
    std::string json_str = R"(
    {
        "server": {
            "port": 1194,
            "proto": "udp",
            "dev": "tun",
            "cert": "/server.crt",
            "key": "/server.key",
            "network": "10.0.0.0/24",
            "network_v6": "fd00::/112",
            "routes_v6": ["fd01::/64", "2001:db8::/32"],
            "push_routes": true,
            "ca_cert": "/ca.crt"
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    ASSERT_EQ(config.server->routes_v6.size(), 2);
    EXPECT_EQ(config.server->routes_v6[0], "fd01::/64");
    EXPECT_EQ(config.server->routes_v6[1], "2001:db8::/32");
}

TEST_F(VpnConfigTest, ParseSubsystemLogLevels)
{
    std::string json_str = R"(
    {
        "server": { "port": 1194, "proto": "udp", "dev": "tun", "ca_cert": "/ca.crt" },
        "logging": {
            "verbosity": "info",
            "subsystems": {
                "dataio": "trace",
                "control": "debug",
                "sessions": 4
            }
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    EXPECT_EQ(config.logging.verbosity, "info");
    ASSERT_EQ(config.logging.subsystem_levels.size(), 3);
    EXPECT_EQ(config.logging.subsystem_levels.at("dataio"), "trace");
    EXPECT_EQ(config.logging.subsystem_levels.at("control"), "debug");
    EXPECT_EQ(config.logging.subsystem_levels.at("sessions"), "4"); // numeric → string
}

TEST_F(VpnConfigTest, ParseSubsystemLogLevelsEmpty)
{
    std::string json_str = R"(
    {
        "server": { "port": 1194, "proto": "udp", "dev": "tun", "ca_cert": "/ca.crt" },
        "logging": {
            "verbosity": "warn"
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    EXPECT_EQ(config.logging.verbosity, "warn");
    EXPECT_TRUE(config.logging.subsystem_levels.empty());
}

TEST_F(VpnConfigTest, FileNotFound)
{
    std::filesystem::path nonexistent = "/nonexistent/file.json";

    EXPECT_THROW(OpenVpnConfigParser::ParseFile(nonexistent), std::runtime_error);
}

// ============================================================================
// Performance tuning config tests
// ============================================================================

TEST_F(VpnConfigTest, DefaultPerformanceSettings)
{
    // An empty config should have the documented defaults
    OpenVpnConfig config;
    config.server.emplace(); // Need server to check server-specific defaults

    EXPECT_EQ(config.performance.stats_interval_seconds, 0);
    EXPECT_EQ(config.performance.socket_recv_buffer, 0);
    EXPECT_EQ(config.performance.socket_send_buffer, 0);
    EXPECT_EQ(config.performance.batch_size, 0);
    EXPECT_EQ(config.server->tun_mtu, 1500);
}

TEST_F(VpnConfigTest, ParsePerformanceTuningFields)
{
    std::string json_str = R"(
    {
        "server": {
            "tun_mtu": 1420
        },
        "performance": {
            "stats_interval_seconds": 30,
            "socket_recv_buffer": 2097152,
            "socket_send_buffer": 1048576,
            "batch_size": 16
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    EXPECT_EQ(config.performance.stats_interval_seconds, 30);
    EXPECT_EQ(config.performance.socket_recv_buffer, 2097152);
    EXPECT_EQ(config.performance.socket_send_buffer, 1048576);
    EXPECT_EQ(config.performance.batch_size, 16);
    EXPECT_EQ(config.server->tun_mtu, 1420);
}

TEST_F(VpnConfigTest, OmittedTuningFieldsGetDefaults)
{
    // When the sections exist but the tuning fields are absent,
    // defaults should apply (0 = OS default / disabled).
    std::string json_str = R"(
    {
        "server": {
            "max_clients": 50,
            "network": "10.8.0.0/24"
        },
        "performance": {
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    EXPECT_EQ(config.performance.socket_recv_buffer, 0);
    EXPECT_EQ(config.performance.socket_send_buffer, 0);
    EXPECT_EQ(config.performance.stats_interval_seconds, 0);
    EXPECT_EQ(config.performance.batch_size, 0);
    EXPECT_EQ(config.server->tun_mtu, 1500);
    EXPECT_EQ(config.server->tun_txqueuelen, 0);
    // Verify the explicitly-set field still parsed
    EXPECT_EQ(config.server->max_clients, 50);
}

TEST_F(VpnConfigTest, ParseTxQueueLen)
{
    std::string json_str = R"(
    {
        "server": {
            "tun_txqueuelen": 200
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    EXPECT_EQ(config.server->tun_txqueuelen, 200);
}

TEST_F(VpnConfigTest, DefaultTxQueueLen)
{
    OpenVpnConfig config;
    config.server.emplace();
    EXPECT_EQ(config.server->tun_txqueuelen, 0);
}

TEST_F(VpnConfigTest, ParseBatchSize)
{
    std::string json_str = R"(
    {
        "performance": {
            "batch_size": 24
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    EXPECT_EQ(config.performance.batch_size, 24);
}

TEST_F(VpnConfigTest, DefaultBatchSize)
{
    OpenVpnConfig config;
    EXPECT_EQ(config.performance.batch_size, 0);
}

// ============================================================================
// Config validation / clamping tests
// ============================================================================

TEST_F(VpnConfigTest, NegativeTunMtuClampedToMinimum)
{
    std::string json_str = R"(
    {
        "server": {
            "tun_mtu": -1
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);
    EXPECT_EQ(config.server->tun_mtu, 576);
}

TEST_F(VpnConfigTest, ExcessiveTunMtuClampedToMaximum)
{
    std::string json_str = R"(
    {
        "server": {
            "tun_mtu": 65535
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);
    EXPECT_EQ(config.server->tun_mtu, 9000);
}

TEST_F(VpnConfigTest, ValidTunMtuPassesThrough)
{
    std::string json_str = R"(
    {
        "server": {
            "tun_mtu": 1400
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);
    EXPECT_EQ(config.server->tun_mtu, 1400);
}

TEST_F(VpnConfigTest, NegativeTxQueueLenClampedToZero)
{
    std::string json_str = R"(
    {
        "server": {
            "tun_txqueuelen": -100
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);
    EXPECT_EQ(config.server->tun_txqueuelen, 0);
}

TEST_F(VpnConfigTest, NegativeSocketBuffersClampedToZero)
{
    std::string json_str = R"(
    {
        "performance": {
            "socket_recv_buffer": -1,
            "socket_send_buffer": -42
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);
    EXPECT_EQ(config.performance.socket_recv_buffer, 0);
    EXPECT_EQ(config.performance.socket_send_buffer, 0);
}

TEST_F(VpnConfigTest, BatchSizeClampedToMax)
{
    std::string json_str = R"(
    {
        "performance": {
            "batch_size": 9999
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);
    EXPECT_EQ(config.performance.batch_size, static_cast<int>(transport::kMaxBatchSize));
}

TEST_F(VpnConfigTest, NegativeBatchSizeClampedToZero)
{
    std::string json_str = R"(
    {
        "performance": {
            "batch_size": -5
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);
    EXPECT_EQ(config.performance.batch_size, 0);
}

// ============================================================================
// client_to_client option
// ============================================================================

TEST_F(VpnConfigTest, ClientToClientDefaultsFalse)
{
    std::string json_str = R"(
    {
        "server": {
            "port": 1194,
            "cert": "/server.crt",
            "key": "/server.key",
            "ca_cert": "/ca.crt"
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);
    EXPECT_FALSE(config.server->client_to_client);
}

TEST_F(VpnConfigTest, ClientToClientParsedWhenTrue)
{
    std::string json_str = R"(
    {
        "server": {
            "port": 1194,
            "cert": "/server.crt",
            "key": "/server.key",
            "ca_cert": "/ca.crt",
            "client_to_client": true
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);
    EXPECT_TRUE(config.server->client_to_client);
}

TEST_F(VpnConfigTest, ClientToClientParsedWhenFalse)
{
    std::string json_str = R"(
    {
        "server": {
            "port": 1194,
            "cert": "/server.crt",
            "key": "/server.key",
            "ca_cert": "/ca.crt",
            "client_to_client": false
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);
    EXPECT_FALSE(config.server->client_to_client);
}

TEST_F(VpnConfigTest, ParseTlsCryptV2ServerKey)
{
    std::string json_str = R"(
    {
        "server": {
            "port": 1194,
            "cert": "/server.crt",
            "key": "/server.key",
            "ca_cert": "/ca.crt",
            "tls_crypt_v2_key": "/path/to/v2-server.key"
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);
    ASSERT_TRUE(config.server.has_value());
    EXPECT_EQ(config.server->tls_crypt_v2_key, "/path/to/v2-server.key");
    EXPECT_TRUE(config.server->tls_crypt_key.empty());
}

TEST_F(VpnConfigTest, ParseTlsCryptV2ClientKey)
{
    std::string json_str = R"(
    {
        "client": {
            "server_host": "10.0.0.1",
            "server_port": 1194,
            "ca_cert": "/ca.crt",
            "cert": "/client.crt",
            "key": "/client.key",
            "tls_crypt_v2_key": "/path/to/v2-client.key",
            "tls_crypt_v2_key_pem": "-----BEGIN OpenVPN tls-crypt-v2 client key-----\ndata\n-----END OpenVPN tls-crypt-v2 client key-----"
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);
    ASSERT_TRUE(config.client.has_value());
    EXPECT_EQ(config.client->tls_crypt_v2_key, "/path/to/v2-client.key");
    EXPECT_FALSE(config.client->tls_crypt_v2_key_pem.empty());
    EXPECT_TRUE(config.client->tls_crypt_key.empty());
}

// ============================================================================
// ValidateServer — full error-path coverage
// ============================================================================

TEST_F(VpnConfigTest, ValidateServer_PortZero)
{
    VpnConfig config;
    config.server.emplace();
    config.server->port = 0;
    EXPECT_THROW(VpnConfigParser::ValidateServer(config), std::runtime_error);
}

TEST_F(VpnConfigTest, ValidateServer_DcoTcpConflict)
{
    VpnConfig config;
    config.server.emplace();
    config.server->proto = "tcp";
    config.performance.enable_dco = true; // default, but explicit for clarity
    EXPECT_THROW(VpnConfigParser::ValidateServer(config), std::runtime_error);
}

TEST_F(VpnConfigTest, ValidateServer_MissingCert)
{
    VpnConfig config;
    config.server.emplace();
    config.server->ca_cert = "/fake/ca.crt";
    // cert is still empty
    EXPECT_THROW(VpnConfigParser::ValidateServer(config), std::runtime_error);
}

TEST_F(VpnConfigTest, ValidateServer_MissingKey)
{
    VpnConfig config;
    config.server.emplace();
    config.server->ca_cert = "/fake/ca.crt";
    config.server->cert = "/fake/server.crt";
    // key is still empty
    EXPECT_THROW(VpnConfigParser::ValidateServer(config), std::runtime_error);
}

TEST_F(VpnConfigTest, ValidateServer_MissingNetwork)
{
    VpnConfig config;
    config.server.emplace();
    config.server->ca_cert = "/fake/ca.crt";
    config.server->cert = "/fake/server.crt";
    config.server->key = "/fake/server.key";
    config.server->network = "";
    EXPECT_THROW(VpnConfigParser::ValidateServer(config), std::runtime_error);
}

TEST_F(VpnConfigTest, ValidateServer_ValidMinimalConfig)
{
    VpnConfig config;
    config.server.emplace();
    config.server->ca_cert = "/fake/ca.crt";
    config.server->cert = "/fake/server.crt";
    config.server->key = "/fake/server.key";
    // network has a default ("10.8.0.0/24"), no other required fields missing
    EXPECT_NO_THROW(VpnConfigParser::ValidateServer(config));
}

TEST_F(VpnConfigTest, ValidateServer_LogsWarningForMissingCertFile)
{
    VpnConfig config;
    config.server.emplace();
    config.server->ca_cert = temp_dir / "nonexistent_ca.crt";
    config.server->cert = temp_dir / "nonexistent_server.crt";
    config.server->key = temp_dir / "nonexistent_server.key";

    std::ostringstream log_output;
    auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_output);
    auto logger = std::make_shared<spdlog::logger>("test_validate_warn", sink);
    logger->set_level(spdlog::level::warn);

    // Should not throw — missing files are warnings only
    EXPECT_NO_THROW(VpnConfigParser::ValidateServer(config, logger));

    const std::string output = log_output.str();
    EXPECT_NE(output.find("nonexistent_ca.crt"), std::string::npos);
    EXPECT_NE(output.find("nonexistent_server.crt"), std::string::npos);
    EXPECT_NE(output.find("nonexistent_server.key"), std::string::npos);
}

TEST_F(VpnConfigTest, ValidateServer_NoWarningWhenCertFilesExist)
{
    // Create actual (empty) placeholder files so existence checks pass
    const auto ca = temp_dir / "ca.crt";
    const auto cert = temp_dir / "server.crt";
    const auto key = temp_dir / "server.key";
    for (const auto &p : {ca, cert, key})
        std::ofstream{p};
    // Restrict the key file to owner-only so the permission check doesn't warn
    std::filesystem::permissions(key, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, std::filesystem::perm_options::replace);

    VpnConfig config;
    config.server.emplace();
    config.server->ca_cert = ca;
    config.server->cert = cert;
    config.server->key = key;

    std::ostringstream log_output;
    auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(log_output);
    auto logger = std::make_shared<spdlog::logger>("test_validate_no_warn", sink);
    logger->set_level(spdlog::level::warn);

    EXPECT_NO_THROW(VpnConfigParser::ValidateServer(config, logger));
    EXPECT_TRUE(log_output.str().empty());
}

// ============================================================================
// ValidateClient — full error-path coverage
// ============================================================================

TEST_F(VpnConfigTest, ValidateClient_NoClientRole)
{
    VpnConfig config;
    EXPECT_THROW(VpnConfigParser::ValidateClient(config), std::runtime_error);
}

TEST_F(VpnConfigTest, ValidateClient_EmptyServerHost)
{
    VpnConfig config;
    config.client.emplace();
    config.client->server_host = "";
    EXPECT_THROW(VpnConfigParser::ValidateClient(config), std::runtime_error);
}

TEST_F(VpnConfigTest, ValidateClient_PortZero)
{
    VpnConfig config;
    config.client.emplace();
    config.client->server_host = "vpn.example.com";
    config.client->server_port = 0;
    EXPECT_THROW(VpnConfigParser::ValidateClient(config), std::runtime_error);
}

TEST_F(VpnConfigTest, ValidateClient_ValidMinimalConfig)
{
    VpnConfig config;
    config.client.emplace();
    config.client->server_host = "vpn.example.com";
    config.client->server_port = 1194;
    EXPECT_NO_THROW(VpnConfigParser::ValidateClient(config));
}

TEST_F(VpnConfigTest, ParseClientDataCiphersFromJson)
{
    std::string json_str = R"(
    {
        "client": {
            "server_host": "vpn.example.com",
            "server_port": 1194,
            "data_ciphers": ["AES-256-GCM", "CHACHA20-POLY1305"],
            "allow_deprecated_data_ciphers": true
        }
    })";

    OpenVpnConfig config = OpenVpnConfigParser::ParseString(json_str);

    ASSERT_TRUE(config.client.has_value());
    ASSERT_EQ(2u, config.client->data_ciphers.size());
    EXPECT_EQ("AES-256-GCM", config.client->data_ciphers[0]);
    EXPECT_EQ("CHACHA20-POLY1305", config.client->data_ciphers[1]);
    EXPECT_TRUE(config.client->allow_deprecated_data_ciphers);
}

TEST_F(VpnConfigTest, ValidateClient_RejectsUnknownDataCipher)
{
    VpnConfig config;
    config.client.emplace();
    config.client->server_host = "vpn.example.com";
    config.client->server_port = 1194;
    config.client->data_ciphers = {"AES-256-GCM", "UNKNOWN-CIPHER"};

    EXPECT_THROW(VpnConfigParser::ValidateClient(config), std::runtime_error);
}

} // namespace clv::vpn