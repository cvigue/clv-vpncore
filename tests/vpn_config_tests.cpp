// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include "openvpn/vpn_config.h"
#include "transport/batch_constants.h"
#include <filesystem>
#include <fstream>
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

} // namespace clv::vpn