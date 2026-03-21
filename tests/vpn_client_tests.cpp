// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include <nlohmann/json.hpp>
#include <asio.hpp>
#include <filesystem>
#include <fstream>
#include <string>

#include "vpn_client.h"

namespace clv::vpn {

// ============================================================================
// VpnClientConfig Tests
// ============================================================================

class VpnClientConfigTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Use a per-test unique directory under the build tree so tests
        // never touch /tmp and parallel ctest processes don't collide.
        const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
        std::string unique_name = std::string("vpn_client_config_test_") + info->name();
        temp_dir_ = std::filesystem::path(TEST_TMP_DIR) / unique_name;
        std::filesystem::create_directories(temp_dir_);
    }

    void TearDown() override
    {
        // Clean up temporary files
        std::filesystem::remove_all(temp_dir_);
    }

    void WriteFile(const std::string &filename, const std::string &content)
    {
        std::ofstream file(temp_dir_ / filename);
        file << content;
        file.flush();
        file.close();
    }

    std::filesystem::path temp_dir_;
};

TEST_F(VpnClientConfigTest, LoadFromFile_ValidConfig)
{
    std::string json_content = R"({
        "client": {
            "server_host": "vpn.example.com",
            "server_port": 1194,
            "protocol": "udp",
            "cert": "/path/to/client.crt",
            "key": "/path/to/client.key",
            "dev_name": "tun0",
            "reconnect_delay_seconds": 10,
            "max_reconnect_attempts": 5,
            "ca_cert": "/path/to/ca.crt",
            "tls_crypt_key": "/path/to/tls-crypt.key",
            "cipher": "AES-256-GCM",
            "auth": "SHA256"
        },
        "logging": {
            "verbosity": 4
        }
    })";

    WriteFile("valid_config.json", json_content);

    auto config = VpnClientConfig::LoadFromFile((temp_dir_ / "valid_config.json").string());

    EXPECT_EQ(config.client->server_host, "vpn.example.com");
    EXPECT_EQ(config.client->server_port, 1194);
    EXPECT_EQ(config.client->protocol, "udp");
    EXPECT_EQ(config.client->ca_cert, "/path/to/ca.crt");
    EXPECT_EQ(config.client->cert, "/path/to/client.crt");
    EXPECT_EQ(config.client->key, "/path/to/client.key");
    EXPECT_EQ(config.client->tls_crypt_key, "/path/to/tls-crypt.key");
    EXPECT_EQ(config.client->cipher, "AES-256-GCM");
    EXPECT_EQ(config.client->auth, "SHA256");
    EXPECT_EQ(config.client->dev_name, "tun0");
    EXPECT_EQ(config.client->reconnect_delay_seconds, 10);
    EXPECT_EQ(config.client->max_reconnect_attempts, 5);
    // verbosity 4 stored as string "4"
    EXPECT_EQ(config.logging.verbosity, "4");
}

TEST_F(VpnClientConfigTest, LoadFromFile_MinimalConfig)
{
    // Test with minimal required fields
    std::string json_content = R"({
        "client": {
            "server_host": "10.0.0.1"
        }
    })";

    WriteFile("minimal_config.json", json_content);

    auto config = VpnClientConfig::LoadFromFile((temp_dir_ / "minimal_config.json").string());

    // Check specified values
    EXPECT_EQ(config.client->server_host, "10.0.0.1");

    // Defaults from ClientConfig struct
    EXPECT_EQ(config.client->server_port, 1194);
    EXPECT_EQ(config.client->protocol, "udp");

    // Crypto defaults when section is absent
    EXPECT_EQ(config.client->cipher, "AES-256-GCM"); // struct default
    EXPECT_EQ(config.client->auth, "SHA256");        // struct default

    // Reconnect defaults
    EXPECT_EQ(config.client->reconnect_delay_seconds, 5);
    EXPECT_EQ(config.client->max_reconnect_attempts, 10);
    EXPECT_EQ(config.logging.verbosity, "info"); // default
}

TEST_F(VpnClientConfigTest, LoadFromFile_FileNotFound)
{
    EXPECT_THROW(
        VpnClientConfig::LoadFromFile("/nonexistent/path/config.json"),
        std::runtime_error);
}

TEST_F(VpnClientConfigTest, LoadFromFile_InvalidJson)
{
    WriteFile("invalid.json", "{ not valid json }");

    EXPECT_THROW(
        VpnClientConfig::LoadFromFile((temp_dir_ / "invalid.json").string()),
        std::runtime_error);
}

TEST_F(VpnClientConfigTest, LoadFromFile_EmptyJson)
{
    WriteFile("empty.json", "{}");

    // Should use defaults for everything
    auto config = VpnClientConfig::LoadFromFile((temp_dir_ / "empty.json").string());

    EXPECT_FALSE(config.HasClientRole());
}

TEST_F(VpnClientConfigTest, LoadFromFile_IPv6Server)
{
    std::string json_content = R"({
        "client": {
            "server_host": "2001:db8::1",
            "server_port": 443,
            "protocol": "udp6"
        }
    })";

    WriteFile("ipv6_config.json", json_content);

    auto config = VpnClientConfig::LoadFromFile((temp_dir_ / "ipv6_config.json").string());

    EXPECT_EQ(config.client->server_host, "2001:db8::1");
    EXPECT_EQ(config.client->server_port, 443);
    EXPECT_EQ(config.client->protocol, "udp6");
}

TEST_F(VpnClientConfigTest, LoadFromFile_ChaCha20Cipher)
{
    std::string json_content = R"({
        "client": {
            "server_host": "vpn.example.com",
            "cipher": "CHACHA20-POLY1305"
        }
    })";

    WriteFile("chacha_config.json", json_content);

    auto config = VpnClientConfig::LoadFromFile((temp_dir_ / "chacha_config.json").string());

    EXPECT_EQ(config.client->cipher, "CHACHA20-POLY1305");
}

// ============================================================================
// VpnClientState Tests
// ============================================================================

TEST(VpnClientStateTest, StateToString)
{
    EXPECT_STREQ(VpnClientStateToString(VpnClientState::Disconnected), "Disconnected");
    EXPECT_STREQ(VpnClientStateToString(VpnClientState::Connecting), "Connecting");
    EXPECT_STREQ(VpnClientStateToString(VpnClientState::TlsHandshake), "TlsHandshake");
    EXPECT_STREQ(VpnClientStateToString(VpnClientState::Authenticating), "Authenticating");
    EXPECT_STREQ(VpnClientStateToString(VpnClientState::Connected), "Connected");
    EXPECT_STREQ(VpnClientStateToString(VpnClientState::Reconnecting), "Reconnecting");
    EXPECT_STREQ(VpnClientStateToString(VpnClientState::Error), "Error");
}

TEST(VpnClientStateTest, UnknownState)
{
    // Cast invalid value to test fallback
    auto unknown = static_cast<VpnClientState>(255);
    EXPECT_STREQ(VpnClientStateToString(unknown), "Unknown");
}

// ============================================================================
// VpnClient Unit Tests
// ============================================================================

class VpnClientTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        config_.client.emplace();
        config_.client->server_host = "127.0.0.1";
        config_.client->server_port = 1194;
        config_.client->protocol = "udp";
        config_.client->cipher = "AES-256-GCM";
        config_.client->auth = "SHA256";
        config_.logging.verbosity = "trace"; // trace level for tests
    }

    void TearDown() override
    {
        // Drop the logger to avoid "already exists" error in next test
        spdlog::drop("vpn_client");
    }

    asio::io_context io_context_;
    VpnConfig config_;
};

TEST_F(VpnClientTest, Construction)
{
    VpnClient client(io_context_, config_);

    EXPECT_EQ(client.GetState(), VpnClientState::Disconnected);
    EXPECT_FALSE(client.IsConnected());
    EXPECT_TRUE(client.GetAssignedIp().empty());
    EXPECT_TRUE(client.GetRoutes().empty());
    EXPECT_TRUE(client.GetDnsServers().empty());
}

TEST_F(VpnClientTest, InitialState)
{
    VpnClient client(io_context_, config_);

    EXPECT_EQ(client.GetState(), VpnClientState::Disconnected);
    EXPECT_FALSE(client.IsConnected());
}

TEST_F(VpnClientTest, UptimeWhenDisconnected)
{
    VpnClient client(io_context_, config_);

    // Uptime should be 0 when not connected
    EXPECT_EQ(client.GetUptime(), std::chrono::seconds(0));
}

TEST_F(VpnClientTest, StatisticsWhenDisconnected)
{
    VpnClient client(io_context_, config_);

    EXPECT_EQ(client.GetBytesSent(), 0UL);
    EXPECT_EQ(client.GetBytesReceived(), 0UL);
}

TEST_F(VpnClientTest, DisconnectWhenNotConnected)
{
    VpnClient client(io_context_, config_);

    // Should be safe to call Disconnect when not connected
    client.Disconnect();

    EXPECT_EQ(client.GetState(), VpnClientState::Disconnected);
}

TEST_F(VpnClientTest, MultipleDisconnectCalls)
{
    VpnClient client(io_context_, config_);

    // Multiple disconnect calls should be safe
    client.Disconnect();
    client.Disconnect();
    client.Disconnect();

    EXPECT_EQ(client.GetState(), VpnClientState::Disconnected);
}

// ============================================================================
// VpnClient Connect Tests (require mock or real server)
// ============================================================================

class VpnClientConnectTest : public VpnClientTest
{
  protected:
    void SetUp() override
    {
        VpnClientTest::SetUp();

        // Per-test unique directory under the build tree (no /tmp, no parallel collisions)
        const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
        std::string unique_name = std::string("vpn_client_connect_test_") + info->name();
        temp_dir_ = std::filesystem::path(TEST_TMP_DIR) / unique_name;
        std::filesystem::create_directories(temp_dir_);
    }

    void TearDown() override
    {
        std::filesystem::remove_all(temp_dir_);
        VpnClientTest::TearDown();
    }

    std::filesystem::path temp_dir_;
};

TEST_F(VpnClientConnectTest, ConnectFailsWithBadTlsCryptPath)
{
    config_.client->tls_crypt_key = "/nonexistent/tls-crypt.key";

    VpnClient client(io_context_, config_);
    client.Connect();

    // Run io_context briefly to let async operations fail
    io_context_.poll();

    // Should transition to Error state due to failed TLS-Crypt load
    EXPECT_EQ(client.GetState(), VpnClientState::Error);
}

TEST_F(VpnClientConnectTest, ConnectWithoutTlsCrypt)
{
    // Don't set tls_crypt_key - should try to connect without TLS-Crypt
    config_.client->tls_crypt_key = "";

    VpnClient client(io_context_, config_);

    // This will fail to resolve or connect, but shouldn't crash
    client.Connect();

    // Run briefly
    io_context_.poll();

    // State should be past Disconnected
    EXPECT_NE(client.GetState(), VpnClientState::Disconnected);

    // Clean shutdown: cancel all coroutine I/O before destroying client/io_context
    client.Disconnect();
    io_context_.restart();
    io_context_.run();
}

TEST_F(VpnClientConnectTest, ConnectWhileRunning)
{
    config_.client->tls_crypt_key = "";

    VpnClient client(io_context_, config_);
    client.Connect();
    io_context_.poll();

    // Second connect should be ignored (logged as warning)
    client.Connect();
    io_context_.poll();

    // Should still be in a connection state
    auto state = client.GetState();
    EXPECT_TRUE(state == VpnClientState::Connecting || state == VpnClientState::TlsHandshake || state == VpnClientState::Error);

    // Clean shutdown: cancel all coroutine I/O before destroying client/io_context
    client.Disconnect();
    io_context_.restart();
    io_context_.run();
}

// ============================================================================
// VpnClient NonCopyable/NonMovable Tests
// ============================================================================

TEST_F(VpnClientTest, NonCopyable)
{
    // These should not compile - static assertion
    static_assert(!std::is_copy_constructible_v<VpnClient>);
    static_assert(!std::is_copy_assignable_v<VpnClient>);
}

TEST_F(VpnClientTest, NonMovable)
{
    // VpnClient should not be movable due to the io_context references
    static_assert(!std::is_move_constructible_v<VpnClient>);
    static_assert(!std::is_move_assignable_v<VpnClient>);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

TEST_F(VpnClientTest, HighPort)
{
    config_.client->server_port = 65535;

    VpnClient client(io_context_, config_);
    EXPECT_EQ(client.GetState(), VpnClientState::Disconnected);
}

TEST_F(VpnClientTest, LowPort)
{
    config_.client->server_port = 1;

    VpnClient client(io_context_, config_);
    EXPECT_EQ(client.GetState(), VpnClientState::Disconnected);
}

TEST_F(VpnClientTest, EmptyServerHost)
{
    config_.client->server_host = "";

    VpnClient client(io_context_, config_);
    EXPECT_EQ(client.GetState(), VpnClientState::Disconnected);

    // Connect should fail gracefully
    // Note: actual behavior depends on resolver handling empty host
}

} // namespace clv::vpn
