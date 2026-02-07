// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include "openvpn/client_config_generator.h"
#include "openvpn/vpn_config.h"
#include <fstream>
#include <filesystem>
#include <iterator>
#include <stdexcept>
#include <string>

using namespace clv::vpn;
namespace fs = std::filesystem;

class ClientConfigGeneratorTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Per-test unique directory under the build tree (no /tmp, no parallel collisions)
        const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
        std::string unique_name = std::string("client_config_gen_test_") + info->name();
        test_dir = fs::path(TEST_TMP_DIR) / unique_name;
        fs::create_directories(test_dir);

        // Create test certificate files
        CreateTestFile(test_dir / "ca.crt", CA_CERT_CONTENT);
        CreateTestFile(test_dir / "client.crt", CLIENT_CERT_CONTENT);
        CreateTestFile(test_dir / "client.key", CLIENT_KEY_CONTENT);
        CreateTestFile(test_dir / "ta.key", TLS_AUTH_KEY_CONTENT);

        // Setup basic server config
        server_config.server.host = "vpn.example.com";
        server_config.server.port = 1194;
        server_config.server.proto = "udp";
        server_config.server.dev = "tun";

        server_config.crypto.ca_cert = test_dir / "ca.crt";
        server_config.crypto.server_cert = test_dir / "server.crt";
        server_config.crypto.server_key = test_dir / "server.key";
        server_config.crypto.cipher = "AES-256-GCM";
        server_config.crypto.auth = "SHA256";
        server_config.crypto.tls_cipher = "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384";

        server_config.network.server_network = "10.8.0.0/24";
        server_config.network.client_dns = {"8.8.8.8", "8.8.4.4"};
        server_config.network.routes = {"192.168.1.0 255.255.255.0"};
        server_config.network.push_routes = true;
    }

    void TearDown() override
    {
        // Clean up test directory
        fs::remove_all(test_dir);
    }

    void CreateTestFile(const fs::path &path, const std::string &content)
    {
        std::ofstream file(path);
        file << content;
    }

    fs::path test_dir;
    OpenVpnConfig server_config;
    ClientConfigGenerator generator;

    // Test certificate content
    static constexpr const char *CA_CERT_CONTENT = "-----BEGIN CERTIFICATE-----\n"
                                                   "MIIBkTCB+wIJAKHHCgVZU6T9MA0GCSqGSIb3DQEBCwUAMA0xCzAJBgNVBAYTAlVT\n"
                                                   "-----END CERTIFICATE-----\n";

    static constexpr const char *CLIENT_CERT_CONTENT = "-----BEGIN CERTIFICATE-----\n"
                                                       "MIIBkTCB+wIJAKHHCgVZU6T8MA0GCSqGSIb3DQEBCwUAMA0xCzAJBgNVBAYTAlVT\n"
                                                       "-----END CERTIFICATE-----\n";

    static constexpr const char *CLIENT_KEY_CONTENT = "-----BEGIN PRIVATE KEY-----\n"
                                                      "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
                                                      "-----END PRIVATE KEY-----\n";

    static constexpr const char *TLS_AUTH_KEY_CONTENT = "#\n"
                                                        "# 2048 bit OpenVPN static key\n"
                                                        "#\n"
                                                        "-----BEGIN OpenVPN Static key V1-----\n"
                                                        "e685bdaf659a25a9e7bc9a834b9e0ddf\n"
                                                        "-----END OpenVPN Static key V1-----\n";
};

// ==================== Basic Generation Tests ====================

TEST_F(ClientConfigGeneratorTest, GenerateBasicConfig)
{
    ClientOptions opts;
    opts.client_name = "test_client";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    std::string config = generator.GenerateConfig(server_config, opts);

    // Verify basic directives
    EXPECT_NE(config.find("client"), std::string::npos);
    EXPECT_NE(config.find("dev tun"), std::string::npos);
    EXPECT_NE(config.find("proto udp"), std::string::npos);
    EXPECT_NE(config.find("remote vpn.example.com 1194"), std::string::npos);
}

TEST_F(ClientConfigGeneratorTest, GenerateWithEmbeddedCertificates)
{
    ClientOptions opts;
    opts.client_name = "alice";
    opts.embed_certificates = true;
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    std::string config = generator.GenerateConfig(server_config, opts);

    // Verify embedded certificates
    EXPECT_NE(config.find("<ca>"), std::string::npos);
    EXPECT_NE(config.find("</ca>"), std::string::npos);
    EXPECT_NE(config.find("<cert>"), std::string::npos);
    EXPECT_NE(config.find("</cert>"), std::string::npos);
    EXPECT_NE(config.find("<key>"), std::string::npos);
    EXPECT_NE(config.find("</key>"), std::string::npos);

    // Verify certificate content is embedded
    EXPECT_NE(config.find("BEGIN CERTIFICATE"), std::string::npos);
    EXPECT_NE(config.find("BEGIN PRIVATE KEY"), std::string::npos);
}

TEST_F(ClientConfigGeneratorTest, GenerateWithExternalCertificates)
{
    ClientOptions opts;
    opts.client_name = "bob";
    opts.embed_certificates = false;
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    std::string config = generator.GenerateConfig(server_config, opts);

    // Verify external references (no embedded tags)
    EXPECT_EQ(config.find("<ca>"), std::string::npos);
    EXPECT_EQ(config.find("<cert>"), std::string::npos);
    EXPECT_EQ(config.find("<key>"), std::string::npos);

    // Verify file references
    EXPECT_NE(config.find("ca "), std::string::npos);
    EXPECT_NE(config.find("cert "), std::string::npos);
    EXPECT_NE(config.find("key "), std::string::npos);
}

// ==================== Crypto Directives Tests ====================

TEST_F(ClientConfigGeneratorTest, CryptoDirectives)
{
    ClientOptions opts;
    opts.client_name = "crypto_test";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    std::string config = generator.GenerateConfig(server_config, opts);

    EXPECT_NE(config.find("cipher AES-256-GCM"), std::string::npos);
    EXPECT_NE(config.find("auth SHA256"), std::string::npos);
    EXPECT_NE(config.find("tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"), std::string::npos);
}

TEST_F(ClientConfigGeneratorTest, TlsAuthEnabled)
{
    ClientOptions opts;
    opts.client_name = "tls_auth_test";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";
    opts.include_tls_auth = true;
    opts.tls_auth_key = test_dir / "ta.key";

    std::string config = generator.GenerateConfig(server_config, opts);

    // Verify TLS-auth is embedded
    EXPECT_NE(config.find("<tls-auth>"), std::string::npos);
    EXPECT_NE(config.find("</tls-auth>"), std::string::npos);
    EXPECT_NE(config.find("OpenVPN Static key"), std::string::npos);
}

// ==================== Network Directives Tests ====================

TEST_F(ClientConfigGeneratorTest, NetworkDirectives)
{
    ClientOptions opts;
    opts.client_name = "network_test";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    std::string config = generator.GenerateConfig(server_config, opts);

    // DNS servers
    EXPECT_NE(config.find("dhcp-option DNS 8.8.8.8"), std::string::npos);
    EXPECT_NE(config.find("dhcp-option DNS 8.8.4.4"), std::string::npos);

    // Routes
    EXPECT_NE(config.find("route 192.168.1.0 255.255.255.0"), std::string::npos);
}

TEST_F(ClientConfigGeneratorTest, CustomDnsServers)
{
    ClientOptions opts;
    opts.client_name = "custom_dns";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";
    opts.custom_dns = {"1.1.1.1", "1.0.0.1"};

    std::string config = generator.GenerateConfig(server_config, opts);

    // Custom DNS should override server defaults
    EXPECT_NE(config.find("dhcp-option DNS 1.1.1.1"), std::string::npos);
    EXPECT_NE(config.find("dhcp-option DNS 1.0.0.1"), std::string::npos);
    EXPECT_EQ(config.find("dhcp-option DNS 8.8.8.8"), std::string::npos);
}

TEST_F(ClientConfigGeneratorTest, ExtraRoutes)
{
    ClientOptions opts;
    opts.client_name = "extra_routes";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";
    opts.extra_routes = {"10.0.0.0 255.0.0.0", "172.16.0.0 255.240.0.0"};

    std::string config = generator.GenerateConfig(server_config, opts);

    // Extra routes should be added
    EXPECT_NE(config.find("route 10.0.0.0 255.0.0.0"), std::string::npos);
    EXPECT_NE(config.find("route 172.16.0.0 255.240.0.0"), std::string::npos);
}

// ==================== Protocol Override Tests ====================

TEST_F(ClientConfigGeneratorTest, CustomRemoteHost)
{
    ClientOptions opts;
    opts.client_name = "custom_host";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";
    opts.remote_host = "custom.vpn.example.com";

    std::string config = generator.GenerateConfig(server_config, opts);

    EXPECT_NE(config.find("remote custom.vpn.example.com 1194"), std::string::npos);
    EXPECT_EQ(config.find("remote vpn.example.com"), std::string::npos);
}

TEST_F(ClientConfigGeneratorTest, TcpProtocol)
{
    server_config.server.proto = "tcp";

    ClientOptions opts;
    opts.client_name = "tcp_test";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    std::string config = generator.GenerateConfig(server_config, opts);

    EXPECT_NE(config.find("proto tcp"), std::string::npos);
    EXPECT_NE(config.find("remote vpn.example.com 1194 tcp"), std::string::npos);
}

// ==================== Options Tests ====================

TEST_F(ClientConfigGeneratorTest, CompressionEnabled)
{
    ClientOptions opts;
    opts.client_name = "compression_test";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";
    opts.enable_compression = true;

    std::string config = generator.GenerateConfig(server_config, opts);

    EXPECT_NE(config.find("comp-lzo"), std::string::npos);
}

TEST_F(ClientConfigGeneratorTest, CustomVerbosity)
{
    ClientOptions opts;
    opts.client_name = "verbosity_test";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";
    opts.verbosity = 5;

    std::string config = generator.GenerateConfig(server_config, opts);

    EXPECT_NE(config.find("verb 5"), std::string::npos);
}

// ==================== Standard Client Directives ====================

TEST_F(ClientConfigGeneratorTest, StandardClientDirectives)
{
    ClientOptions opts;
    opts.client_name = "standard_test";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    std::string config = generator.GenerateConfig(server_config, opts);

    // Standard client behavior directives
    EXPECT_NE(config.find("resolv-retry infinite"), std::string::npos);
    EXPECT_NE(config.find("nobind"), std::string::npos);
    EXPECT_NE(config.find("persist-key"), std::string::npos);
    EXPECT_NE(config.find("persist-tun"), std::string::npos);
}

// ==================== Validation Tests ====================

TEST_F(ClientConfigGeneratorTest, ValidateFilesSuccess)
{
    ClientOptions opts;
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    std::string error = generator.ValidateFiles(server_config, opts);

    EXPECT_TRUE(error.empty());
}

TEST_F(ClientConfigGeneratorTest, ValidateFilesMissingCa)
{
    server_config.crypto.ca_cert = test_dir / "nonexistent.crt";

    ClientOptions opts;
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    std::string error = generator.ValidateFiles(server_config, opts);

    EXPECT_FALSE(error.empty());
    EXPECT_NE(error.find("CA certificate"), std::string::npos);
}

TEST_F(ClientConfigGeneratorTest, ValidateFilesMissingClientCert)
{
    ClientOptions opts;
    opts.client_cert = test_dir / "nonexistent_client.crt";
    opts.client_key = test_dir / "client.key";

    std::string error = generator.ValidateFiles(server_config, opts);

    EXPECT_FALSE(error.empty());
    EXPECT_NE(error.find("Client certificate"), std::string::npos);
}

TEST_F(ClientConfigGeneratorTest, GenerateThrowsOnMissingFiles)
{
    ClientOptions opts;
    opts.client_name = "error_test";
    opts.client_cert = test_dir / "nonexistent.crt";
    opts.client_key = test_dir / "client.key";

    EXPECT_THROW({
        generator.GenerateConfig(server_config, opts);
    },
                 std::runtime_error);
}

// ==================== File I/O Tests ====================

TEST_F(ClientConfigGeneratorTest, WriteToFile)
{
    ClientOptions opts;
    opts.client_name = "file_write_test";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    std::string config = generator.GenerateConfig(server_config, opts);
    fs::path output_path = test_dir / "test_client.ovpn";

    generator.WriteToFile(config, output_path);

    EXPECT_TRUE(fs::exists(output_path));

    // Read back and verify
    std::ifstream file(output_path);
    std::string read_content((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());

    EXPECT_EQ(config, read_content);
}

TEST_F(ClientConfigGeneratorTest, GenerateAndWrite)
{
    ClientOptions opts;
    opts.client_name = "combined_test";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    fs::path output_path = test_dir / "combined.ovpn";

    generator.GenerateAndWrite(server_config, opts, output_path);

    EXPECT_TRUE(fs::exists(output_path));

    // Verify content
    std::ifstream file(output_path);
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("client"), std::string::npos);
    EXPECT_NE(content.find("remote vpn.example.com"), std::string::npos);
}

// ==================== Edge Cases ====================

TEST_F(ClientConfigGeneratorTest, EmptyClientName)
{
    ClientOptions opts;
    opts.client_name = ""; // Empty name is allowed
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    std::string config = generator.GenerateConfig(server_config, opts);

    EXPECT_NE(config.find("client"), std::string::npos);
}

TEST_F(ClientConfigGeneratorTest, NoCertificatesProvided)
{
    ClientOptions opts;
    opts.client_name = "no_certs";
    // No client cert/key provided - should still work (server might not require)

    std::string config = generator.GenerateConfig(server_config, opts);

    // Should have CA but no client cert/key embedded
    EXPECT_NE(config.find("<ca>"), std::string::npos);
    EXPECT_EQ(config.find("<cert>"), std::string::npos);
    EXPECT_EQ(config.find("<key>"), std::string::npos);
}

TEST_F(ClientConfigGeneratorTest, MultipleRoutes)
{
    server_config.network.routes = {
        "192.168.1.0 255.255.255.0",
        "192.168.2.0 255.255.255.0",
        "10.0.0.0 255.0.0.0"};

    ClientOptions opts;
    opts.client_name = "multi_route";
    opts.client_cert = test_dir / "client.crt";
    opts.client_key = test_dir / "client.key";

    std::string config = generator.GenerateConfig(server_config, opts);

    EXPECT_NE(config.find("route 192.168.1.0"), std::string::npos);
    EXPECT_NE(config.find("route 192.168.2.0"), std::string::npos);
    EXPECT_NE(config.find("route 10.0.0.0"), std::string::npos);
}
