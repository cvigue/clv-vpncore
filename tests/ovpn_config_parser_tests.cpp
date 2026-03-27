// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "openvpn/ovpn_config_parser.h"
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <variant>

namespace fs = std::filesystem;
using namespace clv::vpn;

class OvpnConfigParserTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Per-test unique directory under the build tree (no /tmp, no parallel collisions)
        const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
        std::string unique_name = std::string("ovpn_parser_test_") + info->name();
        test_dir = fs::path(TEST_TMP_DIR) / unique_name;
        fs::create_directories(test_dir);
    }

    void TearDown() override
    {
        // Clean up test directory
        if (fs::exists(test_dir))
        {
            fs::remove_all(test_dir);
        }
    }

    fs::path test_dir;
};

// Basic parsing tests

TEST_F(OvpnConfigParserTest, ParseBasicConfig)
{
    std::string ovpn_content = R"(
# OpenVPN Client Config
client
dev tun
proto udp
remote example.com 1194 udp
cipher AES-256-GCM
auth SHA256
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
-----END CERTIFICATE-----
</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    EXPECT_EQ("example.com", config.remote.host);
    EXPECT_EQ(1194, config.remote.port);
    EXPECT_EQ("udp", config.remote.proto);
    EXPECT_EQ("tun", config.dev);
    EXPECT_EQ("AES-256-GCM", config.cipher);
    EXPECT_EQ("SHA256", config.auth);
    EXPECT_EQ(3, config.verbosity);
    EXPECT_TRUE(config.client_mode);
}

TEST_F(OvpnConfigParserTest, ParseInlineCertificates)
{
    std::string ovpn_content = R"(
client
remote example.com 1194
dev tun

<ca>
-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
CLIENT_CERT_DATA_HERE
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN PRIVATE KEY-----
CLIENT_KEY_DATA_HERE
-----END PRIVATE KEY-----
</key>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    EXPECT_TRUE(std::holds_alternative<std::string>(config.ca_cert));
    EXPECT_TRUE(std::get<std::string>(config.ca_cert).find("BEGIN CERTIFICATE") != std::string::npos);
    EXPECT_TRUE(std::holds_alternative<std::string>(config.client_cert));
    EXPECT_TRUE(std::get<std::string>(config.client_cert).find("CLIENT_CERT_DATA_HERE") != std::string::npos);
    EXPECT_TRUE(std::holds_alternative<std::string>(config.client_key));
    EXPECT_TRUE(std::get<std::string>(config.client_key).find("CLIENT_KEY_DATA_HERE") != std::string::npos);
}

TEST_F(OvpnConfigParserTest, ParseExternalFileReferences)
{
    // Create temporary test files
    const auto *info_ = ::testing::UnitTest::GetInstance()->current_test_info();
    std::filesystem::path temp_dir = std::filesystem::path(TEST_TMP_DIR) / (std::string("ovpn_ext_test_") + info_->name());
    std::filesystem::create_directories(temp_dir);

    auto ca_file = temp_dir / "ca.crt";
    auto cert_file = temp_dir / "client.crt";
    auto key_file = temp_dir / "client.key";

    std::ofstream(ca_file) << "CA_CERT_DATA";
    std::ofstream(cert_file) << "CLIENT_CERT_DATA";
    std::ofstream(key_file) << "CLIENT_KEY_DATA";

    std::string ovpn_content = R"(
client
remote vpn.example.org 443 tcp
dev tap
proto tcp
ca )" + ca_file.string() + R"(
cert )" + cert_file.string() + R"(
key )" + key_file.string() + R"(
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    EXPECT_EQ("vpn.example.org", config.remote.host);
    EXPECT_EQ(443, config.remote.port);
    EXPECT_EQ("tcp", config.remote.proto);
    EXPECT_EQ("tap", config.dev);
    EXPECT_TRUE(std::holds_alternative<std::string>(config.ca_cert));
    EXPECT_EQ("CA_CERT_DATA", std::get<std::string>(config.ca_cert));
    EXPECT_TRUE(std::holds_alternative<std::string>(config.client_cert));
    EXPECT_EQ("CLIENT_CERT_DATA", std::get<std::string>(config.client_cert));
    EXPECT_TRUE(std::holds_alternative<std::string>(config.client_key));
    EXPECT_EQ("CLIENT_KEY_DATA", std::get<std::string>(config.client_key));

    // Cleanup
    std::filesystem::remove_all(temp_dir);
}

TEST_F(OvpnConfigParserTest, ParseConnectionBehaviorFlags)
{
    std::string ovpn_content = R"(
client
remote example.com 1194
nobind
persist-key
persist-tun
resolv-retry infinite
<ca>CERT</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    EXPECT_TRUE(config.nobind);
    EXPECT_TRUE(config.persist_key);
    EXPECT_TRUE(config.persist_tun);
    EXPECT_TRUE(config.resolv_retry_infinite);
}

TEST_F(OvpnConfigParserTest, ParseKeepalive)
{
    std::string ovpn_content = R"(
client
remote example.com 1194
keepalive 10 120
<ca>CERT</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    EXPECT_EQ(10, config.keepalive_interval);
    EXPECT_EQ(120, config.keepalive_timeout);
}

TEST_F(OvpnConfigParserTest, ParseCompression)
{
    std::string ovpn_content_lz4 = R"(
client
remote example.com 1194
compress lz4-v2
<ca>CERT</ca>
)";

    ClientConnectionConfig config1 = OvpnConfigParser::ParseString(ovpn_content_lz4);
    EXPECT_EQ("lz4-v2", config1.compression);

    std::string ovpn_content_lzo = R"(
client
remote example.com 1194
comp-lzo
<ca>CERT</ca>
)";

    ClientConnectionConfig config2 = OvpnConfigParser::ParseString(ovpn_content_lzo);
    EXPECT_EQ("comp-lzo", config2.compression);
}

TEST_F(OvpnConfigParserTest, ParseRoutes)
{
    std::string ovpn_content = R"(
client
remote example.com 1194
route 192.168.1.0 255.255.255.0
route 10.0.0.0 255.0.0.0 10.8.0.1
<ca>CERT</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    ASSERT_EQ(2, config.routes.size());
    EXPECT_EQ("192.168.1.0 255.255.255.0", config.routes[0]);
    EXPECT_EQ("10.0.0.0 255.0.0.0 10.8.0.1", config.routes[1]);
}

TEST_F(OvpnConfigParserTest, ParseDhcpOptions)
{
    std::string ovpn_content = R"(
client
remote example.com 1194
dhcp-option DNS 8.8.8.8
dhcp-option DNS 8.8.4.4
dhcp-option DOMAIN example.com
<ca>CERT</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    ASSERT_EQ(2, config.dns_servers.size());
    EXPECT_EQ("8.8.8.8", config.dns_servers[0]);
    EXPECT_EQ("8.8.4.4", config.dns_servers[1]);
    EXPECT_EQ("example.com", config.dns_domain);
}

TEST_F(OvpnConfigParserTest, ParseTlsCipher)
{
    std::string ovpn_content = R"(
client
remote example.com 1194
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
<ca>CERT</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);
    EXPECT_EQ("TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384", config.tls_cipher);
}

TEST_F(OvpnConfigParserTest, ParseRenegotiationSeconds)
{
    std::string ovpn_content = R"(
client
remote example.com 1194
reneg-sec 3600
<ca>CERT</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);
    EXPECT_EQ(3600, config.reneg_seconds);
}

TEST_F(OvpnConfigParserTest, ParseDevNode)
{
    std::string ovpn_content = R"(
client
remote example.com 1194
dev tun
dev-node /dev/net/tun0
<ca>CERT</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);
    EXPECT_EQ("/dev/net/tun0", config.dev_node);
}

TEST_F(OvpnConfigParserTest, IgnoreComments)
{
    std::string ovpn_content = R"(
# This is a comment
client
; This is also a comment
remote example.com 1194
# Another comment
dev tun
<ca>CERT</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    EXPECT_EQ("example.com", config.remote.host);
    EXPECT_EQ("tun", config.dev);
}

TEST_F(OvpnConfigParserTest, HandleBlankLines)
{
    std::string ovpn_content = R"(

client


remote example.com 1194

dev tun
<ca>CERT</ca>

)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    EXPECT_EQ("example.com", config.remote.host);
    EXPECT_EQ("tun", config.dev);
}

TEST_F(OvpnConfigParserTest, CaseInsensitiveKeywords)
{
    std::string ovpn_content = R"(
CLIENT
REMOTE example.com 1194
DEV tun
PROTO udp
<ca>CERT</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    EXPECT_EQ("example.com", config.remote.host);
    EXPECT_EQ("tun", config.dev);
    EXPECT_EQ("udp", config.remote.proto);
}

// File I/O tests

TEST_F(OvpnConfigParserTest, ParseFromFile)
{
    fs::path config_file = test_dir / "test.ovpn";
    std::ofstream file(config_file);
    file << R"(
client
remote example.com 1194
dev tun
proto udp
<ca>CERT</ca>
)";
    file.close();

    ClientConnectionConfig config = OvpnConfigParser::ParseFile(config_file);

    EXPECT_EQ("example.com", config.remote.host);
    EXPECT_EQ(1194, config.remote.port);
}

TEST_F(OvpnConfigParserTest, ParseFileNotFound)
{
    fs::path non_existent = test_dir / "non_existent.ovpn";

    EXPECT_THROW(
        {
            try
            {
                OvpnConfigParser::ParseFile(non_existent);
            }
            catch (const std::runtime_error &e)
            {
                EXPECT_TRUE(std::string(e.what()).find("not found") != std::string::npos);
                throw;
            }
        },
        std::runtime_error);
}

// Validation tests

TEST_F(OvpnConfigParserTest, ValidateMissingRemote)
{
    std::string ovpn_content = R"(
client
dev tun
)";

    EXPECT_THROW(
        {
            try
            {
                OvpnConfigParser::ParseString(ovpn_content);
            }
            catch (const std::runtime_error &e)
            {
                EXPECT_TRUE(std::string(e.what()).find("remote host is required") != std::string::npos);
                throw;
            }
        },
        std::runtime_error);
}

TEST_F(OvpnConfigParserTest, ValidateInvalidProtocol)
{
    std::string ovpn_content = R"(
client
remote example.com 1194
proto invalid
)";

    EXPECT_THROW(
        {
            try
            {
                OvpnConfigParser::ParseString(ovpn_content);
            }
            catch (const std::runtime_error &e)
            {
                EXPECT_TRUE(std::string(e.what()).find("protocol must be") != std::string::npos);
                throw;
            }
        },
        std::runtime_error);
}

TEST_F(OvpnConfigParserTest, ValidateInvalidDevice)
{
    std::string ovpn_content = R"(
client
remote example.com 1194
dev invalid
)";

    EXPECT_THROW(
        {
            try
            {
                OvpnConfigParser::ParseString(ovpn_content);
            }
            catch (const std::runtime_error &e)
            {
                EXPECT_TRUE(std::string(e.what()).find("device must be") != std::string::npos);
                throw;
            }
        },
        std::runtime_error);
}

TEST_F(OvpnConfigParserTest, ValidateMissingCA)
{
    std::string ovpn_content = R"(
client
remote example.com 1194
dev tun
)";

    EXPECT_THROW(
        {
            try
            {
                OvpnConfigParser::ParseString(ovpn_content);
            }
            catch (const std::runtime_error &e)
            {
                EXPECT_TRUE(std::string(e.what()).find("CA certificate is required") != std::string::npos);
                throw;
            }
        },
        std::runtime_error);
}

TEST_F(OvpnConfigParserTest, ValidateMissingExternalFile)
{
    std::string ovpn_content = R"(
client
remote example.com 1194
ca /nonexistent/path/ca.crt
)";

    EXPECT_THROW(
        {
            try
            {
                OvpnConfigParser::ParseString(ovpn_content);
            }
            catch (const std::runtime_error &e)
            {
                EXPECT_TRUE(std::string(e.what()).find("ca file not found") != std::string::npos);
                throw;
            }
        },
        std::runtime_error);
}

// Complex real-world config test

TEST_F(OvpnConfigParserTest, ParseRealWorldConfig)
{
    std::string ovpn_content = R"(
##############################################
# Sample client-side OpenVPN 2.0 config file #
##############################################

client

dev tun

proto udp

remote vpn.example.com 1194

resolv-retry infinite

nobind

persist-key
persist-tun

<ca>
-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
CLIENT_CERTIFICATE_DATA_HERE
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN PRIVATE KEY-----
CLIENT_PRIVATE_KEY_DATA_HERE
-----END PRIVATE KEY-----
</key>

cipher AES-256-GCM
auth SHA256

compress lz4-v2

verb 3

# Custom routes
route 10.0.0.0 255.0.0.0

# DNS settings
dhcp-option DNS 8.8.8.8
dhcp-option DNS 8.8.4.4
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    EXPECT_EQ("vpn.example.com", config.remote.host);
    EXPECT_EQ(1194, config.remote.port);
    EXPECT_EQ("udp", config.remote.proto);
    EXPECT_EQ("tun", config.dev);
    EXPECT_EQ("AES-256-GCM", config.cipher);
    EXPECT_EQ("SHA256", config.auth);
    EXPECT_EQ("lz4-v2", config.compression);
    EXPECT_TRUE(config.nobind);
    EXPECT_TRUE(config.persist_key);
    EXPECT_TRUE(config.persist_tun);
    EXPECT_TRUE(std::holds_alternative<std::string>(config.ca_cert));
    EXPECT_TRUE(std::holds_alternative<std::string>(config.client_cert));
    EXPECT_TRUE(std::holds_alternative<std::string>(config.client_key));
    EXPECT_EQ(1, config.routes.size());
    EXPECT_EQ(2, config.dns_servers.size());
}

// Edge case tests

TEST_F(OvpnConfigParserTest, ParseMinimalConfig)
{
    std::string ovpn_content = R"(
remote example.com 1194
<ca>
CERT_DATA
</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    EXPECT_EQ("example.com", config.remote.host);
    EXPECT_TRUE(std::holds_alternative<std::string>(config.ca_cert));
    // Should use defaults for other values
    EXPECT_EQ("tun", config.dev);
    EXPECT_EQ("udp", config.remote.proto);
}

TEST_F(OvpnConfigParserTest, ParseRemoteWithDefaultPort)
{
    std::string ovpn_content = R"(
remote example.com
<ca>CERT</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    EXPECT_EQ("example.com", config.remote.host);
    EXPECT_EQ(1194, config.remote.port); // Default port
}

TEST_F(OvpnConfigParserTest, ParseTlsAuthInline)
{
    std::string ovpn_content = R"(
remote example.com 1194
<ca>CA_DATA</ca>
<tls-auth>
TLS_AUTH_KEY_DATA
</tls-auth>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);

    EXPECT_TRUE(std::holds_alternative<std::string>(config.tls_auth));
    EXPECT_TRUE(std::get<std::string>(config.tls_auth).find("TLS_AUTH_KEY_DATA") != std::string::npos);
}

TEST_F(OvpnConfigParserTest, ParseConnectTimeout)
{
    std::string ovpn_content = R"(
remote example.com 1194
connect-timeout 60
<ca>CA</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);
    EXPECT_EQ(60, config.connect_timeout);
}

TEST_F(OvpnConfigParserTest, ParseConnectRetry)
{
    std::string ovpn_content = R"(
remote example.com 1194
connect-retry 10
connect-retry-max 5
<ca>CA</ca>
)";

    ClientConnectionConfig config = OvpnConfigParser::ParseString(ovpn_content);
    EXPECT_EQ(10, config.connect_retry_delay);
    EXPECT_EQ(5, config.connect_retry_max);
}

// Error handling tests

TEST_F(OvpnConfigParserTest, HandleMalformedDirective)
{
    std::string ovpn_content = R"(
remote example.com 1194
keepalive 10
<ca>CA</ca>
)";

    EXPECT_THROW(OvpnConfigParser::ParseString(ovpn_content), std::runtime_error);
}

TEST_F(OvpnConfigParserTest, RejectRemotePortOverflow)
{
    std::string ovpn_content = R"(
remote example.com 65536
<ca>CA</ca>
)";

    EXPECT_THROW(OvpnConfigParser::ParseString(ovpn_content), std::runtime_error);
}

TEST_F(OvpnConfigParserTest, RejectRemotePortNegative)
{
    std::string ovpn_content = R"(
remote example.com -1
<ca>CA</ca>
)";

    EXPECT_THROW(OvpnConfigParser::ParseString(ovpn_content), std::runtime_error);
}

TEST_F(OvpnConfigParserTest, HandleMissingClosingTag)
{
    std::string ovpn_content = R"(
remote example.com 1194
<ca>
CERT_DATA
)";

    EXPECT_THROW(
        {
            try
            {
                OvpnConfigParser::ParseString(ovpn_content);
            }
            catch (const std::runtime_error &e)
            {
                EXPECT_TRUE(std::string(e.what()).find("Missing closing tag") != std::string::npos);
                throw;
            }
        },
        std::runtime_error);
}
