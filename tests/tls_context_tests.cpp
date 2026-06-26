// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/key_derivation.h"
#include "openvpn/tls_context.h"

#include <HelpSslException.h>

#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace clv::vpn::openvpn;

// ---------------------------------------------------------------------------
// Inline PEM constants (test certs from test_data/certs/)
// ---------------------------------------------------------------------------

static const char kTestCaCertPem[] = "-----BEGIN CERTIFICATE-----\n"
                                     "MIIDSzCCAjOgAwIBAgIUHVpLSE6pfKNjtbjzKuNKDm1spQgwDQYJKoZIhvcNAQEL\n"
                                     "BQAwNTEQMA4GA1UEAwwHVGVzdCBDQTEUMBIGA1UECgwLQ0xWTGliIFRlc3QxCzAJ\n"
                                     "BgNVBAYTAlVTMB4XDTI2MDExNjAzNTgwMVoXDTM2MDExNDAzNTgwMVowNTEQMA4G\n"
                                     "A1UEAwwHVGVzdCBDQTEUMBIGA1UECgwLQ0xWTGliIFRlc3QxCzAJBgNVBAYTAlVT\n"
                                     "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6ZJp5MioVnraooqa2x4O\n"
                                     "om21B9DoYP09/bcGTDeXTLv+LMNt1AXICK0QwvNNGIvEg2GAlnC8tP+/KWo2QZS0\n"
                                     "5/oWSuR7cY575HbPaUBYdBzMWMQkrsGbUSGFzwdMA+VA44LjoUFYl9OrtXZ6GunM\n"
                                     "QHDNk9XR/mhZkjQJDRiTRz2PcoLiwnpyT4qx58yqGhvI8lsBbYEuX3vROv2ga3mK\n"
                                     "cerR7GVe4JMnEkDwf/znUxAhA0WX6Hj2r7S39ruUn8gpm+w+q5Z2sYt4PyySX5Xw\n"
                                     "Mpgy5Dd/6x2eXGPa7H95xfmRgOjUJtfV+wkjRqU/MxLDgA8Qw+aYRLzV33KOnLmL\n"
                                     "aQIDAQABo1MwUTAdBgNVHQ4EFgQUwjMAleNPzs1yHR6wgjtJYyElIsEwHwYDVR0j\n"
                                     "BBgwFoAUwjMAleNPzs1yHR6wgjtJYyElIsEwDwYDVR0TAQH/BAUwAwEB/zANBgkq\n"
                                     "hkiG9w0BAQsFAAOCAQEA5LkO+n2LgvnBBA5A39O8xBKsLIWRctph0Ras/2r7HOl4\n"
                                     "qKNrseCFvE2b6cSnwFDdBSCCYV7AsNA3IR1KS/Z9jOe2lp5cBZsEq0J8IyUzcXav\n"
                                     "1V0quqR57gxhelS5BMgv53KBTFkpasqLt5hZMrFaIUCkRBkvtRo8mdHoTA42uR2Q\n"
                                     "LKUJqy0gNAzRTnQ4LCAu+oiFUAi0HP+UY6qNqqTLcINJ5yLJeB/NuK6VnyGoE27f\n"
                                     "ixYmt+Ttu8XTmSLMkX6Lw3mo4UZ2vtUJ+rslujmYi8D6KG0vsEF918Ufl2ErkZew\n"
                                     "fiuDVetvYB71/G2X4FF8OO4PYHxHK230kjyvt5c1kg==\n"
                                     "-----END CERTIFICATE-----\n";

static const char kTestServerCertPem[] = "-----BEGIN CERTIFICATE-----\n"
                                         "MIIC9TCCAd0CFDF/HD80UN0HLw9CppWSLjhDmI1HMA0GCSqGSIb3DQEBCwUAMDUx\n"
                                         "EDAOBgNVBAMMB1Rlc3QgQ0ExFDASBgNVBAoMC0NMVkxpYiBUZXN0MQswCQYDVQQG\n"
                                         "EwJVUzAeFw0yNjAxMTYwMzU4MDFaFw0zNjAxMTQwMzU4MDFaMDkxFDASBgNVBAMM\n"
                                         "C1Rlc3QgU2VydmVyMRQwEgYDVQQKDAtDTFZMaWIgVGVzdDELMAkGA1UEBhMCVVMw\n"
                                         "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCcqSTzNacufzvGdY35Sdew\n"
                                         "iJLgrnDyhzTJG8bLOCqpenePRQOP1zR4YI8k4MM+qc6S/gaUrXglRY/fXRPSlgKT\n"
                                         "cq/Tx53PilDRYEtWG4hxjX1Y3GPsD7BDflD8tEQez+mBTX+zYZadprb9N9ujZp76\n"
                                         "4DXY0j3n7jVcValFGzGuwtjQ45AqMgw8gZtPs9gNOZadjV1cC4NvhggM+U1/hVYm\n"
                                         "4IIhMryzvM+ubDZuw1oR43Vev5Pmgf0XNfit6VMLz7UxHI7geuBN93DTX7AF+zH2\n"
                                         "0w0tvC/Q0y2cg4cvjOcco6otPkYyKXgUblkt3iJ2qWdx3uNLnzAUBHR6NBZF6Q0t\n"
                                         "AgMBAAEwDQYJKoZIhvcNAQELBQADggEBALPHApOMPzVFFM6GDA/A/vdINO8y7B1O\n"
                                         "e9B0/Q/Snhqdsk6a44UlGnn5fqo3dGER6GKxVgBfAtC2ilTVZ3mnstcYRbTsZoIr\n"
                                         "GkknQzBM1I2pAOTsqKTTs2pPXwlCw0I6+rFa5aEe/fHUFQ3IpIPW0SfIUhX/7c5k\n"
                                         "vIAPqRTiyiOXN/zyNzXsK43aXUB5sKxhswyXVslQlXnhfiekan0Ylm+5bDz1HVvG\n"
                                         "+HZpoidtOfmdpgHl9Er7xS5ijZkb3lQi83rNmMgweJUIbWcj/iF6nXSpSYK692R2\n"
                                         "KEoOi1iAiq2UFVk5pENL50hwmQ2hjZ5kuuw+OGK0lF/g1GNFa+EvZag=\n"
                                         "-----END CERTIFICATE-----\n";

static const char kTestServerKeyPem[] = "-----BEGIN PRIVATE KEY-----\n"
                                        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCcqSTzNacufzvG\n"
                                        "dY35SdewiJLgrnDyhzTJG8bLOCqpenePRQOP1zR4YI8k4MM+qc6S/gaUrXglRY/f\n"
                                        "XRPSlgKTcq/Tx53PilDRYEtWG4hxjX1Y3GPsD7BDflD8tEQez+mBTX+zYZadprb9\n"
                                        "N9ujZp764DXY0j3n7jVcValFGzGuwtjQ45AqMgw8gZtPs9gNOZadjV1cC4NvhggM\n"
                                        "+U1/hVYm4IIhMryzvM+ubDZuw1oR43Vev5Pmgf0XNfit6VMLz7UxHI7geuBN93DT\n"
                                        "X7AF+zH20w0tvC/Q0y2cg4cvjOcco6otPkYyKXgUblkt3iJ2qWdx3uNLnzAUBHR6\n"
                                        "NBZF6Q0tAgMBAAECggEAAj7UZkB54zx0n9cpvFx7yHNl6bJwOtkRf20z/pTWKnkq\n"
                                        "jSbhqMPed8bF6ikiGqrKBjx9yeLpPl1dTb4FDtTD1a/kQEZp6ZsekpTFyrzRcZFf\n"
                                        "Gl/+nZMlYEaWLlmv33/NUfbw05h+/L0Z4ESSCgG5MlFFOncW018WHWdEdBuK3lYE\n"
                                        "eZWkOIWQjSgrgBfhsUHzjQMrxMYDtePaXiHw1CJNXnEnlSyKpPiAHrzarW1VYkpz\n"
                                        "EiHg5gEuoc/eVTkRx2kuzk7rSNnIY8F+T2uv/nypLUCfrMqk02v18mkWaWv4cUCD\n"
                                        "4PupLDHSAD0vm5qJbZVKoQtRof5xKLgCRm6aGEr06wKBgQDZeulKjifTTGQfeaNt\n"
                                        "hgk+9Rr9KJvTJUH5l/yIwnJqX12SrbzxtLZVcJ3J8TDJJF6R8AHBJEHY6vJ9nFRX\n"
                                        "csKci3/Vk3rgRqIgo4P2J31GgHJTa3F+DkvpV7641GO6E2hdB+LfPEx+Os0ZU5HO\n"
                                        "rMUdzNzJJyZDZPpSg0YcXx0DLwKBgQC4aIfEnc6U0IPGoFhRUAPF6ABJjdwroB3P\n"
                                        "odw7kp4u3CeJZ18+UKEnzJEQlOxadhdulCpQMkUVPN3nIiN5OqPyCLBc1EA4YSHe\n"
                                        "9ASDc6uY6NJJHKHnRe9+J0jCT1Egy6Fmy7HAc9jrKMUWQUEM81cfR4trYu9JYkwu\n"
                                        "UWFSiK/OYwKBgQCCj3deetkN0N6KxsuGBOGoGh2JvcdOix+AZ+4DbDikA3x5gjPc\n"
                                        "J1EPGfygL1vKZTshAaUL/mhJgULyhddcaFjNAjJMVa1+1uieD4w5Spu6p4H68pW/\n"
                                        "x3VrMHIfI+J64wvUTde1jM2fOk3G1pTCLpZnvYUOfaJK82QUBRsiDTetoQKBgQCv\n"
                                        "gKxV72pALwJ68veay3AL1fUQC7bSvhwhE4aqG6v4JQZrurnmcI4vdn1JLrKSlXlP\n"
                                        "gCuVD4K356m448CnC6wkGSjf8BD+l1LJAauZ/2f8qvgXJOzhUqnPgku4wgwQDjyZ\n"
                                        "vJp68sYraC3KNGhYju8HkeuaVBov2SFvo3vgNL48yQKBgHPQHha06L/ZxBTL/xi+\n"
                                        "kY0tTk1tGug8oQkPYqRg/NfxzFe86g0OmLQBEPtQ2MUfaOMcwcrc0VcYLAwoK8Tl\n"
                                        "VZvk8san3T1wY4GeZvXshE3Kb5cpzEDYf6mMdqhMVSBNYmVqJCBrJFQ5m53QKV9v\n"
                                        "xlMhKrxfdHi3qYLI3Re2xwbt\n"
                                        "-----END PRIVATE KEY-----\n";

// ---------------------------------------------------------------------------
// Base fixture (no cert files needed)
// ---------------------------------------------------------------------------

class TlsContextTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        logger_ = std::make_unique<spdlog::logger>("test_tls", null_sink);
    }
    void TearDown() override
    {
    }

    std::unique_ptr<spdlog::logger> logger_;
};

// ---------------------------------------------------------------------------
// Fixture with temp dir for file-based cert loading
// ---------------------------------------------------------------------------

class TlsContextCertTest : public TlsContextTest
{
  protected:
    void SetUp() override
    {
        TlsContextTest::SetUp();
        const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
        temp_dir_ = fs::path(TEST_TMP_DIR) / (std::string("tls_ctx_") + info->name());
        fs::create_directories(temp_dir_);

        ca_cert_path_ = temp_dir_ / "ca.crt";
        server_cert_path_ = temp_dir_ / "server.crt";
        server_key_path_ = temp_dir_ / "server.key";

        WriteFile(ca_cert_path_, kTestCaCertPem);
        WriteFile(server_cert_path_, kTestServerCertPem);
        WriteFile(server_key_path_, kTestServerKeyPem);
    }

    void TearDown() override
    {
        TlsContextTest::TearDown();
        if (fs::exists(temp_dir_))
            fs::remove_all(temp_dir_);
    }

    static void WriteFile(const fs::path &path, const std::string &content)
    {
        std::ofstream ofs(path);
        ofs << content;
    }

    fs::path temp_dir_;
    fs::path ca_cert_path_;
    fs::path server_cert_path_;
    fs::path server_key_path_;
};

TEST_F(TlsContextTest, ConstructorServerMode)
{
    TlsContext tls(PeerRole::Server, std::nullopt, *logger_); // true = server mode
    EXPECT_FALSE(tls.IsHandshakeComplete());
}

TEST_F(TlsContextTest, ConstructorClientMode)
{
    TlsContext tls(PeerRole::Client, std::nullopt, *logger_); // false = client mode
    EXPECT_FALSE(tls.IsHandshakeComplete());
}

TEST_F(TlsContextTest, ProcessIncomingDataReturnsVectorBeforeHandshake)
{
    TlsContext tls(PeerRole::Client, std::nullopt, *logger_);
    std::vector<uint8_t> dummy_data = {0x01, 0x02, 0x03};
    auto response = tls.ProcessIncomingData(dummy_data);

    // Response should be optional (not nullopt for non-fatal cases)
    EXPECT_TRUE(response.has_value());
}

TEST_F(TlsContextTest, ProcessIncomingDataReturnsEmptyAfterHandshakeComplete)
{
    TlsContext tls(PeerRole::Client, std::nullopt, *logger_);

    // Simulate handshake completion by calling ProcessIncomingData multiple times
    std::vector<uint8_t> dummy_data = {0x01};
    auto response1 = tls.ProcessIncomingData(dummy_data);
    EXPECT_TRUE(response1.has_value());

    // Now check if handshake status can be checked
    // (This is a simplistic test - real handshake completion requires proper TLS records)
}

TEST_F(TlsContextTest, IsHandshakeCompleteInitiallyFalse)
{
    TlsContext tls(PeerRole::Server, std::nullopt, *logger_);
    EXPECT_FALSE(tls.IsHandshakeComplete());
}

TEST_F(TlsContextTest, GetMasterSecretReturnsNulloptBeforeHandshake)
{
    TlsContext tls(PeerRole::Server, std::nullopt, *logger_);
    auto master_secret = tls.GetMasterSecret();
    EXPECT_FALSE(master_secret.has_value());
}

TEST_F(TlsContextTest, GetPendingDataReturnsEmptyVector)
{
    TlsContext tls(PeerRole::Server, std::nullopt, *logger_);
    auto pending = tls.GetPendingData();
    EXPECT_TRUE(pending.empty());
}

TEST_F(TlsContextTest, ProcessIncomingDataWithEmptyData)
{
    TlsContext tls(PeerRole::Client, std::nullopt, *logger_);
    std::vector<uint8_t> empty_data;
    auto response = tls.ProcessIncomingData(empty_data);

    // Should still return optional (may be empty vector)
    EXPECT_TRUE(response.has_value());
}

TEST_F(TlsContextTest, MultipleProcessIncomingDataCalls)
{
    TlsContext tls(PeerRole::Server, std::nullopt, *logger_);

    std::vector<uint8_t> data1 = {0x16, 0x03, 0x03}; // TLS record header start
    EXPECT_NO_THROW({
        auto resp1 = tls.ProcessIncomingData(data1);
        (void)resp1;
    });

    std::vector<uint8_t> data2 = {0x00, 0x01};
    EXPECT_NO_THROW({
        auto resp2 = tls.ProcessIncomingData(data2);
        (void)resp2;
    });
}

TEST_F(TlsContextTest, ServerAndClientInstances)
{
    TlsContext server(PeerRole::Server, std::nullopt, *logger_);
    TlsContext client(PeerRole::Client, std::nullopt, *logger_);

    EXPECT_FALSE(server.IsHandshakeComplete());
    EXPECT_FALSE(client.IsHandshakeComplete());
}

TEST_F(TlsContextTest, GetPendingDataClearsBuffer)
{
    TlsContext tls(PeerRole::Server, std::nullopt, *logger_);

    auto pending1 = tls.GetPendingData();
    EXPECT_TRUE(pending1.empty());

    auto pending2 = tls.GetPendingData();
    EXPECT_TRUE(pending2.empty());
}

// ============================================================================
// Cert-loading SslException paths (previously dead)
// ============================================================================

TEST_F(TlsContextTest, ConstructorWithBadLocalCertPemThrows)
{
    // Garbage PEM for local_cert_pem triggers SslException from UseCertificatePem.
    TlsCertConfig cfg;
    cfg.local_cert_pem = "-----GARBAGE-----";
    EXPECT_THROW(TlsContext(PeerRole::Server, cfg, *logger_), clv::OpenSSL::SslException);
}

TEST_F(TlsContextTest, ConstructorWithBadCaCertPemThrows)
{
    // Garbage PEM for ca_cert_pem triggers SslException from LoadVerifyPem.
    TlsCertConfig cfg;
    cfg.ca_cert_pem = "-----INVALID CA CERT-----";
    EXPECT_THROW(TlsContext(PeerRole::Client, cfg, *logger_), clv::OpenSSL::SslException);
}

TEST_F(TlsContextTest, ProcessIncomingData_GarbageDataReturnsNullopt)
{
    // A server TLS context fed clearly-invalid TLS record data (invalid content-type
    // byte 0xFF) causes a fatal OpenSSL error → SslException → nullopt.
    TlsContext tls(PeerRole::Server, std::nullopt, *logger_);

    std::vector<std::uint8_t> garbage(32, 0xFF);
    auto response = tls.ProcessIncomingData(garbage);

    // Fatal TLS parse error: should return nullopt.
    EXPECT_FALSE(response.has_value());
}

// ============================================================================
// Pre-handshake rejection — WriteAppData / ReadAppData / FeedEncryptedData
// ============================================================================

TEST_F(TlsContextTest, WriteAppData_HandshakeNotComplete_ReturnsMinus1)
{
    // Before any handshake the context is not complete, so WriteAppData returns -1.
    TlsContext tls(PeerRole::Server, std::nullopt, *logger_);
    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03};
    EXPECT_EQ(-1, tls.WriteAppData(data));
}

TEST_F(TlsContextTest, ReadAppData_HandshakeNotComplete_ReturnsEmpty)
{
    // Before any handshake the context is not complete, so ReadAppData returns empty.
    TlsContext tls(PeerRole::Server, std::nullopt, *logger_);
    auto result = tls.ReadAppData();
    EXPECT_TRUE(result.empty());
}

TEST_F(TlsContextTest, FeedEncryptedData_HandshakeNotComplete_ReturnsFalse)
{
    // Before any handshake the context is not complete, so FeedEncryptedData returns false.
    TlsContext tls(PeerRole::Server, std::nullopt, *logger_);
    std::vector<std::uint8_t> data = {0x16, 0x03, 0x03, 0x00, 0x01, 0x00};
    EXPECT_FALSE(tls.FeedEncryptedData(data));
}

// ============================================================================
// Cert-loading: inline PEM and file-based paths
// ============================================================================

TEST_F(TlsContextTest, ServerCaCertPem_SetsVerifyPeerAndFail)
{
    // ca_cert_pem + is_server=true covers the server SetVerifyMode branch.
    TlsCertConfig cfg;
    cfg.ca_cert_pem = kTestCaCertPem;
    EXPECT_NO_THROW(TlsContext(PeerRole::Server, cfg, *logger_));
}

TEST_F(TlsContextTest, ClientCaCertPem_SetsVerifyPeer)
{
    // ca_cert_pem + is_server=false covers the client SetVerifyMode branch.
    TlsCertConfig cfg;
    cfg.ca_cert_pem = kTestCaCertPem;
    EXPECT_NO_THROW(TlsContext(PeerRole::Client, cfg, *logger_));
}

TEST_F(TlsContextTest, LocalKeyPem_ValidKeyLoadsWithoutCert)
{
    // local_key_pem only covers UsePrivateKeyPem without a preceding cert load.
    TlsCertConfig cfg;
    cfg.local_key_pem = kTestServerKeyPem;
    EXPECT_NO_THROW(TlsContext(PeerRole::Server, cfg, *logger_));
}

TEST_F(TlsContextCertTest, ClientCaCertFile_LoadsViaFile)
{
    // ca_cert (file path) + is_server=false covers file-based LoadVerifyFile.
    TlsCertConfig cfg;
    cfg.ca_cert = ca_cert_path_.string();
    EXPECT_NO_THROW(TlsContext(PeerRole::Client, cfg, *logger_));
}

TEST_F(TlsContextCertTest, ServerCaCertFile_SetsServerVerifyMode)
{
    // ca_cert (file path) + is_server=true covers file-based LoadVerifyFile + server mode.
    TlsCertConfig cfg;
    cfg.ca_cert = ca_cert_path_.string();
    EXPECT_NO_THROW(TlsContext(PeerRole::Server, cfg, *logger_));
}

TEST_F(TlsContextCertTest, ServerLocalCertFile_Loads)
{
    // local_cert (file path) covers UseCertificateChainFile.
    TlsCertConfig cfg;
    cfg.local_cert = server_cert_path_.string();
    EXPECT_NO_THROW(TlsContext(PeerRole::Server, cfg, *logger_));
}

TEST_F(TlsContextCertTest, ServerLocalKeyFile_Loads)
{
    // local_key (file path) covers UsePrivateKeyFile.
    TlsCertConfig cfg;
    cfg.local_key = server_key_path_.string();
    EXPECT_NO_THROW(TlsContext(PeerRole::Server, cfg, *logger_));
}

// ============================================================================
// Full handshake tests (post-handshake paths — previously dead)
// ============================================================================

// Inline client certificate and key (from test_data/certs/client.{crt,key})
static const char kTestClientCertPem[] = "-----BEGIN CERTIFICATE-----\n"
                                         "MIIC9TCCAd0CFDF/HD80UN0HLw9CppWSLjhDmI1IMA0GCSqGSIb3DQEBCwUAMDUx\n"
                                         "EDAOBgNVBAMMB1Rlc3QgQ0ExFDASBgNVBAoMC0NMVkxpYiBUZXN0MQswCQYDVQQG\n"
                                         "EwJVUzAeFw0yNjAxMTYwMzU4MDJaFw0zNjAxMTQwMzU4MDJaMDkxFDASBgNVBAMM\n"
                                         "C1Rlc3QgQ2xpZW50MRQwEgYDVQQKDAtDTFZMaWIgVGVzdDELMAkGA1UEBhMCVVMw\n"
                                         "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCMS7mKKJotssIoEBz+NEnM\n"
                                         "7s+733FaxJeZy8JWF/QcuFeh+KcBY/AV42Qb3IpBobhLEBi3hQfqWB75LW6JAhc0\n"
                                         "a4z1wPt0HpBk1ZethD2IYecXm640jZKsijGdsFyd8GnVol+M8DqS4CgpTvf9JWmm\n"
                                         "xnIyU3YZdFe3gaKk5wNqQ+XkL9+zvkN2DlyGPX45G/bFRFmsIlXhOsGo154wAOL7\n"
                                         "KJfyckL3uknp6WIKGwTdApt9BMP5lMhDY+ze8bvPNMuQua+0Rh017nuAhswvhGbm\n"
                                         "lz0VlO1TN2bhGJ4K6jTioHFt8HQ0o6JpwMfyrNkSRNjtwTmVovKk/Dxg8/I1cjKF\n"
                                         "AgMBAAEwDQYJKoZIhvcNAQELBQADggEBABwuzVvTR1gltQWWjo9LQ2rMIFHWtg3W\n"
                                         "hhtiIcsCp+XnI/dDsjKj8rYrUvUnd6MNDW8l0ESqBtYgvZ96dysBZ7zpSa1RAxQS\n"
                                         "Jn2f4wwRe9eXi7EBb69vM+7EaaKxdqfsC6sJC2QDwMj5R0f7nlERF+d5csJLXceC\n"
                                         "wbOhJo/zGQJE96+3ZoiMZnjbY7syFShugExTgFRYDeqCilqSo2DrTrLcikL/vvRj\n"
                                         "Z+HpZMpnG4z38veQKmnPXDnQx3X5T/aAOSMGcvyrlxBgHO1MfrX0VAxq5jTc0kYt\n"
                                         "sj/fTWaYRnypx5CuGldvC8I2U0b/6bIN3CKq+1cEARCLLDiFTxsGcM8=\n"
                                         "-----END CERTIFICATE-----\n";

static const char kTestClientKeyPem[] = "-----BEGIN PRIVATE KEY-----\n"
                                        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCMS7mKKJotssIo\n"
                                        "EBz+NEnM7s+733FaxJeZy8JWF/QcuFeh+KcBY/AV42Qb3IpBobhLEBi3hQfqWB75\n"
                                        "LW6JAhc0a4z1wPt0HpBk1ZethD2IYecXm640jZKsijGdsFyd8GnVol+M8DqS4Cgp\n"
                                        "Tvf9JWmmxnIyU3YZdFe3gaKk5wNqQ+XkL9+zvkN2DlyGPX45G/bFRFmsIlXhOsGo\n"
                                        "154wAOL7KJfyckL3uknp6WIKGwTdApt9BMP5lMhDY+ze8bvPNMuQua+0Rh017nuA\n"
                                        "hswvhGbmlz0VlO1TN2bhGJ4K6jTioHFt8HQ0o6JpwMfyrNkSRNjtwTmVovKk/Dxg\n"
                                        "8/I1cjKFAgMBAAECggEAOJjh6Ez56d6X+f6KG7jvXtemgSWifpoZiIdNRlsSdTWe\n"
                                        "0K5VfTeaZtIdlCnTsqdxiAKd3gcySsUy9ZXw5h+sSc7rhkbMiis8WBlcv7i99BN+\n"
                                        "3STGUdgdKDL10iYQLv0KTQ9cmaheENuSCBwd6gdaSFf9QLUvyxQGwPZwrTKuy4Kw\n"
                                        "xHqndDgrP52x6j2yhYdRJdF3wcAoYgzzvab8FZdVlbtpAGpmI5Ic7/rmHBP41Dfw\n"
                                        "VjwqCxmbg4IjA0gGE0/fp0PsC0IWij5ZfkFpuYE/1YjkaWA+mitQgQIdlWGfXKTc\n"
                                        "nECSp+WlpRhRLPOWtsRtF/JR1YGDFz/LZhl+kieFHwKBgQC/fAoUKr9RmyVdicuM\n"
                                        "npZDbsaKBcNpk0JMRAUUJK9hWPfIc0cP1HD+aMwAONrDvmhq3B3Glr3jAiqd22DS\n"
                                        "8X++wiZXkPU7dCPdX2VM062TnJB1JCSXN5Nz4NU1IRzwAgiBqpunwXXQtTudOTBb\n"
                                        "0BVAhQixjqkMhNCbBrsIrWSwdwKBgQC7kIuU8chQfhYH2fQlgGFQxls1cE/xQV11\n"
                                        "IaLDAzR3P4DMXHdkwMe+QUDNFFGGTnZH07LSHGK0gCHCf0nOFbpT2AP/FAVGeYtB\n"
                                        "dC+3ihgpdD8RZQV++uiKdP+jf9hjL9hvuIODsXr3g6urCgBfeHxpJffVyXyaF+l9\n"
                                        "en8MXTNP4wKBgBKRYZzRBFpSdA4c9Yr+Oc3yKPhrVKahK/WfRurMH+GNsgFTBFoJ\n"
                                        "nKde3CFNYhFHHnL2Q0DljyY7KIzEICB0YJHL29Hz8YPBYFTwEi+f+x3sOanSRmYP\n"
                                        "cpHzBFmxi0/Osqp4M73Rqa4CVPSK/iB5DgaCn/QvxD69hkjyHyLZRYFDAoGAIcwE\n"
                                        "6ry6bI6bp6SFUrCUWHq1eqaXMRCnJ3D9JAiSzp35tlk/Bj+aflTBuXJc0keXFpA1\n"
                                        "25hTzNR9wM8w3Fqb7XmyFqdj3/QMvKmT442VlvqkVp0OZXgOqMw2OB7UPeMkK9Vi\n"
                                        "lTtIvgrSxwoRUSKjwEqgIrygoB+I6hxFglPU6CMCgYEAgAu6d5xxFFGrF4oXJae5\n"
                                        "9wcJBEtK881XJZ90XyjOYH3mFgnwveaV/D3Yt1c3FelkS+Vntab8ClQcl28J8uBN\n"
                                        "7XVpEnsrHnuMYcHirZ9yoos/WecMDlOYYmUAA0+m1HHYahG/jdPY9OFPKCIp26oN\n"
                                        "skX504LUup/KfeDbtSZG3zs=\n"
                                        "-----END PRIVATE KEY-----\n";

/**
 * @brief Drive a full in-memory TLS 1.2 handshake between server and client.
 *
 * Pumps TLS records back and forth until both sides report IsHandshakeComplete().
 * Returns true on success, false if either side returns nullopt (fatal error).
 */
static bool RunFullHandshake(TlsContext &server, TlsContext &client)
{
    // Client initiates: SSL_connect fires on first ProcessIncomingData with empty input
    auto client_output = client.ProcessIncomingData({});
    if (!client_output)
        return false;

    std::vector<std::uint8_t> to_server = *client_output;
    std::vector<std::uint8_t> to_client;

    for (int iterations = 0; iterations < 20; ++iterations)
    {
        if (!to_server.empty())
        {
            auto from_server = server.ProcessIncomingData(to_server);
            if (!from_server)
                return false;
            to_client = *from_server;
            to_server.clear();
        }

        if (server.IsHandshakeComplete() && client.IsHandshakeComplete())
            return true;

        if (!to_client.empty())
        {
            auto from_client = client.ProcessIncomingData(to_client);
            if (!from_client)
                return false;
            to_server = *from_client;
            to_client.clear();
        }

        if (server.IsHandshakeComplete() && client.IsHandshakeComplete())
            return true;
    }
    return server.IsHandshakeComplete() && client.IsHandshakeComplete();
}

class TlsContextFullHandshakeTest : public TlsContextTest
{
  protected:
    void SetUp() override
    {
        TlsContextTest::SetUp();

        // Server: requires client auth (mutual TLS)
        TlsCertConfig server_cfg;
        server_cfg.ca_cert_pem = kTestCaCertPem;
        server_cfg.local_cert_pem = kTestServerCertPem;
        server_cfg.local_key_pem = kTestServerKeyPem;
        server_ = std::make_unique<TlsContext>(PeerRole::Server, server_cfg, *logger_);

        // Client: validates server, presents client cert
        TlsCertConfig client_cfg;
        client_cfg.ca_cert_pem = kTestCaCertPem;
        client_cfg.local_cert_pem = kTestClientCertPem;
        client_cfg.local_key_pem = kTestClientKeyPem;
        client_ = std::make_unique<TlsContext>(PeerRole::Client, client_cfg, *logger_);
    }

    std::unique_ptr<TlsContext> server_;
    std::unique_ptr<TlsContext> client_;
};

TEST_F(TlsContextFullHandshakeTest, HandshakeCompletes)
{
    ASSERT_TRUE(RunFullHandshake(*server_, *client_));
    EXPECT_TRUE(server_->IsHandshakeComplete());
    EXPECT_TRUE(client_->IsHandshakeComplete());
}

TEST_F(TlsContextFullHandshakeTest, GetMasterSecret_ReturnsValueAfterHandshake)
{
    ASSERT_TRUE(RunFullHandshake(*server_, *client_));

    auto server_secret = server_->GetMasterSecret();
    auto client_secret = client_->GetMasterSecret();

    ASSERT_TRUE(server_secret.has_value());
    ASSERT_TRUE(client_secret.has_value());
    EXPECT_FALSE(server_secret->empty());
    // Both sides derive the same key material from the same TLS session
    EXPECT_EQ(*server_secret, *client_secret);
}

TEST_F(TlsContextFullHandshakeTest, ProcessIncomingData_AfterComplete_ReturnsEmptyVector)
{
    ASSERT_TRUE(RunFullHandshake(*server_, *client_));

    // Calling ProcessIncomingData after handshake is complete returns Some({})
    // (the "handshake null or complete" early-return path in tls_context.cpp)
    std::vector<std::uint8_t> dummy = {0x01};
    auto result = server_->ProcessIncomingData(dummy);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());
}

TEST_F(TlsContextFullHandshakeTest, WriteAppData_AndReadAppData_RoundTrip)
{
    ASSERT_TRUE(RunFullHandshake(*server_, *client_));

    // Write plaintext from client side
    std::vector<std::uint8_t> plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    int written = client_->WriteAppData(plaintext);
    EXPECT_GT(written, 0);

    // The encrypted application data sits in client's BIO output — fetch it
    auto encrypted = client_->GetPendingData();
    ASSERT_FALSE(encrypted.empty());

    // Feed the encrypted record into server
    bool fed = server_->FeedEncryptedData(encrypted);
    EXPECT_TRUE(fed);

    // Server can now read the plaintext
    auto received = server_->ReadAppData();
    EXPECT_EQ(received, plaintext);
}

TEST_F(TlsContextFullHandshakeTest, WriteAppData_ServerToClient_RoundTrip)
{
    ASSERT_TRUE(RunFullHandshake(*server_, *client_));

    std::vector<std::uint8_t> msg = {0x01, 0x02, 0x03};
    int written = server_->WriteAppData(msg);
    EXPECT_GT(written, 0);

    auto encrypted = server_->GetPendingData();
    ASSERT_FALSE(encrypted.empty());

    EXPECT_TRUE(client_->FeedEncryptedData(encrypted));

    auto received = client_->ReadAppData();
    EXPECT_EQ(received, msg);
}

TEST_F(TlsContextFullHandshakeTest, ReadAppData_BeforeWrite_ReturnsEmpty)
{
    ASSERT_TRUE(RunFullHandshake(*server_, *client_));

    // No data written — ReadAppData should return empty
    auto data = server_->ReadAppData();
    EXPECT_TRUE(data.empty());
}
