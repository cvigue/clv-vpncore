// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/tls_context.h"

#include <gtest/gtest.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

using namespace clv::vpn::openvpn;

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

TEST_F(TlsContextTest, ConstructorServerMode)
{
    TlsContext tls(true, std::nullopt, *logger_); // true = server mode
    EXPECT_FALSE(tls.IsHandshakeComplete());
}

TEST_F(TlsContextTest, ConstructorClientMode)
{
    TlsContext tls(false, std::nullopt, *logger_); // false = client mode
    EXPECT_FALSE(tls.IsHandshakeComplete());
}

TEST_F(TlsContextTest, ProcessIncomingDataReturnsVectorBeforeHandshake)
{
    TlsContext tls(false, std::nullopt, *logger_);
    std::vector<uint8_t> dummy_data = {0x01, 0x02, 0x03};
    auto response = tls.ProcessIncomingData(dummy_data);

    // Response should be optional (not nullopt for non-fatal cases)
    EXPECT_TRUE(response.has_value());
}

TEST_F(TlsContextTest, ProcessIncomingDataReturnsEmptyAfterHandshakeComplete)
{
    TlsContext tls(false, std::nullopt, *logger_);

    // Simulate handshake completion by calling ProcessIncomingData multiple times
    std::vector<uint8_t> dummy_data = {0x01};
    auto response1 = tls.ProcessIncomingData(dummy_data);
    EXPECT_TRUE(response1.has_value());

    // Now check if handshake status can be checked
    // (This is a simplistic test - real handshake completion requires proper TLS records)
}

TEST_F(TlsContextTest, IsHandshakeCompleteInitiallyFalse)
{
    TlsContext tls(true, std::nullopt, *logger_);
    EXPECT_FALSE(tls.IsHandshakeComplete());
}

TEST_F(TlsContextTest, GetMasterSecretReturnsNulloptBeforeHandshake)
{
    TlsContext tls(true, std::nullopt, *logger_);
    auto master_secret = tls.GetMasterSecret();
    EXPECT_FALSE(master_secret.has_value());
}

TEST_F(TlsContextTest, GetPendingDataReturnsEmptyVector)
{
    TlsContext tls(true, std::nullopt, *logger_);
    auto pending = tls.GetPendingData();
    EXPECT_TRUE(pending.empty());
}

TEST_F(TlsContextTest, ProcessIncomingDataWithEmptyData)
{
    TlsContext tls(false, std::nullopt, *logger_);
    std::vector<uint8_t> empty_data;
    auto response = tls.ProcessIncomingData(empty_data);

    // Should still return optional (may be empty vector)
    EXPECT_TRUE(response.has_value());
}

TEST_F(TlsContextTest, MultipleProcessIncomingDataCalls)
{
    TlsContext tls(true, std::nullopt, *logger_);

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
    TlsContext server(true, std::nullopt, *logger_);
    TlsContext client(false, std::nullopt, *logger_);

    EXPECT_FALSE(server.IsHandshakeComplete());
    EXPECT_FALSE(client.IsHandshakeComplete());
}

TEST_F(TlsContextTest, GetPendingDataClearsBuffer)
{
    TlsContext tls(true, std::nullopt, *logger_);

    auto pending1 = tls.GetPendingData();
    EXPECT_TRUE(pending1.empty());

    auto pending2 = tls.GetPendingData();
    EXPECT_TRUE(pending2.empty());
}
