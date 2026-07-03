// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/crypto_log.h"
#include "openvpn/crypto_algorithms.h"
#include "openvpn/crypto_context.h"
#include "openvpn/data_v2_wire.h"
#include "openvpn/crypto_context_limits.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>
#include <thread>
#include <vector>

namespace clv::vpn::openvpn::test {

class CryptoContextLimitsTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        logger_ = std::make_unique<spdlog::logger>("test_limits", null_sink);
        channel_.emplace(*logger_);
    }

    static EncryptionKey MakeAes128GcmKey()
    {
        EncryptionKey key;
        key.cipher_algorithm = CipherAlgorithm::AES_128_GCM;
        key.cipher_key.assign(16, 0xAB);
        key.cipher_iv.assign(8, 0xCD);
        key.hmac_algorithm = HmacAlgorithm::NONE;
        key.is_valid = true;
        return key;
    }

    static EncryptionKey MakeChaChaKey()
    {
        EncryptionKey key;
        key.cipher_algorithm = CipherAlgorithm::CHACHA20_POLY1305;
        key.cipher_key.assign(32, 0x11);
        key.cipher_iv.assign(8, 0x22);
        key.hmac_algorithm = HmacAlgorithm::NONE;
        key.is_valid = true;
        return key;
    }

    void InstallAesKeys(std::uint8_t key_id = 0)
    {
        auto key = MakeAes128GcmKey();
        channel_->InstallNewKeys(key, key, key_id);
    }

    std::optional<CryptoContext> channel_;
    std::unique_ptr<spdlog::logger> logger_;
};

TEST_F(CryptoContextLimitsTest, PacketIdWrapTriggerConstant)
{
    EXPECT_EQ(0xFF000000u, kPacketIdWrapTrigger);
    EXPECT_LT(0xFEFFFFFFu, kPacketIdWrapTrigger);
}

TEST_F(CryptoContextLimitsTest, GcmUsageThresholdRequestsRekey)
{
    LegacyAeadUsageTracker usage;
    const std::size_t chunk = kLegacyAeadMaxPlaintextBytes;
    const auto per_encrypt = LegacyAeadUsageForEncrypt(chunk).Total();

    while (usage.TotalUsage() + per_encrypt < kLegacyAeadUsageRenegThreshold)
        usage.RecordEncrypt(chunk);

    EXPECT_FALSE(usage.NeedsReneg());
    usage.RecordEncrypt(chunk);
    EXPECT_TRUE(usage.NeedsReneg());
    EXPECT_FALSE(usage.IsBlocked());
}

TEST_F(CryptoContextLimitsTest, GcmUsagePerMaxPacketIsInvocationsPlusBlocks)
{
    const auto delta = LegacyAeadUsageForEncrypt(kLegacyAeadMaxPlaintextBytes);
    EXPECT_EQ(1u, delta.invocations);
    EXPECT_EQ(100u, LegacyAeadPlaintextBlocks(kLegacyAeadMaxPlaintextBytes));
    EXPECT_EQ(1u, LegacyAeadPlaintextBlocks(kLegacyDataV2AadBytes));
    EXPECT_EQ(1u, LegacyAeadPlaintextBlocks(kLegacyDataV2TagBytes));
    EXPECT_EQ(103u, delta.Total());

    LegacyAeadUsage usage{};
    LegacyAeadApplyEncrypt(usage, kLegacyAeadMaxPlaintextBytes);
    EXPECT_EQ(delta.invocations, usage.invocations);
    EXPECT_EQ(delta.blocks, usage.blocks);
    EXPECT_EQ(delta.Total(), usage.Total());
}

TEST_F(CryptoContextLimitsTest, ConcurrentAllocateProducesUniqueIds)
{
    InstallAesKeys();

    constexpr int kThreads = 8;
    constexpr int kPerThread = 1000;
    std::vector<std::uint32_t> ids;
    ids.reserve(static_cast<std::size_t>(kThreads * kPerThread));
    std::mutex ids_mutex;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t)
    {
        threads.emplace_back([this, &ids, &ids_mutex]()
        {
            for (int i = 0; i < kPerThread; ++i)
            {
                auto id = channel_->AllocateOutboundPacketId();
                ASSERT_TRUE(id.has_value());
                std::lock_guard lock(ids_mutex);
                ids.push_back(*id);
            }
        });
    }
    for (auto &th : threads)
        th.join();

    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    EXPECT_EQ(static_cast<std::size_t>(kThreads * kPerThread), ids.size());
    EXPECT_EQ(1u, ids.front());
    EXPECT_EQ(static_cast<std::uint32_t>(kThreads * kPerThread), ids.back());
}

TEST_F(CryptoContextLimitsTest, WrapTriggerBlocksAndRequestsRekey)
{
    InstallAesKeys();

    channel_->SetOutboundPacketIdForTest(0xFEFFFFFFu);
    auto last_id = channel_->AllocateOutboundPacketId();
    ASSERT_TRUE(last_id.has_value());
    EXPECT_EQ(0xFEFFFFFFu, *last_id);
    EXPECT_FALSE(channel_->IsRekeyRequestedForTest());
    EXPECT_FALSE(channel_->IsOutboundEncryptBlocked());

    auto blocked = channel_->AllocateOutboundPacketId();
    EXPECT_FALSE(blocked.has_value());
    EXPECT_TRUE(channel_->IsRekeyRequestedForTest());
    EXPECT_TRUE(channel_->IsOutboundEncryptBlocked());
    EXPECT_TRUE(channel_->TakeRekeyRequest());
}

TEST_F(CryptoContextLimitsTest, GcmUsageViaCryptoContextRequestsRekey)
{
    InstallAesKeys();

    const std::size_t chunk = kLegacyAeadMaxPlaintextBytes;
    const auto per_encrypt = LegacyAeadUsageForEncrypt(chunk).Total();
    const auto below_threshold = kLegacyAeadUsageRenegThreshold - per_encrypt;
    const auto invocations = below_threshold / 2;
    const auto blocks = below_threshold - invocations;

    channel_->SetAeadUsageForTest(blocks, invocations);
    EXPECT_FALSE(channel_->IsRekeyRequestedForTest());

    channel_->RecordOutboundEncrypt(chunk, CipherAlgorithm::AES_128_GCM);
    EXPECT_TRUE(channel_->IsRekeyRequestedForTest());
    EXPECT_FALSE(channel_->IsOutboundEncryptBlocked());
    EXPECT_TRUE(channel_->TakeRekeyRequest());
}

TEST_F(CryptoContextLimitsTest, GcmHardLimitBlocksEncrypt)
{
    InstallAesKeys();

    const auto delta = LegacyAeadUsageForEncrypt(1);
    const auto limit_minus_delta = kLegacyAeadUsageLimit - delta.Total();
    channel_->SetAeadUsageForTest(limit_minus_delta / 2,
                                  limit_minus_delta - (limit_minus_delta / 2));

    channel_->RecordOutboundEncrypt(1, CipherAlgorithm::AES_128_GCM);
    EXPECT_TRUE(channel_->IsOutboundEncryptBlocked());
    EXPECT_FALSE(channel_->AllocateOutboundPacketId().has_value());

    std::vector<std::uint8_t> buf(kDataV2Overhead + 16, 0);
    EXPECT_EQ(channel_->EncryptPacketInPlace(buf, 16, SessionId{1}), 0u);
}

TEST_F(CryptoContextLimitsTest, RekeyClearsBlockAndPreservesCounterBelowWrap)
{
    InstallAesKeys(0);

    for (int i = 0; i < 10; ++i)
    {
        auto id = channel_->AllocateOutboundPacketId();
        ASSERT_TRUE(id.has_value());
    }
    EXPECT_EQ(11u, channel_->GetOutboundPacketId());

    auto key = MakeAes128GcmKey();
    channel_->InstallNewKeys(key, key, 1);

    EXPECT_FALSE(channel_->IsOutboundEncryptBlocked());
    EXPECT_FALSE(channel_->IsRekeyRequestedForTest());
    EXPECT_EQ(11u, channel_->GetOutboundPacketId());

    auto id = channel_->AllocateOutboundPacketId();
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(11u, *id);
    EXPECT_EQ(12u, channel_->GetOutboundPacketId());
}

TEST_F(CryptoContextLimitsTest, RekeyAfterWrapResetsCounterAndUnblocks)
{
    InstallAesKeys(0);

    channel_->SetOutboundPacketIdForTest(kPacketIdWrapTrigger);
    EXPECT_FALSE(channel_->AllocateOutboundPacketId().has_value());
    EXPECT_TRUE(channel_->IsOutboundEncryptBlocked());

    auto key = MakeAes128GcmKey();
    channel_->InstallNewKeys(key, key, 1);

    EXPECT_FALSE(channel_->IsOutboundEncryptBlocked());
    EXPECT_EQ(1u, channel_->GetOutboundPacketId());

    auto id = channel_->AllocateOutboundPacketId();
    ASSERT_TRUE(id.has_value());
    EXPECT_EQ(1u, *id);
}

TEST_F(CryptoContextLimitsTest, ChaChaUsageDoesNotRequestRekey)
{
    auto key = MakeChaChaKey();
    channel_->InstallNewKeys(key, key, 0);

    channel_->SetAeadUsageForTest(kLegacyAeadUsageLimit / 2, kLegacyAeadUsageLimit / 2);
    channel_->RecordOutboundEncrypt(kLegacyAeadMaxPlaintextBytes, CipherAlgorithm::CHACHA20_POLY1305);

    EXPECT_FALSE(channel_->IsRekeyRequestedForTest());
    EXPECT_FALSE(channel_->IsOutboundEncryptBlocked());
    EXPECT_TRUE(channel_->AllocateOutboundPacketId().has_value());
}

TEST(KeyMaterialFingerprint, EmptyMaterialReturnsNone)
{
    EXPECT_EQ("none", KeyMaterialFingerprint(std::span<const std::uint8_t>{}));
}

TEST(KeyMaterialFingerprint, DistinctKeysDistinctFingerprints)
{
    std::vector<std::uint8_t> a(16, 0xAB);
    std::vector<std::uint8_t> b(16, 0xCD);
    EXPECT_NE(KeyMaterialFingerprint(a), KeyMaterialFingerprint(b));
    EXPECT_EQ(8u, KeyMaterialFingerprint(a).size());
}

} // namespace clv::vpn::openvpn::test
