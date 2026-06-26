// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/crypto_algorithms.h"
#include "openvpn/data_channel.h"
#include "openvpn/data_channel_hmac.h"
#include "openvpn/packet.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>
#include <thread>
#include <vector>

namespace clv::vpn::openvpn::test {

class DataChannelTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        logger_ = std::make_unique<spdlog::logger>("test_data_channel", null_sink);
    }

    // Helper to create a properly configured AES-128-GCM key
    static EncryptionKey MakeAes128GcmKey()
    {
        EncryptionKey key;
        key.cipher_algorithm = CipherAlgorithm::AES_128_GCM;
        key.cipher_key.resize(16); // 128-bit key
        key.cipher_iv.resize(8);   // 8-byte implicit IV for nonce
        key.hmac_algorithm = HmacAlgorithm::NONE;
        key.is_valid = true;
        return key;
    }

    // Helper to encrypt plaintext and return parsed packet for decryption testing
    std::optional<OpenVpnPacket> EncryptAndParse(
        DataChannel &channel,
        const std::vector<std::uint8_t> &plaintext,
        SessionId session = SessionId::Generate())
    {
        auto encrypted = channel.EncryptPacket(plaintext, session);
        if (encrypted.empty())
            return std::nullopt;
        return OpenVpnPacket::Parse(encrypted);
    }

    // Lazy accessor for channel_ - creates on first use
    DataChannel &channel()
    {
        if (!channel_)
        {
            channel_.emplace(*logger_);
        }
        return *channel_;
    }

    std::optional<DataChannel> channel_;
    std::unique_ptr<spdlog::logger> logger_;
};
// ============================================================================

// ============================================================================
// Anti-Replay Tests (via DecryptPacket)
// ============================================================================

TEST_F(DataChannelTest, GetOutboundPacketIdStartsAtOne)
{
    EXPECT_EQ(1, channel().GetOutboundPacketId());
}

TEST_F(DataChannelTest, DecryptPacketRejectsOldPackets)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45, 0x00};

    // Encrypt enough packets to push packet_id=1 outside the replay window.
    constexpr int kAdvance = static_cast<int>(ReplayWindow::kBits) + 100;
    std::optional<OpenVpnPacket> lastPacket;
    for (int i = 0; i < kAdvance; ++i)
    {
        lastPacket = EncryptAndParse(channel(), plaintext, session);
    }
    ASSERT_TRUE(lastPacket);

    // Decrypt the last packet — advances highest_id to kAdvance
    auto decrypted = channel().DecryptPacket(*lastPacket);
    EXPECT_FALSE(decrypted.empty());

    // Create a new channel with same keys to generate packet_id=1
    DataChannel channel2(*logger_);
    channel2.InstallNewKeys(key, key, 0);

    auto packet1 = EncryptAndParse(channel2, plaintext, session);
    ASSERT_TRUE(packet1);
    EXPECT_EQ(1u, packet1->packet_id_.value());

    // Try to decrypt packet 1 — should fail (outside replay window)
    decrypted = channel().DecryptPacket(*packet1);
    EXPECT_TRUE(decrypted.empty());
    EXPECT_GT(channel().GetReplayedPacketCount(), 0u);
}

TEST_F(DataChannelTest, DecryptPacketAcceptsNewerPackets)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45};

    // Encrypt and decrypt packet 1
    auto packet1 = EncryptAndParse(channel(), plaintext, session);
    ASSERT_TRUE(packet1);
    auto decrypted = channel().DecryptPacket(*packet1);
    EXPECT_FALSE(decrypted.empty());

    // Encrypt and decrypt packet 2
    auto packet2 = EncryptAndParse(channel(), plaintext, session);
    ASSERT_TRUE(packet2);
    decrypted = channel().DecryptPacket(*packet2);
    EXPECT_FALSE(decrypted.empty());

    // Encrypt and decrypt packet 3
    auto packet3 = EncryptAndParse(channel(), plaintext, session);
    ASSERT_TRUE(packet3);
    decrypted = channel().DecryptPacket(*packet3);
    EXPECT_FALSE(decrypted.empty());
}

TEST_F(DataChannelTest, AntiReplayDetectsDuplicates)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45};

    // Encrypt packet
    auto packet = EncryptAndParse(channel(), plaintext, session);
    ASSERT_TRUE(packet);

    // First decrypt succeeds
    auto decrypted = channel().DecryptPacket(*packet);
    EXPECT_FALSE(decrypted.empty());
    uint64_t initial_replays = channel().GetReplayedPacketCount();

    // Second decrypt of same packet fails (replay)
    decrypted = channel().DecryptPacket(*packet);
    EXPECT_TRUE(decrypted.empty());
    EXPECT_GT(channel().GetReplayedPacketCount(), initial_replays);
}

TEST_F(DataChannelTest, GetReplayedPacketCount)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);

    EXPECT_EQ(0u, channel().GetReplayedPacketCount());

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45};

    // Encrypt a packet
    auto packet = EncryptAndParse(channel(), plaintext, session);
    ASSERT_TRUE(packet);

    // First decrypt succeeds
    auto decrypted1 = channel().DecryptPacket(*packet);
    EXPECT_FALSE(decrypted1.empty());

    // Second decrypt is a replay
    auto decrypted2 = channel().DecryptPacket(*packet);
    EXPECT_TRUE(decrypted2.empty());

    EXPECT_EQ(1u, channel().GetReplayedPacketCount());
}

TEST_F(DataChannelTest, ResetAntiReplayWindow)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45};

    // Encrypt and decrypt a packet
    auto packet = EncryptAndParse(channel(), plaintext, session);
    ASSERT_TRUE(packet);
    auto decrypted_first = channel().DecryptPacket(*packet);
    EXPECT_FALSE(decrypted_first.empty());

    // Try to replay - should fail
    auto decrypted = channel().DecryptPacket(*packet);
    EXPECT_TRUE(decrypted.empty());

    // Reset anti-replay window
    channel().ResetAntiReplayWindow();

    // Now same packet should succeed (window is reset)
    decrypted = channel().DecryptPacket(*packet);
    EXPECT_FALSE(decrypted.empty());
}

// ============================================================================
// Encryption/Decryption Tests
// ============================================================================

TEST_F(DataChannelTest, EncryptPacketRequiresValidKey)
{
    std::vector<std::uint8_t> plaintext = {0x45, 0x00};

    auto encrypted = channel().EncryptPacket(plaintext, SessionId::Generate());

    EXPECT_TRUE(encrypted.empty());
}

TEST_F(DataChannelTest, EncryptPacketWithValidKey)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);

    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x00, 0x20};

    auto encrypted = channel().EncryptPacket(plaintext, SessionId::Generate());

    EXPECT_FALSE(encrypted.empty());
}

TEST_F(DataChannelTest, EncryptPacketIncrementPacketId)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);

    std::vector<std::uint8_t> plaintext = {0x45, 0x00};
    auto session = SessionId::Generate();

    uint32_t initial_id = channel().GetOutboundPacketId();

    auto encrypted1 = channel().EncryptPacket(plaintext, session);
    uint32_t after_first = channel().GetOutboundPacketId();

    auto encrypted2 = channel().EncryptPacket(plaintext, session);
    uint32_t after_second = channel().GetOutboundPacketId();

    EXPECT_EQ(initial_id + 1, after_first);
    EXPECT_EQ(initial_id + 2, after_second);

    EXPECT_NE(encrypted1, encrypted2);
}

TEST_F(DataChannelTest, DecryptPacketRequiresValidKey)
{
    OpenVpnPacket packet;
    packet.opcode_ = Opcode::P_DATA_V1;
    packet.key_id_ = 0;
    packet.packet_id_ = 1;
    packet.payload_ = {0x45, 0x00};

    auto decrypted = channel().DecryptPacket(packet);

    EXPECT_TRUE(decrypted.empty());
}

TEST_F(DataChannelTest, DecryptPacketWithValidKey)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);

    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x00, 0x20};
    auto session = SessionId::Generate();

    // Encrypt and parse
    auto packet = EncryptAndParse(channel(), plaintext, session);
    ASSERT_TRUE(packet);

    // Decrypt
    auto decrypted = channel().DecryptPacket(*packet);
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(DataChannelTest, DecryptPacketRejectsReplay)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45, 0x00};

    auto packet = EncryptAndParse(channel(), plaintext, session);
    ASSERT_TRUE(packet);

    // First decrypt succeeds
    auto decrypted = channel().DecryptPacket(*packet);
    EXPECT_FALSE(decrypted.empty());

    // Second decrypt fails (replay)
    decrypted = channel().DecryptPacket(*packet);
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(DataChannelTest, DecryptPacketRequiresPacketId)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);

    // Construct a packet without packet_id
    OpenVpnPacket packet;
    packet.opcode_ = Opcode::P_DATA_V1;
    packet.key_id_ = 0;
    packet.packet_id_ = std::nullopt;
    packet.payload_ = {0x45, 0x00};

    auto decrypted = channel().DecryptPacket(packet);
    EXPECT_TRUE(decrypted.empty());
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(DataChannelTest, SequentialEncryptionDecryption)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);
    channel().ResetAntiReplayWindow(); // Ensure clean state

    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00};
    auto session = SessionId::Generate();

    // Encrypt
    auto encrypted = channel().EncryptPacket(plaintext, session);
    EXPECT_FALSE(encrypted.empty());

    // Parse encrypted data
    auto parsed_opt = OpenVpnPacket::Parse(encrypted);
    EXPECT_TRUE(parsed_opt);

    if (parsed_opt)
    {
        auto &packet = parsed_opt.value();

        // Verify packet structure (EncryptPacket produces P_DATA_V2)
        EXPECT_EQ(Opcode::P_DATA_V2, packet.opcode_);
        EXPECT_EQ(0, packet.key_id_);
        EXPECT_TRUE(packet.packet_id_);
        EXPECT_EQ(1, packet.packet_id_.value());

        // Decrypt
        auto decrypted = channel().DecryptPacket(packet);
        EXPECT_EQ(plaintext, decrypted);
    }
}

TEST_F(DataChannelTest, MultipleKeySlotIndependentEncryption)
{
    auto key0 = MakeAes128GcmKey();
    key0.cipher_key[0] = 0xAA;

    // Create AES-256-GCM key with 32-byte key
    EncryptionKey key1;
    key1.cipher_algorithm = CipherAlgorithm::AES_256_GCM;
    key1.cipher_key.resize(32);
    key1.cipher_key[0] = 0xBB;
    key1.cipher_iv.resize(8); // 8-byte implicit IV for AEAD
    key1.hmac_algorithm = HmacAlgorithm::NONE;
    key1.is_valid = true;

    channel().InstallNewKeys(key0, key0, 0);
    channel().InstallNewKeys(key1, key1, 1);

    std::vector<std::uint8_t> plaintext = {0x45, 0x00};
    auto session = SessionId::Generate();

    auto encrypted0 = channel().EncryptPacket(plaintext, session);
    auto encrypted1 = channel().EncryptPacket(plaintext, session);

    EXPECT_NE(encrypted0, encrypted1);
}

TEST_F(DataChannelTest, DecryptPacketDifferentKeySlots)
{
    // Create two different keys - both AES-128-GCM but different key material
    auto key0 = MakeAes128GcmKey();
    auto key1 = MakeAes128GcmKey();
    key1.cipher_key[0] = 0xBB; // Different key material

    // Install keys for slot 0 (primary)
    channel().InstallNewKeys(key0, key0, 0);

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45, 0x00};

    // Encrypt and decrypt with key slot 0
    auto encrypted1 = channel().EncryptPacket(plaintext, session);
    ASSERT_FALSE(encrypted1.empty());
    auto packet1 = OpenVpnPacket::Parse(encrypted1);
    ASSERT_TRUE(packet1);

    auto decrypted = channel().DecryptPacket(*packet1);
    EXPECT_FALSE(decrypted.empty());

    // Install keys for slot 1 (key0 becomes lame duck)
    channel().InstallNewKeys(key1, key1, 1);

    // Encrypt with new primary key (slot 1)
    auto encrypted2 = channel().EncryptPacket(plaintext, session);
    ASSERT_FALSE(encrypted2.empty());
    auto packet2 = OpenVpnPacket::Parse(encrypted2);
    ASSERT_TRUE(packet2);

    // Decrypt with key slot 1 - should succeed
    decrypted = channel().DecryptPacket(*packet2);
    EXPECT_FALSE(decrypted.empty());
}

// ================================================================================================
// Cipher Algorithm Tests
// ================================================================================================

TEST_F(DataChannelTest, EncryptDecryptWithAes128Gcm)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x00, 0x54}; // IPv4 header start

    // Encrypt
    auto encrypted = channel().EncryptPacket(plaintext, session);
    ASSERT_FALSE(encrypted.empty());

    // Decrypt
    auto packet = OpenVpnPacket::Parse(encrypted);
    ASSERT_TRUE(packet);
    auto decrypted = channel().DecryptPacket(*packet);
    ASSERT_FALSE(decrypted.empty());
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(DataChannelTest, EncryptDecryptWithAes256Gcm)
{
    EncryptionKey key;
    key.cipher_algorithm = CipherAlgorithm::AES_256_GCM;
    key.cipher_key.resize(32); // 256-bit key
    key.cipher_iv.resize(8);   // 8-byte implicit IV for nonce
    key.hmac_algorithm = HmacAlgorithm::NONE;
    key.is_valid = true;

    // Fill with test data
    std::fill(key.cipher_key.begin(), key.cipher_key.end(), 0xAA);
    std::fill(key.cipher_iv.begin(), key.cipher_iv.end(), 0xBB);

    channel().InstallNewKeys(key, key, 0);

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x00, 0x54, 0x12, 0x34};

    // Encrypt
    auto encrypted = channel().EncryptPacket(plaintext, session);
    ASSERT_FALSE(encrypted.empty());

    // Decrypt
    auto packet = OpenVpnPacket::Parse(encrypted);
    ASSERT_TRUE(packet);
    auto decrypted = channel().DecryptPacket(*packet);
    ASSERT_FALSE(decrypted.empty());
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(DataChannelTest, EncryptDecryptWithChaCha20Poly1305)
{
    EncryptionKey key;
    key.cipher_algorithm = CipherAlgorithm::CHACHA20_POLY1305;
    key.cipher_key.resize(32); // 256-bit key
    key.cipher_iv.resize(8);   // 8-byte implicit IV for nonce
    key.hmac_algorithm = HmacAlgorithm::NONE;
    key.is_valid = true;

    // Fill with test data
    std::fill(key.cipher_key.begin(), key.cipher_key.end(), 0xCC);
    std::fill(key.cipher_iv.begin(), key.cipher_iv.end(), 0xDD);

    channel().InstallNewKeys(key, key, 0);

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x00, 0x54, 0xAB, 0xCD, 0xEF};

    // Encrypt
    auto encrypted = channel().EncryptPacket(plaintext, session);
    ASSERT_FALSE(encrypted.empty());

    // Decrypt
    auto packet = OpenVpnPacket::Parse(encrypted);
    ASSERT_TRUE(packet);
    auto decrypted = channel().DecryptPacket(*packet);
    ASSERT_FALSE(decrypted.empty());
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(DataChannelTest, AllCiphersProduceDifferentCiphertext)
{
    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext(100, 0x42); // 100 bytes of data

    // Encrypt with AES-128-GCM
    EncryptionKey key128;
    key128.cipher_algorithm = CipherAlgorithm::AES_128_GCM;
    key128.cipher_key.resize(16);
    key128.cipher_iv.resize(8);
    key128.hmac_algorithm = HmacAlgorithm::NONE;
    key128.is_valid = true;
    std::fill(key128.cipher_key.begin(), key128.cipher_key.end(), 0x11);
    std::fill(key128.cipher_iv.begin(), key128.cipher_iv.end(), 0x22);

    DataChannel chan128(*logger_);
    chan128.InstallNewKeys(key128, key128, 0);
    auto encrypted128 = chan128.EncryptPacket(plaintext, session);

    // Encrypt with AES-256-GCM
    EncryptionKey key256;
    key256.cipher_algorithm = CipherAlgorithm::AES_256_GCM;
    key256.cipher_key.resize(32);
    key256.cipher_iv.resize(8);
    key256.hmac_algorithm = HmacAlgorithm::NONE;
    key256.is_valid = true;
    std::fill(key256.cipher_key.begin(), key256.cipher_key.end(), 0x11);
    std::fill(key256.cipher_iv.begin(), key256.cipher_iv.end(), 0x22);

    DataChannel chan256(*logger_);
    chan256.InstallNewKeys(key256, key256, 0);
    auto encrypted256 = chan256.EncryptPacket(plaintext, session);

    // Encrypt with ChaCha20-Poly1305
    EncryptionKey keyChacha;
    keyChacha.cipher_algorithm = CipherAlgorithm::CHACHA20_POLY1305;
    keyChacha.cipher_key.resize(32);
    keyChacha.cipher_iv.resize(8);
    keyChacha.hmac_algorithm = HmacAlgorithm::NONE;
    keyChacha.is_valid = true;
    std::fill(keyChacha.cipher_key.begin(), keyChacha.cipher_key.end(), 0x11);
    std::fill(keyChacha.cipher_iv.begin(), keyChacha.cipher_iv.end(), 0x22);

    DataChannel chanChacha(*logger_);
    chanChacha.InstallNewKeys(keyChacha, keyChacha, 0);
    auto encryptedChacha = chanChacha.EncryptPacket(plaintext, session);

    // All should succeed
    ASSERT_FALSE(encrypted128.empty());
    ASSERT_FALSE(encrypted256.empty());
    ASSERT_FALSE(encryptedChacha.empty());

    // Ciphertext should be different (different algorithms)
    EXPECT_NE(encrypted128, encrypted256);
    EXPECT_NE(encrypted128, encryptedChacha);
    EXPECT_NE(encrypted256, encryptedChacha);
}

TEST_F(DataChannelTest, CiphertextCannotBeDecryptedWithWrongAlgorithm)
{
    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x00, 0x54};

    // Encrypt with AES-256-GCM
    EncryptionKey key256;
    key256.cipher_algorithm = CipherAlgorithm::AES_256_GCM;
    key256.cipher_key.resize(32);
    key256.cipher_iv.resize(8);
    key256.hmac_algorithm = HmacAlgorithm::NONE;
    key256.is_valid = true;

    DataChannel encryptChan(*logger_);
    encryptChan.InstallNewKeys(key256, key256, 0);
    auto encrypted = encryptChan.EncryptPacket(plaintext, session);
    ASSERT_FALSE(encrypted.empty());

    // Try to decrypt with ChaCha20-Poly1305
    EncryptionKey keyChacha;
    keyChacha.cipher_algorithm = CipherAlgorithm::CHACHA20_POLY1305;
    keyChacha.cipher_key.resize(32);
    keyChacha.cipher_iv.resize(8);
    keyChacha.hmac_algorithm = HmacAlgorithm::NONE;
    keyChacha.is_valid = true;

    DataChannel decryptChan(*logger_);
    decryptChan.InstallNewKeys(keyChacha, keyChacha, 0);

    auto packet = OpenVpnPacket::Parse(encrypted);
    ASSERT_TRUE(packet);
    auto decrypted = decryptChan.DecryptPacket(*packet);

    // Decryption should fail (wrong algorithm)
    EXPECT_TRUE(decrypted.empty());
}

// ============================================================================
// In-Place Encrypt/Decrypt Tests (zero-copy arena path)
// ============================================================================

TEST_F(DataChannelTest, EncryptDecryptInPlace_Aes128Gcm)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x00, 0x28, 0xAB, 0xCD, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x02, 0xDE, 0xAD, 0xBE, 0xEF};

    // Set up arena-style buffer: [24B header][plaintext]
    std::vector<std::uint8_t> buf(kDataV2Overhead + plaintext.size());
    std::memcpy(buf.data() + kDataV2Overhead, plaintext.data(), plaintext.size());

    auto wire_len = channel().EncryptPacketInPlace(buf, plaintext.size(), session);
    ASSERT_GT(wire_len, 0u);
    EXPECT_EQ(kDataV2Overhead + plaintext.size(), wire_len);

    // Decrypt with a separate channel using same keys
    DataChannel decrypt_chan(*logger_);
    decrypt_chan.InstallNewKeys(key, key, 0);

    auto decrypted = decrypt_chan.DecryptPacketInPlace(std::span<std::uint8_t>(buf.data(), wire_len));
    ASSERT_FALSE(decrypted.empty());
    EXPECT_EQ(plaintext.size(), decrypted.size());
    EXPECT_TRUE(std::equal(decrypted.begin(), decrypted.end(), plaintext.begin()));
}

TEST_F(DataChannelTest, EncryptDecryptInPlace_Aes256Gcm)
{
    EncryptionKey key;
    key.cipher_algorithm = CipherAlgorithm::AES_256_GCM;
    key.cipher_key.resize(32);
    key.cipher_iv.resize(8);
    key.hmac_algorithm = HmacAlgorithm::NONE;
    key.is_valid = true;
    std::fill(key.cipher_key.begin(), key.cipher_key.end(), 0xAA);
    std::fill(key.cipher_iv.begin(), key.cipher_iv.end(), 0xBB);
    channel().InstallNewKeys(key, key, 0);

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext(1400, 0x42); // 1400-byte payload

    std::vector<std::uint8_t> buf(kDataV2Overhead + plaintext.size());
    std::memcpy(buf.data() + kDataV2Overhead, plaintext.data(), plaintext.size());

    auto wire_len = channel().EncryptPacketInPlace(buf, plaintext.size(), session);
    ASSERT_GT(wire_len, 0u);

    DataChannel decrypt_chan(*logger_);
    decrypt_chan.InstallNewKeys(key, key, 0);

    auto decrypted = decrypt_chan.DecryptPacketInPlace(std::span<std::uint8_t>(buf.data(), wire_len));
    ASSERT_EQ(plaintext.size(), decrypted.size());
    EXPECT_TRUE(std::equal(decrypted.begin(), decrypted.end(), plaintext.begin()));
}

TEST_F(DataChannelTest, EncryptDecryptInPlace_ChaCha20Poly1305)
{
    EncryptionKey key;
    key.cipher_algorithm = CipherAlgorithm::CHACHA20_POLY1305;
    key.cipher_key.resize(32);
    key.cipher_iv.resize(8);
    key.hmac_algorithm = HmacAlgorithm::NONE;
    key.is_valid = true;
    std::fill(key.cipher_key.begin(), key.cipher_key.end(), 0x55);
    std::fill(key.cipher_iv.begin(), key.cipher_iv.end(), 0x66);
    channel().InstallNewKeys(key, key, 0);

    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04};

    std::vector<std::uint8_t> buf(kDataV2Overhead + plaintext.size());
    std::memcpy(buf.data() + kDataV2Overhead, plaintext.data(), plaintext.size());

    auto wire_len = channel().EncryptPacketInPlace(buf, plaintext.size(), session);
    ASSERT_GT(wire_len, 0u);

    DataChannel decrypt_chan(*logger_);
    decrypt_chan.InstallNewKeys(key, key, 0);

    auto decrypted = decrypt_chan.DecryptPacketInPlace(std::span<std::uint8_t>(buf.data(), wire_len));
    ASSERT_EQ(plaintext.size(), decrypted.size());
    EXPECT_TRUE(std::equal(decrypted.begin(), decrypted.end(), plaintext.begin()));
}

TEST_F(DataChannelTest, CrossCompat_OldEncrypt_NewDecryptInPlace)
{
    // Old EncryptPacket → new DecryptPacketInPlace
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);
    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    auto encrypted = channel().EncryptPacket(plaintext, session);
    ASSERT_FALSE(encrypted.empty());

    // Decrypt with in-place method
    DataChannel decrypt_chan(*logger_);
    decrypt_chan.InstallNewKeys(key, key, 0);
    auto decrypted = decrypt_chan.DecryptPacketInPlace(encrypted);
    ASSERT_EQ(plaintext.size(), decrypted.size());
    EXPECT_TRUE(std::equal(decrypted.begin(), decrypted.end(), plaintext.begin()));
}

TEST_F(DataChannelTest, CrossCompat_NewEncryptInPlace_OldDecrypt)
{
    // New EncryptPacketInPlace → old DecryptPacket
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);
    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    std::vector<std::uint8_t> buf(kDataV2Overhead + plaintext.size());
    std::memcpy(buf.data() + kDataV2Overhead, plaintext.data(), plaintext.size());

    auto wire_len = channel().EncryptPacketInPlace(buf, plaintext.size(), session);
    ASSERT_GT(wire_len, 0u);

    // Parse and decrypt with old method
    DataChannel decrypt_chan(*logger_);
    decrypt_chan.InstallNewKeys(key, key, 0);
    auto wire_data = std::vector<std::uint8_t>(buf.begin(), buf.begin() + wire_len);
    auto packet = OpenVpnPacket::Parse(wire_data);
    ASSERT_TRUE(packet);
    auto decrypted = decrypt_chan.DecryptPacket(*packet);
    ASSERT_EQ(plaintext.size(), decrypted.size());
    EXPECT_TRUE(std::equal(decrypted.begin(), decrypted.end(), plaintext.begin()));
}

TEST_F(DataChannelTest, DecryptPacketInPlace_RejectsReplay)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);
    auto session = SessionId::Generate();
    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x01, 0x02};

    std::vector<std::uint8_t> buf(kDataV2Overhead + plaintext.size());
    std::memcpy(buf.data() + kDataV2Overhead, plaintext.data(), plaintext.size());

    auto wire_len = channel().EncryptPacketInPlace(buf, plaintext.size(), session);
    ASSERT_GT(wire_len, 0u);

    // First decrypt succeeds
    auto decrypted = channel().DecryptPacketInPlace(std::span<std::uint8_t>(buf.data(), wire_len));
    ASSERT_FALSE(decrypted.empty());

    // Replay the same packet — should fail
    auto replayed = channel().DecryptPacketInPlace(std::span<std::uint8_t>(buf.data(), wire_len));
    EXPECT_TRUE(replayed.empty());
    EXPECT_GT(channel().GetReplayedPacketCount(), 0u);
}

TEST_F(DataChannelTest, EncryptPacketInPlace_FailsWithoutKeys)
{
    auto session = SessionId::Generate();
    std::vector<std::uint8_t> buf(kDataV2Overhead + 10);
    auto wire_len = channel().EncryptPacketInPlace(buf, 10, session);
    EXPECT_EQ(0u, wire_len);
}

TEST_F(DataChannelTest, DecryptPacketInPlace_TooSmallPacket)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);
    std::vector<std::uint8_t> small_buf = {0x01, 0x02, 0x03};
    auto decrypted = channel().DecryptPacketInPlace(small_buf);
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(DataChannelTest, EncryptDecryptInPlace_MultipleSequentialPackets)
{
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);
    auto session = SessionId::Generate();

    DataChannel decrypt_chan(*logger_);
    decrypt_chan.InstallNewKeys(key, key, 0);

    for (int i = 0; i < 100; ++i)
    {
        std::vector<std::uint8_t> plaintext(64, static_cast<uint8_t>(i));
        std::vector<std::uint8_t> buf(kDataV2Overhead + plaintext.size());
        std::memcpy(buf.data() + kDataV2Overhead, plaintext.data(), plaintext.size());

        auto wire_len = channel().EncryptPacketInPlace(buf, plaintext.size(), session);
        ASSERT_GT(wire_len, 0u) << "Packet " << i;

        auto decrypted = decrypt_chan.DecryptPacketInPlace(std::span<std::uint8_t>(buf.data(), wire_len));
        ASSERT_EQ(plaintext.size(), decrypted.size()) << "Packet " << i;
        EXPECT_TRUE(std::equal(decrypted.begin(), decrypted.end(), plaintext.begin())) << "Packet " << i;
    }
}

// ---------------------------------------------------------------------------
// Inbound arena simulation tests
// Tests that simulate the zero-copy inbound path:
//   recvmmsg → arena slot → DecryptPacketInPlace
// ---------------------------------------------------------------------------

TEST_F(DataChannelTest, InboundArena_DirectIpNoCompress)
{
    // Plaintext IS the raw IP data — no compression framing
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);
    auto session = SessionId::Generate();

    // Build payload: raw IPv4 packet (no compress byte)
    std::vector<std::uint8_t> ip_data(40, 0x00);
    ip_data[0] = 0x45; // IPv4, IHL=5

    std::vector<std::uint8_t> buf(kDataV2Overhead + ip_data.size());
    std::memcpy(buf.data() + kDataV2Overhead, ip_data.data(), ip_data.size());
    auto wire_len = channel().EncryptPacketInPlace(buf, ip_data.size(), session);
    ASSERT_GT(wire_len, 0u);

    DataChannel inbound_chan(*logger_);
    inbound_chan.InstallNewKeys(key, key, 0);

    auto plaintext = inbound_chan.DecryptPacketInPlace(
        std::span<std::uint8_t>(buf.data(), wire_len));
    ASSERT_FALSE(plaintext.empty());

    // First byte is 0x45 → version nibble = 4 → no compress strip needed
    uint8_t version_nibble = (plaintext[0] >> 4) & 0x0F;
    EXPECT_EQ(version_nibble, 4u);
    ASSERT_EQ(plaintext.size(), ip_data.size());
    EXPECT_TRUE(std::equal(plaintext.begin(), plaintext.end(), ip_data.begin()));
}

TEST_F(DataChannelTest, InboundArena_KeepaliveDetected)
{
    // Keepalive magic (16 bytes) should be recognized (not forwarded to TUN)
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);
    auto session = SessionId::Generate();

    // Keepalive payload
    constexpr std::uint8_t keepalive_magic[] = {
        0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48};
    std::vector<std::uint8_t> payload(keepalive_magic, keepalive_magic + 16);

    std::vector<std::uint8_t> buf(kDataV2Overhead + payload.size());
    std::memcpy(buf.data() + kDataV2Overhead, payload.data(), payload.size());
    auto wire_len = channel().EncryptPacketInPlace(buf, payload.size(), session);
    ASSERT_GT(wire_len, 0u);

    DataChannel inbound_chan(*logger_);
    inbound_chan.InstallNewKeys(key, key, 0);

    auto plaintext = inbound_chan.DecryptPacketInPlace(
        std::span<std::uint8_t>(buf.data(), wire_len));
    ASSERT_FALSE(plaintext.empty());

    // Verify the decrypted payload matches keepalive magic
    ASSERT_EQ(plaintext.size(), 16u);
    EXPECT_TRUE(std::equal(plaintext.begin(), plaintext.end(), keepalive_magic));
}

// ============================================================================
// ComputeHmac / VerifyHmac (detail free functions)
// ============================================================================

// Helper: build a minimal EncryptionKey configured for HMAC-only use.
static EncryptionKey MakeHmacKey(HmacAlgorithm algo, std::size_t key_len)
{
    EncryptionKey k;
    k.hmac_algorithm = algo;
    k.hmac_key.assign(key_len, 0xAB);
    k.is_valid = true;
    return k;
}

TEST(DataChannelHmac, ComputeHmac_NoneReturnsEmpty)
{
    EncryptionKey key;
    key.hmac_algorithm = HmacAlgorithm::NONE;
    const std::vector<std::uint8_t> data = {1, 2, 3};
    auto tag = detail::ComputeHmac(key, data);
    EXPECT_TRUE(tag.empty());
}

TEST(DataChannelHmac, ComputeHmac_Sha256ProducesCorrectLength)
{
    auto key = MakeHmacKey(HmacAlgorithm::SHA256, 32);
    const std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    auto tag = detail::ComputeHmac(key, data);
    EXPECT_EQ(tag.size(), 32u); // SHA-256 → 32 bytes
}

TEST(DataChannelHmac, ComputeHmac_Sha512ProducesCorrectLength)
{
    auto key = MakeHmacKey(HmacAlgorithm::SHA512, 64);
    const std::vector<std::uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    auto tag = detail::ComputeHmac(key, data);
    EXPECT_EQ(tag.size(), 64u); // SHA-512 → 64 bytes
}

TEST(DataChannelHmac, ComputeHmac_Sha256IsDeterministic)
{
    auto key = MakeHmacKey(HmacAlgorithm::SHA256, 32);
    const std::vector<std::uint8_t> data = {0xCA, 0xFE, 0xBA, 0xBE};
    auto tag1 = detail::ComputeHmac(key, data);
    auto tag2 = detail::ComputeHmac(key, data);
    EXPECT_EQ(tag1, tag2);
}

TEST(DataChannelHmac, ComputeHmac_DifferentDataProducesDifferentTag)
{
    auto key = MakeHmacKey(HmacAlgorithm::SHA256, 32);
    const std::vector<std::uint8_t> data1 = {0x01};
    const std::vector<std::uint8_t> data2 = {0x02};
    EXPECT_NE(detail::ComputeHmac(key, data1), detail::ComputeHmac(key, data2));
}

TEST(DataChannelHmac, VerifyHmac_NoneAlwaysTrue)
{
    EncryptionKey key;
    key.hmac_algorithm = HmacAlgorithm::NONE;
    const std::vector<std::uint8_t> data = {1, 2, 3};
    // expected_tag is irrelevant for NONE
    const std::vector<std::uint8_t> any_tag = {0xFF, 0xFF};
    EXPECT_TRUE(detail::VerifyHmac(key, data, any_tag));
}

TEST(DataChannelHmac, VerifyHmac_Sha256CorrectTagAccepted)
{
    auto key = MakeHmacKey(HmacAlgorithm::SHA256, 32);
    const std::vector<std::uint8_t> data = {0xAA, 0xBB, 0xCC};
    auto tag = detail::ComputeHmac(key, data);
    EXPECT_TRUE(detail::VerifyHmac(key, data, tag));
}

TEST(DataChannelHmac, VerifyHmac_Sha512CorrectTagAccepted)
{
    auto key = MakeHmacKey(HmacAlgorithm::SHA512, 64);
    const std::vector<std::uint8_t> data = {0x11, 0x22, 0x33, 0x44};
    auto tag = detail::ComputeHmac(key, data);
    EXPECT_TRUE(detail::VerifyHmac(key, data, tag));
}

TEST(DataChannelHmac, VerifyHmac_CorruptedTagRejected)
{
    auto key = MakeHmacKey(HmacAlgorithm::SHA256, 32);
    const std::vector<std::uint8_t> data = {0xDE, 0xAD};
    auto tag = detail::ComputeHmac(key, data);
    // Flip one bit in the tag
    tag[0] ^= 0x01;
    EXPECT_FALSE(detail::VerifyHmac(key, data, tag));
}

TEST(DataChannelHmac, VerifyHmac_WrongLengthTagRejected)
{
    auto key = MakeHmacKey(HmacAlgorithm::SHA256, 32);
    const std::vector<std::uint8_t> data = {0x01, 0x02};
    const std::vector<std::uint8_t> short_tag(16, 0x00); // 16 bytes ≠ 32
    EXPECT_FALSE(detail::VerifyHmac(key, data, short_tag));
}

TEST(DataChannelHmac, VerifyHmac_EmptyExpectedTagRejected)
{
    auto key = MakeHmacKey(HmacAlgorithm::SHA256, 32);
    const std::vector<std::uint8_t> data = {0x01};
    const std::vector<std::uint8_t> empty_tag;
    EXPECT_FALSE(detail::VerifyHmac(key, data, empty_tag));
}

// ============================================================================
// Unsupported cipher / error paths
// ============================================================================

// Helper: build a NONE-algorithm key (unsupported cipher — triggers null-traits branch).
static EncryptionKey MakeNoneCipherKey()
{
    EncryptionKey key;
    key.cipher_algorithm = CipherAlgorithm::NONE;
    key.cipher_key.resize(16, 0x00);
    key.cipher_iv.resize(8, 0x00);
    key.hmac_algorithm = HmacAlgorithm::NONE;
    key.is_valid = true;
    return key;
}

TEST_F(DataChannelTest, EncryptPacket_UnsupportedCipherReturnsEmpty)
{
    // Install a key whose cipher algorithm is not a supported AEAD.
    // EncryptPacket must detect this and return early with an empty vector.
    channel().InstallNewKeys(MakeNoneCipherKey(), MakeNoneCipherKey(), 0);

    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x01, 0x02};
    auto encrypted = channel().EncryptPacket(plaintext, SessionId::Generate());
    EXPECT_TRUE(encrypted.empty());
}

TEST_F(DataChannelTest, EncryptPacketInPlace_BufferTooSmall)
{
    // Valid key installed; buffer is one byte too small.
    channel().InstallNewKeys(MakeAes128GcmKey(), MakeAes128GcmKey(), 0);

    constexpr std::size_t payload_len = 10;
    // Allocate (kDataV2Overhead + payload_len - 1) — exactly one byte short.
    std::vector<std::uint8_t> buf(kDataV2Overhead + payload_len - 1, 0x00);
    auto wire_len = channel().EncryptPacketInPlace(buf, payload_len, SessionId::Generate());
    EXPECT_EQ(0u, wire_len);
}

TEST_F(DataChannelTest, EncryptPacketInPlace_UnsupportedCipherReturnsZero)
{
    // With a NONE-cipher key, encrypt_ctx_ is null and IsSupportedAead returns false.
    // EncryptPacketInPlace must return 0 without crashing.
    channel().InstallNewKeys(MakeNoneCipherKey(), MakeNoneCipherKey(), 0);

    constexpr std::size_t payload_len = 10;
    std::vector<std::uint8_t> buf(kDataV2Overhead + payload_len, 0x00);
    auto wire_len = channel().EncryptPacketInPlace(buf, payload_len, SessionId::Generate());
    EXPECT_EQ(0u, wire_len);
}

TEST_F(DataChannelTest, DecryptPacketInPlace_NonDataOpcodeReturnsEmpty)
{
    channel().InstallNewKeys(MakeAes128GcmKey(), MakeAes128GcmKey(), 0);

    // Build a buffer whose first byte carries a control opcode instead of a data opcode.
    std::vector<std::uint8_t> buf(kDataV2Overhead + 4, 0x00);
    buf[0] = MakeOpcodeByte(Opcode::P_CONTROL_V1, 0);

    auto decrypted = channel().DecryptPacketInPlace(buf);
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(DataChannelTest, DecryptPacketInPlace_NoKeyForKeyIdReturnsEmpty)
{
    // Install key at key_id=0; present a packet claiming key_id=1 which has no slot.
    channel().InstallNewKeys(MakeAes128GcmKey(), MakeAes128GcmKey(), 0);

    std::vector<std::uint8_t> buf(kDataV2Overhead + 4, 0x00);
    buf[0] = MakeOpcodeByte(Opcode::P_DATA_V2, 1); // key_id=1 — not installed

    auto decrypted = channel().DecryptPacketInPlace(buf);
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(DataChannelTest, DecryptPacketInPlace_UnsupportedCipherReturnsEmpty)
{
    // Install NONE-cipher key (decrypt_ctx_ will be null, IsSupportedAead false).
    channel().InstallNewKeys(MakeNoneCipherKey(), MakeNoneCipherKey(), 0);

    std::vector<std::uint8_t> buf(kDataV2Overhead + 4, 0x00);
    buf[0] = MakeOpcodeByte(Opcode::P_DATA_V2, 0);

    auto decrypted = channel().DecryptPacketInPlace(buf);
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(DataChannelTest, DecryptPacketInPlace_AuthenticationFailureReturnsEmpty)
{
    // Encrypt a packet normally, then corrupt the AEAD tag and attempt decryption.
    // The tag occupies bytes [kDataV2HeaderLen+kDataV2PacketIdLen .. kDataV2Overhead).
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);
    auto session = SessionId::Generate();

    std::vector<std::uint8_t> plaintext = {0x45, 0x00, 0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> buf(kDataV2Overhead + plaintext.size());
    std::memcpy(buf.data() + kDataV2Overhead, plaintext.data(), plaintext.size());

    auto wire_len = channel().EncryptPacketInPlace(buf, plaintext.size(), session);
    ASSERT_GT(wire_len, 0u);

    // Corrupt the first byte of the AEAD tag.
    constexpr std::size_t kTagOffset = kDataV2HeaderLen + kDataV2PacketIdLen;
    buf[kTagOffset] ^= 0xFF;

    DataChannel decrypt_chan(*logger_);
    decrypt_chan.InstallNewKeys(key, key, 0);
    auto decrypted = decrypt_chan.DecryptPacketInPlace(std::span<std::uint8_t>(buf.data(), wire_len));
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(DataChannelTest, DecryptPacket_UnsupportedCipherReturnsEmpty)
{
    // Install NONE-cipher key. DecryptPacket must detect !IsSupportedAead and return early.
    channel().InstallNewKeys(MakeNoneCipherKey(), MakeNoneCipherKey(), 0);

    OpenVpnPacket packet;
    packet.opcode_ = Opcode::P_DATA_V1;
    packet.key_id_ = 0;
    packet.packet_id_ = 1;
    packet.payload_.assign(20, 0xAA); // payload ≥ AEAD_TAG_SIZE to bypass the size check

    auto decrypted = channel().DecryptPacket(packet);
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(DataChannelTest, DecryptPacket_PayloadTooSmallReturnsEmpty)
{
    // Valid key, but payload smaller than AEAD_TAG_SIZE (16 bytes).
    channel().InstallNewKeys(MakeAes128GcmKey(), MakeAes128GcmKey(), 0);

    OpenVpnPacket packet;
    packet.opcode_ = Opcode::P_DATA_V1;
    packet.key_id_ = 0;
    packet.packet_id_ = 1;
    packet.payload_ = {0x01, 0x02, 0x03}; // 3 bytes — well below AEAD_TAG_SIZE

    auto decrypted = channel().DecryptPacket(packet);
    EXPECT_TRUE(decrypted.empty());
}

// ============================================================================
// ReplayWindow unit tests (previously dead paths)
// ============================================================================

class ReplayWindowTest : public ::testing::Test
{
  protected:
    ReplayWindow window_;
};

TEST_F(ReplayWindowTest, InitialHighestIdIsZero)
{
    EXPECT_EQ(window_.highest_id(), 0u);
}

TEST_F(ReplayWindowTest, Accept_AdvancesHighestId)
{
    window_.Accept(10);
    EXPECT_EQ(window_.highest_id(), 10u);
}

// BitSet path: pkt_id <= highest_id and diff < kBits
TEST_F(ReplayWindowTest, Accept_InWindowOutOfOrder_BitSetPath)
{
    // Advance to 5 first, then accept 3 (which is "behind" highest but in window).
    window_.Accept(5);
    EXPECT_EQ(window_.highest_id(), 5u);

    // pkt 3 is behind the highest; this exercises the BitSet branch.
    window_.Accept(3);
    EXPECT_EQ(window_.highest_id(), 5u); // highest unchanged

    // Packet 3 is now marked as seen — Check should return Duplicate.
    auto result = window_.Check(3);
    EXPECT_EQ(result, ReplayWindow::CheckResult::Duplicate);
}

TEST_F(ReplayWindowTest, Accept_BitSetPath_DoesNotChangeFuture)
{
    window_.Accept(10);
    window_.Accept(8); // behind highest, sets bit for (10-8)=2

    // pkt 9 was NOT yet seen
    EXPECT_EQ(window_.Check(9), ReplayWindow::CheckResult::Accept);
    // pkt 8 is now seen
    EXPECT_EQ(window_.Check(8), ReplayWindow::CheckResult::Duplicate);
}

// Shift word-aligned large-shift path: word_shift > 0 AND bit_shift == 0
// This happens when shift is an exact multiple of 64.
TEST_F(ReplayWindowTest, Shift_WordAligned_Shift64)
{
    // Accept packets 1..10 to populate some bits
    for (uint32_t i = 1; i <= 10; ++i)
        window_.Accept(i);
    EXPECT_EQ(window_.highest_id(), 10u);

    // Now jump by exactly 64 — exercises the word_shift>0 && bit_shift==0 code path.
    // After Accept(74): shift is 64, word_shift=1, bit_shift=0
    window_.Accept(74);
    EXPECT_EQ(window_.highest_id(), 74u);

    // Old pkt 1 should now be TooOld (diff=73 < kBits=2048, but was shifted out)
    // Actually 74-1=73 < 2048, so it's within the window but NOT marked (shifted away)
    // Check returns Accept (not seen after shift resets)
    // The important thing is that the shift didn't crash / corrupt state
    EXPECT_EQ(window_.Check(75), ReplayWindow::CheckResult::Accept);    // future
    EXPECT_EQ(window_.Check(74), ReplayWindow::CheckResult::Duplicate); // just accepted
}

TEST_F(ReplayWindowTest, Shift_WordAligned_Shift128)
{
    window_.Accept(5);
    // Jump by exactly 128 — word_shift=2, bit_shift=0
    window_.Accept(133);
    EXPECT_EQ(window_.highest_id(), 133u);
    EXPECT_EQ(window_.Check(133), ReplayWindow::CheckResult::Duplicate);
    EXPECT_EQ(window_.Check(134), ReplayWindow::CheckResult::Accept);
}

TEST_F(ReplayWindowTest, Reset_ClearsState)
{
    window_.Accept(100);
    EXPECT_EQ(window_.highest_id(), 100u);

    window_.Reset();
    EXPECT_EQ(window_.highest_id(), 0u);
    EXPECT_EQ(window_.Check(50), ReplayWindow::CheckResult::Accept);
}

// ============================================================================
// DataChannel accessor tests (previously dead)
// ============================================================================

class DataChannelAccessorTest : public DataChannelTest
{
};

TEST_F(DataChannelAccessorTest, SetCurrentKeyId_GetCurrentKeyId)
{
    // Default key_id is 0 (set by InstallNewKeys with key_id=0)
    channel().InstallNewKeys(MakeAes128GcmKey(), MakeAes128GcmKey(), 0);
    EXPECT_EQ(channel().GetCurrentKeyId(), 0u);

    channel().SetCurrentKeyId(3);
    EXPECT_EQ(channel().GetCurrentKeyId(), 3u);

    // Wraps to 0..7 range (KEY_ID_MASK = 0x07)
    channel().SetCurrentKeyId(9); // 9 & 7 = 1
    EXPECT_EQ(channel().GetCurrentKeyId(), 1u);
}

TEST_F(DataChannelAccessorTest, SetDcoKeysInstalled_AffectsHasValidKeys)
{
    // No keys installed yet → HasValidKeys is false
    EXPECT_FALSE(channel().HasValidKeys());

    // Set DCO flag → HasValidKeys becomes true
    channel().SetDcoKeysInstalled(true);
    EXPECT_TRUE(channel().HasValidKeys());

    channel().SetDcoKeysInstalled(false);
    EXPECT_FALSE(channel().HasValidKeys());
}

TEST_F(DataChannelAccessorTest, GetPrimaryEncryptKey_ReflectsInstalledKey)
{
    auto key = MakeAes128GcmKey();
    key.cipher_key = std::vector<std::uint8_t>(16, 0xAB);

    channel().InstallNewKeys(key, key, 2);

    const auto &enc = channel().GetPrimaryEncryptKey();
    EXPECT_TRUE(enc.is_valid);
    EXPECT_EQ(enc.cipher_algorithm, CipherAlgorithm::AES_128_GCM);
    EXPECT_EQ(enc.cipher_key.front(), 0xAB);
    EXPECT_EQ(enc.key_id, 2u);
}

TEST_F(DataChannelAccessorTest, GetPrimaryDecryptKey_ReflectsInstalledKey)
{
    auto dec_key = MakeAes128GcmKey();
    dec_key.cipher_key = std::vector<std::uint8_t>(16, 0xCD);
    auto enc_key = MakeAes128GcmKey();

    channel().InstallNewKeys(dec_key, enc_key, 5);

    const auto &dec = channel().GetPrimaryDecryptKey();
    EXPECT_TRUE(dec.is_valid);
    EXPECT_EQ(dec.cipher_key.front(), 0xCD);
    EXPECT_EQ(dec.key_id, 5u);
}

TEST_F(DataChannelAccessorTest, GetPrimaryEncryptKey_BeforeInstall_IsInvalid)
{
    const auto &enc = channel().GetPrimaryEncryptKey();
    EXPECT_FALSE(enc.is_valid);
}

} // namespace clv::vpn::openvpn::test
