// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/crypto_algorithms.h"
#include "openvpn/data_channel.h"
#include "openvpn/packet.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>
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
//   recvmmsg → arena slot → DecryptPacketInPlace → compression strip
// ---------------------------------------------------------------------------

TEST_F(DataChannelTest, InboundArena_CompressNoneStrip)
{
    // Simulate: outbound path puts COMPRESS_NONE (0xFA) + IP data,
    // inbound arena receives the wire packet, decrypt returns
    // [compress_byte | ip_data], caller strips compress byte.
    auto key = MakeAes128GcmKey();
    channel().InstallNewKeys(key, key, 0);
    auto session = SessionId::Generate();

    // Build payload: 0xFA (compress-none) + fake IPv4 packet (version=4)
    std::vector<std::uint8_t> ip_data(64, 0xCC);
    ip_data[0] = 0x45; // IPv4, IHL=5
    std::vector<std::uint8_t> payload;
    payload.push_back(0xFA); // COMPRESS_NONE
    payload.insert(payload.end(), ip_data.begin(), ip_data.end());

    // Encrypt using EncryptPacketInPlace (as outbound path does)
    std::vector<std::uint8_t> buf(kDataV2Overhead + payload.size());
    std::memcpy(buf.data() + kDataV2Overhead, payload.data(), payload.size());
    auto wire_len = channel().EncryptPacketInPlace(buf, payload.size(), session);
    ASSERT_GT(wire_len, 0u);

    // --- Inbound simulation: buf[0..wire_len) is what recvmmsg delivered ---
    DataChannel inbound_chan(*logger_);
    inbound_chan.InstallNewKeys(key, key, 0);

    auto plaintext = inbound_chan.DecryptPacketInPlace(
        std::span<std::uint8_t>(buf.data(), wire_len));
    ASSERT_FALSE(plaintext.empty());
    // plaintext should be [0xFA | 0x45 0x00 ... ip_data]
    ASSERT_EQ(plaintext.size(), payload.size());
    EXPECT_EQ(plaintext[0], 0xFA);
    EXPECT_EQ(plaintext[1], 0x45);

    // Simulate compress strip (same logic as DecryptAndStripInPlace):
    // First byte is not an IP version nibble → strip it
    uint8_t first = plaintext[0];
    uint8_t version_nibble = (first >> 4) & 0x0F;
    EXPECT_NE(version_nibble, 4u); // 0xFA >> 4 = 0x0F, not 4
    EXPECT_NE(version_nibble, 6u); // not IPv6 either
    EXPECT_EQ(first, 0xFA);        // COMPRESS_NONE

    auto ip_span = plaintext.subspan(1); // strip compress byte
    ASSERT_EQ(ip_span.size(), ip_data.size());
    EXPECT_TRUE(std::equal(ip_span.begin(), ip_span.end(), ip_data.begin()));
}

TEST_F(DataChannelTest, InboundArena_DirectIpNoCompress)
{
    // When session doesn't use compression framing, plaintext IS the IP data
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

} // namespace clv::vpn::openvpn::test
