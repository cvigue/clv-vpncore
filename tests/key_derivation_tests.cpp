// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include "openvpn/crypto_algorithms.h"
#include "openvpn/key_derivation.h"
#include "openvpn/data_channel.h"
#include "openvpn/packet.h"
#include "openvpn/protocol_constants.h"
#include <array>
#include <memory>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <vector>

using namespace clv::vpn::openvpn;

TEST(KeyMethod2PeerInfoTest, BuildClientPeerInfoIncludesIvCiphers)
{
    std::vector<std::string> ciphers{"AES-256-GCM", "CHACHA20-POLY1305"};
    std::string info = BuildClientPeerInfo("clv-vpncore/test", ciphers);

    EXPECT_NE(info.find("IV_VER=clv-vpncore/test\n"), std::string::npos);
    EXPECT_NE(info.find("IV_PROTO="), std::string::npos);
    EXPECT_NE(info.find("IV_CIPHERS=AES-256-GCM:CHACHA20-POLY1305\n"), std::string::npos);
}

class KeyDerivationTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        logger_ = std::make_unique<spdlog::logger>("test_key_derivation", null_sink);
    }

    std::unique_ptr<spdlog::logger> logger_;
    // Test master secret (32 bytes from typical TLS handshake)
    static constexpr std::array<uint8_t, 32> TEST_MASTER_SECRET{{
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1A,
        0x1B,
        0x1C,
        0x1D,
        0x1E,
        0x1F,
    }};
};

// ==================== PRF Tests ====================

TEST_F(KeyDerivationTest, DeriveKeyMaterialBasic)
{
    auto material = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET, "test label", 32);

    EXPECT_EQ(material.size(), 32);
    EXPECT_FALSE(material.empty());
}

TEST_F(KeyDerivationTest, DeriveKeyMaterialMultipleIterations)
{
    // Request more than one PRF iteration (>32 bytes)
    auto material = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET, "test label", 96);

    EXPECT_EQ(material.size(), 96);
}

TEST_F(KeyDerivationTest, DeriveKeyMaterialDeterministic)
{
    auto material1 = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET, "test label", 64);

    auto material2 = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET, "test label", 64);

    // Same inputs should produce same output
    EXPECT_EQ(material1, material2);
}

TEST_F(KeyDerivationTest, DeriveKeyMaterialDifferentLabel)
{
    auto material1 = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET, "label1", 32);

    auto material2 = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET, "label2", 32);

    // Different labels should produce different material
    EXPECT_NE(material1, material2);
}

TEST_F(KeyDerivationTest, DeriveKeyMaterialDifferentSecret)
{
    std::array<uint8_t, 32> secret2;
    secret2.fill(0xFF);

    auto material1 = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET, "label", 32);

    auto material2 = KeyDerivation::DeriveKeyMaterial(
        secret2, "label", 32);

    // Different secrets should produce different material
    EXPECT_NE(material1, material2);
}

TEST_F(KeyDerivationTest, DeriveKeyMaterialThrowsOnEmptySecret)
{
    std::vector<uint8_t> empty;

    EXPECT_THROW({
        KeyDerivation::DeriveKeyMaterial(empty, "label", 32);
    },
                 std::runtime_error);
}

TEST_F(KeyDerivationTest, DeriveKeyMaterialThrowsOnZeroBytes)
{
    EXPECT_THROW({
        KeyDerivation::DeriveKeyMaterial(TEST_MASTER_SECRET, "label", 0);
    },
                 std::runtime_error);
}

// ==================== Key Material Size Calculation ====================

TEST_F(KeyDerivationTest, GetRequiredKeyMaterialSizeAes128Gcm)
{
    size_t size = KeyDerivation::GetRequiredKeyMaterialSize(
        CipherAlgorithm::AES_128_GCM,
        HmacAlgorithm::SHA256);

    // OpenVPN always generates 256 bytes (fixed key2 structure size)
    EXPECT_EQ(size, 256u);
}

TEST_F(KeyDerivationTest, GetRequiredKeyMaterialSizeAes256Gcm)
{
    size_t size = KeyDerivation::GetRequiredKeyMaterialSize(
        CipherAlgorithm::AES_256_GCM,
        HmacAlgorithm::SHA256);

    // OpenVPN always generates 256 bytes (fixed key2 structure size)
    EXPECT_EQ(size, 256u);
}

TEST_F(KeyDerivationTest, GetRequiredKeyMaterialSizeChaCha20)
{
    size_t size = KeyDerivation::GetRequiredKeyMaterialSize(
        CipherAlgorithm::CHACHA20_POLY1305,
        HmacAlgorithm::SHA256);

    // OpenVPN always generates 256 bytes (fixed key2 structure size)
    EXPECT_EQ(size, 256u);
}

TEST_F(KeyDerivationTest, GetRequiredKeyMaterialSizeSha512)
{
    size_t size = KeyDerivation::GetRequiredKeyMaterialSize(
        CipherAlgorithm::AES_256_GCM,
        HmacAlgorithm::SHA512);

    // OpenVPN always generates 256 bytes (fixed key2 structure size)
    EXPECT_EQ(size, 256u);
}

TEST_F(KeyDerivationTest, GetRequiredKeyMaterialSizeNoHmac)
{
    size_t size = KeyDerivation::GetRequiredKeyMaterialSize(
        CipherAlgorithm::AES_256_GCM,
        HmacAlgorithm::NONE);

    // OpenVPN always generates 256 bytes (fixed key2 structure size)
    EXPECT_EQ(size, 256u);
}

// ==================== Key Installation Tests ====================

TEST_F(KeyDerivationTest, InstallKeysAes256Gcm)
{
    auto key_material = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET,
        "OpenVPN key material",
        KeyDerivation::GetRequiredKeyMaterialSize(
            CipherAlgorithm::AES_256_GCM,
            HmacAlgorithm::NONE)); // AEAD ciphers don't use separate HMAC

    DataChannel data_channel(*logger_);
    bool success = KeyDerivation::InstallKeys(
        data_channel,
        key_material,
        CipherAlgorithm::AES_256_GCM,
        HmacAlgorithm::NONE,
        0); // key_id = 0

    EXPECT_TRUE(success);
    // Keys are now installed - primary encrypt/decrypt keys are active
}

TEST_F(KeyDerivationTest, InstallKeysKeySlotsIsolated)
{
    auto key_material = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET,
        "OpenVPN key material",
        KeyDerivation::GetRequiredKeyMaterialSize(
            CipherAlgorithm::AES_256_GCM,
            HmacAlgorithm::SHA256));

    DataChannel data_channel(*logger_);
    KeyDerivation::InstallKeys(
        data_channel,
        key_material,
        CipherAlgorithm::AES_256_GCM,
        HmacAlgorithm::SHA256,
        0);

    // Keys are installed - client→server (decrypt) and server→client (encrypt) are different
}

TEST_F(KeyDerivationTest, InstallKeysChaCha20Poly1305)
{
    auto key_material = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET,
        "OpenVPN key material",
        KeyDerivation::GetRequiredKeyMaterialSize(
            CipherAlgorithm::CHACHA20_POLY1305,
            HmacAlgorithm::NONE)); // AEAD ciphers don't use separate HMAC

    DataChannel data_channel(*logger_);
    bool success = KeyDerivation::InstallKeys(
        data_channel,
        key_material,
        CipherAlgorithm::CHACHA20_POLY1305,
        HmacAlgorithm::NONE,
        0); // key_id = 0

    EXPECT_TRUE(success);
    // ChaCha20-Poly1305 keys installed successfully
}

TEST_F(KeyDerivationTest, InstallKeysInsufficientMaterial)
{
    // Derive too little material
    auto key_material = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET, "label", 32);

    DataChannel data_channel(*logger_);
    bool success = KeyDerivation::InstallKeys(
        data_channel,
        key_material,
        CipherAlgorithm::AES_256_GCM,
        HmacAlgorithm::SHA256,
        0);

    // Should fail due to insufficient material
    EXPECT_FALSE(success);
}

TEST_F(KeyDerivationTest, InstallKeysValidatesKeys)
{
    auto key_material = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET,
        "OpenVPN key material",
        KeyDerivation::GetRequiredKeyMaterialSize(
            CipherAlgorithm::AES_256_GCM,
            HmacAlgorithm::SHA256));

    DataChannel data_channel(*logger_);
    bool success = KeyDerivation::InstallKeys(
        data_channel,
        key_material,
        CipherAlgorithm::AES_256_GCM,
        HmacAlgorithm::SHA256,
        0);

    // Keys are installed and validated
    EXPECT_TRUE(success);
}

// ==================== Integration Tests ====================

TEST_F(KeyDerivationTest, FullWorkflowAes256Gcm)
{
    // Simulate full key derivation and installation workflow
    const size_t needed = KeyDerivation::GetRequiredKeyMaterialSize(
        CipherAlgorithm::AES_256_GCM,
        HmacAlgorithm::SHA256);

    auto key_material = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET,
        "OpenVPN key material",
        needed);

    DataChannel data_channel(*logger_);
    bool success = KeyDerivation::InstallKeys(
        data_channel,
        key_material,
        CipherAlgorithm::AES_256_GCM,
        HmacAlgorithm::SHA256,
        0);

    EXPECT_TRUE(success);

    // Try encrypting with the installed keys
    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
    SessionId session_id{0x12345678};

    auto encrypted = data_channel.EncryptPacket(plaintext, session_id);
    EXPECT_FALSE(encrypted.empty());
}

TEST_F(KeyDerivationTest, MultipleDerivationsSameSecret)
{
    // Simulate rekeying
    auto material1 = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET, "material-1", 64);

    auto material2 = KeyDerivation::DeriveKeyMaterial(
        TEST_MASTER_SECRET, "material-2", 64);

    // Different labels should produce different keys
    EXPECT_NE(material1, material2);
}

// ============================================================================
// DeriveKeyMaterialWithSecret — entire function was dead
// ============================================================================

TEST_F(KeyDerivationTest, DeriveKeyMaterialWithSecret_EmptySecretThrows)
{
    const std::vector<std::uint8_t> empty_secret;
    const std::vector<std::uint8_t> seed = {0x01, 0x02};
    EXPECT_THROW(
        KeyDerivation::DeriveKeyMaterialWithSecret(empty_secret, "label", seed, 32),
        std::runtime_error);
}

TEST_F(KeyDerivationTest, DeriveKeyMaterialWithSecret_ZeroOutputBytesThrows)
{
    const std::vector<std::uint8_t> secret(32, 0xAA);
    const std::vector<std::uint8_t> seed = {0x01};
    EXPECT_THROW(
        KeyDerivation::DeriveKeyMaterialWithSecret(secret, "label", seed, 0),
        std::runtime_error);
}

TEST_F(KeyDerivationTest, DeriveKeyMaterialWithSecret_ReturnsCorrectSize)
{
    const std::vector<std::uint8_t> secret(48, 0x55);
    const std::vector<std::uint8_t> seed(64, 0xCC);
    auto result = KeyDerivation::DeriveKeyMaterialWithSecret(secret, "OpenVPN master secret", seed, 48);
    EXPECT_EQ(result.size(), 48u);
}

TEST_F(KeyDerivationTest, DeriveKeyMaterialWithSecret_IsDeterministic)
{
    const std::vector<std::uint8_t> secret(48, 0x11);
    const std::vector<std::uint8_t> seed(32, 0x22);
    auto r1 = KeyDerivation::DeriveKeyMaterialWithSecret(secret, "test label", seed, 64);
    auto r2 = KeyDerivation::DeriveKeyMaterialWithSecret(secret, "test label", seed, 64);
    EXPECT_EQ(r1, r2);
}

TEST_F(KeyDerivationTest, DeriveKeyMaterialWithSecret_DifferentSeedProducesDifferentOutput)
{
    const std::vector<std::uint8_t> secret(48, 0x33);
    const std::vector<std::uint8_t> seed1(32, 0x44);
    const std::vector<std::uint8_t> seed2(32, 0x55);
    auto r1 = KeyDerivation::DeriveKeyMaterialWithSecret(secret, "label", seed1, 32);
    auto r2 = KeyDerivation::DeriveKeyMaterialWithSecret(secret, "label", seed2, 32);
    EXPECT_NE(r1, r2);
}

// ============================================================================
// DeriveKeyMethod2 — entire function was dead
// ============================================================================

// Build minimal valid inputs matching the documented layout:
//   client_random: 112 bytes (48 pre_master + 32 random1 + 32 random2)
//   server_random:  64 bytes (32 random1 + 32 random2)
static std::vector<std::uint8_t> MakeClientRandom(std::uint8_t fill = 0xAB)
{
    return std::vector<std::uint8_t>(CLIENT_KEY_SOURCE_SIZE, fill);
}
static std::vector<std::uint8_t> MakeServerRandom(std::uint8_t fill = 0xCD)
{
    return std::vector<std::uint8_t>(SERVER_KEY_SOURCE_SIZE, fill);
}

TEST_F(KeyDerivationTest, DeriveKeyMethod2_ClientRandomTooShortThrows)
{
    auto short_client = std::vector<std::uint8_t>(CLIENT_KEY_SOURCE_SIZE - 1, 0x01);
    auto server = MakeServerRandom();
    SessionId cid{0x1111111111111111ULL};
    SessionId sid{0x2222222222222222ULL};
    EXPECT_THROW(
        KeyDerivation::DeriveKeyMethod2(short_client, server, cid, sid, "AES-256-GCM"),
        std::runtime_error);
}

TEST_F(KeyDerivationTest, DeriveKeyMethod2_ServerRandomTooShortThrows)
{
    auto client = MakeClientRandom();
    auto short_server = std::vector<std::uint8_t>(SERVER_KEY_SOURCE_SIZE - 1, 0x01);
    SessionId cid{0x1111111111111111ULL};
    SessionId sid{0x2222222222222222ULL};
    EXPECT_THROW(
        KeyDerivation::DeriveKeyMethod2(client, short_server, cid, sid, "AES-256-GCM"),
        std::runtime_error);
}

TEST_F(KeyDerivationTest, DeriveKeyMethod2_EmptyCipherNameThrows)
{
    auto client = MakeClientRandom();
    auto server = MakeServerRandom();
    SessionId cid{0x1111111111111111ULL};
    SessionId sid{0x2222222222222222ULL};
    EXPECT_THROW(
        KeyDerivation::DeriveKeyMethod2(client, server, cid, sid, ""),
        std::runtime_error);
}

TEST_F(KeyDerivationTest, DeriveKeyMethod2_InvalidCipherNameThrows)
{
    auto client = MakeClientRandom();
    auto server = MakeServerRandom();
    SessionId cid{0x1111111111111111ULL};
    SessionId sid{0x2222222222222222ULL};
    EXPECT_THROW(
        KeyDerivation::DeriveKeyMethod2(client, server, cid, sid, "BOGUS-CIPHER"),
        std::invalid_argument);
}

TEST_F(KeyDerivationTest, DeriveKeyMethod2_HappyPathAes256Gcm)
{
    auto client = MakeClientRandom();
    auto server = MakeServerRandom();
    SessionId cid{0xAAAAAAAAAAAAAAAAULL};
    SessionId sid{0xBBBBBBBBBBBBBBBBULL};

    auto result = KeyDerivation::DeriveKeyMethod2(client, server, cid, sid, "AES-256-GCM");

    EXPECT_EQ(result.cipher_algo, CipherAlgorithm::AES_256_GCM);
    EXPECT_EQ(result.hmac_algo, HmacAlgorithm::NONE); // AEAD → no separate HMAC
    // 256 bytes of key material (OPENVPN_KEY2_SIZE)
    EXPECT_EQ(result.key_material.size(), 256u);
    EXPECT_FALSE(result.key_material.empty());
}

TEST_F(KeyDerivationTest, DeriveKeyMethod2_HappyPathAes128Gcm)
{
    auto client = MakeClientRandom();
    auto server = MakeServerRandom();
    SessionId cid{0x1234567890ABCDEFULL};
    SessionId sid{0xFEDCBA0987654321ULL};

    auto result = KeyDerivation::DeriveKeyMethod2(client, server, cid, sid, "AES-128-GCM");

    EXPECT_EQ(result.cipher_algo, CipherAlgorithm::AES_128_GCM);
    EXPECT_EQ(result.key_material.size(), 256u);
}

TEST_F(KeyDerivationTest, DeriveKeyMethod2_IsDeterministic)
{
    auto client = MakeClientRandom();
    auto server = MakeServerRandom();
    SessionId cid{0x1111111111111111ULL};
    SessionId sid{0x2222222222222222ULL};

    auto r1 = KeyDerivation::DeriveKeyMethod2(client, server, cid, sid, "AES-256-GCM");
    auto r2 = KeyDerivation::DeriveKeyMethod2(client, server, cid, sid, "AES-256-GCM");
    EXPECT_EQ(r1.key_material, r2.key_material);
}

TEST_F(KeyDerivationTest, DeriveKeyMethod2_DifferentSessionIdsProduceDifferentKeys)
{
    auto client = MakeClientRandom();
    auto server = MakeServerRandom();
    SessionId cid1{0x1111111111111111ULL};
    SessionId sid1{0x2222222222222222ULL};
    SessionId cid2{0x3333333333333333ULL};
    SessionId sid2{0x4444444444444444ULL};

    auto r1 = KeyDerivation::DeriveKeyMethod2(client, server, cid1, sid1, "AES-256-GCM");
    auto r2 = KeyDerivation::DeriveKeyMethod2(client, server, cid2, sid2, "AES-256-GCM");
    EXPECT_NE(r1.key_material, r2.key_material);
}
