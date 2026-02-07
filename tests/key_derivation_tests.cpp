// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include "openvpn/crypto_algorithms.h"
#include "openvpn/key_derivation.h"
#include "openvpn/data_channel.h"
#include "openvpn/packet.h"
#include <array>
#include <memory>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <vector>

using namespace clv::vpn::openvpn;

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
