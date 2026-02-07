// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/aead_utils.h"
#include "openvpn/crypto_algorithms.h"
#include <gtest/gtest.h>
#include <vector>

namespace clv::vpn::openvpn::test {

class AeadUtilsTest : public ::testing::Test
{
};

// ================================================================================================
// ReorderTagToFront Tests
// ================================================================================================

TEST_F(AeadUtilsTest, ReorderTagToFront_ValidData)
{
    // Create test data: [ ciphertext (4 bytes) ] [ tag (16 bytes) ]
    std::vector<std::uint8_t> input(20);
    // Ciphertext bytes: 0xAA, 0xBB, 0xCC, 0xDD
    input[0] = 0xAA;
    input[1] = 0xBB;
    input[2] = 0xCC;
    input[3] = 0xDD;
    // Tag bytes: 0x01..0x10
    for (std::size_t i = 0; i < AEAD_TAG_SIZE; ++i)
    {
        input[4 + i] = static_cast<std::uint8_t>(i + 1);
    }

    // Expected output: [ tag (16 bytes) ] [ ciphertext (4 bytes) ]
    auto result = ReorderTagToFront(input);

    ASSERT_EQ(20u, result.size());
    // Verify tag is now at front
    for (std::size_t i = 0; i < AEAD_TAG_SIZE; ++i)
    {
        EXPECT_EQ(static_cast<std::uint8_t>(i + 1), result[i]) << "Tag byte " << i << " mismatch";
    }
    // Verify ciphertext is after tag
    EXPECT_EQ(0xAA, result[16]);
    EXPECT_EQ(0xBB, result[17]);
    EXPECT_EQ(0xCC, result[18]);
    EXPECT_EQ(0xDD, result[19]);
}

TEST_F(AeadUtilsTest, ReorderTagToFront_ExactTagSize)
{
    // Edge case: data is exactly AEAD_TAG_SIZE (no ciphertext, only tag)
    std::vector<std::uint8_t> input(AEAD_TAG_SIZE);
    for (std::size_t i = 0; i < AEAD_TAG_SIZE; ++i)
    {
        input[i] = static_cast<std::uint8_t>(i);
    }

    auto result = ReorderTagToFront(input);

    // Should return tag as-is (no ciphertext to move)
    ASSERT_EQ(AEAD_TAG_SIZE, result.size());
    EXPECT_EQ(input, result);
}

TEST_F(AeadUtilsTest, ReorderTagToFront_EmptyData)
{
    std::vector<std::uint8_t> input;
    auto result = ReorderTagToFront(input);
    EXPECT_TRUE(result.empty());
}

TEST_F(AeadUtilsTest, ReorderTagToFront_TooSmall)
{
    // Data smaller than AEAD_TAG_SIZE should return empty
    std::vector<std::uint8_t> input = {0x01, 0x02, 0x03}; // 3 bytes < 16
    auto result = ReorderTagToFront(input);
    EXPECT_TRUE(result.empty());
}

TEST_F(AeadUtilsTest, ReorderTagToFront_LargePayload)
{
    // Test with larger payload (typical packet size)
    const std::size_t ciphertext_size = 1024;
    std::vector<std::uint8_t> input(ciphertext_size + AEAD_TAG_SIZE);

    // Fill ciphertext with pattern
    for (std::size_t i = 0; i < ciphertext_size; ++i)
    {
        input[i] = static_cast<std::uint8_t>(i % 256);
    }
    // Fill tag with distinct pattern
    for (std::size_t i = 0; i < AEAD_TAG_SIZE; ++i)
    {
        input[ciphertext_size + i] = 0xFF - static_cast<std::uint8_t>(i);
    }

    auto result = ReorderTagToFront(input);

    ASSERT_EQ(input.size(), result.size());
    // Verify tag at front
    for (std::size_t i = 0; i < AEAD_TAG_SIZE; ++i)
    {
        EXPECT_EQ(0xFF - static_cast<std::uint8_t>(i), result[i]);
    }
    // Verify ciphertext after tag
    for (std::size_t i = 0; i < ciphertext_size; ++i)
    {
        EXPECT_EQ(static_cast<std::uint8_t>(i % 256), result[AEAD_TAG_SIZE + i]);
    }
}

// ================================================================================================
// ReorderTagToBack Tests
// ================================================================================================

TEST_F(AeadUtilsTest, ReorderTagToBack_ValidData)
{
    // Create test data: [ tag (16 bytes) ] [ ciphertext (4 bytes) ]
    std::vector<std::uint8_t> input(20);
    // Tag bytes: 0x01..0x10
    for (std::size_t i = 0; i < AEAD_TAG_SIZE; ++i)
    {
        input[i] = static_cast<std::uint8_t>(i + 1);
    }
    // Ciphertext bytes: 0xAA, 0xBB, 0xCC, 0xDD
    input[16] = 0xAA;
    input[17] = 0xBB;
    input[18] = 0xCC;
    input[19] = 0xDD;

    // Expected output: [ ciphertext (4 bytes) ] [ tag (16 bytes) ]
    auto result = ReorderTagToBack(input);

    ASSERT_EQ(20u, result.size());
    // Verify ciphertext is now at front
    EXPECT_EQ(0xAA, result[0]);
    EXPECT_EQ(0xBB, result[1]);
    EXPECT_EQ(0xCC, result[2]);
    EXPECT_EQ(0xDD, result[3]);
    // Verify tag is after ciphertext
    for (std::size_t i = 0; i < AEAD_TAG_SIZE; ++i)
    {
        EXPECT_EQ(static_cast<std::uint8_t>(i + 1), result[4 + i]) << "Tag byte " << i << " mismatch";
    }
}

TEST_F(AeadUtilsTest, ReorderTagToBack_ExactTagSize)
{
    // Edge case: data is exactly AEAD_TAG_SIZE (no ciphertext, only tag)
    std::vector<std::uint8_t> input(AEAD_TAG_SIZE);
    for (std::size_t i = 0; i < AEAD_TAG_SIZE; ++i)
    {
        input[i] = static_cast<std::uint8_t>(i);
    }

    auto result = ReorderTagToBack(input);

    // Should return tag as-is (no ciphertext to move)
    ASSERT_EQ(AEAD_TAG_SIZE, result.size());
    EXPECT_EQ(input, result);
}

TEST_F(AeadUtilsTest, ReorderTagToBack_EmptyData)
{
    std::vector<std::uint8_t> input;
    auto result = ReorderTagToBack(input);
    EXPECT_TRUE(result.empty());
}

TEST_F(AeadUtilsTest, ReorderTagToBack_TooSmall)
{
    // Data smaller than AEAD_TAG_SIZE should return empty
    std::vector<std::uint8_t> input = {0x01, 0x02, 0x03, 0x04, 0x05}; // 5 bytes < 16
    auto result = ReorderTagToBack(input);
    EXPECT_TRUE(result.empty());
}

TEST_F(AeadUtilsTest, ReorderTagToBack_LargePayload)
{
    // Test with larger payload (typical packet size)
    const std::size_t ciphertext_size = 1024;
    std::vector<std::uint8_t> input(ciphertext_size + AEAD_TAG_SIZE);

    // Fill tag with pattern
    for (std::size_t i = 0; i < AEAD_TAG_SIZE; ++i)
    {
        input[i] = 0xFF - static_cast<std::uint8_t>(i);
    }
    // Fill ciphertext with distinct pattern
    for (std::size_t i = 0; i < ciphertext_size; ++i)
    {
        input[AEAD_TAG_SIZE + i] = static_cast<std::uint8_t>(i % 256);
    }

    auto result = ReorderTagToBack(input);

    ASSERT_EQ(input.size(), result.size());
    // Verify ciphertext at front
    for (std::size_t i = 0; i < ciphertext_size; ++i)
    {
        EXPECT_EQ(static_cast<std::uint8_t>(i % 256), result[i]);
    }
    // Verify tag at back
    for (std::size_t i = 0; i < AEAD_TAG_SIZE; ++i)
    {
        EXPECT_EQ(0xFF - static_cast<std::uint8_t>(i), result[ciphertext_size + i]);
    }
}

// ================================================================================================
// Round-trip Tests
// ================================================================================================

TEST_F(AeadUtilsTest, RoundTrip_FrontToBackToFront)
{
    // Start with: [ ciphertext ] [ tag ]
    std::vector<std::uint8_t> original = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // ciphertext (8 bytes)
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08, // tag (16 bytes)
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10};

    // Convert to OpenVPN format and back
    auto openvpn_format = ReorderTagToFront(original);
    auto back_to_original = ReorderTagToBack(openvpn_format);

    ASSERT_EQ(original.size(), back_to_original.size());
    EXPECT_EQ(original, back_to_original);
}

TEST_F(AeadUtilsTest, RoundTrip_BackToFrontToBack)
{
    // Start with: [ tag ] [ ciphertext ]
    std::vector<std::uint8_t> original = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // tag (16 bytes)
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88 // ciphertext (8 bytes)
    };

    // Convert to SslHelp format and back
    auto sslhelp_format = ReorderTagToBack(original);
    auto back_to_original = ReorderTagToFront(sslhelp_format);

    ASSERT_EQ(original.size(), back_to_original.size());
    EXPECT_EQ(original, back_to_original);
}

TEST_F(AeadUtilsTest, RoundTrip_PreservesAllBytes)
{
    // Test that no data is lost or corrupted during round-trip
    std::vector<std::uint8_t> original(256); // Diverse payload
    for (std::size_t i = 0; i < original.size(); ++i)
    {
        original[i] = static_cast<std::uint8_t>(i);
    }

    // Multiple round trips
    auto temp1 = ReorderTagToFront(original);
    auto temp2 = ReorderTagToBack(temp1);
    auto temp3 = ReorderTagToFront(temp2);
    auto final = ReorderTagToBack(temp3);

    EXPECT_EQ(original, final) << "Data corruption after multiple round-trips";
}

// ================================================================================================
// Integration-style Tests
// ================================================================================================

TEST_F(AeadUtilsTest, VerifyOpenVpnFormat)
{
    // Simulate OpenVPN P_DATA_V2 packet: [ TAG ] [ ciphertext ]
    std::vector<std::uint8_t> openvpn_packet = {
        // Tag (16 bytes) - first in OpenVPN format
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xBB,
        0xBB,
        0xBB,
        0xBB,
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xDD,
        0xDD,
        0xDD,
        0xDD,
        // Ciphertext (4 bytes)
        0x01,
        0x02,
        0x03,
        0x04};

    // Convert to SslHelp/BoringSSL format for decryption
    auto sslhelp_format = ReorderTagToBack(openvpn_packet);

    // Verify ciphertext is now at front
    EXPECT_EQ(0x01, sslhelp_format[0]);
    EXPECT_EQ(0x02, sslhelp_format[1]);
    EXPECT_EQ(0x03, sslhelp_format[2]);
    EXPECT_EQ(0x04, sslhelp_format[3]);
    // Verify tag is at back
    EXPECT_EQ(0xAA, sslhelp_format[4]);
    EXPECT_EQ(0xAA, sslhelp_format[5]);
}

TEST_F(AeadUtilsTest, VerifySslHelpFormat)
{
    // Simulate SslHelp output: [ ciphertext ] [ TAG ]
    std::vector<std::uint8_t> sslhelp_output = {
        // Ciphertext (4 bytes)
        0x01,
        0x02,
        0x03,
        0x04,
        // Tag (16 bytes) - last in SslHelp format
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xBB,
        0xBB,
        0xBB,
        0xBB,
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xDD,
        0xDD,
        0xDD,
        0xDD};

    // Convert to OpenVPN format for transmission
    auto openvpn_format = ReorderTagToFront(sslhelp_output);

    // Verify tag is now at front
    EXPECT_EQ(0xAA, openvpn_format[0]);
    EXPECT_EQ(0xAA, openvpn_format[1]);
    // Verify ciphertext is after tag
    EXPECT_EQ(0x01, openvpn_format[16]);
    EXPECT_EQ(0x02, openvpn_format[17]);
    EXPECT_EQ(0x03, openvpn_format[18]);
    EXPECT_EQ(0x04, openvpn_format[19]);
}

} // namespace clv::vpn::openvpn::test
