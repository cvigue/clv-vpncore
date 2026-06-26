// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/tls_crypt_v2.h"
#include "openvpn/tls_crypt.h"

#include <openssl/pem.h>
#include <openssl/rand.h>

#include <gtest/gtest.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace clv::vpn::openvpn;

// ── Test Fixture ────────────────────────────────────────────────────────────

class TlsCryptV2Test : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        logger_ = std::make_shared<spdlog::logger>("test_tls_crypt_v2", null_sink);

        const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
        temp_dir_ = fs::path(TEST_TMP_DIR) / (std::string("tlscryptv2_") + info->name());
        fs::create_directories(temp_dir_);
    }

    void TearDown() override
    {
        if (fs::exists(temp_dir_))
            fs::remove_all(temp_dir_);
    }

    /// Generate a deterministic 128-byte server key for testing
    static std::array<std::uint8_t, TLS_CRYPT_V2_SERVER_KEY_LEN> MakeTestServerKey()
    {
        std::array<std::uint8_t, TLS_CRYPT_V2_SERVER_KEY_LEN> key{};
        EXPECT_EQ(RAND_bytes(key.data(), static_cast<int>(key.size())), 1);
        return key;
    }

    /// Build a PEM string from raw server key bytes
    static std::string MakeServerKeyPem(std::span<const std::uint8_t> key_data)
    {
        // Use the class static helper indirectly — PEM_write_bio
        BIO *bio = BIO_new(BIO_s_mem());
        EXPECT_NE(bio, nullptr);
        EXPECT_NE(PEM_write_bio(bio,
                                "OpenVPN tls-crypt-v2 server key",
                                "",
                                key_data.data(),
                                static_cast<long>(key_data.size())),
                  0);
        char *buf = nullptr;
        long len = BIO_get_mem_data(bio, &buf);
        std::string pem(buf, static_cast<size_t>(len));
        BIO_free(bio);
        return pem;
    }

    /// Create a simple timestamp metadata blob (type 0x01 + 8-byte big-endian timestamp)
    static std::vector<std::uint8_t> MakeTimestampMetadata()
    {
        std::vector<std::uint8_t> meta;
        meta.push_back(TLS_CRYPT_METADATA_TYPE_TIMESTAMP);
        auto now = static_cast<std::int64_t>(std::time(nullptr));
        // big-endian
        for (int i = 7; i >= 0; --i)
            meta.push_back(static_cast<std::uint8_t>((now >> (i * 8)) & 0xFF));
        return meta;
    }

    /// Create a user metadata blob (type 0x00 + arbitrary payload)
    static std::vector<std::uint8_t> MakeUserMetadata(const std::string &payload)
    {
        std::vector<std::uint8_t> meta;
        meta.push_back(TLS_CRYPT_METADATA_TYPE_USER);
        meta.insert(meta.end(), payload.begin(), payload.end());
        return meta;
    }

    std::shared_ptr<spdlog::logger> logger_;
    fs::path temp_dir_;
};

// ═══════════════════════════════════════════════════════════════════════════
//  Server Key Loading
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsCryptV2Test, FromKeyData_ValidSize)
{
    auto key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(key, *logger_);
    ASSERT_TRUE(v2.has_value());
}

TEST_F(TlsCryptV2Test, FromKeyData_TooShort)
{
    std::vector<std::uint8_t> short_key(64, 0xAA);
    auto v2 = TlsCryptV2::FromKeyData(short_key, *logger_);
    EXPECT_FALSE(v2.has_value());
}

TEST_F(TlsCryptV2Test, FromKeyData_TooLong)
{
    std::vector<std::uint8_t> long_key(256, 0xBB);
    auto v2 = TlsCryptV2::FromKeyData(long_key, *logger_);
    EXPECT_FALSE(v2.has_value());
}

TEST_F(TlsCryptV2Test, FromKeyString_ValidPem)
{
    auto key = MakeTestServerKey();
    auto pem = MakeServerKeyPem(key);
    auto v2 = TlsCryptV2::FromKeyString(pem, *logger_);
    ASSERT_TRUE(v2.has_value());
}

TEST_F(TlsCryptV2Test, FromKeyString_EmptyFails)
{
    auto v2 = TlsCryptV2::FromKeyString("", *logger_);
    EXPECT_FALSE(v2.has_value());
}

TEST_F(TlsCryptV2Test, FromKeyString_WrongLabelFails)
{
    // Create PEM with wrong label
    auto key = MakeTestServerKey();
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio(bio, "OpenVPN Static key V1", "", key.data(), static_cast<long>(key.size()));
    char *buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    std::string wrong_pem(buf, static_cast<size_t>(len));
    BIO_free(bio);

    auto v2 = TlsCryptV2::FromKeyString(wrong_pem, *logger_);
    EXPECT_FALSE(v2.has_value());
}

TEST_F(TlsCryptV2Test, FromKeyString_TruncatedKeyFails)
{
    // PEM with only 64 bytes
    std::array<std::uint8_t, 64> short_key{};
    RAND_bytes(short_key.data(), 64);
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio(bio, "OpenVPN tls-crypt-v2 server key", "", short_key.data(), 64);
    char *buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    std::string pem(buf, static_cast<size_t>(len));
    BIO_free(bio);

    auto v2 = TlsCryptV2::FromKeyString(pem, *logger_);
    EXPECT_FALSE(v2.has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
//  WKc Wrap / Unwrap Round-Trip
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsCryptV2Test, WrapUnwrap_RoundTrip)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    // Generate a random client key
    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    auto metadata = MakeTimestampMetadata();

    auto wkc = v2->WrapClientKey(client_key, metadata);
    ASSERT_TRUE(wkc);
    EXPECT_GT(wkc->size(), TLS_CRYPT_V2_CLIENT_KEY_LEN);

    auto result = v2->UnwrapClientKey(*wkc);
    ASSERT_TRUE(result);
    EXPECT_EQ(result->client_key, client_key);
    EXPECT_EQ(result->metadata, metadata);
}

TEST_F(TlsCryptV2Test, WrapUnwrap_MetadataTimestamp)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    auto metadata = MakeTimestampMetadata();
    ASSERT_EQ(metadata[0], TLS_CRYPT_METADATA_TYPE_TIMESTAMP);
    ASSERT_EQ(metadata.size(), 9u); // 1 type + 8 timestamp bytes

    auto wkc = v2->WrapClientKey(client_key, metadata);
    ASSERT_TRUE(wkc);

    auto result = v2->UnwrapClientKey(*wkc);
    ASSERT_TRUE(result);
    EXPECT_EQ(result->metadata, metadata);
}

TEST_F(TlsCryptV2Test, WrapUnwrap_MetadataUser)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    auto metadata = MakeUserMetadata("test-client-cn=alice");
    ASSERT_EQ(metadata[0], TLS_CRYPT_METADATA_TYPE_USER);

    auto wkc = v2->WrapClientKey(client_key, metadata);
    ASSERT_TRUE(wkc);

    auto result = v2->UnwrapClientKey(*wkc);
    ASSERT_TRUE(result);
    EXPECT_EQ(result->metadata, metadata);
}

TEST_F(TlsCryptV2Test, WrapUnwrap_EmptyMetadata)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    // Empty metadata (no type byte even — edge case)
    std::vector<std::uint8_t> empty_meta;

    auto wkc = v2->WrapClientKey(client_key, empty_meta);
    ASSERT_TRUE(wkc);

    auto result = v2->UnwrapClientKey(*wkc);
    ASSERT_TRUE(result);
    EXPECT_EQ(result->client_key, client_key);
    EXPECT_TRUE(result->metadata.empty());
}

TEST_F(TlsCryptV2Test, WrapUnwrap_MaxMetadata)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    // Max size metadata
    std::vector<std::uint8_t> max_meta(TLS_CRYPT_V2_MAX_METADATA_LEN, 0x42);
    max_meta[0] = TLS_CRYPT_METADATA_TYPE_USER;

    auto wkc = v2->WrapClientKey(client_key, max_meta);
    ASSERT_TRUE(wkc);

    auto result = v2->UnwrapClientKey(*wkc);
    ASSERT_TRUE(result);
    EXPECT_EQ(result->metadata, max_meta);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Unwrap Rejection
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsCryptV2Test, Unwrap_WrongServerKey)
{
    auto key1 = MakeTestServerKey();
    auto key2 = MakeTestServerKey();
    auto v2_wrap = TlsCryptV2::FromKeyData(key1, *logger_);
    auto v2_unwrap = TlsCryptV2::FromKeyData(key2, *logger_);
    ASSERT_TRUE(v2_wrap);
    ASSERT_TRUE(v2_unwrap);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    auto wkc = v2_wrap->WrapClientKey(client_key, MakeTimestampMetadata());
    ASSERT_TRUE(wkc);

    // Unwrap with different server key → HMAC failure
    auto result = v2_unwrap->UnwrapClientKey(*wkc);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptV2Test, Unwrap_TamperedCiphertext)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    auto wkc = v2->WrapClientKey(client_key, MakeTimestampMetadata());
    ASSERT_TRUE(wkc);

    // Flip a byte in the ciphertext region (after tag, before net_len)
    (*wkc)[40] ^= 0xFF;

    auto result = v2->UnwrapClientKey(*wkc);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptV2Test, Unwrap_TamperedHmacTag)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    auto wkc = v2->WrapClientKey(client_key, MakeTimestampMetadata());
    ASSERT_TRUE(wkc);

    // Flip a byte in the HMAC tag
    (*wkc)[0] ^= 0xFF;

    auto result = v2->UnwrapClientKey(*wkc);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptV2Test, Unwrap_TamperedNetLen)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    auto wkc = v2->WrapClientKey(client_key, MakeTimestampMetadata());
    ASSERT_TRUE(wkc);

    // Corrupt the net_len field (last 2 bytes)
    (*wkc)[wkc->size() - 1] ^= 0xFF;

    auto result = v2->UnwrapClientKey(*wkc);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptV2Test, Unwrap_TruncatedBlob)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    // Way too short
    std::vector<std::uint8_t> tiny(16, 0x00);
    auto result = v2->UnwrapClientKey(tiny);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptV2Test, Unwrap_EmptyInput)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::vector<std::uint8_t> empty;
    auto result = v2->UnwrapClientKey(empty);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptV2Test, Unwrap_CorruptedHmacTagReturnsNullopt)
{
    // Generate a valid WKc, then corrupt the HMAC tag (first 32 bytes) so that
    // CRYPTO_memcmp fails → UnwrapClientKey returns nullopt.
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    auto wkc = v2->WrapClientKey(client_key, MakeTimestampMetadata());
    ASSERT_TRUE(wkc);

    // Flip a byte in the second half of the 32-byte HMAC tag (bytes 16-31).
    // Using byte 16 leaves the AES-CTR IV (first 16 bytes) intact so the
    // decryption succeeds but the HMAC comparison fails.
    ASSERT_GE(wkc->size(), 32u);
    (*wkc)[16] ^= 0xFF;

    auto result = v2->UnwrapClientKey(*wkc);
    EXPECT_FALSE(result.has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
//  Client Key File PEM Parsing
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsCryptV2Test, LoadClientKeyString_Valid)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    auto gen = v2->GenerateClientKey(MakeTimestampMetadata());
    ASSERT_TRUE(gen);

    auto pem = TlsCryptV2::EncodeClientKeyPem(gen->client_key, gen->wkc_blob);
    ASSERT_TRUE(pem);

    auto loaded = TlsCryptV2::LoadClientKeyString(*pem, *logger_);
    ASSERT_TRUE(loaded);
    EXPECT_EQ(loaded->client_key, gen->client_key);
    EXPECT_EQ(loaded->wkc_blob, gen->wkc_blob);
}

TEST_F(TlsCryptV2Test, LoadClientKeyString_WrongLabel)
{
    // PEM with server key label but client-sized data
    std::vector<std::uint8_t> data(300, 0xAA);
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio(bio, "OpenVPN tls-crypt-v2 server key", "", data.data(), static_cast<long>(data.size()));
    char *buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    std::string pem(buf, static_cast<size_t>(len));
    BIO_free(bio);

    auto loaded = TlsCryptV2::LoadClientKeyString(pem, *logger_);
    EXPECT_FALSE(loaded.has_value());
}

TEST_F(TlsCryptV2Test, LoadClientKeyString_TooShort)
{
    // PEM with correct label but < 256 bytes
    std::vector<std::uint8_t> data(100, 0xBB);
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio(bio, "OpenVPN tls-crypt-v2 client key", "", data.data(), static_cast<long>(data.size()));
    char *buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    std::string pem(buf, static_cast<size_t>(len));
    BIO_free(bio);

    auto loaded = TlsCryptV2::LoadClientKeyString(pem, *logger_);
    EXPECT_FALSE(loaded.has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
//  Per-Session TlsCrypt Construction
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsCryptV2Test, SessionCrypt_FromKc)
{
    // Verify that TlsCrypt::FromKeyData works with a Kc extracted from WKc
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    auto gen = v2->GenerateClientKey(MakeTimestampMetadata());
    ASSERT_TRUE(gen);

    // This is how the server builds a per-session TlsCrypt
    auto session_crypt = clv::vpn::openvpn::TlsCrypt::FromKeyData(gen->client_key, *logger_);
    ASSERT_TRUE(session_crypt);
}

TEST_F(TlsCryptV2Test, SessionCrypt_DifferentKcCannotCrossDecrypt)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    auto gen1 = v2->GenerateClientKey(MakeTimestampMetadata());
    auto gen2 = v2->GenerateClientKey(MakeTimestampMetadata());
    ASSERT_TRUE(gen1);
    ASSERT_TRUE(gen2);
    EXPECT_NE(gen1->client_key, gen2->client_key);

    auto crypt1 = clv::vpn::openvpn::TlsCrypt::FromKeyData(gen1->client_key, *logger_);
    auto crypt2 = clv::vpn::openvpn::TlsCrypt::FromKeyData(gen2->client_key, *logger_);
    ASSERT_TRUE(crypt1);
    ASSERT_TRUE(crypt2);

    // Build a minimal control packet to wrap
    std::vector<std::uint8_t> test_packet = {0x38, // opcode byte (P_CONTROL_HARD_RESET_CLIENT_V3 << 3)
                                             0,
                                             0,
                                             0,
                                             0,
                                             0,
                                             0,
                                             0,
                                             1, // session_id
                                             0x01,
                                             0x02,
                                             0x03}; // payload

    auto wrapped = crypt1->Wrap(test_packet, false);
    ASSERT_TRUE(wrapped);

    // Unwrapping with different key should fail HMAC
    auto unwrapped = crypt2->Unwrap(*wrapped, true);
    EXPECT_FALSE(unwrapped.has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
//  Client Key Generation
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsCryptV2Test, GenerateClientKey_Unique)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    auto gen1 = v2->GenerateClientKey(MakeTimestampMetadata());
    auto gen2 = v2->GenerateClientKey(MakeTimestampMetadata());
    ASSERT_TRUE(gen1);
    ASSERT_TRUE(gen2);

    EXPECT_NE(gen1->client_key, gen2->client_key);
    EXPECT_NE(gen1->wkc_blob, gen2->wkc_blob);
}

TEST_F(TlsCryptV2Test, GenerateClientKey_WkcUnwrapsToSameKc)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    auto metadata = MakeUserMetadata("cn=bob");
    auto gen = v2->GenerateClientKey(metadata);
    ASSERT_TRUE(gen);

    auto result = v2->UnwrapClientKey(gen->wkc_blob);
    ASSERT_TRUE(result);
    EXPECT_EQ(result->client_key, gen->client_key);
    EXPECT_EQ(result->metadata, metadata);
}

TEST_F(TlsCryptV2Test, GenerateClientKey_PemRoundTrip)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    auto gen = v2->GenerateClientKey(MakeTimestampMetadata());
    ASSERT_TRUE(gen);

    // PEM encode
    auto pem = TlsCryptV2::EncodeClientKeyPem(gen->client_key, gen->wkc_blob);
    ASSERT_TRUE(pem);

    // PEM decode
    auto loaded = TlsCryptV2::LoadClientKeyString(*pem, *logger_);
    ASSERT_TRUE(loaded);

    EXPECT_EQ(loaded->client_key, gen->client_key);
    EXPECT_EQ(loaded->wkc_blob, gen->wkc_blob);

    // Unwrap the loaded WKc to verify it still works
    auto unwrapped = v2->UnwrapClientKey(loaded->wkc_blob);
    ASSERT_TRUE(unwrapped);
    EXPECT_EQ(unwrapped->client_key, gen->client_key);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Wire Format Conformance
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsCryptV2Test, WkcBlob_NetLenAtTail)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    auto wkc = v2->WrapClientKey(client_key, MakeTimestampMetadata());
    ASSERT_TRUE(wkc);

    // Last 2 bytes should be htons(wkc->size())
    std::uint16_t net_len_raw = 0;
    std::memcpy(&net_len_raw, wkc->data() + wkc->size() - 2, 2);
    EXPECT_EQ(ntohs(net_len_raw), wkc->size());
}

TEST_F(TlsCryptV2Test, WkcBlob_HmacTagFirst32Bytes)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    auto wkc = v2->WrapClientKey(client_key, MakeTimestampMetadata());
    ASSERT_TRUE(wkc);

    // First 32 bytes are the HMAC tag (non-zero for any realistic key)
    bool all_zero = std::all_of(wkc->begin(), wkc->begin() + 32, [](std::uint8_t b)
    { return b == 0; });
    EXPECT_FALSE(all_zero);
}

TEST_F(TlsCryptV2Test, WkcBlob_SizeConsistency)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    RAND_bytes(client_key.data(), static_cast<int>(client_key.size()));

    auto meta = MakeTimestampMetadata(); // 9 bytes
    auto wkc = v2->WrapClientKey(client_key, meta);
    ASSERT_TRUE(wkc);

    // Expected size: tag(32) + encrypted(256 + 9) + net_len(2) = 299
    // AES-256-CTR: ciphertext same length as plaintext (no padding)
    EXPECT_EQ(wkc->size(), 32u + 256u + meta.size() + 2u);
}

TEST_F(TlsCryptV2Test, WrapClientKey_WrongKeySizeFails)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::vector<std::uint8_t> short_key(128, 0xAA);
    auto wkc = v2->WrapClientKey(short_key, MakeTimestampMetadata());
    EXPECT_FALSE(wkc.has_value());
}

TEST_F(TlsCryptV2Test, WrapClientKey_MetadataTooLargeFails)
{
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    std::array<std::uint8_t, TLS_CRYPT_V2_CLIENT_KEY_LEN> client_key{};
    std::vector<std::uint8_t> huge_meta(TLS_CRYPT_V2_MAX_METADATA_LEN + 1, 0xCC);
    auto wkc = v2->WrapClientKey(client_key, huge_meta);
    EXPECT_FALSE(wkc.has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
//  File-based Key Loading (previously dead)
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(TlsCryptV2Test, FromKeyFile_Valid)
{
    // Write a valid server key PEM to a temp file and load it.
    auto server_key = MakeTestServerKey();
    std::string pem = MakeServerKeyPem(server_key);

    auto path = (temp_dir_ / "server.key").string();
    {
        std::ofstream f(path);
        f << pem;
    }

    auto v2 = TlsCryptV2::FromKeyFile(path, *logger_);
    ASSERT_TRUE(v2.has_value());
}

TEST_F(TlsCryptV2Test, FromKeyFile_FileNotFound)
{
    auto v2 = TlsCryptV2::FromKeyFile("/nonexistent/path/no.key", *logger_);
    EXPECT_FALSE(v2.has_value());
}

TEST_F(TlsCryptV2Test, FromKeyFile_GarbageContent)
{
    auto path = (temp_dir_ / "garbage.key").string();
    {
        std::ofstream f(path);
        f << "this is not a PEM file";
    }

    auto v2 = TlsCryptV2::FromKeyFile(path, *logger_);
    EXPECT_FALSE(v2.has_value());
}

TEST_F(TlsCryptV2Test, LoadClientKeyFile_Valid)
{
    // Generate a client key, encode to PEM, write to temp file, load back.
    auto server_key = MakeTestServerKey();
    auto v2 = TlsCryptV2::FromKeyData(server_key, *logger_);
    ASSERT_TRUE(v2);

    auto gen = v2->GenerateClientKey(MakeTimestampMetadata());
    ASSERT_TRUE(gen);

    auto pem = TlsCryptV2::EncodeClientKeyPem(gen->client_key, gen->wkc_blob);
    ASSERT_TRUE(pem);

    auto path = (temp_dir_ / "client.key").string();
    {
        std::ofstream f(path);
        f << *pem;
    }

    auto loaded = TlsCryptV2::LoadClientKeyFile(path, *logger_);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->client_key, gen->client_key);
    EXPECT_EQ(loaded->wkc_blob, gen->wkc_blob);
}

TEST_F(TlsCryptV2Test, LoadClientKeyFile_FileNotFound)
{
    auto loaded = TlsCryptV2::LoadClientKeyFile("/nonexistent/client.key", *logger_);
    EXPECT_FALSE(loaded.has_value());
}

TEST_F(TlsCryptV2Test, LoadClientKeyFile_TooShort)
{
    // PEM with correct label but fewer than TLS_CRYPT_V2_CLIENT_KEY_LEN bytes.
    std::vector<std::uint8_t> tiny(100, 0xBB);
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio(bio, "OpenVPN tls-crypt-v2 client key", "", tiny.data(), static_cast<long>(tiny.size()));
    char *buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    std::string pem(buf, static_cast<size_t>(len));
    BIO_free(bio);

    auto path = (temp_dir_ / "short_client.key").string();
    {
        std::ofstream f(path);
        f << pem;
    }

    auto loaded = TlsCryptV2::LoadClientKeyFile(path, *logger_);
    EXPECT_FALSE(loaded.has_value());
}
