// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/tls_crypt.h"
#include "openvpn/packet.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <numeric>
#include <optional>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>
#include <span>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace clv::vpn::openvpn;

// OpenVPN static key format: 256 bytes of hex inside PEM envelope.
// This is a deterministic test key — NOT for production use.
static const std::string kTestKeyString = R"(#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
ae21eb58f6a3b3621d924a795437603d
69677066303aedd8d822b5281737c3e1
a9adc19f62fc329c78b05a715b92e6ef
474e44d870596a071c9c2b7b006f7a50
12fd11f766f3768aec84b34eca921630
728537a9e42a76dbbfc6113d81305f6e
8c9c0253215ec5f1e09bb0c1eba9275f
80bc6d57a11a899288ca14c0f55e5a28
d576be4c86d593fbbe9ed2d55346c10c
59ad6d1479284223561535290e5db9aa
076e4b085fd73704f426e7e758aa5108
061407b814ef04e230af53ae67068f8b
148b3f13af910687d92c37bcce262e74
90aa3773149dfe6d894b1af094d0a955
fc20e02843f573014fd381b10db82b67
3251a2cf4128652dfdb072cd1438b88d
-----END OpenVPN Static key V1-----
)";

// 256 raw bytes matching kTestKeyString (pre-parsed for FromKeyData tests)
static std::vector<std::uint8_t> MakeTestKeyData()
{
    // Parse hex pairs from kTestKeyString
    std::vector<std::uint8_t> data;
    data.reserve(256);
    bool in_key = false;
    std::istringstream ss(kTestKeyString);
    std::string line;
    while (std::getline(ss, line))
    {
        if (line.find("-----BEGIN") != std::string::npos)
        {
            in_key = true;
            continue;
        }
        if (line.find("-----END") != std::string::npos)
            break;
        if (!in_key)
            continue;
        for (size_t i = 0; i + 1 < line.size(); i += 2)
        {
            if (std::isxdigit(line[i]) && std::isxdigit(line[i + 1]))
                data.push_back(
                    static_cast<std::uint8_t>(std::stoul(line.substr(i, 2), nullptr, 16)));
        }
    }
    return data;
}

class TlsCryptTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        logger_ = std::make_unique<spdlog::logger>("test_tls_crypt", null_sink);

        const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
        temp_dir_ = fs::path(TEST_TMP_DIR) / (std::string("tls_crypt_") + info->name());
        fs::create_directories(temp_dir_);
    }

    void TearDown() override
    {
        if (fs::exists(temp_dir_))
            fs::remove_all(temp_dir_);
    }

    /// Build a minimal plaintext suitable for Wrap(): [opcode_byte] [session_id:8] [payload...]
    static std::vector<std::uint8_t> MakePlaintext(Opcode opcode, std::uint8_t key_id,
                                                   std::uint64_t session_id,
                                                   std::span<const std::uint8_t> payload = {})
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(MakeOpcodeByte(opcode, key_id));
        for (int i = 7; i >= 0; --i)
            buf.push_back(static_cast<std::uint8_t>((session_id >> (i * 8)) & 0xFF));
        buf.insert(buf.end(), payload.begin(), payload.end());
        return buf;
    }

    std::unique_ptr<spdlog::logger> logger_;
    fs::path temp_dir_;
};

// ─── Construction / Key Loading ─────────────────────────────────────

TEST_F(TlsCryptTest, FromKeyStringValid)
{
    auto tc = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc.has_value());
}

TEST_F(TlsCryptTest, FromKeyStringEmptyFails)
{
    auto tc = TlsCrypt::FromKeyString("", *logger_);
    EXPECT_FALSE(tc.has_value());
}

TEST_F(TlsCryptTest, FromKeyStringTruncatedFails)
{
    // Only the first half of the key envelope
    std::string truncated = R"(-----BEGIN OpenVPN Static key V1-----
ae21eb58f6a3b3621d924a795437603d
69677066303aedd8d822b5281737c3e1
-----END OpenVPN Static key V1-----)";
    auto tc = TlsCrypt::FromKeyString(truncated, *logger_);
    EXPECT_FALSE(tc.has_value());
}

TEST_F(TlsCryptTest, FromKeyStringGarbageFails)
{
    auto tc = TlsCrypt::FromKeyString("not a key at all", *logger_);
    EXPECT_FALSE(tc.has_value());
}

TEST_F(TlsCryptTest, FromKeyDataValid)
{
    auto key_data = MakeTestKeyData();
    ASSERT_EQ(key_data.size(), 256u);
    auto tc = TlsCrypt::FromKeyData(key_data, *logger_);
    ASSERT_TRUE(tc.has_value());
}

TEST_F(TlsCryptTest, FromKeyDataWrongSizeFails)
{
    std::vector<std::uint8_t> short_key(128, 0xAA);
    EXPECT_FALSE(TlsCrypt::FromKeyData(short_key, *logger_).has_value());

    std::vector<std::uint8_t> long_key(512, 0xBB);
    EXPECT_FALSE(TlsCrypt::FromKeyData(long_key, *logger_).has_value());

    std::vector<std::uint8_t> empty_key;
    EXPECT_FALSE(TlsCrypt::FromKeyData(empty_key, *logger_).has_value());
}

TEST_F(TlsCryptTest, FromKeyFileValid)
{
    auto key_path = temp_dir_ / "tls-crypt.key";
    std::ofstream(key_path) << kTestKeyString;

    auto tc = TlsCrypt::FromKeyFile(key_path.string(), *logger_);
    ASSERT_TRUE(tc.has_value());
}

TEST_F(TlsCryptTest, FromKeyFileNonexistentFails)
{
    auto tc = TlsCrypt::FromKeyFile("/nonexistent/path/key.key", *logger_);
    EXPECT_FALSE(tc.has_value());
}

TEST_F(TlsCryptTest, FromKeyFileEmptyFails)
{
    auto key_path = temp_dir_ / "empty.key";
    std::ofstream(key_path) << "";

    auto tc = TlsCrypt::FromKeyFile(key_path.string(), *logger_);
    EXPECT_FALSE(tc.has_value());
}

// ─── Wrap / Unwrap Round-Trip ───────────────────────────────────────

TEST_F(TlsCryptTest, WrapUnwrapRoundTripClientToServer)
{
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc_server = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    const std::uint64_t session_id = 0x0102030405060708ULL;
    std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    auto plaintext = MakePlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0, session_id, payload);

    // Client wraps (server_mode=false), server unwraps (server_mode=true)
    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());
    EXPECT_GT(wrapped->size(), plaintext.size()); // encrypted + HMAC overhead

    auto unwrapped = tc_server->Unwrap(*wrapped, true);
    ASSERT_TRUE(unwrapped.has_value());

    // Unwrap returns: [opcode] [session_id:8] [payload]
    ASSERT_EQ(unwrapped->size(), plaintext.size());
    EXPECT_EQ((*unwrapped)[0], plaintext[0]); // opcode byte preserved
    EXPECT_EQ(std::vector<std::uint8_t>(unwrapped->begin(), unwrapped->end()),
              std::vector<std::uint8_t>(plaintext.begin(), plaintext.end()));
}

TEST_F(TlsCryptTest, WrapUnwrapRoundTripServerToClient)
{
    auto tc_server = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_server && tc_client);

    const std::uint64_t session_id = 0xABCDABCDABCDABCDULL;
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
    auto plaintext = MakePlaintext(Opcode::P_CONTROL_HARD_RESET_SERVER_V3, 0, session_id, payload);

    // Server wraps (server_mode=true), client unwraps (server_mode=false)
    auto wrapped = tc_server->Wrap(plaintext, true);
    ASSERT_TRUE(wrapped.has_value());

    auto unwrapped = tc_client->Unwrap(*wrapped, false);
    ASSERT_TRUE(unwrapped.has_value());
    EXPECT_EQ(*unwrapped, plaintext);
}

TEST_F(TlsCryptTest, WrapUnwrapEmptyPayload)
{
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc_server = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    // opcode + session_id, no payload
    auto plaintext = MakePlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0, 0x1111111111111111ULL);

    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    auto unwrapped = tc_server->Unwrap(*wrapped, true);
    ASSERT_TRUE(unwrapped.has_value());
    EXPECT_EQ(*unwrapped, plaintext);
}

TEST_F(TlsCryptTest, WrapUnwrapLargePayload)
{
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc_server = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    // 4 KB payload (simulates large TLS handshake fragment)
    std::vector<std::uint8_t> payload(4096);
    std::iota(payload.begin(), payload.end(), 0);
    auto plaintext = MakePlaintext(Opcode::P_CONTROL_V1, 0, 0x2222222222222222ULL, payload);

    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    auto unwrapped = tc_server->Unwrap(*wrapped, true);
    ASSERT_TRUE(unwrapped.has_value());
    EXPECT_EQ(*unwrapped, plaintext);
}

// ─── Direction Mismatch ─────────────────────────────────────────────

TEST_F(TlsCryptTest, UnwrapWithWrongDirectionFails)
{
    auto tc1 = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc2 = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc1 && tc2);

    auto plaintext = MakePlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0, 0x3333333333333333ULL, std::vector<std::uint8_t>{0xAA, 0xBB});

    // Wrap as client (server_mode=false)
    auto wrapped = tc1->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Try to unwrap as client too (should fail — wrong key direction)
    auto bad_unwrap = tc2->Unwrap(*wrapped, false);
    EXPECT_FALSE(bad_unwrap.has_value());
}

TEST_F(TlsCryptTest, UnwrapServerWrappedAsServerFails)
{
    auto tc1 = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc2 = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc1 && tc2);

    auto plaintext = MakePlaintext(Opcode::P_CONTROL_HARD_RESET_SERVER_V3, 0, 0x4444444444444444ULL);

    auto wrapped = tc1->Wrap(plaintext, true);
    ASSERT_TRUE(wrapped.has_value());

    // Try to unwrap as server (should fail — server wraps for client, not server)
    auto bad_unwrap = tc2->Unwrap(*wrapped, true);
    EXPECT_FALSE(bad_unwrap.has_value());
}

// ─── Tamper Detection ───────────────────────────────────────────────

TEST_F(TlsCryptTest, TamperedCiphertextFails)
{
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc_server = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    auto plaintext = MakePlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0, 0x5555555555555555ULL, std::vector<std::uint8_t>{0x01, 0x02, 0x03, 0x04});
    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Flip a bit in the ciphertext region (after header + HMAC = after byte 49)
    auto tampered = *wrapped;
    if (tampered.size() > 50)
        tampered[50] ^= 0xFF;

    auto result = tc_server->Unwrap(tampered, true);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptTest, TamperedHmacFails)
{
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc_server = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    auto plaintext = MakePlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0, 0x6666666666666666ULL, std::vector<std::uint8_t>{0xAA});
    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Flip a bit in the HMAC tag (bytes 17..48)
    auto tampered = *wrapped;
    tampered[20] ^= 0x01;

    auto result = tc_server->Unwrap(tampered, true);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptTest, TamperedHeaderFails)
{
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc_server = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    auto plaintext = MakePlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0, 0x7777777777777777ULL, std::vector<std::uint8_t>{0xBB, 0xCC});
    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Flip a bit in the header opcode byte
    auto tampered = *wrapped;
    tampered[0] ^= 0x08;

    auto result = tc_server->Unwrap(tampered, true);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptTest, TruncatedPacketFails)
{
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc_server = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    auto plaintext = MakePlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0, 0x8888888888888888ULL, std::vector<std::uint8_t>{0x01, 0x02});
    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Truncate to less than minimum packet size (49 bytes)
    std::vector<std::uint8_t> truncated(wrapped->begin(), wrapped->begin() + 30);

    auto result = tc_server->Unwrap(truncated, true);
    EXPECT_FALSE(result.has_value());
}

// ─── Wrong Key Material ──────────────────────────────────────────────

TEST_F(TlsCryptTest, WrongKeyDecryptFails)
{
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_client.has_value());

    // Create a different key (all zeros)
    std::vector<std::uint8_t> other_key(256, 0x00);
    auto tc_other = TlsCrypt::FromKeyData(other_key, *logger_);
    ASSERT_TRUE(tc_other.has_value());

    auto plaintext = MakePlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0, 0x9999999999999999ULL, std::vector<std::uint8_t>{0xDE, 0xAD});
    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Try to unwrap with wrong key
    auto result = tc_other->Unwrap(*wrapped, true);
    EXPECT_FALSE(result.has_value());
}

// ─── Replay Protection ──────────────────────────────────────────────

TEST_F(TlsCryptTest, ReplayDetection)
{
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc_server = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    auto plaintext = MakePlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0, 0xAAAAAAAAAAAAAAAAULL, std::vector<std::uint8_t>{0x01});

    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // First unwrap succeeds
    auto result1 = tc_server->Unwrap(*wrapped, true);
    ASSERT_TRUE(result1.has_value());

    // Replaying same packet fails (same session_id, same packet_id)
    auto result2 = tc_server->Unwrap(*wrapped, true);
    EXPECT_FALSE(result2.has_value());
}

TEST_F(TlsCryptTest, MonotonicallyIncreasingPacketIdsAccepted)
{
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc_server = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    const std::uint64_t session_id = 0xBBBBBBBBBBBBBBBBULL;

    // Each Wrap() increments the internal packet_id counter, so sequential
    // wraps from the same client should all unwrap successfully.
    for (int i = 0; i < 5; ++i)
    {
        std::vector<std::uint8_t> payload = {static_cast<std::uint8_t>(i)};
        auto pt = MakePlaintext(Opcode::P_CONTROL_V1, 0, session_id, payload);
        auto wrapped = tc_client->Wrap(pt, false);
        ASSERT_TRUE(wrapped.has_value()) << "Wrap failed at iteration " << i;

        auto unwrapped = tc_server->Unwrap(*wrapped, true);
        ASSERT_TRUE(unwrapped.has_value()) << "Unwrap failed at iteration " << i;
        EXPECT_EQ(*unwrapped, pt);
    }
}

TEST_F(TlsCryptTest, OutOfOrderPacketIdRejected)
{
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc_server = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    const std::uint64_t session_id = 0xCCCCCCCCCCCCCCCCULL;

    // Wrap two packets in order
    auto pt1 = MakePlaintext(Opcode::P_CONTROL_V1, 0, session_id, std::vector<std::uint8_t>{0x01});
    auto pt2 = MakePlaintext(Opcode::P_CONTROL_V1, 0, session_id, std::vector<std::uint8_t>{0x02});

    auto wrapped1 = tc_client->Wrap(pt1, false);
    auto wrapped2 = tc_client->Wrap(pt2, false);
    ASSERT_TRUE(wrapped1 && wrapped2);

    // Unwrap packet 2 first (higher packet_id)
    auto r2 = tc_server->Unwrap(*wrapped2, true);
    ASSERT_TRUE(r2.has_value());

    // Now unwrap packet 1 (lower packet_id) — should be rejected as replay
    auto r1 = tc_server->Unwrap(*wrapped1, true);
    EXPECT_FALSE(r1.has_value());
}

// ─── Wire Format Invariants ─────────────────────────────────────────

TEST_F(TlsCryptTest, WrapProducesCorrectWireFormat)
{
    auto tc = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc.has_value());

    const std::uint64_t session_id = 0x0102030405060708ULL;
    auto plaintext = MakePlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0, session_id, std::vector<std::uint8_t>{0xAA, 0xBB, 0xCC});

    auto wrapped = tc->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Wire format: [opcode:1] [session_id:8] [packet_id:8] [hmac:32] [ciphertext]
    // Minimum overhead: 1 + 8 + 8 + 32 = 49 bytes header
    // Payload was 3 bytes -> ciphertext should be >= 3 bytes (CTR mode, same length)
    EXPECT_GE(wrapped->size(), 49u + 3u);

    // Opcode byte should be preserved in the header
    EXPECT_EQ((*wrapped)[0], MakeOpcodeByte(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0));

    // Session ID should be in bytes 1-8
    std::uint64_t wire_sid = 0;
    for (int i = 0; i < 8; ++i)
        wire_sid = (wire_sid << 8) | (*wrapped)[1 + i];
    EXPECT_EQ(wire_sid, session_id);
}

TEST_F(TlsCryptTest, WrapTooSmallInputFails)
{
    auto tc = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc.has_value());

    // Less than 9 bytes (opcode + session_id)
    std::vector<std::uint8_t> too_small = {0x50};
    auto result = tc->Wrap(too_small, false);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptTest, UnwrapTooSmallFails)
{
    auto tc = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc.has_value());

    // Less than minimum 49 bytes
    std::vector<std::uint8_t> tiny(10, 0x00);
    auto result = tc->Unwrap(tiny, true);
    EXPECT_FALSE(result.has_value());
}

// ─── Different Sessions Have Independent Replay State ───────────────

TEST_F(TlsCryptTest, DifferentSessionsHaveIndependentReplayWindows)
{
    auto tc_client = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    auto tc_server = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    // Two different session IDs
    const std::uint64_t sid1 = 0x1111111111111111ULL;
    const std::uint64_t sid2 = 0x2222222222222222ULL;

    auto pt1 = MakePlaintext(Opcode::P_CONTROL_V1, 0, sid1, std::vector<std::uint8_t>{0x01});
    auto pt2 = MakePlaintext(Opcode::P_CONTROL_V1, 0, sid2, std::vector<std::uint8_t>{0x02});

    auto w1 = tc_client->Wrap(pt1, false);
    auto w2 = tc_client->Wrap(pt2, false);
    ASSERT_TRUE(w1 && w2);

    // Unwrap both — different sessions, both should succeed even though
    // w2 has higher packet_id than w1 (they're in different session buckets)
    auto r1 = tc_server->Unwrap(*w1, true);
    auto r2 = tc_server->Unwrap(*w2, true);
    EXPECT_TRUE(r1.has_value());
    EXPECT_TRUE(r2.has_value());
}

// ─── CTR Mode Produces Different Ciphertext For Same Plaintext ──────

TEST_F(TlsCryptTest, SamePlaintextProducesDifferentCiphertext)
{
    auto tc = TlsCrypt::FromKeyString(kTestKeyString, *logger_);
    ASSERT_TRUE(tc.has_value());

    auto plaintext = MakePlaintext(Opcode::P_CONTROL_V1, 0, 0xDDDDDDDDDDDDDDDDULL, std::vector<std::uint8_t>{0x42, 0x42, 0x42});

    auto w1 = tc->Wrap(plaintext, false);
    auto w2 = tc->Wrap(plaintext, false);
    ASSERT_TRUE(w1 && w2);

    // Same plaintext but different packet_id -> different HMAC -> different IV -> different ciphertext
    EXPECT_NE(*w1, *w2);
}

// ─── Key File Format Edge Cases ─────────────────────────────────────

TEST_F(TlsCryptTest, FromKeyStringWithExtraWhitespaceAndComments)
{
    // Add extra comments and whitespace that should be ignored
    std::string key_with_noise = "# Extra comment at top\n"
                                 "\n"
                                 "# Another comment\n"
                                 + kTestKeyString;
    auto tc = TlsCrypt::FromKeyString(key_with_noise, *logger_);
    EXPECT_TRUE(tc.has_value());
}

TEST_F(TlsCryptTest, FromKeyStringMissingEndMarkerFails)
{
    // Has BEGIN but no END — parser will read past the hex and end with wrong size
    std::string no_end = "-----BEGIN OpenVPN Static key V1-----\n"
                         "ae21eb58f6a3b3621d924a795437603d\n";
    auto tc = TlsCrypt::FromKeyString(no_end, *logger_);
    EXPECT_FALSE(tc.has_value());
}
