// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/tls_crypt.h"
#include "openvpn/packet.h"
#include "test_log_util.h"
#include "tls_crypt_test_util.h"

#include <util/byte_packer.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <numeric>
#include <spdlog/logger.h>
#include <span>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace clv::vpn::openvpn;
using clv::vpn::test::MakeTlsCryptPlaintext;
using clv::vpn::test::TlsCryptTestKeyData;
using clv::vpn::test::TlsCryptTestKeyPemString;

class TlsCryptTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        replay_.Reset();
        logger_ = &clv::vpn::test::NullLogger();

        const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
        temp_dir_ = fs::path(TEST_TMP_DIR) / (std::string("tls_crypt_") + info->name());
        fs::create_directories(temp_dir_);
    }

    void TearDown() override
    {
        if (fs::exists(temp_dir_))
            fs::remove_all(temp_dir_);
    }

    spdlog::logger *logger_{nullptr};
    fs::path temp_dir_;
    TlsCryptReplayState replay_;
};

// ─── Construction / Key Loading ─────────────────────────────────────

TEST_F(TlsCryptTest, FromKeyStringValid)
{
    auto tc = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
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
    auto key_data = TlsCryptTestKeyData();
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
    std::ofstream(key_path) << TlsCryptTestKeyPemString();

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
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    const std::uint64_t session_id = 0x0102030405060708ULL;
    std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, session_id, payload);

    // Client wraps (server_mode=false), server unwraps (server_mode=true)
    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());
    EXPECT_GT(wrapped->size(), plaintext.size()); // encrypted + HMAC overhead

    auto unwrapped = tc_server->Unwrap(*wrapped, true, replay_);
    ASSERT_TRUE(unwrapped.has_value());

    // Unwrap returns: [opcode] [session_id:8] [payload]
    ASSERT_EQ(unwrapped->size(), plaintext.size());
    EXPECT_EQ((*unwrapped)[0], plaintext[0]); // opcode byte preserved
    EXPECT_EQ(std::vector<std::uint8_t>(unwrapped->begin(), unwrapped->end()),
              std::vector<std::uint8_t>(plaintext.begin(), plaintext.end()));
}

TEST_F(TlsCryptTest, WrapUnwrapRoundTripServerToClient)
{
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_server && tc_client);

    const std::uint64_t session_id = 0xABCDABCDABCDABCDULL;
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_SERVER_V2, session_id, payload);

    // Server wraps (server_mode=true), client unwraps (server_mode=false)
    auto wrapped = tc_server->Wrap(plaintext, true);
    ASSERT_TRUE(wrapped.has_value());

    auto unwrapped = tc_client->Unwrap(*wrapped, false, replay_);
    ASSERT_TRUE(unwrapped.has_value());
    EXPECT_EQ(*unwrapped, plaintext);
}

TEST_F(TlsCryptTest, WrapUnwrapEmptyPayload)
{
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    // opcode + session_id, no payload
    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0x1111111111111111ULL);

    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    auto unwrapped = tc_server->Unwrap(*wrapped, true, replay_);
    ASSERT_TRUE(unwrapped.has_value());
    EXPECT_EQ(*unwrapped, plaintext);
}

TEST_F(TlsCryptTest, WrapUnwrapLargePayload)
{
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    // 4 KB payload (simulates large TLS handshake fragment)
    std::vector<std::uint8_t> payload(4096);
    std::iota(payload.begin(), payload.end(), 0);
    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_V1, 0x2222222222222222ULL, payload);

    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    auto unwrapped = tc_server->Unwrap(*wrapped, true, replay_);
    ASSERT_TRUE(unwrapped.has_value());
    EXPECT_EQ(*unwrapped, plaintext);
}

// ─── Direction Mismatch ─────────────────────────────────────────────

TEST_F(TlsCryptTest, UnwrapWithWrongDirectionFails)
{
    auto tc1 = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc2 = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc1 && tc2);

    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0x3333333333333333ULL, std::vector<std::uint8_t>{0xAA, 0xBB});

    // Wrap as client (server_mode=false)
    auto wrapped = tc1->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Try to unwrap as client too (should fail — wrong key direction)
    auto bad_unwrap = tc2->Unwrap(*wrapped, false, replay_);
    EXPECT_FALSE(bad_unwrap.has_value());
}

TEST_F(TlsCryptTest, UnwrapServerWrappedAsServerFails)
{
    auto tc1 = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc2 = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc1 && tc2);

    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_SERVER_V2, 0x4444444444444444ULL);

    auto wrapped = tc1->Wrap(plaintext, true);
    ASSERT_TRUE(wrapped.has_value());

    // Try to unwrap as server (should fail — server wraps for client, not server)
    auto bad_unwrap = tc2->Unwrap(*wrapped, true, replay_);
    EXPECT_FALSE(bad_unwrap.has_value());
}

// ─── Tamper Detection ───────────────────────────────────────────────

TEST_F(TlsCryptTest, TamperedCiphertextFails)
{
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0x5555555555555555ULL, std::vector<std::uint8_t>{0x01, 0x02, 0x03, 0x04});
    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Flip a bit in the ciphertext region (after header + HMAC = after byte 49)
    auto tampered = *wrapped;
    if (tampered.size() > 50)
        tampered[50] ^= 0xFF;

    auto result = tc_server->Unwrap(tampered, true, replay_);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptTest, TamperedHmacFails)
{
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0x6666666666666666ULL, std::vector<std::uint8_t>{0xAA});
    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Flip a bit in the HMAC tag (bytes 17..48)
    auto tampered = *wrapped;
    tampered[20] ^= 0x01;

    auto result = tc_server->Unwrap(tampered, true, replay_);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptTest, TamperedHeaderFails)
{
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0x7777777777777777ULL, std::vector<std::uint8_t>{0xBB, 0xCC});
    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Flip a bit in the header opcode byte
    auto tampered = *wrapped;
    tampered[0] ^= 0x08;

    auto result = tc_server->Unwrap(tampered, true, replay_);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptTest, TruncatedPacketFails)
{
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0x8888888888888888ULL, std::vector<std::uint8_t>{0x01, 0x02});
    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Truncate to less than minimum packet size (49 bytes)
    std::vector<std::uint8_t> truncated(wrapped->begin(), wrapped->begin() + 30);

    auto result = tc_server->Unwrap(truncated, true, replay_);
    EXPECT_FALSE(result.has_value());
}

// ─── Wrong Key Material ──────────────────────────────────────────────

TEST_F(TlsCryptTest, WrongKeyDecryptFails)
{
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client.has_value());

    // Create a different key (all zeros)
    std::vector<std::uint8_t> other_key(256, 0x00);
    auto tc_other = TlsCrypt::FromKeyData(other_key, *logger_);
    ASSERT_TRUE(tc_other.has_value());

    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0x9999999999999999ULL, std::vector<std::uint8_t>{0xDE, 0xAD});
    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Try to unwrap with wrong key
    auto result = tc_other->Unwrap(*wrapped, true, replay_);
    EXPECT_FALSE(result.has_value());
}

// ─── Replay Protection ──────────────────────────────────────────────

TEST_F(TlsCryptTest, ReplayDetection)
{
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0xAAAAAAAAAAAAAAAAULL, std::vector<std::uint8_t>{0x01});

    auto wrapped = tc_client->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // First unwrap succeeds
    auto result1 = tc_server->Unwrap(*wrapped, true, replay_);
    ASSERT_TRUE(result1.has_value());

    // Replaying same packet fails (same session_id, same packet_id)
    auto result2 = tc_server->Unwrap(*wrapped, true, replay_);
    EXPECT_FALSE(result2.has_value());
}

TEST_F(TlsCryptTest, MonotonicallyIncreasingPacketIdsAccepted)
{
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    const std::uint64_t session_id = 0xBBBBBBBBBBBBBBBBULL;

    // Each Wrap() increments the internal packet_id counter, so sequential
    // wraps from the same client should all unwrap successfully.
    for (int i = 0; i < 5; ++i)
    {
        std::vector<std::uint8_t> payload = {static_cast<std::uint8_t>(i)};
        auto pt = MakeTlsCryptPlaintext(Opcode::P_CONTROL_V1, session_id, payload);
        auto wrapped = tc_client->Wrap(pt, false);
        ASSERT_TRUE(wrapped.has_value()) << "Wrap failed at iteration " << i;

        auto unwrapped = tc_server->Unwrap(*wrapped, true, replay_);
        ASSERT_TRUE(unwrapped.has_value()) << "Unwrap failed at iteration " << i;
        EXPECT_EQ(*unwrapped, pt);
    }
}

TEST_F(TlsCryptTest, ReorderWithinWindowAccepted)
{
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    const std::uint64_t session_id = 0xCCCCCCCCCCCCCCCCULL;

    // Wrap two packets in order (counters 1 then 2)
    auto pt1 = MakeTlsCryptPlaintext(Opcode::P_CONTROL_V1, session_id, std::vector<std::uint8_t>{0x01});
    auto pt2 = MakeTlsCryptPlaintext(Opcode::P_CONTROL_V1, session_id, std::vector<std::uint8_t>{0x02});

    auto wrapped1 = tc_client->Wrap(pt1, false);
    auto wrapped2 = tc_client->Wrap(pt2, false);
    ASSERT_TRUE(wrapped1 && wrapped2);

    // Unwrap higher counter first, then lower — sliding window accepts reorder
    auto r2 = tc_server->Unwrap(*wrapped2, true, replay_);
    ASSERT_TRUE(r2.has_value());
    auto r1 = tc_server->Unwrap(*wrapped1, true, replay_);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, pt1);

    // Exact-byte replay of either is rejected
    EXPECT_FALSE(tc_server->Unwrap(*wrapped1, true, replay_).has_value());
    EXPECT_FALSE(tc_server->Unwrap(*wrapped2, true, replay_).has_value());
}

TEST_F(TlsCryptTest, CounterFarBehindWindowRejected)
{
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    const std::uint64_t session_id = 0xDDDDDDDDDDDDDDDDULL;

    // Advance the window past ReplayWindow::kBits so counter 1 is too old.
    std::optional<std::vector<std::uint8_t>> first_wrapped;
    for (std::uint32_t i = 0; i < ReplayWindow::kBits + 2; ++i)
    {
        auto pt = MakeTlsCryptPlaintext(Opcode::P_CONTROL_V1, session_id, std::vector<std::uint8_t>{static_cast<std::uint8_t>(i & 0xff)});
        auto wrapped = tc_client->Wrap(pt, false);
        ASSERT_TRUE(wrapped.has_value());
        if (!first_wrapped)
            first_wrapped = wrapped;
        ASSERT_TRUE(tc_server->Unwrap(*wrapped, true, replay_).has_value()) << "i=" << i;
    }

    // First packet's counter is now outside the window
    EXPECT_FALSE(tc_server->Unwrap(*first_wrapped, true, replay_).has_value());
}

// ─── Wire Format Invariants ─────────────────────────────────────────

TEST_F(TlsCryptTest, WrapProducesCorrectWireFormat)
{
    auto tc = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc.has_value());

    const std::uint64_t session_id = 0x0102030405060708ULL;
    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, session_id, std::vector<std::uint8_t>{0xAA, 0xBB, 0xCC});

    auto wrapped = tc->Wrap(plaintext, false);
    ASSERT_TRUE(wrapped.has_value());

    // Wire format: [opcode:1] [session_id:8] [packet_id:8] [hmac:32] [ciphertext]
    // Minimum overhead: 1 + 8 + 8 + 32 = 49 bytes header
    // Payload was 3 bytes -> ciphertext should be >= 3 bytes (CTR mode, same length)
    EXPECT_GE(wrapped->size(), 49u + 3u);

    // Opcode byte should be preserved in the header
    EXPECT_EQ((*wrapped)[0], MakeOpcodeByte(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 0));

    // Session ID should be in bytes 1-8
    EXPECT_EQ(clv::netcore::read_uint<8>(std::span(*wrapped).subspan(1)), session_id);
}

TEST_F(TlsCryptTest, WrapTooSmallInputFails)
{
    auto tc = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc.has_value());

    // Less than 9 bytes (opcode + session_id)
    std::vector<std::uint8_t> too_small = {0x50};
    auto result = tc->Wrap(too_small, false);
    EXPECT_FALSE(result.has_value());
}

TEST_F(TlsCryptTest, UnwrapTooSmallFails)
{
    auto tc = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc.has_value());

    // Less than minimum 49 bytes
    std::vector<std::uint8_t> tiny(10, 0x00);
    auto result = tc->Unwrap(tiny, true, replay_);
    EXPECT_FALSE(result.has_value());
}

// ─── Different Sessions Have Independent Replay State ───────────────

TEST_F(TlsCryptTest, DifferentSessionsHaveIndependentReplayWindows)
{
    auto tc_client = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client && tc_server);

    // Two different session IDs — each owns its own TlsCryptReplayState
    const std::uint64_t sid1 = 0x1111111111111111ULL;
    const std::uint64_t sid2 = 0x2222222222222222ULL;
    TlsCryptReplayState replay1;
    TlsCryptReplayState replay2;

    auto pt1 = MakeTlsCryptPlaintext(Opcode::P_CONTROL_V1, sid1, std::vector<std::uint8_t>{0x01});
    auto pt2 = MakeTlsCryptPlaintext(Opcode::P_CONTROL_V1, sid2, std::vector<std::uint8_t>{0x02});

    auto w1 = tc_client->Wrap(pt1, false);
    auto w2 = tc_client->Wrap(pt2, false);
    ASSERT_TRUE(w1 && w2);

    // Independent windows: both succeed even though w2 has a higher send counter
    auto r1 = tc_server->Unwrap(*w1, true, replay1);
    auto r2 = tc_server->Unwrap(*w2, true, replay2);
    EXPECT_TRUE(r1.has_value());
    EXPECT_TRUE(r2.has_value());

    // Replay into the other session's window still fails on its own state
    EXPECT_FALSE(tc_server->Unwrap(*w1, true, replay1).has_value());
    EXPECT_FALSE(tc_server->Unwrap(*w2, true, replay2).has_value());
}

TEST_F(TlsCryptTest, MoveSeedPreservesHighest)
{
    TlsCryptReplayState scratch;
    ASSERT_TRUE(scratch.CheckAndAccept(std::uint64_t{3} << 32));
    EXPECT_EQ(scratch.highest(), 3u);

    TlsCryptReplayState seeded = std::move(scratch);
    EXPECT_EQ(seeded.highest(), 3u);
    // Exact counter replay rejected after move-seed
    EXPECT_FALSE(seeded.CheckAndAccept(std::uint64_t{3} << 32));
    // Next counter accepted
    EXPECT_TRUE(seeded.CheckAndAccept(std::uint64_t{4} << 32));
}

TEST_F(TlsCryptTest, PeekWireSessionId)
{
    const std::uint64_t sid = 0x0102030405060708ULL;
    auto pt = MakeTlsCryptPlaintext(Opcode::P_CONTROL_V1, sid, std::vector<std::uint8_t>{0x01});
    auto peeked = PeekWireSessionId(pt);
    ASSERT_TRUE(peeked.has_value());
    EXPECT_EQ(*peeked, sid);
    EXPECT_FALSE(PeekWireSessionId(std::span<const std::uint8_t>{}).has_value());
}

// Characterizes the peer-id gate invariant (server_control_base.h ProcessNetworkPacket;
// _planning/tls-crypt-replay-state.md §4.2). The gate itself is not unit-reachable, so
// this locks the primitive-level property it relies on: two sessions each start their
// wrapper counter at 1, and the sliding window keys only on that counter — so reusing an
// advanced window for a new session's first packet is a DETERMINISTIC replay reject. The
// gate must therefore route a mismatched wire session_id to a fresh (scratch) window.
// Guards against regressing the gate to `session ? member : scratch`.
TEST_F(TlsCryptTest, PeerIdGateInvariant_NewClientNotReplayRejected)
{
    auto tc_server = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_server);

    // Established session X advances its window well past counter 1.
    auto tc_client_x = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client_x);
    const std::uint64_t sid_x = 0xAAAAAAAAAAAAAAAAULL;
    TlsCryptReplayState window_x;
    for (int i = 0; i < 4; ++i)
    {
        auto pt = MakeTlsCryptPlaintext(Opcode::P_CONTROL_V1, sid_x, std::vector<std::uint8_t>{static_cast<std::uint8_t>(i)});
        auto w = tc_client_x->Wrap(pt, false);
        ASSERT_TRUE(w);
        ASSERT_TRUE(tc_server->Unwrap(*w, true, window_x).has_value());
    }
    ASSERT_GT(window_x.highest(), 1u);

    // New client (fresh instance → wrapper counter restarts at 1), new session id,
    // arriving on the same endpoint while X is still established.
    auto tc_client_y = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc_client_y);
    const std::uint64_t sid_y = 0xBBBBBBBBBBBBBBBBULL;
    auto pt_y = MakeTlsCryptPlaintext(Opcode::P_CONTROL_HARD_RESET_CLIENT_V2, sid_y, std::vector<std::uint8_t>{0x01});
    auto w_y = tc_client_y->Wrap(pt_y, false);
    ASSERT_TRUE(w_y);

    // The mismatched wire session_id is visible pre-HMAC — the gate's discriminator.
    auto wire_sid = PeekWireSessionId(*w_y);
    ASSERT_TRUE(wire_sid.has_value());
    EXPECT_NE(*wire_sid, sid_x); // != established peer id → gate must select scratch

    // Correct (scratch) path: the new client's HARD_RESET is accepted.
    TlsCryptReplayState scratch;
    EXPECT_TRUE(tc_server->Unwrap(*w_y, true, scratch).has_value());

    // Wrong (`session ? member : scratch`) path: counter 1 against X's advanced window
    // is a deterministic replay reject — the failure this gate prevents.
    EXPECT_FALSE(tc_server->Unwrap(*w_y, true, window_x).has_value());
}

// ─── CTR Mode Produces Different Ciphertext For Same Plaintext ──────

TEST_F(TlsCryptTest, SamePlaintextProducesDifferentCiphertext)
{
    auto tc = TlsCrypt::FromKeyString(TlsCryptTestKeyPemString(), *logger_);
    ASSERT_TRUE(tc.has_value());

    auto plaintext = MakeTlsCryptPlaintext(Opcode::P_CONTROL_V1, 0xDDDDDDDDDDDDDDDDULL, std::vector<std::uint8_t>{0x42, 0x42, 0x42});

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
                                 + TlsCryptTestKeyPemString();
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
