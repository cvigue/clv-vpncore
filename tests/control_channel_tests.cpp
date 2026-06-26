// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/control_channel.h"
#include "openvpn/control_channel_fragment.h"
#include "openvpn/key_derivation.h"
#include "openvpn/packet.h"
#include "openvpn/tls_context.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <initializer_list>
#include <memory>
#include <optional>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>
#include <vector>

namespace clv::vpn::openvpn {

class ControlChannelTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        logger_ = std::make_unique<spdlog::logger>("test_control_channel", null_sink);
        channel_ = std::make_unique<ControlChannel>(*logger_);
    }

    ControlChannel &channel()
    {
        return *channel_;
    }

    std::unique_ptr<spdlog::logger> logger_;
    std::unique_ptr<ControlChannel> channel_;
};

// Initialization tests
TEST_F(ControlChannelTest, DefaultStateIsDisconnected)
{
    EXPECT_EQ(channel().GetState(), ControlChannel::State::Disconnected);
    EXPECT_FALSE(channel().IsActive());
}

TEST_F(ControlChannelTest, InitializeTransitionsFromDisconnected)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, session_id, std::nullopt)); // true = is_server
    EXPECT_EQ(channel().GetSessionId().value, session_id.value);
}

TEST_F(ControlChannelTest, InitializeOnlyFromDisconnected)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, session_id, std::nullopt));
    SessionId other_session = SessionId::Generate();
    EXPECT_FALSE(channel().Initialize(PeerRole::Server, other_session, std::nullopt));
}

// Hard reset tests
TEST_F(ControlChannelTest, StartHardResetFromDisconnected)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Client, session_id, std::nullopt)); // false = is_client
    auto packet_data = channel().StartHardReset(0);
    EXPECT_FALSE(packet_data.empty());
    EXPECT_EQ(channel().GetState(), ControlChannel::State::HardResetPending);
}

TEST_F(ControlChannelTest, StartHardResetGeneratesValidPacket)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Client, session_id, std::nullopt));
    auto packet_data = channel().StartHardReset(3);
    EXPECT_FALSE(packet_data.empty());
    auto parsed = OpenVpnPacket::Parse(packet_data);
    ASSERT_TRUE(parsed.has_value());
    auto pkt = parsed.value();
    EXPECT_EQ(pkt.key_id_, 3);
    EXPECT_TRUE(pkt.session_id_.has_value());
    EXPECT_EQ(pkt.session_id_.value(), session_id.value);
    EXPECT_EQ(pkt.opcode_, Opcode::P_CONTROL_HARD_RESET_CLIENT_V3);
}

TEST_F(ControlChannelTest, HandleHardResetTransitionsToTlsHandshake)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, session_id, std::nullopt));
    OpenVpnPacket reset_packet;
    reset_packet.opcode_ = Opcode::P_CONTROL_HARD_RESET_SERVER_V3;
    reset_packet.key_id_ = 0;
    reset_packet.session_id_ = session_id.value;
    reset_packet.packet_id_ = 1;
    reset_packet.payload_ = {};
    EXPECT_TRUE(channel().HandleHardReset(reset_packet));
    EXPECT_EQ(channel().GetState(), ControlChannel::State::TlsHandshake);
}

// Sequencing tests
TEST_F(ControlChannelTest, PacketIdSequenceStrictlyIncreasing)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, session_id, std::nullopt));
    auto id1 = channel().GetNextPacketId();
    auto id2 = channel().GetNextPacketId();
    auto id3 = channel().GetNextPacketId();
    EXPECT_LT(id1, id2);
    EXPECT_LT(id2, id3);
}

// Soft reset tests
TEST_F(ControlChannelTest, SoftResetOnlyFromActiveState)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, session_id, std::nullopt));
    TlsCertConfig dummy_cert{};
    auto soft_reset = channel().RequestSoftReset(PeerRole::Server, dummy_cert);
    EXPECT_TRUE(soft_reset.empty());
}

// Retransmission tests
TEST_F(ControlChannelTest, ProcessRetransmissionsReturnsEmptyWhenNoRetransmitsNeeded)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Client, session_id, std::nullopt));
    auto reset_pkt = channel().StartHardReset(0);
    EXPECT_FALSE(reset_pkt.empty());
    auto retransmit_list = channel().ProcessRetransmissions();
    EXPECT_TRUE(retransmit_list.empty());
}

TEST_F(ControlChannelTest, ProcessRetransmissionsTriggersAfterTimeout)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Client, session_id, std::nullopt));
    auto reset_pkt = channel().StartHardReset(0);
    EXPECT_FALSE(reset_pkt.empty());
    auto future = std::chrono::steady_clock::now() + std::chrono::milliseconds(600);
    auto retransmit_list = channel().ProcessRetransmissions(future);
    EXPECT_FALSE(retransmit_list.empty());
    EXPECT_EQ(retransmit_list.size(), 1);
}

TEST_F(ControlChannelTest, AckedPacketsNotRetransmitted)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Client, session_id, std::nullopt));
    auto reset_pkt = channel().StartHardReset(0);
    EXPECT_FALSE(reset_pkt.empty());
    OpenVpnPacket ack_pkt;
    ack_pkt.opcode_ = Opcode::P_ACK_V1;
    ack_pkt.key_id_ = 0;
    ack_pkt.session_id_ = session_id.value;
    ack_pkt.packet_id_array_ = {1};
    ack_pkt.payload_ = {};
    EXPECT_TRUE(channel().HandleAck(ack_pkt));
    auto future = std::chrono::steady_clock::now() + std::chrono::milliseconds(150);
    auto retransmit_list = channel().ProcessRetransmissions(future);
    EXPECT_TRUE(retransmit_list.empty());
}

TEST_F(ControlChannelTest, AckTrackerBackoffAndCap)
{
    AckTracker tracker;
    tracker.sent_at_ = std::chrono::steady_clock::now();

    EXPECT_EQ(tracker.CurrentRetransmitTimeout(), std::chrono::milliseconds(500));

    tracker.retransmit_count_ = 1;
    EXPECT_EQ(tracker.CurrentRetransmitTimeout(), std::chrono::milliseconds(1000));

    tracker.retransmit_count_ = 2;
    EXPECT_EQ(tracker.CurrentRetransmitTimeout(), std::chrono::milliseconds(2000));

    tracker.retransmit_count_ = 6; // would be 32s without cap
    EXPECT_EQ(tracker.CurrentRetransmitTimeout(), std::chrono::milliseconds(8000));
}

TEST_F(ControlChannelTest, ShouldRetransmitUsesBackoff)
{
    AckTracker tracker;
    tracker.sent_at_ = std::chrono::steady_clock::now();

    // At t0 no retransmit
    EXPECT_FALSE(tracker.ShouldRetransmit(tracker.sent_at_ + std::chrono::milliseconds(400)));

    // After initial RTO
    EXPECT_TRUE(tracker.ShouldRetransmit(tracker.sent_at_ + std::chrono::milliseconds(600)));

    // Increment count and verify larger delay
    tracker.retransmit_count_ = 3; // effective timeout 4000ms
    tracker.sent_at_ = std::chrono::steady_clock::now();
    EXPECT_FALSE(tracker.ShouldRetransmit(tracker.sent_at_ + std::chrono::milliseconds(3000)));
    EXPECT_TRUE(tracker.ShouldRetransmit(tracker.sent_at_ + std::chrono::milliseconds(4100)));
}

// Integration tests
TEST_F(ControlChannelTest, ClientHandshakeSequence)
{
    SessionId client_session = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Client, client_session, std::nullopt));
    auto client_reset = channel().StartHardReset(0);
    EXPECT_FALSE(client_reset.empty());
    EXPECT_EQ(channel().GetState(), ControlChannel::State::HardResetPending);
    auto parsed_reset = OpenVpnPacket::Parse(client_reset);
    ASSERT_TRUE(parsed_reset.has_value());
    EXPECT_EQ(parsed_reset->opcode_, Opcode::P_CONTROL_HARD_RESET_CLIENT_V3);
}

TEST_F(ControlChannelTest, ServerRespondsToClientReset)
{
    SessionId client_session = SessionId::Generate();
    ControlChannel client(*logger_);
    client.Initialize(PeerRole::Client, client_session, std::nullopt);
    ControlChannel server(*logger_);
    server.Initialize(PeerRole::Server, SessionId::Generate(), std::nullopt);
    auto client_reset = client.StartHardReset(0);
    auto parsed = OpenVpnPacket::Parse(client_reset);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(server.HandleHardReset(parsed.value()));
    EXPECT_EQ(server.GetState(), ControlChannel::State::TlsHandshake);
}

TEST_F(ControlChannelTest, PacketKeyIdPreservedAcrossOperations)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Client, session_id, std::nullopt));
    auto reset_pkt = channel().StartHardReset(5);
    auto parsed = OpenVpnPacket::Parse(reset_pkt);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->key_id_, 5);
}

// Note: Hard reset packet generation is tested in integration tests.
// Unit testing is complex due to packet_id being stored in payload and
// requiring proper HMAC/tls-crypt wrapping for V3 packets.

TEST_F(ControlChannelTest, GenerateHardResetResponseInvalidOpcode)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, session_id, std::nullopt));

    // Try to generate response for invalid opcode
    auto response = channel().GenerateHardResetResponse(Opcode::P_DATA_V1);
    EXPECT_TRUE(response.empty());
}

TEST_F(ControlChannelTest, HardResetResponseMatchesClientVersion)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, session_id, std::nullopt));

    // Test V1
    OpenVpnPacket client_v1;
    client_v1.opcode_ = Opcode::P_CONTROL_HARD_RESET_CLIENT_V1;
    client_v1.key_id_ = 0;
    client_v1.session_id_ = 0x11111111;
    client_v1.packet_id_ = 1;
    EXPECT_TRUE(channel().HandleHardReset(client_v1));

    auto response_v1 = channel().GenerateHardResetResponse(client_v1.opcode_);
    auto parsed_v1 = OpenVpnPacket::Parse(response_v1);
    ASSERT_TRUE(parsed_v1.has_value());
    EXPECT_EQ(parsed_v1->opcode_, Opcode::P_CONTROL_HARD_RESET_SERVER_V1);
}

// Test for reset response packet format after ACK serialization refactoring
TEST_F(ControlChannelTest, HardResetResponseContainsPiggybackedAck)
{
    SessionId server_session = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, server_session, std::nullopt));

    // Client sends hard reset with packet_id=0
    OpenVpnPacket client_reset;
    client_reset.opcode_ = Opcode::P_CONTROL_HARD_RESET_CLIENT_V2;
    client_reset.key_id_ = 0;
    client_reset.session_id_ = 0xDEADBEEF12345678ULL;
    client_reset.packet_id_ = 0;
    EXPECT_TRUE(channel().HandleHardReset(client_reset));

    // Generate server response - should ACK client's packet_id=0
    auto response = channel().GenerateHardResetResponse(client_reset.opcode_);
    ASSERT_FALSE(response.empty());

    // Parse and verify structure
    auto parsed = OpenVpnPacket::Parse(response);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->opcode_, Opcode::P_CONTROL_HARD_RESET_SERVER_V2);
    EXPECT_EQ(parsed->session_id_, server_session.value);

    // Must have piggybacked ACK for client's packet_id=0
    ASSERT_EQ(parsed->packet_id_array_.size(), 1);
    EXPECT_EQ(parsed->packet_id_array_[0], 0);

    // Must have remote_session_id (client's session)
    ASSERT_TRUE(parsed->remote_session_id_.has_value());
    EXPECT_EQ(parsed->remote_session_id_.value(), 0xDEADBEEF12345678ULL);

    // Must have our packet_id
    ASSERT_TRUE(parsed->packet_id_.has_value());
    EXPECT_EQ(parsed->packet_id_.value(), 0); // First outbound packet

    // Payload should be empty for hard reset
    EXPECT_TRUE(parsed->payload_.empty());
}

// ACK tracking tests - verify we only ACK after successful processing
TEST_F(ControlChannelTest, RejectedPacketDoesNotQueueAck_WrongState)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, session_id, std::nullopt));
    // State is Disconnected, not TlsHandshake - ProcessTlsData should reject

    OpenVpnPacket control_packet;
    control_packet.opcode_ = Opcode::P_CONTROL_V1;
    control_packet.key_id_ = 0;
    control_packet.session_id_ = session_id.value;
    control_packet.packet_id_ = 0;
    control_packet.payload_ = {0x16, 0x03, 0x01, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};

    size_t ack_count_before = channel().GetPendingAckCount();
    auto result = channel().ProcessTlsData(control_packet);

    EXPECT_FALSE(result.has_value());                            // Rejected
    EXPECT_EQ(channel().GetPendingAckCount(), ack_count_before); // No ACK queued
}

TEST_F(ControlChannelTest, RejectedPacketDoesNotQueueAck_DuplicatePacketId)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, session_id, std::nullopt));

    // Transition to TlsHandshake state via HandleHardReset
    OpenVpnPacket reset_packet;
    reset_packet.opcode_ = Opcode::P_CONTROL_HARD_RESET_CLIENT_V3;
    reset_packet.key_id_ = 0;
    reset_packet.session_id_ = 0x1234567890ABCDEFULL;
    reset_packet.packet_id_ = 0;
    EXPECT_TRUE(channel().HandleHardReset(reset_packet));
    EXPECT_EQ(channel().GetState(), ControlChannel::State::TlsHandshake);

    // First control packet with packet_id=1 should be processed
    // (packet_id=0 was consumed by hard reset)
    OpenVpnPacket control_packet;
    control_packet.opcode_ = Opcode::P_CONTROL_V1;
    control_packet.key_id_ = 0;
    control_packet.session_id_ = session_id.value;
    control_packet.packet_id_ = 1;
    // Valid TLS ClientHello-ish payload (just needs to not crash TLS)
    control_packet.payload_ = {};

    auto result1 = channel().ProcessTlsData(control_packet);
    // May succeed or fail depending on TLS, but packet_id tracking should work
    uint32_t last_id_after_first = channel().GetLastReceivedPacketId();

    // Now try to send the SAME packet_id again - should be rejected as duplicate
    size_t ack_count_before = channel().GetPendingAckCount();
    auto result2 = channel().ProcessTlsData(control_packet);

    EXPECT_FALSE(result2.has_value());                                   // Rejected as duplicate
    EXPECT_EQ(channel().GetPendingAckCount(), ack_count_before);         // No new ACK queued
    EXPECT_EQ(channel().GetLastReceivedPacketId(), last_id_after_first); // Unchanged
}

TEST_F(ControlChannelTest, RejectedPacketDoesNotQueueAck_MissingPacketId)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, session_id, std::nullopt));

    // Transition to TlsHandshake state
    OpenVpnPacket reset_packet;
    reset_packet.opcode_ = Opcode::P_CONTROL_HARD_RESET_CLIENT_V3;
    reset_packet.key_id_ = 0;
    reset_packet.session_id_ = 0x1234567890ABCDEFULL;
    reset_packet.packet_id_ = 0;
    EXPECT_TRUE(channel().HandleHardReset(reset_packet));

    // Control packet without packet_id - should be rejected
    OpenVpnPacket control_packet;
    control_packet.opcode_ = Opcode::P_CONTROL_V1;
    control_packet.key_id_ = 0;
    control_packet.session_id_ = session_id.value;
    control_packet.packet_id_ = std::nullopt; // Missing!
    control_packet.payload_ = {};

    size_t ack_count_before = channel().GetPendingAckCount();
    auto result = channel().ProcessTlsData(control_packet);

    EXPECT_FALSE(result.has_value());                            // Rejected
    EXPECT_EQ(channel().GetPendingAckCount(), ack_count_before); // No ACK queued
}

// ============================================================================
// HandleSoftReset — error paths (entire function was dead)
// ============================================================================

// Helper: build a minimal P_CONTROL_SOFT_RESET_V1 packet.
static OpenVpnPacket MakeSoftResetPacket(std::uint32_t packet_id = 1)
{
    OpenVpnPacket pkt;
    pkt.opcode_ = Opcode::P_CONTROL_SOFT_RESET_V1;
    pkt.key_id_ = 0;
    pkt.packet_id_ = packet_id;
    return pkt;
}

TEST_F(ControlChannelTest, HandleSoftReset_NonSoftResetOpcodeReturnsEmpty)
{
    SessionId sid = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, sid, std::nullopt));

    // A data packet is not a soft reset — must be rejected immediately.
    OpenVpnPacket data_pkt;
    data_pkt.opcode_ = Opcode::P_DATA_V2;
    data_pkt.packet_id_ = 1;

    TlsCertConfig empty_cfg;
    auto result = channel().HandleSoftReset(data_pkt, empty_cfg);
    EXPECT_TRUE(result.empty());
}

TEST_F(ControlChannelTest, HandleSoftReset_WrongStateDisconnectedReturnsEmpty)
{
    // After Initialize, channel is in Disconnected — not Active or KeyMaterialReady.
    SessionId sid = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, sid, std::nullopt));
    EXPECT_EQ(channel().GetState(), ControlChannel::State::Disconnected);

    TlsCertConfig empty_cfg;
    auto result = channel().HandleSoftReset(MakeSoftResetPacket(), empty_cfg);
    EXPECT_TRUE(result.empty());
}

TEST_F(ControlChannelTest, HandleSoftReset_WrongStateHardResetPendingReturnsEmpty)
{
    // Client-side: StartHardReset puts channel into HardResetPending.
    SessionId sid = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Client, sid, std::nullopt));
    auto reset_bytes = channel().StartHardReset(0);
    ASSERT_FALSE(reset_bytes.empty());
    EXPECT_EQ(channel().GetState(), ControlChannel::State::HardResetPending);

    TlsCertConfig empty_cfg;
    auto result = channel().HandleSoftReset(MakeSoftResetPacket(), empty_cfg);
    EXPECT_TRUE(result.empty());
}

TEST_F(ControlChannelTest, HandleSoftReset_DuplicateDuringTlsHandshakeReturnsAck)
{
    // Get channel into TlsHandshake state via Initialize + HandleHardReset.
    SessionId sid = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, sid, std::nullopt));

    OpenVpnPacket hard_reset;
    hard_reset.opcode_ = Opcode::P_CONTROL_HARD_RESET_CLIENT_V3;
    hard_reset.key_id_ = 0;
    hard_reset.session_id_ = SessionId::Generate().value;
    hard_reset.packet_id_ = 1;
    ASSERT_TRUE(channel().HandleHardReset(hard_reset));
    ASSERT_EQ(channel().GetState(), ControlChannel::State::TlsHandshake);

    // A soft reset arriving while already renegotiating must be treated as a
    // retransmit: channel returns an explicit ACK without changing state.
    TlsCertConfig empty_cfg;
    auto ack = channel().HandleSoftReset(MakeSoftResetPacket(2), empty_cfg);
    EXPECT_FALSE(ack.empty());                                            // Should produce an ACK
    EXPECT_EQ(channel().GetState(), ControlChannel::State::TlsHandshake); // State unchanged
}

// ============================================================================
// HandleHardReset — error paths (previously dead per coverage)
// ============================================================================

TEST_F(ControlChannelTest, HandleHardReset_ReturnsFalseWithoutInitialize)
{
    // A freshly constructed channel has no TLS context, so HandleHardReset
    // must reject the packet immediately.
    OpenVpnPacket hard_reset;
    hard_reset.opcode_ = Opcode::P_CONTROL_HARD_RESET_CLIENT_V3;
    hard_reset.key_id_ = 0;
    hard_reset.session_id_ = SessionId::Generate().value;
    hard_reset.packet_id_ = 1;

    EXPECT_FALSE(channel().HandleHardReset(hard_reset));
}

TEST_F(ControlChannelTest, HandleHardReset_ReturnsFalseForNonHardResetOpcode)
{
    SessionId sid = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, sid, std::nullopt));

    // A P_CONTROL_V1 packet is not a hard reset.
    OpenVpnPacket ctrl_pkt;
    ctrl_pkt.opcode_ = Opcode::P_CONTROL_V1;
    ctrl_pkt.key_id_ = 0;
    ctrl_pkt.packet_id_ = 1;

    EXPECT_FALSE(channel().HandleHardReset(ctrl_pkt));
}

TEST_F(ControlChannelTest, HandleHardReset_ReturnsFalseInWrongState)
{
    // Move channel to TlsHandshake via first HandleHardReset, then send a
    // second hard reset — wrong state (not Disconnected or HardResetPending).
    SessionId sid = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, sid, std::nullopt));

    OpenVpnPacket hard_reset;
    hard_reset.opcode_ = Opcode::P_CONTROL_HARD_RESET_CLIENT_V3;
    hard_reset.key_id_ = 0;
    hard_reset.session_id_ = SessionId::Generate().value;
    hard_reset.packet_id_ = 1;

    ASSERT_TRUE(channel().HandleHardReset(hard_reset));
    ASSERT_EQ(channel().GetState(), ControlChannel::State::TlsHandshake);

    // Second hard reset in TlsHandshake state → rejected.
    hard_reset.packet_id_ = 2;
    EXPECT_FALSE(channel().HandleHardReset(hard_reset));
}

// ============================================================================
// InitiateTlsHandshake — failure paths (previously dead per coverage)
// ============================================================================

TEST_F(ControlChannelTest, InitiateTlsHandshake_WrongStateReturnsNullopt)
{
    // After Initialize the channel is in Disconnected state, not TlsHandshake.
    SessionId sid = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(PeerRole::Server, sid, std::nullopt));
    EXPECT_EQ(channel().GetState(), ControlChannel::State::Disconnected);

    auto result = channel().InitiateTlsHandshake();
    EXPECT_FALSE(result.has_value());
}

TEST_F(ControlChannelTest, InitiateTlsHandshake_NoTlsContextReturnsNullopt)
{
    // Channel created but never initialized → no TLS context.
    auto result = channel().InitiateTlsHandshake();
    EXPECT_FALSE(result.has_value());
}

} // namespace clv::vpn::openvpn

// ============================================================================
// detail::GroupTlsRecords — previously dead via private FragmentTlsResponse
// ============================================================================

namespace clv::vpn::openvpn::detail {

namespace {

/// Build a minimal synthetic TLS record: [type][0x03][0x03][len_hi][len_lo][payload...]
std::vector<std::uint8_t> MakeTlsRecord(std::uint8_t type, std::size_t payload_size)
{
    std::vector<std::uint8_t> rec;
    rec.push_back(type); // content type (e.g. 22 = handshake)
    rec.push_back(0x03); // version major (TLS 1.x)
    rec.push_back(0x03); // version minor (TLS 1.2)
    auto len = static_cast<std::uint16_t>(payload_size);
    rec.push_back(static_cast<std::uint8_t>(len >> 8));
    rec.push_back(static_cast<std::uint8_t>(len & 0xFF));
    rec.insert(rec.end(), payload_size, 0xAB); // dummy payload
    return rec;
}

/// Concatenate multiple records into one byte buffer.
std::vector<std::uint8_t> Concat(std::initializer_list<std::vector<std::uint8_t>> recs)
{
    std::vector<std::uint8_t> buf;
    for (const auto &r : recs)
        buf.insert(buf.end(), r.begin(), r.end());
    return buf;
}

} // namespace

TEST(GroupTlsRecords, EmptyInputProducesNoGroups)
{
    auto [groups, truncated] = GroupTlsRecords({}, 1250);
    EXPECT_TRUE(groups.empty());
    EXPECT_FALSE(truncated);
}

TEST(GroupTlsRecords, SingleSmallRecordProducesOneGroup)
{
    auto rec = MakeTlsRecord(22, 100); // 5 + 100 = 105 bytes
    auto [groups, truncated] = GroupTlsRecords(rec, 1250);

    ASSERT_EQ(groups.size(), 1u);
    EXPECT_EQ(groups[0].size(), 105u);
    EXPECT_FALSE(truncated);
}

TEST(GroupTlsRecords, MultipleSmallRecordsFitInOneGroup)
{
    // Three 100-byte records (105 each = 315 total) — all fit within 1250 bytes.
    auto data = Concat({MakeTlsRecord(22, 100), MakeTlsRecord(22, 100), MakeTlsRecord(22, 100)});
    auto [groups, truncated] = GroupTlsRecords(data, 1250);

    ASSERT_EQ(groups.size(), 1u);
    EXPECT_EQ(groups[0].size(), 315u);
    EXPECT_FALSE(truncated);
}

TEST(GroupTlsRecords, MultiFragmentSplit)
{
    // Build two records that together exceed the MTU (200 bytes).
    // Each record is 5 + 120 = 125 bytes.  Two records = 250 > 200 MTU.
    // So the second record must be flushed into a new group.
    auto rec = MakeTlsRecord(22, 120); // 125 bytes each
    auto data = Concat({rec, rec});    // 250 bytes total

    auto [groups, truncated] = GroupTlsRecords(data, 200);

    ASSERT_EQ(groups.size(), 2u);
    EXPECT_EQ(groups[0].size(), 125u);
    EXPECT_EQ(groups[1].size(), 125u);
    EXPECT_FALSE(truncated);
}

TEST(GroupTlsRecords, MalformedRecordBreaksLoop)
{
    // A valid first record, then a header that claims 5000 bytes of payload
    // but the buffer is truncated — GroupTlsRecords must set truncated=true
    // and return only the first group.
    auto valid_rec = MakeTlsRecord(22, 50);                              // 55 bytes
    std::vector<std::uint8_t> bad_header = {22, 0x03, 0x03, 0x13, 0x88}; // claims 5000 bytes
    auto data = Concat({valid_rec, bad_header});                         // total 60 bytes, but header claims 5005

    auto [groups, truncated] = GroupTlsRecords(data, 1250);

    EXPECT_TRUE(truncated);
    // The first valid record is still in a group.
    ASSERT_EQ(groups.size(), 1u);
    EXPECT_EQ(groups[0].size(), 55u);
}

TEST(GroupTlsRecords, ExactlyMtuSizeDoesNotSplit)
{
    // A record that is exactly the MTU size should not trigger a split.
    constexpr size_t mtu = 200;
    auto rec = MakeTlsRecord(22, mtu - 5); // total = exactly mtu bytes
    auto [groups, truncated] = GroupTlsRecords(rec, mtu);

    ASSERT_EQ(groups.size(), 1u);
    EXPECT_FALSE(truncated);
}

} // namespace clv::vpn::openvpn::detail
