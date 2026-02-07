// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/control_channel.h"
#include "openvpn/packet.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
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
    EXPECT_TRUE(channel().Initialize(true, session_id, std::nullopt)); // true = is_server
    EXPECT_EQ(channel().GetSessionId().value, session_id.value);
}

TEST_F(ControlChannelTest, InitializeOnlyFromDisconnected)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(true, session_id, std::nullopt));
    SessionId other_session = SessionId::Generate();
    EXPECT_FALSE(channel().Initialize(true, other_session, std::nullopt));
}

// Hard reset tests
TEST_F(ControlChannelTest, StartHardResetFromDisconnected)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(false, session_id, std::nullopt)); // false = is_client
    auto packet_data = channel().StartHardReset(0);
    EXPECT_FALSE(packet_data.empty());
    EXPECT_EQ(channel().GetState(), ControlChannel::State::HardResetPending);
}

TEST_F(ControlChannelTest, StartHardResetGeneratesValidPacket)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(false, session_id, std::nullopt));
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
    EXPECT_TRUE(channel().Initialize(true, session_id, std::nullopt));
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
    EXPECT_TRUE(channel().Initialize(true, session_id, std::nullopt));
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
    EXPECT_TRUE(channel().Initialize(true, session_id, std::nullopt));
    auto soft_reset = channel().RequestSoftReset();
    EXPECT_TRUE(soft_reset.empty());
}

// Retransmission tests
TEST_F(ControlChannelTest, ProcessRetransmissionsReturnsEmptyWhenNoRetransmitsNeeded)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(false, session_id, std::nullopt));
    auto reset_pkt = channel().StartHardReset(0);
    EXPECT_FALSE(reset_pkt.empty());
    auto retransmit_list = channel().ProcessRetransmissions();
    EXPECT_TRUE(retransmit_list.empty());
}

TEST_F(ControlChannelTest, ProcessRetransmissionsTriggersAfterTimeout)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(false, session_id, std::nullopt));
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
    EXPECT_TRUE(channel().Initialize(false, session_id, std::nullopt));
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
    EXPECT_TRUE(channel().Initialize(false, client_session, std::nullopt));
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
    client.Initialize(false, client_session, std::nullopt);
    ControlChannel server(*logger_);
    server.Initialize(true, SessionId::Generate(), std::nullopt);
    auto client_reset = client.StartHardReset(0);
    auto parsed = OpenVpnPacket::Parse(client_reset);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(server.HandleHardReset(parsed.value()));
    EXPECT_EQ(server.GetState(), ControlChannel::State::TlsHandshake);
}

TEST_F(ControlChannelTest, PacketKeyIdPreservedAcrossOperations)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(false, session_id, std::nullopt));
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
    EXPECT_TRUE(channel().Initialize(true, session_id, std::nullopt));

    // Try to generate response for invalid opcode
    auto response = channel().GenerateHardResetResponse(Opcode::P_DATA_V1);
    EXPECT_TRUE(response.empty());
}

TEST_F(ControlChannelTest, HardResetResponseMatchesClientVersion)
{
    SessionId session_id = SessionId::Generate();
    EXPECT_TRUE(channel().Initialize(true, session_id, std::nullopt));

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
    EXPECT_TRUE(channel().Initialize(true, server_session, std::nullopt));

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
    EXPECT_TRUE(channel().Initialize(true, session_id, std::nullopt));
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
    EXPECT_TRUE(channel().Initialize(true, session_id, std::nullopt));

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
    EXPECT_TRUE(channel().Initialize(true, session_id, std::nullopt));

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

} // namespace clv::vpn::openvpn
