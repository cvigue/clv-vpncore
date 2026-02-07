// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"
#include <cstdint>
#include <openvpn/packet.h>
#include <HelpSslHmac.h>
#include <span>
#include <string>
#include <vector>

using namespace clv::vpn::openvpn;

namespace {

[[maybe_unused]] void AppendUint32(std::vector<std::uint8_t> &buf, std::uint32_t value)
{
    buf.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

[[maybe_unused]] void AppendUint64(std::vector<std::uint8_t> &buf, std::uint64_t value)
{
    AppendUint32(buf, static_cast<std::uint32_t>(value >> 32));
    AppendUint32(buf, static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
}

} // namespace

// ============================================================================
// Opcode/Key ID Helpers
// ============================================================================

TEST(OpenVpnPacket, opcode_extraction)
{
    // Opcode 0x04 (P_CONTROL_V1), key_id 0
    std::uint8_t byte = 0x20; // 0b00100000 = (4 << 3) | 0
    EXPECT_EQ(GetOpcode(byte), Opcode::P_CONTROL_V1);
    EXPECT_EQ(GetKeyId(byte), 0);

    // Opcode 0x06 (P_DATA_V1), key_id 2
    byte = 0x32; // 0b00110010 = (6 << 3) | 2
    EXPECT_EQ(GetOpcode(byte), Opcode::P_DATA_V1);
    EXPECT_EQ(GetKeyId(byte), 2);

    // Opcode 0x0A (P_CONTROL_HARD_RESET_CLIENT_V3), key_id 7
    byte = 0x57; // 0b01010111 = (10 << 3) | 7
    EXPECT_EQ(GetOpcode(byte), Opcode::P_CONTROL_HARD_RESET_CLIENT_V3);
    EXPECT_EQ(GetKeyId(byte), 7);
}

TEST(OpenVpnPacket, opcode_construction)
{
    EXPECT_EQ(MakeOpcodeByte(Opcode::P_CONTROL_V1, 0), 0x20);
    EXPECT_EQ(MakeOpcodeByte(Opcode::P_DATA_V1, 2), 0x32);
    EXPECT_EQ(MakeOpcodeByte(Opcode::P_CONTROL_HARD_RESET_CLIENT_V3, 7), 0x57);
}

TEST(OpenVpnPacket, is_control_packet)
{
    EXPECT_TRUE(IsControlPacket(Opcode::P_CONTROL_V1));
    EXPECT_TRUE(IsControlPacket(Opcode::P_CONTROL_HARD_RESET_CLIENT_V2));
    EXPECT_TRUE(IsControlPacket(Opcode::P_ACK_V1));
    EXPECT_FALSE(IsControlPacket(Opcode::P_DATA_V1));
    EXPECT_FALSE(IsControlPacket(Opcode::P_DATA_V2));
}

TEST(OpenVpnPacket, is_data_packet)
{
    EXPECT_TRUE(IsDataPacket(Opcode::P_DATA_V1));
    EXPECT_TRUE(IsDataPacket(Opcode::P_DATA_V2));
    EXPECT_FALSE(IsDataPacket(Opcode::P_CONTROL_V1));
    EXPECT_FALSE(IsDataPacket(Opcode::P_ACK_V1));
}

// ============================================================================
// SessionId
// ============================================================================

TEST(SessionId, generate_unique)
{
    auto id1 = SessionId::Generate();
    auto id2 = SessionId::Generate();
    EXPECT_NE(id1.value, id2.value); // Should be random
}

TEST(SessionId, to_from_bytes)
{
    SessionId id{0x0102030405060708ULL};
    auto bytes = id.ToBytes();

    ASSERT_EQ(bytes.size(), 8);
    // Network byte order (big-endian)
    EXPECT_EQ(bytes[0], 0x01);
    EXPECT_EQ(bytes[1], 0x02);
    EXPECT_EQ(bytes[7], 0x08);

    auto restored = SessionId::FromBytes(bytes);
    EXPECT_EQ(restored.value, id.value);
}

// ============================================================================
// Control Packet Parsing (P_CONTROL_HARD_RESET_CLIENT_V2)
// ============================================================================

TEST(OpenVpnPacket, parse_control_hard_reset_client)
{
    // Simulated P_CONTROL_HARD_RESET_CLIENT_V2 packet
    // Format: [opcode_byte] [session_id:8] [ack_count:1] [packet_id:4] [payload...]
    std::vector<std::uint8_t> raw_packet = {
        0x38, // Opcode 0x07 (P_CONTROL_HARD_RESET_CLIENT_V2), key_id 0
        0x00,
        0x01,
        0x02,
        0x03, // Session ID (high 4 bytes)
        0x04,
        0x05,
        0x06,
        0x07, // Session ID (low 4 bytes)
        0x00, // ACK count = 0 (no piggybacked ACKs)
        0x00,
        0x00,
        0x00,
        0x01, // Packet ID = 1
        0x48,
        0x65,
        0x6c,
        0x6c,
        0x6f // Payload: "Hello"
    };

    auto packet = OpenVpnPacket::Parse(raw_packet);
    ASSERT_TRUE(packet.has_value());

    EXPECT_EQ(packet->opcode_, Opcode::P_CONTROL_HARD_RESET_CLIENT_V2);
    EXPECT_EQ(packet->key_id_, 0);
    EXPECT_TRUE(packet->session_id_.has_value());
    EXPECT_EQ(*packet->session_id_, 0x0001020304050607ULL);
    // Hard reset packets: packet_id IS parsed from the wire
    EXPECT_TRUE(packet->packet_id_.has_value());
    EXPECT_EQ(*packet->packet_id_, 1u);     // packet_id = 1
    EXPECT_EQ(packet->payload_.size(), 5u); // Just "Hello"
    EXPECT_EQ(std::string(packet->payload_.begin(), packet->payload_.end()), "Hello");
    EXPECT_TRUE(packet->IsValid());
}

// NOTE: tls-auth tests removed - this server only supports tls-crypt/tls-crypt-v2
// tls-auth HMAC is not supported. TLS-Crypt handles encryption+authentication at the outer layer.

// ============================================================================
// Control Packet Serialization
// ============================================================================

TEST(OpenVpnPacket, serialize_control_packet)
{
    OpenVpnPacket packet;
    packet.opcode_ = Opcode::P_CONTROL_V1;
    packet.key_id_ = 1;
    packet.session_id_ = 0xAABBCCDDEEFF0011ULL;
    packet.packet_id_ = 42;
    packet.payload_ = {'T', 'e', 's', 't'};

    auto serialized = packet.Serialize();

    // Expected: [opcode_byte:1] [session_id:8] [ack_count:1] [packet_id:4] [payload:4]
    ASSERT_EQ(serialized.size(), 1 + 8 + 1 + 4 + 4);

    EXPECT_EQ(serialized[0], MakeOpcodeByte(Opcode::P_CONTROL_V1, 1));

    // Session ID in network byte order
    EXPECT_EQ(serialized[1], 0xAA);
    EXPECT_EQ(serialized[8], 0x11);

    // ACK count = 0
    EXPECT_EQ(serialized[9], 0x00);

    // Packet ID in network byte order
    EXPECT_EQ(serialized[10], 0x00);
    EXPECT_EQ(serialized[13], 42);

    // Payload
    EXPECT_EQ(serialized[14], 'T');
    EXPECT_EQ(serialized[17], 't');
}

// ============================================================================
// ACK Packet Parsing
// ============================================================================

TEST(OpenVpnPacket, parse_ack_packet)
{
    // P_ACK_V1 with 3 acknowledged packet IDs
    std::vector<std::uint8_t> raw_packet = {
        0x28, // Opcode 0x05 (P_ACK_V1), key_id 0
        0x12,
        0x34,
        0x56,
        0x78, // Session ID (high)
        0x9A,
        0xBC,
        0xDE,
        0xF0, // Session ID (low)
        0x03, // ACK count = 3
        0x00,
        0x00,
        0x00,
        0x01, // ACK packet ID 1
        0x00,
        0x00,
        0x00,
        0x02, // ACK packet ID 2
        0x00,
        0x00,
        0x00,
        0x03 // ACK packet ID 3
    };

    auto packet = OpenVpnPacket::Parse(raw_packet);
    ASSERT_TRUE(packet.has_value());

    EXPECT_EQ(packet->opcode_, Opcode::P_ACK_V1);
    EXPECT_TRUE(packet->session_id_.has_value());
    EXPECT_EQ(packet->packet_id_array_.size(), 3);
    EXPECT_EQ(packet->packet_id_array_[0], 1);
    EXPECT_EQ(packet->packet_id_array_[1], 2);
    EXPECT_EQ(packet->packet_id_array_[2], 3);
    EXPECT_TRUE(packet->IsValid());
}

TEST(OpenVpnPacket, serialize_ack_packet)
{
    OpenVpnPacket packet;
    packet.opcode_ = Opcode::P_ACK_V1;
    packet.key_id_ = 0;
    packet.session_id_ = 0x123456789ABCDEF0ULL;
    packet.packet_id_array_ = {1, 2, 3};

    auto serialized = packet.Serialize();

    // Expected: [opcode] [session:8] [count:1] [id1:4] [id2:4] [id3:4]
    ASSERT_EQ(serialized.size(), 1 + 8 + 1 + 12);
    EXPECT_EQ(serialized[9], 3); // ACK count

    // Parse back and verify
    auto parsed = OpenVpnPacket::Parse(serialized);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->packet_id_array_, packet.packet_id_array_);
}

// ============================================================================
// Data Packet Parsing (P_DATA_V1)
// ============================================================================

TEST(OpenVpnPacket, parse_data_packet)
{
    // P_DATA_V1 with encrypted IP packet payload
    std::vector<std::uint8_t> raw_packet = {
        0x30, // Opcode 0x06 (P_DATA_V1), key_id 0
        0x00,
        0x00,
        0x00,
        0x64, // Packet ID = 100
        0x45,
        0x00,
        0x00,
        0x54 // Start of IP packet (version 4, header length 5...)
    };

    auto packet = OpenVpnPacket::Parse(raw_packet);
    ASSERT_TRUE(packet.has_value());

    EXPECT_EQ(packet->opcode_, Opcode::P_DATA_V1);
    EXPECT_EQ(packet->key_id_, 0);
    EXPECT_TRUE(packet->packet_id_.has_value());
    EXPECT_EQ(*packet->packet_id_, 100);
    EXPECT_EQ(packet->payload_.size(), 4);
    EXPECT_EQ(packet->payload_[0], 0x45); // IPv4 header start
    EXPECT_TRUE(packet->IsValid());
}

TEST(OpenVpnPacket, serialize_data_packet)
{
    OpenVpnPacket packet;
    packet.opcode_ = Opcode::P_DATA_V1;
    packet.key_id_ = 2;
    packet.packet_id_ = 999;
    packet.payload_ = {0x45, 0x00, 0x00, 0x54}; // Simulated IP packet

    auto serialized = packet.Serialize();

    // Expected: [opcode] [packet_id:4] [payload:4]
    ASSERT_EQ(serialized.size(), 1 + 4 + 4);
    EXPECT_EQ(serialized[0], MakeOpcodeByte(Opcode::P_DATA_V1, 2));

    // Parse back and verify
    auto parsed = OpenVpnPacket::Parse(serialized);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed->packet_id_, packet.packet_id_);
    EXPECT_EQ(parsed->payload_, packet.payload_);
}

// ============================================================================
// Data Packet V2 (with peer-id)
// ============================================================================

TEST(OpenVpnPacket, parse_data_v2_packet)
{
    // P_DATA_V2 (opcode 0x09)
    // Format: [opcode+key_id:1] [peer-id:3] [packet_id:4] [payload]
    std::vector<std::uint8_t> raw_packet = {
        0x48, // Opcode 0x09 (P_DATA_V2), key_id 0
        0x00,
        0x00,
        0x01, // peer-id = 1
        0x00,
        0x00,
        0x01,
        0xF4, // Packet ID = 500
        0xFF,
        0xFF // Encrypted payload
    };

    auto packet = OpenVpnPacket::Parse(raw_packet);
    ASSERT_TRUE(packet.has_value());

    EXPECT_EQ(packet->opcode_, Opcode::P_DATA_V2);
    EXPECT_TRUE(packet->packet_id_.has_value());
    EXPECT_EQ(*packet->packet_id_, 500u);
    EXPECT_EQ(packet->payload_.size(), 2u);
}

// ============================================================================
// Roundtrip Tests
// ============================================================================

TEST(OpenVpnPacket, roundtrip_control_packet)
{
    // Use a regular control packet (not hard reset) for roundtrip test
    // Hard reset packets have special payload format handled by control channel
    OpenVpnPacket original;
    original.opcode_ = Opcode::P_CONTROL_V1;
    original.key_id_ = 3;
    original.session_id_ = 0xDEADBEEFCAFEBABEULL;
    original.packet_id_ = 12345;
    original.payload_ = {'R', 'o', 'u', 'n', 'd', 't', 'r', 'i', 'p'};

    auto serialized = original.Serialize();
    ASSERT_FALSE(serialized.empty());

    auto parsed = OpenVpnPacket::Parse(serialized);
    ASSERT_TRUE(parsed.has_value());

    EXPECT_EQ(parsed->opcode_, original.opcode_);
    EXPECT_EQ(parsed->key_id_, original.key_id_);
    EXPECT_EQ(parsed->session_id_, original.session_id_);
    EXPECT_EQ(parsed->packet_id_, original.packet_id_);
    EXPECT_EQ(parsed->payload_, original.payload_);
}

TEST(OpenVpnPacket, roundtrip_data_packet)
{
    OpenVpnPacket original;
    original.opcode_ = Opcode::P_DATA_V2;
    original.key_id_ = 1;
    original.packet_id_ = 999999;
    original.payload_.resize(1400, 0xAB); // Typical UDP payload size

    auto serialized = original.Serialize();
    auto parsed = OpenVpnPacket::Parse(serialized);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->opcode_, original.opcode_);
    EXPECT_EQ(parsed->packet_id_, original.packet_id_);
    EXPECT_EQ(parsed->payload_.size(), 1400);
}

// ============================================================================
// Error Cases
// ============================================================================

TEST(OpenVpnPacket, parse_empty_packet)
{
    std::vector<std::uint8_t> empty;
    auto packet = OpenVpnPacket::Parse(empty);
    EXPECT_FALSE(packet.has_value());
}

TEST(OpenVpnPacket, parse_truncated_control_packet)
{
    // Control packet but missing session ID
    std::vector<std::uint8_t> truncated = {0x20, 0x01, 0x02}; // Only 3 bytes
    auto packet = OpenVpnPacket::Parse(truncated);
    EXPECT_FALSE(packet.has_value());
}

TEST(OpenVpnPacket, serialize_invalid_control_packet)
{
    OpenVpnPacket packet;
    packet.opcode_ = Opcode::P_CONTROL_V1;
    packet.key_id_ = 0;
    // Missing session_id and packet_id

    EXPECT_FALSE(packet.IsValid());
    auto serialized = packet.Serialize();
    EXPECT_TRUE(serialized.empty()); // Should fail gracefully
}

TEST(OpenVpnPacket, serialize_invalid_data_packet)
{
    OpenVpnPacket packet;
    packet.opcode_ = Opcode::P_DATA_V1;
    packet.key_id_ = 0;
    // Missing packet_id

    EXPECT_FALSE(packet.IsValid());
    auto serialized = packet.Serialize();
    EXPECT_TRUE(serialized.empty());
}

// ============================================================================
// ACK Count Limit Tests
// ============================================================================

TEST(OpenVpnPacket, parse_ack_packet_at_limit)
{
    // ACK packet with exactly MAX_ACK_COUNT (8) acknowledgments
    std::vector<std::uint8_t> raw_packet = {
        0x28, // Opcode 0x05 (P_ACK_V1), key_id 0
        0x00,
        0x00,
        0x00,
        0x00, // Session ID (high)
        0x00,
        0x00,
        0x00,
        0x01, // Session ID (low)
        0x08, // ACK count = 8 (at limit)
        0x00,
        0x00,
        0x00,
        0x01, // ACK ID 1
        0x00,
        0x00,
        0x00,
        0x02, // ACK ID 2
        0x00,
        0x00,
        0x00,
        0x03, // ACK ID 3
        0x00,
        0x00,
        0x00,
        0x04, // ACK ID 4
        0x00,
        0x00,
        0x00,
        0x05, // ACK ID 5
        0x00,
        0x00,
        0x00,
        0x06, // ACK ID 6
        0x00,
        0x00,
        0x00,
        0x07, // ACK ID 7
        0x00,
        0x00,
        0x00,
        0x08 // ACK ID 8
    };

    auto packet = OpenVpnPacket::Parse(raw_packet);
    ASSERT_TRUE(packet.has_value());
    EXPECT_EQ(packet->packet_id_array_.size(), 8);
    EXPECT_TRUE(packet->IsValid());
}

TEST(OpenVpnPacket, parse_ack_packet_exceeds_limit)
{
    // ACK packet with 9 acknowledgments (exceeds MAX_ACK_COUNT of 8)
    std::vector<std::uint8_t> raw_packet = {
        0x28, // Opcode 0x05 (P_ACK_V1), key_id 0
        0x00,
        0x00,
        0x00,
        0x00, // Session ID (high)
        0x00,
        0x00,
        0x00,
        0x01, // Session ID (low)
        0x09, // ACK count = 9 (exceeds limit!)
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x03,
        0x00,
        0x00,
        0x00,
        0x04,
        0x00,
        0x00,
        0x00,
        0x05,
        0x00,
        0x00,
        0x00,
        0x06,
        0x00,
        0x00,
        0x00,
        0x07,
        0x00,
        0x00,
        0x00,
        0x08,
        0x00,
        0x00,
        0x00,
        0x09};

    auto packet = OpenVpnPacket::Parse(raw_packet);
    // Should be rejected due to ACK count exceeding limit
    EXPECT_FALSE(packet.has_value());
}

TEST(OpenVpnPacket, serialize_ack_at_limit)
{
    OpenVpnPacket packet;
    packet.opcode_ = Opcode::P_ACK_V1;
    packet.key_id_ = 0;
    packet.session_id_ = 0x0000000100000000ULL;
    packet.packet_id_array_ = {10, 20, 30, 40, 50, 60, 70, 80}; // Exactly 8 (at limit)

    auto serialized = packet.Serialize();
    ASSERT_FALSE(serialized.empty());

    // Should parse back successfully
    auto parsed = OpenVpnPacket::Parse(serialized);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->packet_id_array_.size(), 8);
}

TEST(OpenVpnPacket, serialize_ack_exceeds_limit)
{
    OpenVpnPacket packet;
    packet.opcode_ = Opcode::P_ACK_V1;
    packet.key_id_ = 0;
    packet.session_id_ = 0x0000000100000000ULL;
    packet.packet_id_array_ = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // 9 ACKs (exceeds limit of 8)

    auto serialized = packet.Serialize();
    // Should fail gracefully
    EXPECT_TRUE(serialized.empty());
}
