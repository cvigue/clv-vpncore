// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "packet.h"
#include "protocol_constants.h"
#include "util/byte_packer.h"
#include <openssl/rand.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace clv::vpn::openvpn {

using netcore::multi_uint_to_bytes;
using netcore::read_uint;
using netcore::uint_to_bytes;

// ========== Parse Helpers ==========

/**
 * @brief Parse ACK array from control packet
 * @param data Full packet data
 * @param offset Current offset (updated on success)
 * @param packet Packet to populate with ACKs and remote_session_id
 * @return true on success, false on parse error
 * @note Returns true with no ACKs if no data available (optional ACK array)
 * @note We use out parameters here to allow partial parsing and updating of the relevant fields.
 */
static bool ParseAckArray(std::span<const std::uint8_t> data, std::size_t &offset, OpenVpnPacket &packet)
{
    // ACK array is optional - if no data left, just return success
    if (data.size() <= offset)
        return true;

    std::uint8_t ack_count = data[offset++];
    if (ack_count > OpenVpnPacket::MAX_ACK_COUNT)
        return false;

    if (ack_count > 0)
    {
        // Read ACK IDs (4 bytes each)
        if (data.size() < offset + ack_count * 4)
            return false;
        for (std::uint8_t i = 0; i < ack_count; ++i)
        {
            packet.packet_id_array_.push_back(read_uint<4>(data.subspan(offset)));
            offset += 4;
        }
        // Remote session ID follows ACK array (8 bytes)
        if (data.size() < offset + 8)
            return false;
        packet.remote_session_id_ = read_uint<8>(data.subspan(offset));
        offset += 8;
    }

    return true;
}

/**
 * @brief Parse P_ACK_V1 packet (pure ACK, no packet_id)
 * Format: [ack_count:1][ack_ids:4*n][remote_session_id:8 if n>0]
 * Note: remote_session_id is optional for parsing (may not be present in older packets)
 * @note We use out parameters here to allow partial parsing and updating of the relevant fields.
 */
static bool ParsePureAck(std::span<const std::uint8_t> data, std::size_t &offset, OpenVpnPacket &packet)
{
    if (data.size() < offset + 1)
        return false;

    std::uint8_t ack_count = data[offset++];
    if (ack_count == 0 || ack_count > OpenVpnPacket::MAX_ACK_COUNT)
        return false; // P_ACK_V1 must have at least one ACK

    if (data.size() < offset + ack_count * 4)
        return false;

    for (std::uint8_t i = 0; i < ack_count; ++i)
    {
        packet.packet_id_array_.push_back(read_uint<4>(data.subspan(offset)));
        offset += 4;
    }

    // Remote session ID is optional (8 bytes) - read if present
    if (data.size() >= offset + 8)
    {
        packet.remote_session_id_ = read_uint<8>(data.subspan(offset));
        offset += 8;
    }

    return true;
}

/**
 * @brief Parse control packet with optional ACKs and packet_id
 * Used for: P_CONTROL_V1, P_CONTROL_HARD_RESET_*, P_CONTROL_SOFT_RESET_V1
 * @note packet_id is optional - some packets (e.g., minimal hard reset) may not have it
 * @note We use out parameters here to allow partial parsing and updating of the relevant fields.
 */
static bool ParseControlWithPacketId(std::span<const std::uint8_t> data,
                                     std::size_t &offset, OpenVpnPacket &packet)
{
    // Parse optional ACK array
    if (!ParseAckArray(data, offset, packet))
        return false;

    // Parse packet_id (4 bytes) - optional
    if (data.size() >= offset + 4)
    {
        packet.packet_id_ = read_uint<4>(data.subspan(offset));
        offset += 4;
    }

    return true;
}

/**
 * @brief Parse data packet (P_DATA_V1 or P_DATA_V2)
 * @note We use out parameters here to allow partial parsing and updating of the relevant fields.
 */
static bool ParseDataPacket(std::span<const std::uint8_t> data,
                            std::size_t &offset,
                            OpenVpnPacket &packet)
{
    std::size_t header_start = 0;
    std::size_t header_len = 1; // opcode byte

    if (packet.opcode_ == Opcode::P_DATA_V2)
    {
        // Peer-id (3 bytes)
        if (data.size() < offset + 3)
            return false;
        packet.peer_id_ = read_uint<3>(data.subspan(offset));
        offset += 3;
        header_len += 3;
    }

    // Packet ID (4 bytes)
    if (data.size() < offset + 4)
        return false;
    packet.packet_id_ = read_uint<4>(data.subspan(offset));
    offset += 4;
    header_len += 4;

    // Store AAD (header bytes for AEAD ciphers)
    packet.aad_.assign(data.begin() + header_start, data.begin() + header_start + header_len);

    return true;
}

// ========== Serialize Helpers ==========

/**
 * @brief Serialize ACK array with optional remote_session_id
 * @return true on success, false if ack_count exceeds limit
 */
static bool SerializeAckArray(std::vector<std::uint8_t> &result,
                              const std::vector<std::uint32_t> &ack_ids,
                              std::optional<std::uint64_t> remote_session_id)
{
    if (ack_ids.size() > OpenVpnPacket::MAX_ACK_COUNT)
        return false;

    result.push_back(static_cast<std::uint8_t>(ack_ids.size()));
    for (std::uint32_t id : ack_ids)
    {
        auto id_bytes = uint_to_bytes(id);
        result.insert(result.end(), id_bytes.begin(), id_bytes.end());
    }

    // Remote session ID required when ack_count > 0
    if (!ack_ids.empty() && remote_session_id)
    {
        auto rsid_bytes = uint_to_bytes(*remote_session_id);
        result.insert(result.end(), rsid_bytes.begin(), rsid_bytes.end());
    }

    return true;
}

std::optional<OpenVpnPacket> OpenVpnPacket::Parse(std::span<const std::uint8_t> data)
{
    if (data.empty())
        return std::nullopt;

    OpenVpnPacket packet;

    // Parse opcode byte [opcode:5 | key_id:3]
    const std::uint8_t opcode_byte = data[0];
    packet.opcode_ = GetOpcode(opcode_byte);
    packet.key_id_ = GetKeyId(opcode_byte);

    std::size_t offset = 1;

    if (IsControlPacket(packet.opcode_))
    {
        // Control packets: session_id (8 bytes) + type-specific fields
        if (data.size() < offset + 8)
            return std::nullopt;

        packet.session_id_ = read_uint<8>(data.subspan(offset));
        offset += 8;

        if (packet.opcode_ == Opcode::P_ACK_V1)
        {
            // P_ACK_V1: ACK array only (no packet_id)
            if (!ParsePureAck(data, offset, packet))
                return std::nullopt;
        }
        else
        {
            // All other control packets: optional ACKs + packet_id
            if (!ParseControlWithPacketId(data, offset, packet))
                return std::nullopt;
        }
    }
    else if (IsDataPacket(packet.opcode_))
    {
        // Data packets: optional peer-id + packet_id + AAD
        if (!ParseDataPacket(data, offset, packet))
            return std::nullopt;
    }
    else
    {
        // Unknown opcode
        return std::nullopt;
    }

    // Remaining bytes are payload
    if (offset < data.size())
        packet.payload_.assign(data.begin() + offset, data.end());

    return packet;
}

std::vector<std::uint8_t> OpenVpnPacket::Serialize() const
{
    std::vector<std::uint8_t> result;

    // Opcode byte [opcode:5 | key_id:3]
    result.push_back(MakeOpcodeByte(opcode_, key_id_));

    // Control packets: session ID + packet ID(s) + optional HMAC
    if (IsControlPacket(opcode_))
    {
        if (!session_id_)
            return {}; // Invalid: control packets must have session ID

        // Session ID (8 bytes)
        auto session_bytes = uint_to_bytes(*session_id_);
        result.insert(result.end(), session_bytes.begin(), session_bytes.end());

        // P_ACK_V1: only ACK array (no packet_id)
        if (opcode_ == Opcode::P_ACK_V1)
        {
            if (!SerializeAckArray(result, packet_id_array_, remote_session_id_))
                return {};
        }
        else
        {
            // All other control packets (including hard/soft reset):
            // [ack_count][ack_ids][remote_session_id if count>0][packet_id][payload]
            if (!packet_id_)
                return {};

            if (!SerializeAckArray(result, packet_id_array_, remote_session_id_))
                return {};

            auto id_bytes = uint_to_bytes(*packet_id_);
            result.insert(result.end(), id_bytes.begin(), id_bytes.end());
        }
    }
    else if (IsDataPacket(opcode_))
    {
        // Data packets: [peer-id (3 bytes, P_DATA_V2 only)] + packet_id (4 bytes)
        if (!packet_id_)
            return {}; // Invalid

        if (opcode_ == Opcode::P_DATA_V2)
        {
            // P_DATA_V2: include peer-id (3 bytes, lower 24 bits)
            auto peer_bytes = uint_to_bytes<3>(peer_id_.value_or(0));
            result.insert(result.end(), peer_bytes.begin(), peer_bytes.end());
        }

        auto id_bytes = uint_to_bytes(*packet_id_);
        result.insert(result.end(), id_bytes.begin(), id_bytes.end());
    }
    else
    {
        // Unknown opcode - invalid packet
        return {};
    }

    // Payload
    result.insert(result.end(), payload_.begin(), payload_.end());

    return result;
}

bool OpenVpnPacket::IsValid() const
{
    // Control packets must have session_id
    if (IsControlPacket(opcode_))
    {
        if (!session_id_)
            return false;

        // P_ACK_V1 must have packet_id_array
        if (opcode_ == Opcode::P_ACK_V1)
        {
            return !packet_id_array_.empty();
        }

        // All control packets (including hard/soft reset) use packet_id_ field
        return packet_id_.has_value();
    }

    // Data packets must have packet_id
    if (IsDataPacket(opcode_))
        return packet_id_.has_value();

    return false;
}

SessionId SessionId::Generate()
{
    std::uint64_t val = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&val), sizeof(val)) != 1)
        throw std::runtime_error("RAND_bytes failed generating session ID");
    return SessionId{val};
}

SessionId SessionId::FromBytes(std::span<const std::uint8_t> data)
{
    if (data.size() < 8)
        return SessionId{0};

    return SessionId{read_uint<8>(data)};
}

std::vector<std::uint8_t> SessionId::ToBytes() const
{
    auto bytes = uint_to_bytes(value);
    return std::vector<std::uint8_t>(bytes.begin(), bytes.end());
}

// ========== OpenVpnPacket Factory Methods ==========

OpenVpnPacket OpenVpnPacket::HardReset(bool is_client,
                                       int version,
                                       std::uint8_t key_id,
                                       std::uint64_t session_id,
                                       std::uint32_t packet_id)
{
    Opcode opcode;
    switch (version)
    {
    case 1:
        opcode = is_client ? Opcode::P_CONTROL_HARD_RESET_CLIENT_V1
                           : Opcode::P_CONTROL_HARD_RESET_SERVER_V1;
        break;
    case 2:
        opcode = is_client ? Opcode::P_CONTROL_HARD_RESET_CLIENT_V2
                           : Opcode::P_CONTROL_HARD_RESET_SERVER_V2;
        break;
    case 3:
    default:
        opcode = is_client ? Opcode::P_CONTROL_HARD_RESET_CLIENT_V3
                           : Opcode::P_CONTROL_HARD_RESET_SERVER_V3;
        break;
    }

    OpenVpnPacket pkt;
    pkt.opcode_ = opcode;
    pkt.key_id_ = key_id & KEY_ID_MASK;
    pkt.session_id_ = session_id;
    pkt.packet_id_ = packet_id;
    pkt.payload_ = {};
    return pkt;
}

OpenVpnPacket OpenVpnPacket::HardResetResponse(Opcode client_opcode,
                                               std::uint8_t key_id,
                                               std::uint64_t session_id,
                                               std::uint32_t packet_id)
{
    Opcode response_opcode;
    switch (client_opcode)
    {
    case Opcode::P_CONTROL_HARD_RESET_CLIENT_V1:
        response_opcode = Opcode::P_CONTROL_HARD_RESET_SERVER_V1;
        break;
    case Opcode::P_CONTROL_HARD_RESET_CLIENT_V2:
        response_opcode = Opcode::P_CONTROL_HARD_RESET_SERVER_V2;
        break;
    case Opcode::P_CONTROL_HARD_RESET_CLIENT_V3:
    default:
        response_opcode = Opcode::P_CONTROL_HARD_RESET_SERVER_V3;
        break;
    }

    OpenVpnPacket pkt;
    pkt.opcode_ = response_opcode;
    pkt.key_id_ = key_id & KEY_ID_MASK;
    pkt.session_id_ = session_id;
    pkt.packet_id_ = packet_id;
    pkt.payload_ = {}; // Hard reset has no TLS payload
    return pkt;
}

OpenVpnPacket OpenVpnPacket::SoftReset(std::uint8_t key_id,
                                       std::uint64_t session_id,
                                       std::uint32_t packet_id)
{
    OpenVpnPacket pkt;
    pkt.opcode_ = Opcode::P_CONTROL_SOFT_RESET_V1;
    pkt.key_id_ = key_id & KEY_ID_MASK;
    pkt.session_id_ = session_id;
    pkt.packet_id_ = packet_id;
    pkt.payload_ = {}; // Soft reset has no TLS payload
    return pkt;
}

OpenVpnPacket OpenVpnPacket::Control(std::uint8_t key_id,
                                     std::uint64_t session_id,
                                     std::uint32_t packet_id,
                                     std::vector<std::uint8_t> payload)
{
    OpenVpnPacket pkt;
    pkt.opcode_ = Opcode::P_CONTROL_V1;
    pkt.key_id_ = key_id & KEY_ID_MASK;
    pkt.session_id_ = session_id;
    pkt.packet_id_ = packet_id;
    pkt.payload_ = std::move(payload);
    return pkt;
}

OpenVpnPacket OpenVpnPacket::Ack(std::uint8_t key_id,
                                 std::uint64_t session_id,
                                 std::uint64_t remote_session_id,
                                 std::vector<std::uint32_t> ack_ids)
{
    OpenVpnPacket pkt;
    pkt.opcode_ = Opcode::P_ACK_V1;
    pkt.key_id_ = key_id & KEY_ID_MASK;
    pkt.session_id_ = session_id;
    pkt.remote_session_id_ = remote_session_id;
    pkt.packet_id_array_ = std::move(ack_ids);
    pkt.payload_ = {};
    return pkt;
}

OpenVpnPacket OpenVpnPacket::DataV2(std::uint8_t key_id,
                                    std::uint32_t peer_id,
                                    std::uint32_t packet_id)
{
    OpenVpnPacket pkt;
    pkt.opcode_ = Opcode::P_DATA_V2;
    pkt.key_id_ = key_id & KEY_ID_MASK;
    pkt.peer_id_ = peer_id & PEER_ID_MASK; // Only lower 24 bits used
    pkt.packet_id_ = packet_id;
    pkt.payload_ = {};         // Will be filled with encrypted data
    pkt.aad_ = pkt.BuildAad(); // Pre-compute AAD for encryption
    return pkt;
}

std::vector<std::uint8_t> OpenVpnPacket::BuildAad() const
{
    // AAD is only meaningful for P_DATA_V2 packets
    if (opcode_ != Opcode::P_DATA_V2 || !packet_id_)
        return {};

    // P_DATA_V2 AAD format: [opcode/key_id/peer_id (4 bytes)] [packet_id (4 bytes)]
    // opcode_peer_id = (opcode << 3 | key_id) << 24 | peer_id
    std::uint32_t opcode_peer_id = (MakeOpcodeByte(opcode_, key_id_) << 24)
                                   | (peer_id_.value_or(0) & PEER_ID_MASK);

    auto aad_array = multi_uint_to_bytes(opcode_peer_id, packet_id_.value());
    return std::vector<std::uint8_t>(aad_array.begin(), aad_array.end());
}

} // namespace clv::vpn::openvpn
