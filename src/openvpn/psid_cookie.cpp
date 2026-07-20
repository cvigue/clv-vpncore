// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include "openvpn/psid_cookie.h"
#include "openvpn/packet.h"

#include <HelpSslHmac.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <util/byte_packer.h>

#include <openssl/rand.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstring>
#include <stdexcept>
#include <utility>
#include <vector>

namespace clv::vpn::openvpn {
namespace {

using clv::netcore::multi_uint_to_bytes;
using clv::netcore::read_uint;

std::vector<std::uint8_t> PackSockaddr(const PsidCookieEndpoint &endpoint)
{
    if (endpoint.addr.is_v4())
    {
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(endpoint.port);
        const auto bytes = endpoint.addr.to_v4().to_bytes();
        static_assert(sizeof(sa.sin_addr) == bytes.size());
        std::memcpy(&sa.sin_addr, bytes.data(), bytes.size());
        const auto *raw = reinterpret_cast<const std::uint8_t *>(&sa);
        return std::vector<std::uint8_t>(raw, raw + sizeof(sa));
    }

    if (endpoint.addr.is_v6())
    {
        sockaddr_in6 sa{};
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons(endpoint.port);
        const auto bytes = endpoint.addr.to_v6().to_bytes();
        static_assert(sizeof(sa.sin6_addr) == bytes.size());
        std::memcpy(&sa.sin6_addr, bytes.data(), bytes.size());
        const auto *raw = reinterpret_cast<const std::uint8_t *>(&sa);
        return std::vector<std::uint8_t>(raw, raw + sizeof(sa));
    }

    throw std::invalid_argument("PsidCookieEndpoint: unsupported address family");
}

} // namespace

PsidCookieKey PsidCookieKey::Generate()
{
    std::array<std::uint8_t, 32> key{};
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1)
        throw std::runtime_error("PsidCookieKey::Generate: RAND_bytes failed");
    return PsidCookieKey{key};
}

std::optional<PsidCookieKey> PsidCookieKey::FromBytes(std::span<const std::uint8_t> key)
{
    if (key.size() != 32)
        return std::nullopt;
    std::array<std::uint8_t, 32> arr{};
    std::copy(key.begin(), key.end(), arr.begin());
    return PsidCookieKey{arr};
}

SessionId CalculateSessionIdHmac(const PsidCookieKey &key,
                                 SessionId client_sid,
                                 const PsidCookieEndpoint &endpoint,
                                 int handshake_window,
                                 int offset,
                                 std::uint32_t now_seconds)
{
    if (handshake_window < 0)
        handshake_window = 0;

    // OpenVPN: session_id_time = now / ((handwindow+1)/2) + offset
    const std::uint32_t interval = static_cast<std::uint32_t>((handshake_window + 1) / 2);
    const std::uint32_t denom = interval == 0 ? 1u : interval;
    const std::uint32_t session_id_time = now_seconds / denom + static_cast<std::uint32_t>(offset);

    std::vector<std::uint8_t> data;

    // Host endian for time (OpenVPN: "we do not care about endian")
    const auto *time_bytes = reinterpret_cast<const std::uint8_t *>(&session_id_time);
    data.insert(data.end(), time_bytes, time_bytes + sizeof(session_id_time));

    auto addr_bytes = PackSockaddr(endpoint);
    data.insert(data.end(), addr_bytes.begin(), addr_bytes.end());

    // Client sid as wire/big-endian bytes (matches OpenVPN's raw sid.id[])
    auto sid_bytes = client_sid.ToBytes();
    data.insert(data.end(), sid_bytes.begin(), sid_bytes.end());

    const auto hmac = clv::OpenSSL::HmacSha256(key.bytes(), data);
    return SessionId::FromBytes(std::span<const std::uint8_t>(hmac.data(), 8));
}

bool CheckSessionIdHmac(const PsidCookieKey &key,
                        SessionId server_sid,
                        SessionId client_sid,
                        const PsidCookieEndpoint &endpoint,
                        int handshake_window,
                        std::uint32_t now_seconds)
{
    // OpenVPN 2: offsets -2 .. 1
    for (int offset = -2; offset <= 1; ++offset)
    {
        const auto expected = CalculateSessionIdHmac(key,
                                                     client_sid,
                                                     endpoint,
                                                     handshake_window,
                                                     offset,
                                                     now_seconds);
        if (expected.value == server_sid.value)
            return true;
    }
    return false;
}

std::vector<std::uint8_t> BuildEarlyNegFlagsTlv(std::uint16_t flags)
{
    // [type:u16 BE][length:u16 BE][flags:u16 BE]
    auto arr = multi_uint_to_bytes(TLV_TYPE_EARLY_NEG_FLAGS, kEarlyNegFlagsLength, flags);
    return std::vector<std::uint8_t>(arr.begin(), arr.end());
}

std::optional<std::uint16_t> ParseEarlyNegFlagsTlv(std::span<const std::uint8_t> payload)
{
    // Walk TLVs; accept first EARLY_NEG_FLAGS.
    std::size_t offset = 0;
    while (offset + kTlvHeaderSize <= payload.size())
    {
        const auto type = read_uint<kTlvTypeSize>(payload.subspan(offset));
        const auto length = read_uint<kTlvLengthSize>(payload.subspan(offset + kTlvTypeSize));
        offset += kTlvHeaderSize;
        if (offset + length > payload.size())
            return std::nullopt;
        if (type == TLV_TYPE_EARLY_NEG_FLAGS && length == kEarlyNegFlagsLength)
            return static_cast<std::uint16_t>(read_uint<kEarlyNegFlagsLength>(payload.subspan(offset)));
        offset += length;
    }
    return std::nullopt;
}

OpenVpnPacket BuildCookieHardResetResponse(Opcode client_opcode,
                                           std::uint64_t server_sid,
                                           std::uint64_t client_sid,
                                           std::uint32_t ack_packet_id,
                                           std::uint8_t key_id,
                                           std::vector<std::uint8_t> payload,
                                           std::uint32_t our_packet_id,
                                           bool force_server_v2)
{
    const Opcode effective = force_server_v2 ? Opcode::P_CONTROL_HARD_RESET_CLIENT_V2 : client_opcode;
    auto pkt = OpenVpnPacket::HardResetResponse(effective, key_id, server_sid, our_packet_id);
    pkt.withAcks(std::vector<std::uint32_t>{ack_packet_id}, client_sid);
    pkt.payload_ = std::move(payload);
    return pkt;
}

bool IsEarlyHandshakeCookieEcho(const OpenVpnPacket &packet, bool has_own_packet_id)
{
    if (packet.packet_id_array_.size() != 1)
        return false;
    if (!packet.remote_session_id_)
        return false;
    if (packet.packet_id_array_[0] > 1)
        return false;
    if (has_own_packet_id)
    {
        if (!packet.packet_id_ || *packet.packet_id_ > 1)
            return false;
    }
    return true;
}

} // namespace clv::vpn::openvpn
