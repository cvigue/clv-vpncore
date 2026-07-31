// Copyright (c) 2026- Charlie Vigue. All rights reserved.

// Peer-id demux and peer float on the server RX path.
//
// MultiPeerPolicy::DecryptInPlace is driven directly: UdpCore's RxLoop only
// classifies opcodes and writes TUN, so the demux and float decisions all live
// in the policy.

#include "multi_peer_policy.h"
#include "peer_slot_table.h"
#include "openvpn/connection.h"
#include "openvpn/crypto_context.h"
#include "openvpn/data_v2_wire.h"
#include "openvpn/packet.h"
#include "openvpn/session_manager.h"
#include "udp_engine_types.h"

#include <gtest/gtest.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

using namespace clv::vpn;
using namespace clv::vpn::openvpn;

namespace {

spdlog::logger &FloatLogger()
{
    static auto sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    static spdlog::logger logger("test_peer_float", sink);
    return logger;
}

transport::PeerEndpoint Ep(const char *ip, std::uint16_t port)
{
    return transport::PeerEndpoint{.addr = asio::ip::make_address(ip), .port = port};
}

EncryptionKey MakeKey(std::uint8_t seed)
{
    EncryptionKey key;
    key.cipher_algorithm = CipherAlgorithm::AES_256_GCM;
    key.cipher_key.assign(32, seed);
    key.cipher_iv.assign(12, static_cast<std::uint8_t>(seed + 1));
    key.is_valid = true;
    return key;
}

/// Records float notifications instead of posting to a control io_context.
struct RecordingFloatSink : PeerFloatSink
{
    struct Event
    {
        std::uint64_t session_id;
        transport::PeerEndpoint endpoint;
    };
    std::vector<Event> events;

    void OnPeerFloat(std::uint64_t session_id,
                     const transport::PeerEndpoint &endpoint) override
    {
        events.push_back({session_id, endpoint});
    }
};

/// One keyed session, one occupied slot, one published RX snapshot.
struct FloatFixture
{
    static constexpr std::uint32_t kPeerId = 0; // 0 is a real peer-id
    static constexpr std::uint64_t kSessionId = 0xABCDEF0123456789ull;

    PeerSlotTable slots{4};
    DataPlaneContext ctx;
    RecordingFloatSink sink;
    MultiPeerPolicy policy{FloatLogger()};
    CryptoContext client{FloatLogger()};
    std::unique_ptr<Connection> conn;
    PeerSlotTable::Lease lease;

    FloatFixture()
    {
        Connection::Endpoint cep{asio::ip::make_address("192.0.2.10"), 1194};
        conn = std::make_unique<Connection>(SessionId{kSessionId}, cep, true,
                                            std::nullopt, FloatLogger());

        auto lease_opt = slots.Reserve();
        lease = std::move(*lease_opt);
        slots.Occupy(lease.value(), kSessionId, Ep("192.0.2.10", 1194));

        // Same key both directions so the fixture can forge client traffic.
        auto key = MakeKey(0x11);
        client.InstallNewKeys(key, key, 0);

        SessionIndex idx;
        idx.entries[kSessionId] = SessionEntry{
            .conn = conn.get(),
            .encrypt_key = key,
            .decrypt_key = key,
            .key_id = 0,
            .peer_id = lease.value(),
            .endpoint = Ep("192.0.2.10", 1194),
        };
        idx.by_endpoint[Ep("192.0.2.10", 1194)] = kSessionId;
        ctx.PublishSessions(idx);

        policy.ctx = &ctx;
        policy.slots = &slots;
        policy.float_sink = &sink;
        ctx.core->register_thread();
    }

    ~FloatFixture()
    {
        ctx.core->unregister_thread();
    }

    /// Build a client→server P_DATA_V2 datagram for this session's peer-id.
    std::vector<std::uint8_t> MakeDatagram(std::uint32_t peer_id, std::uint8_t payload_byte)
    {
        constexpr std::size_t kPayload = 32;
        std::vector<std::uint8_t> buf(kDataV2Overhead + kPayload, payload_byte);
        buf[kDataV2Overhead] = 0x45; // look like IPv4 so ClassifyDecryptedPayload forwards
        auto packet_id = client.AllocateOutboundPacketId();
        const auto wire_len = client.EncryptPacketInPlaceWithId(buf, kPayload, peer_id, *packet_id);
        buf.resize(wire_len);
        return buf;
    }

    /// Feed one datagram through the RX policy.
    std::span<std::uint8_t> Receive(std::vector<std::uint8_t> &datagram,
                                    const transport::PeerEndpoint &from)
    {
        transport::IncomingSlot slot{
            .buf = datagram.data(),
            .capacity = datagram.size(),
            .len = datagram.size(),
            .sender = from,
        };
        return policy.DecryptInPlace(slot);
    }

    transport::PeerEndpoint SlotEndpoint()
    {
        transport::PeerEndpoint out;
        EXPECT_TRUE(slots.ReadEndpoint(lease.value(), out));
        return out;
    }
};

} // namespace

TEST(PeerFloat, DemuxesByPeerIdNotBySourceAddress)
{
    FloatFixture fx;

    // Same address the slot was seeded with: plain demux, no float.
    auto pkt = fx.MakeDatagram(fx.lease.value(), 0x22);
    auto plaintext = fx.Receive(pkt, Ep("192.0.2.10", 1194));

    EXPECT_FALSE(plaintext.empty());
    EXPECT_TRUE(fx.sink.events.empty());
}

TEST(PeerFloat, FloatsOnAuthenticatedDatagramFromNewAddress)
{
    FloatFixture fx;

    auto pkt = fx.MakeDatagram(fx.lease.value(), 0x33);
    auto plaintext = fx.Receive(pkt, Ep("198.51.100.7", 5555));
    ASSERT_FALSE(plaintext.empty());

    // Egress follows immediately: no snapshot republish involved.
    EXPECT_EQ(fx.SlotEndpoint(), Ep("198.51.100.7", 5555));

    ASSERT_EQ(fx.sink.events.size(), 1u);
    EXPECT_EQ(fx.sink.events[0].session_id, FloatFixture::kSessionId);
    EXPECT_EQ(fx.sink.events[0].endpoint, Ep("198.51.100.7", 5555));
}

TEST(PeerFloat, ReplayFromNewAddressDoesNotFloat)
{
    FloatFixture fx;

    auto pkt = fx.MakeDatagram(fx.lease.value(), 0x44);
    auto copy = pkt;

    ASSERT_FALSE(fx.Receive(pkt, Ep("192.0.2.10", 1194)).empty());
    ASSERT_TRUE(fx.sink.events.empty());

    // Captured datagram replayed from the attacker's address: AEAD would
    // accept it, the replay window must not.
    EXPECT_TRUE(fx.Receive(copy, Ep("203.0.113.99", 6666)).empty());
    EXPECT_EQ(fx.SlotEndpoint(), Ep("192.0.2.10", 1194));
    EXPECT_TRUE(fx.sink.events.empty());
}

TEST(PeerFloat, UnauthenticatedDatagramDoesNotFloat)
{
    FloatFixture fx;

    auto pkt = fx.MakeDatagram(fx.lease.value(), 0x55);
    pkt[pkt.size() - 1] ^= 0xFF; // corrupt the AEAD tag

    EXPECT_TRUE(fx.Receive(pkt, Ep("203.0.113.5", 7777)).empty());
    EXPECT_EQ(fx.SlotEndpoint(), Ep("192.0.2.10", 1194));
    EXPECT_TRUE(fx.sink.events.empty());
}

TEST(PeerFloat, UnknownPeerIdIsDroppedWithoutTouchingAnySlot)
{
    FloatFixture fx;

    // Slot 3 is Free; a datagram claiming it must not resolve or float.
    auto pkt = fx.MakeDatagram(3, 0x66);
    EXPECT_TRUE(fx.Receive(pkt, Ep("203.0.113.5", 7777)).empty());
    EXPECT_TRUE(fx.sink.events.empty());
    EXPECT_EQ(fx.SlotEndpoint(), Ep("192.0.2.10", 1194));
}

TEST(PeerFloat, ReservedSlotIsNotReachableFromRx)
{
    FloatFixture fx;

    auto pending = fx.slots.Reserve();
    ASSERT_TRUE(pending);
    auto pkt = fx.MakeDatagram(pending->value(), 0x77);

    EXPECT_TRUE(fx.Receive(pkt, Ep("203.0.113.5", 7777)).empty());
    EXPECT_TRUE(fx.sink.events.empty());
}

TEST(PeerFloat, RetiringSlotIsNotReachableFromRx)
{
    FloatFixture fx;

    fx.slots.Retire(fx.lease.value());

    auto pkt = fx.MakeDatagram(fx.lease.value(), 0x88);
    EXPECT_TRUE(fx.Receive(pkt, Ep("192.0.2.10", 1194)).empty());
    EXPECT_TRUE(fx.sink.events.empty());
}

TEST(PeerFloat, DataV1IsNotDemuxedOnTheDataPath)
{
    FloatFixture fx;

    auto pkt = fx.MakeDatagram(fx.lease.value(), 0x99);
    // Rewrite the opcode to P_DATA_V1, which carries no peer-id.
    pkt[0] = static_cast<std::uint8_t>(static_cast<std::uint8_t>(Opcode::P_DATA_V1) << OPCODE_SHIFT);

    EXPECT_TRUE(fx.Receive(pkt, Ep("192.0.2.10", 1194)).empty());
    EXPECT_TRUE(fx.sink.events.empty());
}

TEST(PeerFloat, RuntsAreDroppedBeforePeerIdIsRead)
{
    FloatFixture fx;

    std::vector<std::uint8_t> pkt(2, 0x00);
    EXPECT_TRUE(fx.Receive(pkt, Ep("192.0.2.10", 1194)).empty());
    EXPECT_TRUE(fx.sink.events.empty());
}

TEST(PeerFloat, TxDestinationFollowsSlotEndpoint)
{
    FloatFixture fx;

    // TX reads the slot, so a float is visible without republishing sessions.
    fx.slots.PublishEndpoint(fx.lease.value(), Ep("198.51.100.20", 4444));

    transport::PeerEndpoint dest;
    ASSERT_TRUE(fx.slots.ReadEndpoint(fx.lease.value(), dest));
    EXPECT_EQ(dest, Ep("198.51.100.20", 4444));
}

TEST(PeerFloat, FloatOntoAnotherOccupiedEndpointStillUpdatesSlot)
{
    FloatFixture fx;

    auto other = fx.slots.Reserve();
    ASSERT_TRUE(other);
    const auto other_ep = Ep("203.0.113.10", 1194);
    fx.slots.Occupy(other->value(), 0x1111, other_ep);

    auto pkt = fx.MakeDatagram(fx.lease.value(), 0xAA);
    ASSERT_FALSE(fx.Receive(pkt, other_ep).empty());

    // RX cannot see the control-plane endpoint index, so the slot moves
    // even when another Occupied slot already claims that sockaddr.
    EXPECT_EQ(fx.SlotEndpoint(), other_ep);
    ASSERT_EQ(fx.sink.events.size(), 1u);

    SessionManager sm;
    const SessionId id_a{FloatFixture::kSessionId};
    const SessionId id_b{0x1111};
    sm.GetOrCreateSession(id_a, Connection::Endpoint{asio::ip::make_address("192.0.2.10"), 1194},
                          true, std::nullopt, FloatLogger());
    sm.GetOrCreateSession(id_b, Connection::Endpoint{other_ep.addr, other_ep.port},
                          true, std::nullopt, FloatLogger());
    EXPECT_FALSE(sm.RebindEndpoint(id_a, Connection::Endpoint{other_ep.addr, other_ep.port}));
}

TEST(PeerFloat, RapidFloatBurstIsThrottledToOneCatchup)
{
    FloatFixture fx;

    // First authenticated move from a new source floats immediately.
    auto p1 = fx.MakeDatagram(fx.lease.value(), 0xB1);
    ASSERT_FALSE(fx.Receive(p1, Ep("198.51.100.7", 5555)).empty());
    ASSERT_EQ(fx.sink.events.size(), 1u);
    EXPECT_EQ(fx.SlotEndpoint(), Ep("198.51.100.7", 5555));

    // Further moves within the catch-up interval still decrypt (data keeps
    // flowing) but the control-plane republish is throttled. The slot stays on
    // the last committed endpoint so it never desyncs from the posted control
    // index; the settled source is picked up on the next float past the interval.
    auto p2 = fx.MakeDatagram(fx.lease.value(), 0xB2);
    ASSERT_FALSE(fx.Receive(p2, Ep("198.51.100.8", 6666)).empty());
    auto p3 = fx.MakeDatagram(fx.lease.value(), 0xB3);
    ASSERT_FALSE(fx.Receive(p3, Ep("198.51.100.9", 7777)).empty());

    EXPECT_EQ(fx.sink.events.size(), 1u);
    EXPECT_EQ(fx.SlotEndpoint(), Ep("198.51.100.7", 5555));
}
