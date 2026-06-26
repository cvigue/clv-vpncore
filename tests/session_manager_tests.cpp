// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/connection.h"
#include "openvpn/packet.h"
#include "openvpn/session_manager.h"
#include <net/ipv6_utils.h>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace clv::vpn;
namespace ipv6 = clv::net::ipv6;

class ConnectionTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        logger_ = std::make_unique<spdlog::logger>("test_session", null_sink);
    }

    Connection::Endpoint CreateEndpoint(uint32_t ip = 0xC0A80001, uint16_t port = 1194)
    {
        return {asio::ip::address_v4(ip), port};
    }

    std::unique_ptr<spdlog::logger> logger_;
};

TEST_F(ConnectionTest, ConstructionServerMode)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    Connection session(session_id, endpoint, true, std::nullopt, *logger_); // true = server mode

    EXPECT_EQ(session.GetSessionId().value, session_id.value);
    EXPECT_EQ(session.GetEndpoint().addr, endpoint.addr);
    EXPECT_EQ(session.GetEndpoint().port, endpoint.port);
}

TEST_F(ConnectionTest, ConstructionClientMode)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    Connection session(session_id, endpoint, false, std::nullopt, *logger_); // false = client mode

    EXPECT_EQ(session.GetSessionId().value, session_id.value);
    EXPECT_FALSE(session.IsEstablished());
}

TEST_F(ConnectionTest, LastActivityUpdates)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    Connection session(session_id, endpoint, true, std::nullopt, *logger_);

    auto time1 = session.GetLastActivity();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    session.UpdateLastActivity();
    auto time2 = session.GetLastActivity();

    EXPECT_LT(time1, time2);
}

TEST_F(ConnectionTest, ControlChannelAccess)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    Connection session(session_id, endpoint, true, std::nullopt, *logger_);

    auto &control = session.GetControlChannel();
    EXPECT_EQ(control.GetSessionId().value, session_id.value);
}

TEST_F(ConnectionTest, DataChannelAccess)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    Connection session(session_id, endpoint, true, std::nullopt, *logger_);

    auto &data = session.GetDataChannel();
    EXPECT_EQ(data.GetOutboundPacketId(), 1);
    EXPECT_FALSE(data.HasValidKeys());
    EXPECT_EQ(data.GetReplayedPacketCount(), 0);
}

TEST_F(ConnectionTest, GetCipherSuite)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    Connection session(session_id, endpoint, true, std::nullopt, *logger_);

    // Cipher suite should be empty until negotiated
    auto cipher = session.GetCipherSuite();
    EXPECT_TRUE(cipher.empty());
}

// ── Uncovered accessor tests ─────────────────────────────────────────────────

TEST_F(ConnectionTest, GetRole_ReturnsServerOrClient)
{
    auto sid = openvpn::SessionId::Generate();
    auto ep = CreateEndpoint();
    Connection server(sid, ep, ConnectionRole::Server, std::nullopt, *logger_);
    Connection client(sid, ep, ConnectionRole::Client, std::nullopt, *logger_);

    EXPECT_EQ(server.GetRole(), ConnectionRole::Server);
    EXPECT_EQ(client.GetRole(), ConnectionRole::Client);
}

TEST_F(ConnectionTest, IsServer_ReflectsRole)
{
    auto sid = openvpn::SessionId::Generate();
    auto ep = CreateEndpoint();
    Connection server(sid, ep, ConnectionRole::Server, std::nullopt, *logger_);
    Connection client(sid, ep, ConnectionRole::Client, std::nullopt, *logger_);

    EXPECT_TRUE(server.IsServer());
    EXPECT_FALSE(client.IsServer());
}

TEST_F(ConnectionTest, UpdateLastOutbound_UpdatesTimestamp)
{
    auto sid = openvpn::SessionId::Generate();
    auto ep = CreateEndpoint();
    Connection session(sid, ep, true, std::nullopt, *logger_);

    auto t1 = session.GetLastOutbound();
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    session.UpdateLastOutbound();
    auto t2 = session.GetLastOutbound();

    EXPECT_LT(t1, t2);
}

TEST_F(ConnectionTest, AssignedIpv4_SetGet)
{
    auto sid = openvpn::SessionId::Generate();
    Connection session(sid, CreateEndpoint(), true, std::nullopt, *logger_);

    EXPECT_FALSE(session.GetAssignedIpv4().has_value());
    session.SetAssignedIpv4(0xC0A80101u); // 192.168.1.1
    ASSERT_TRUE(session.GetAssignedIpv4().has_value());
    EXPECT_EQ(*session.GetAssignedIpv4(), 0xC0A80101u);
}

TEST_F(ConnectionTest, AssignedIpv6_SetGet)
{
    auto sid = openvpn::SessionId::Generate();
    Connection session(sid, CreateEndpoint(), true, std::nullopt, *logger_);

    EXPECT_FALSE(session.GetAssignedIpv6().has_value());
    ipv6::Ipv6Address addr{};
    addr[0] = 0x20;
    addr[1] = 0x01;
    session.SetAssignedIpv6(addr);
    ASSERT_TRUE(session.GetAssignedIpv6().has_value());
    EXPECT_EQ((*session.GetAssignedIpv6())[0], 0x20u);
}

TEST_F(ConnectionTest, SentKeyMethod2_SetGet)
{
    auto sid = openvpn::SessionId::Generate();
    Connection session(sid, CreateEndpoint(), true, std::nullopt, *logger_);

    EXPECT_FALSE(session.HasSentKeyMethod2());
    session.SetSentKeyMethod2(true);
    EXPECT_TRUE(session.HasSentKeyMethod2());
    session.SetSentKeyMethod2(false);
    EXPECT_FALSE(session.HasSentKeyMethod2());
}

TEST_F(ConnectionTest, ServerRandom_SetGet)
{
    auto sid = openvpn::SessionId::Generate();
    Connection session(sid, CreateEndpoint(), true, std::nullopt, *logger_);

    EXPECT_TRUE(session.GetServerRandom().empty());
    std::vector<uint8_t> rnd(48, 0xAA);
    session.SetServerRandom(rnd);
    EXPECT_EQ(session.GetServerRandom(), rnd);
}

TEST_F(ConnectionTest, ClientRandom_SetGet)
{
    auto sid = openvpn::SessionId::Generate();
    Connection session(sid, CreateEndpoint(), false, std::nullopt, *logger_);

    EXPECT_TRUE(session.GetClientRandom().empty());
    std::vector<uint8_t> rnd(48, 0xBB);
    session.SetClientRandom(rnd);
    EXPECT_EQ(session.GetClientRandom(), rnd);
}

TEST_F(ConnectionTest, HasTransport_FalseByDefault)
{
    auto sid = openvpn::SessionId::Generate();
    Connection session(sid, CreateEndpoint(), true, std::nullopt, *logger_);

    EXPECT_FALSE(session.HasTransport());
}

TEST_F(ConnectionTest, Endpoint_EqualityOperator)
{
    Connection::Endpoint e1{asio::ip::address_v4(0xC0A80001), 1194};
    Connection::Endpoint e2{asio::ip::address_v4(0xC0A80001), 1194};
    Connection::Endpoint e3{asio::ip::address_v4(0xC0A80002), 1194};

    EXPECT_EQ(e1, e2);
    EXPECT_NE(e1, e3);
}

TEST_F(ConnectionTest, ConstGetDataChannel_ReturnsConst)
{
    auto sid = openvpn::SessionId::Generate();
    const Connection session(sid, CreateEndpoint(), true, std::nullopt, *logger_);

    const auto &dc = session.GetDataChannel();
    EXPECT_FALSE(dc.HasValidKeys());
}

TEST_F(ConnectionTest, ConstGetControlChannel_ReturnsConst)
{
    auto sid = openvpn::SessionId::Generate();
    const Connection session(sid, CreateEndpoint(), true, std::nullopt, *logger_);

    const auto &cc = session.GetControlChannel();
    EXPECT_EQ(cc.GetSessionId().value, sid.value);
}

class SessionManagerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        logger_ = std::make_unique<spdlog::logger>("test_manager", null_sink);
    }

    SessionManager manager;
    std::unique_ptr<spdlog::logger> logger_;

    Connection::Endpoint CreateEndpoint(uint32_t ip = 0xC0A80001, uint16_t port = 1194)
    {
        return {asio::ip::address_v4(ip), port};
    }
};

TEST_F(SessionManagerTest, CreateAndRetrieveSession)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();

    auto &session1 = manager.GetOrCreateSession(session_id, endpoint, true, std::nullopt, *logger_);
    EXPECT_EQ(session1.GetSessionId().value, session_id.value);

    // Retrieving again should return the same session
    auto *session2 = manager.FindSession(session_id);
    EXPECT_EQ(session2->GetSessionId().value, session_id.value);
}

TEST_F(SessionManagerTest, FindNonexistentSession)
{
    auto nonexistent = openvpn::SessionId::Generate();
    auto *session = manager.FindSession(nonexistent);
    EXPECT_EQ(session, nullptr);
}

TEST_F(SessionManagerTest, FindSessionByEndpoint)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint(0xC0A80001, 1194);
    manager.GetOrCreateSession(session_id, endpoint, true, std::nullopt, *logger_);

    auto *found = manager.FindSessionByEndpoint(endpoint);
    EXPECT_NE(found, nullptr);
    EXPECT_EQ(found->GetSessionId().value, session_id.value);
}

TEST_F(SessionManagerTest, MultipleSessionsTracking)
{
    auto id1 = openvpn::SessionId::Generate();
    auto id2 = openvpn::SessionId::Generate();
    auto id3 = openvpn::SessionId::Generate();

    manager.GetOrCreateSession(id1, CreateEndpoint(0xC0A80001, 1194), true, std::nullopt, *logger_);
    manager.GetOrCreateSession(id2, CreateEndpoint(0xC0A80002, 1195), true, std::nullopt, *logger_);
    manager.GetOrCreateSession(id3, CreateEndpoint(0xC0A80003, 1196), true, std::nullopt, *logger_);

    EXPECT_EQ(manager.GetSessionCount(), 3);

    auto ids = manager.GetAllSessionIds();
    EXPECT_EQ(ids.size(), 3);
}

TEST_F(SessionManagerTest, RemoveSession)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    manager.GetOrCreateSession(session_id, endpoint, true, std::nullopt, *logger_);

    EXPECT_EQ(manager.GetSessionCount(), 1);
    bool removed = manager.RemoveSession(session_id);
    EXPECT_TRUE(removed);
    EXPECT_EQ(manager.GetSessionCount(), 0);

    auto *found = manager.FindSession(session_id);
    EXPECT_EQ(found, nullptr);
}

TEST_F(SessionManagerTest, RemoveNonexistentSession)
{
    auto nonexistent = openvpn::SessionId::Generate();
    bool removed = manager.RemoveSession(nonexistent);
    EXPECT_FALSE(removed);
}

TEST_F(SessionManagerTest, CleanupStaleSession)
{
    auto id1 = openvpn::SessionId::Generate();
    auto id2 = openvpn::SessionId::Generate();

    manager.GetOrCreateSession(id1, CreateEndpoint(0xC0A80001, 1194), true, std::nullopt, *logger_);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    manager.GetOrCreateSession(id2, CreateEndpoint(0xC0A80002, 1195), true, std::nullopt, *logger_);

    EXPECT_EQ(manager.GetSessionCount(), 2);

    // Clean up sessions inactive for 100ms — id1 slept 200ms so it qualifies
    size_t removed = manager.CleanupStaleSession(std::chrono::milliseconds(100));
    EXPECT_EQ(removed, 1); // id1 should be removed

    // id2 should still be there
    EXPECT_EQ(manager.GetSessionCount(), 1);
    auto *found = manager.FindSession(id2);
    EXPECT_NE(found, nullptr);
}

TEST_F(SessionManagerTest, ClearAllSessions)
{
    auto id1 = openvpn::SessionId::Generate();
    auto id2 = openvpn::SessionId::Generate();

    manager.GetOrCreateSession(id1, CreateEndpoint(0xC0A80001, 1194), true, std::nullopt, *logger_);
    manager.GetOrCreateSession(id2, CreateEndpoint(0xC0A80002, 1195), true, std::nullopt, *logger_);

    EXPECT_EQ(manager.GetSessionCount(), 2);
    manager.ClearAllSessions();
    EXPECT_EQ(manager.GetSessionCount(), 0);
}

TEST_F(SessionManagerTest, DuplicateEndpointHandling)
{
    auto id1 = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();

    manager.GetOrCreateSession(id1, endpoint, true, std::nullopt, *logger_);
    // Try to create another session with same endpoint but different ID
    // FindSessionByEndpoint should return the first one
    auto *found = manager.FindSessionByEndpoint(endpoint);
    EXPECT_EQ(found->GetSessionId().value, id1.value);
}

TEST_F(SessionManagerTest, GetAllSessionIds)
{
    auto id1 = openvpn::SessionId::Generate();
    auto id2 = openvpn::SessionId::Generate();
    auto id3 = openvpn::SessionId::Generate();

    manager.GetOrCreateSession(id1, CreateEndpoint(0xC0A80001, 1194), true, std::nullopt, *logger_);
    manager.GetOrCreateSession(id2, CreateEndpoint(0xC0A80002, 1195), true, std::nullopt, *logger_);
    manager.GetOrCreateSession(id3, CreateEndpoint(0xC0A80003, 1196), true, std::nullopt, *logger_);

    auto ids = manager.GetAllSessionIds();
    EXPECT_EQ(ids.size(), 3);

    // Verify all IDs are present
    std::unordered_set<uint64_t> id_set;
    for (auto &id : ids)
    {
        id_set.insert(id.value);
    }
    EXPECT_TRUE(id_set.count(id1.value));
    EXPECT_TRUE(id_set.count(id2.value));
    EXPECT_TRUE(id_set.count(id3.value));
}

TEST_F(SessionManagerTest, EndpointIndexClearedAfterRemove)
{
    auto id = openvpn::SessionId::Generate();
    auto ep = CreateEndpoint(0xC0A80001, 1194);
    manager.GetOrCreateSession(id, ep, true, std::nullopt, *logger_);

    EXPECT_NE(manager.FindSessionByEndpoint(ep), nullptr);
    manager.RemoveSession(id);
    EXPECT_EQ(manager.FindSessionByEndpoint(ep), nullptr);
}

TEST_F(SessionManagerTest, EndpointIndexClearedAfterCleanup)
{
    auto id1 = openvpn::SessionId::Generate();
    auto id2 = openvpn::SessionId::Generate();
    auto ep1 = CreateEndpoint(0xC0A80001, 1194);
    auto ep2 = CreateEndpoint(0xC0A80002, 1195);

    manager.GetOrCreateSession(id1, ep1, true, std::nullopt, *logger_);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    manager.GetOrCreateSession(id2, ep2, true, std::nullopt, *logger_);

    // Cleanup stale — id1 should expire, id2 should survive
    auto removed = manager.CleanupStaleSession(std::chrono::milliseconds(100));
    EXPECT_EQ(removed, 1u);

    EXPECT_EQ(manager.FindSessionByEndpoint(ep1), nullptr);
    EXPECT_NE(manager.FindSessionByEndpoint(ep2), nullptr);
}

TEST_F(SessionManagerTest, EndpointIndexClearedAfterClearAll)
{
    auto id = openvpn::SessionId::Generate();
    auto ep = CreateEndpoint(0xC0A80001, 1194);
    manager.GetOrCreateSession(id, ep, true, std::nullopt, *logger_);

    EXPECT_NE(manager.FindSessionByEndpoint(ep), nullptr);
    manager.ClearAllSessions();
    EXPECT_EQ(manager.FindSessionByEndpoint(ep), nullptr);
}

TEST_F(SessionManagerTest, EndpointLookupWithIPv6)
{
    auto id = openvpn::SessionId::Generate();
    Connection::Endpoint ep{asio::ip::make_address("::1"), 5000};
    manager.GetOrCreateSession(id, ep, true, std::nullopt, *logger_);

    auto *found = manager.FindSessionByEndpoint(ep);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->GetSessionId().value, id.value);
}

// ============================================================================
// GetOrCreateSession — existing-session return path (previously dead)
// ============================================================================

TEST_F(SessionManagerTest, GetOrCreateSession_SameId_ReturnsSameObject)
{
    auto id = openvpn::SessionId::Generate();
    auto ep = CreateEndpoint(0xC0A80001, 1194);

    // First call: creates the session
    auto &first = manager.GetOrCreateSession(id, ep, true, std::nullopt, *logger_);

    // Second call with same session_id: exercises the "it != sessions_.end()" return path
    auto &second = manager.GetOrCreateSession(id, ep, true, std::nullopt, *logger_);

    // Must be the same Connection object
    EXPECT_EQ(&first, &second);
    EXPECT_EQ(manager.GetSessionCount(), 1u);
}

TEST_F(SessionManagerTest, GetOrCreateSession_DifferentIds_CreatesSeparateSessions)
{
    auto id1 = openvpn::SessionId::Generate();
    auto id2 = openvpn::SessionId::Generate();

    manager.GetOrCreateSession(id1, CreateEndpoint(0xC0A80001, 1194), true, std::nullopt, *logger_);
    manager.GetOrCreateSession(id2, CreateEndpoint(0xC0A80002, 1195), true, std::nullopt, *logger_);

    EXPECT_EQ(manager.GetSessionCount(), 2u);
}

// ============================================================================
// ExtractSession (previously dead)
// ============================================================================

TEST_F(SessionManagerTest, ExtractSession_RemovesAndReturnsSession)
{
    auto id = openvpn::SessionId::Generate();
    auto ep = CreateEndpoint(0xC0A80001, 1194);
    manager.GetOrCreateSession(id, ep, true, std::nullopt, *logger_);
    ASSERT_EQ(manager.GetSessionCount(), 1u);

    auto extracted = manager.ExtractSession(id);

    ASSERT_NE(extracted, nullptr);
    EXPECT_EQ(extracted->GetSessionId().value, id.value);

    // After extraction the session is gone
    EXPECT_EQ(manager.GetSessionCount(), 0u);
    EXPECT_EQ(manager.FindSession(id), nullptr);
    EXPECT_EQ(manager.FindSessionByEndpoint(ep), nullptr);
}

TEST_F(SessionManagerTest, ExtractSession_MissingId_ReturnsNullptr)
{
    auto id = openvpn::SessionId::Generate();
    auto extracted = manager.ExtractSession(id);

    EXPECT_EQ(extracted, nullptr);
}

// ---------------------------------------------------------------------------
// Connection rekey timer tests
// ---------------------------------------------------------------------------

TEST_F(ConnectionTest, CancelRekeyTimer_NopWhenNotArmed)
{
    auto sid = openvpn::SessionId::Generate();
    Connection conn(sid, CreateEndpoint(), true, std::nullopt, *logger_);

    // Must not crash or throw when no timer has been armed.
    EXPECT_NO_THROW(conn.CancelRekeyTimer());
}

// ---------------------------------------------------------------------------
// SessionManager::CancelAllRekeyTimers unit tests
// ---------------------------------------------------------------------------

TEST_F(SessionManagerTest, CancelAllRekeyTimers_EmptyManager_IsNop)
{
    // Must not crash when there are no sessions.
    EXPECT_NO_THROW(manager.CancelAllRekeyTimers());
}

TEST_F(SessionManagerTest, CancelAllRekeyTimers_SkipsUnarmedSessions)
{
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    spdlog::logger logger("test_sm_unarmed", null_sink);

    // Add sessions without arming their timers.
    for (int i = 0; i < 3; ++i)
    {
        auto sid = openvpn::SessionId::Generate();
        Connection::Endpoint ep{asio::ip::address_v4(0xC0A80001u + static_cast<uint32_t>(i)),
                                static_cast<uint16_t>(1194 + i)};
        manager.GetOrCreateSession(sid, ep, true, std::nullopt, logger);
    }

    EXPECT_NO_THROW(manager.CancelAllRekeyTimers());
}

// ---------------------------------------------------------------------------
// Integration: CancelRekeyTimer stops a real co_await on the session's timer
// ---------------------------------------------------------------------------

TEST(RekeyCancelIntegration, CancelStopsTimerAwait)
{
    asio::io_context ctx;
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    spdlog::logger logger("test_rekey_int", null_sink);

    auto sid = openvpn::SessionId::Generate();
    Connection::Endpoint ep{asio::ip::address_v4(0xC0A80001u), 1194};
    Connection conn(sid, ep, true, std::nullopt, logger);

    bool cancelled = false;

    // Simulate what RekeyLoop does: arm the session's timer and await it.
    auto coro = [&]() -> asio::awaitable<void>
    {
        conn.ArmRekeyTimer(ctx, std::chrono::hours(1));
        try
        {
            co_await conn.RekeyTimer().async_wait(asio::use_awaitable);
        }
        catch (const asio::system_error &)
        {
            cancelled = true;
            co_return;
        }
    };

    asio::co_spawn(ctx, coro(), asio::detached);

    // Post the cancel after the coroutine has started and is suspended.
    asio::post(ctx, [&conn]
    { conn.CancelRekeyTimer(); });

    ctx.run();

    EXPECT_TRUE(cancelled);
}

TEST(RekeyCancelIntegration, CancelAllRekeyTimers_DrainsTwoSessions)
{
    asio::io_context ctx;
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    spdlog::logger logger("test_rekey_multi", null_sink);

    SessionManager mgr;
    int cancel_count = 0;

    auto sid1 = openvpn::SessionId::Generate();
    auto sid2 = openvpn::SessionId::Generate();
    Connection::Endpoint ep1{asio::ip::address_v4(0xC0A80001u), 1194};
    Connection::Endpoint ep2{asio::ip::address_v4(0xC0A80002u), 1195};
    Connection *conn1 = &mgr.GetOrCreateSession(sid1, ep1, true, std::nullopt, logger);
    Connection *conn2 = &mgr.GetOrCreateSession(sid2, ep2, true, std::nullopt, logger);

    auto make_coro = [&cancel_count, &ctx](Connection *conn_ptr) -> asio::awaitable<void>
    {
        conn_ptr->ArmRekeyTimer(ctx, std::chrono::hours(1));
        try
        {
            co_await conn_ptr->RekeyTimer().async_wait(asio::use_awaitable);
        }
        catch (const asio::system_error &)
        {
            ++cancel_count;
            co_return;
        }
    };

    asio::co_spawn(ctx, make_coro(conn1), asio::detached);
    asio::co_spawn(ctx, make_coro(conn2), asio::detached);

    // Post the batch cancel after both coroutines are suspended.
    asio::post(ctx, [&mgr]
    { mgr.CancelAllRekeyTimers(); });

    ctx.run();

    EXPECT_EQ(cancel_count, 2);
}
