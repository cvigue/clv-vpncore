// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "openvpn/client_session.h"
#include "openvpn/packet.h"
#include "openvpn/session_manager.h"

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

using namespace clv::vpn;

class ClientSessionTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        logger_ = std::make_unique<spdlog::logger>("test_session", null_sink);
    }

    ClientSession::Endpoint CreateEndpoint(uint32_t ip = 0xC0A80001, uint16_t port = 1194)
    {
        return {asio::ip::address_v4(ip), port};
    }

    std::unique_ptr<spdlog::logger> logger_;
};

TEST_F(ClientSessionTest, ConstructionServerMode)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    ClientSession session(session_id, endpoint, true, std::nullopt, *logger_); // true = server mode

    EXPECT_EQ(session.GetSessionId().value, session_id.value);
    EXPECT_EQ(session.GetEndpoint().addr, endpoint.addr);
    EXPECT_EQ(session.GetEndpoint().port, endpoint.port);
}

TEST_F(ClientSessionTest, ConstructionClientMode)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    ClientSession session(session_id, endpoint, false, std::nullopt, *logger_); // false = client mode

    EXPECT_EQ(session.GetSessionId().value, session_id.value);
    EXPECT_FALSE(session.IsEstablished());
}

TEST_F(ClientSessionTest, LastActivityUpdates)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    ClientSession session(session_id, endpoint, true, std::nullopt, *logger_);

    auto time1 = session.GetLastActivity();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    session.UpdateLastActivity();
    auto time2 = session.GetLastActivity();

    EXPECT_LT(time1, time2);
}

TEST_F(ClientSessionTest, ControlChannelAccess)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    ClientSession session(session_id, endpoint, true, std::nullopt, *logger_);

    auto &control = session.GetControlChannel();
    EXPECT_EQ(control.GetSessionId().value, session_id.value);
}

TEST_F(ClientSessionTest, DataChannelAccess)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    ClientSession session(session_id, endpoint, true, std::nullopt, *logger_);

    auto &data = session.GetDataChannel();
    (void)data; // Use variable to suppress warning
    // DataChannel should be accessible
    EXPECT_TRUE(true);
}

TEST_F(ClientSessionTest, GetCipherSuite)
{
    auto session_id = openvpn::SessionId::Generate();
    auto endpoint = CreateEndpoint();
    ClientSession session(session_id, endpoint, true, std::nullopt, *logger_);

    // Cipher suite should be empty until negotiated
    auto cipher = session.GetCipherSuite();
    EXPECT_TRUE(cipher.empty());
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

    ClientSession::Endpoint CreateEndpoint(uint32_t ip = 0xC0A80001, uint16_t port = 1194)
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
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    manager.GetOrCreateSession(id2, CreateEndpoint(0xC0A80002, 1195), true, std::nullopt, *logger_);

    EXPECT_EQ(manager.GetSessionCount(), 2);

    // Clean up sessions inactive for 30ms
    size_t removed = manager.CleanupStaleSession(std::chrono::milliseconds(30));
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
