// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "ip_pool_manager.h"
#include "openvpn/client_session.h"
#include "openvpn/control_channel.h"
#include "openvpn/packet.h"
#include "openvpn/session_manager.h"
#include "routing_table.h"

#include <arpa/inet.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <set>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace clv::vpn;
using namespace clv::vpn::openvpn;

/**
 * @brief Integration tests for multi-client VPN handshake scenarios
 *
 * Tests the interaction between SessionManager, ControlChannel, and routing.
 * Simulates multiple clients connecting and performing TLS handshakes.
 */
class VpnServerIntegrationTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        logger_ = std::make_unique<spdlog::logger>("test_integration", null_sink);
    }

    SessionManager session_manager_;
    RoutingTableIpv4 routing_table_;
    std::unique_ptr<spdlog::logger> logger_;

    ClientSession::Endpoint CreateEndpoint(uint32_t ip = 0xC0A80001, uint16_t port = 1194)
    {
        return {asio::ip::address_v4(ip), port};
    }

    /**
     * @brief Simulate a client sending a hard reset packet
     */
    std::vector<std::uint8_t> CreateClientHardReset(SessionId session_id, uint8_t key_id = 0)
    {
        OpenVpnPacket packet;
        packet.opcode_ = Opcode::P_CONTROL_HARD_RESET_CLIENT_V3;
        packet.key_id_ = key_id;
        packet.session_id_ = session_id.value;
        packet.packet_id_ = 1; // First packet from client
        packet.payload_ = {};  // No payload in hard reset

        return packet.Serialize();
    }

    /**
     * @brief Simulate a server sending a hard reset response
     */
    std::vector<std::uint8_t> CreateServerHardReset(SessionId session_id, uint8_t key_id = 0)
    {
        OpenVpnPacket packet;
        packet.opcode_ = Opcode::P_CONTROL_HARD_RESET_SERVER_V3;
        packet.key_id_ = key_id;
        packet.session_id_ = session_id.value;
        packet.packet_id_ = 1; // First response from server
        packet.payload_ = {};

        return packet.Serialize();
    }
};

// Test: Single client connection through hard reset
TEST_F(VpnServerIntegrationTest, SingleClientHardResetFlow)
{
    auto session_id = SessionId::Generate();
    auto endpoint = CreateEndpoint(0xC0A80001, 5000);

    // Client initiates handshake
    auto hard_reset_data = CreateClientHardReset(session_id);
    ASSERT_FALSE(hard_reset_data.empty());

    // Parse the hard reset packet
    auto packet_opt = OpenVpnPacket::Parse(hard_reset_data);
    ASSERT_TRUE(packet_opt.has_value());
    auto packet = packet_opt.value();

    // Server receives hard reset and creates session
    auto &session = session_manager_.GetOrCreateSession(session_id, endpoint, true, std::nullopt, *logger_);
    EXPECT_EQ(session.GetSessionId().value, session_id.value);

    // Server handles hard reset in control channel
    bool handled = session.GetControlChannel().HandleHardReset(packet);
    EXPECT_TRUE(handled);
    EXPECT_EQ(session.GetControlChannel().GetState(), ControlChannel::State::TlsHandshake);
}

// Test: Multiple clients with different session IDs
TEST_F(VpnServerIntegrationTest, MultipleClientSessionCreation)
{
    std::vector<SessionId> session_ids;
    std::vector<ClientSession::Endpoint> endpoints;

    // Create 3 clients
    for (int i = 0; i < 3; ++i)
    {
        auto session_id = SessionId::Generate();
        auto endpoint = CreateEndpoint(0xC0A80001 + i, static_cast<uint16_t>(5000 + i));

        session_ids.push_back(session_id);
        endpoints.push_back(endpoint);

        auto &session = session_manager_.GetOrCreateSession(session_id, endpoint, true, std::nullopt, *logger_);
        EXPECT_EQ(session.GetSessionId().value, session_id.value);
    }

    // Verify all sessions are tracked
    EXPECT_EQ(session_manager_.GetSessionCount(), 3);

    // Verify each session can be retrieved
    for (int i = 0; i < 3; ++i)
    {
        auto *found = session_manager_.FindSession(session_ids[i]);
        ASSERT_NE(found, nullptr);
        EXPECT_EQ(found->GetEndpoint().addr, endpoints[i].addr);
        EXPECT_EQ(found->GetEndpoint().port, endpoints[i].port);
    }
}

// Test: Multiple clients with endpoint-based lookup
TEST_F(VpnServerIntegrationTest, MultipleClientEndpointLookup)
{
    std::vector<SessionId> session_ids;
    std::vector<ClientSession::Endpoint> endpoints;

    // Create clients
    for (int i = 0; i < 3; ++i)
    {
        auto session_id = SessionId::Generate();
        auto endpoint = CreateEndpoint(0xC0A80010 + i, static_cast<uint16_t>(5100 + i));

        session_ids.push_back(session_id);
        endpoints.push_back(endpoint);

        session_manager_.GetOrCreateSession(session_id, endpoint, true, std::nullopt, *logger_);
    }

    // Look up by endpoint
    for (int i = 0; i < 3; ++i)
    {
        auto *found = session_manager_.FindSessionByEndpoint(endpoints[i]);
        ASSERT_NE(found, nullptr);
        EXPECT_EQ(found->GetSessionId().value, session_ids[i].value);
    }
}

// Test: Control packet routing to correct session
TEST_F(VpnServerIntegrationTest, ControlPacketRoutingMultipleClients)
{
    // Create 2 clients
    auto session_id_1 = SessionId::Generate();
    auto session_id_2 = SessionId::Generate();
    auto endpoint_1 = CreateEndpoint(0xC0A80020, 5200);
    auto endpoint_2 = CreateEndpoint(0xC0A80021, 5201);

    auto &session_1 = session_manager_.GetOrCreateSession(session_id_1, endpoint_1, true, std::nullopt, *logger_);
    auto &session_2 = session_manager_.GetOrCreateSession(session_id_2, endpoint_2, true, std::nullopt, *logger_);

    // Initialize both sessions for hard reset handling
    auto reset_1 = CreateClientHardReset(session_id_1);
    auto reset_2 = CreateClientHardReset(session_id_2);

    auto packet_1 = OpenVpnPacket::Parse(reset_1).value();
    auto packet_2 = OpenVpnPacket::Parse(reset_2).value();

    // Handle resets in respective sessions
    session_1.GetControlChannel().HandleHardReset(packet_1);
    session_2.GetControlChannel().HandleHardReset(packet_2);

    // Verify states
    EXPECT_EQ(session_1.GetControlChannel().GetState(), ControlChannel::State::TlsHandshake);
    EXPECT_EQ(session_2.GetControlChannel().GetState(), ControlChannel::State::TlsHandshake);

    // Verify sessions are distinct
    EXPECT_NE(&session_1, &session_2);
}

// Test: Routing table with multiple clients
TEST_F(VpnServerIntegrationTest, RoutingTableMultipleRoutes)
{
    auto session_id_1 = SessionId::Generate();
    auto session_id_2 = SessionId::Generate();
    auto session_id_3 = SessionId::Generate();

    // Add routes for 3 clients with different subnets
    routing_table_.AddRoute(0x0A080000, 24, session_id_1.value); // 10.8.0.0/24
    routing_table_.AddRoute(0x0A090000, 24, session_id_2.value); // 10.9.0.0/24
    routing_table_.AddRoute(0x0A0A0000, 24, session_id_3.value); // 10.10.0.0/24

    // Test lookups for each subnet
    EXPECT_EQ(routing_table_.Lookup(0x0A080050).value(), session_id_1.value); // 10.8.0.80
    EXPECT_EQ(routing_table_.Lookup(0x0A090050).value(), session_id_2.value); // 10.9.0.80
    EXPECT_EQ(routing_table_.Lookup(0x0A0A0050).value(), session_id_3.value); // 10.10.0.80
}

// Test: Longest-prefix-match routing with overlapping subnets
TEST_F(VpnServerIntegrationTest, RoutingTableLongestPrefixMatch)
{
    auto session_id_1 = SessionId::Generate();
    auto session_id_2 = SessionId::Generate();

    // Add overlapping routes (smaller prefix first, then larger)
    routing_table_.AddRoute(0x0A080000, 16, session_id_1.value); // 10.8.0.0/16
    routing_table_.AddRoute(0x0A080000, 24, session_id_2.value); // 10.8.0.0/24

    // Lookup should match the longest prefix (/24)
    EXPECT_EQ(routing_table_.Lookup(0x0A080050).value(), session_id_2.value);

    // Lookup outside the /24 but inside /16 should match /16
    EXPECT_EQ(routing_table_.Lookup(0x0A081050).value(), session_id_1.value);
}

// Test: Session activity tracking across multiple clients
TEST_F(VpnServerIntegrationTest, MultipleClientActivityTracking)
{
    std::vector<SessionId> session_ids;
    std::vector<ClientSession *> sessions;

    // Create clients
    for (int i = 0; i < 3; ++i)
    {
        auto session_id = SessionId::Generate();
        auto endpoint = CreateEndpoint(0xC0A80030 + i, static_cast<uint16_t>(5300 + i));

        session_ids.push_back(session_id);
        sessions.push_back(&session_manager_.GetOrCreateSession(session_id, endpoint, true, std::nullopt, *logger_));
    }

    // Get initial activity times
    auto time_1_initial = sessions[0]->GetLastActivity();
    auto time_2_initial = sessions[1]->GetLastActivity();
    auto time_3_initial = sessions[2]->GetLastActivity();

    // Simulate client 2 sending data (updates activity)
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    sessions[1]->UpdateLastActivity();

    auto time_1_later = sessions[0]->GetLastActivity();
    auto time_2_later = sessions[1]->GetLastActivity();
    auto time_3_later = sessions[2]->GetLastActivity();

    // Client 2 should have newer activity than before
    EXPECT_EQ(time_1_initial, time_1_later);
    EXPECT_GT(time_2_later, time_2_initial);
    EXPECT_EQ(time_3_initial, time_3_later);
}

// Test: Session cleanup and stale connection removal
TEST_F(VpnServerIntegrationTest, MultipleClientStaleSessionCleanup)
{
    auto id1 = SessionId::Generate();
    auto id2 = SessionId::Generate();
    auto id3 = SessionId::Generate();

    // Create first client
    session_manager_.GetOrCreateSession(id1, CreateEndpoint(0xC0A80040, 5400), true, std::nullopt, *logger_);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Create second client
    session_manager_.GetOrCreateSession(id2, CreateEndpoint(0xC0A80041, 5401), true, std::nullopt, *logger_);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Create third client
    session_manager_.GetOrCreateSession(id3, CreateEndpoint(0xC0A80042, 5402), true, std::nullopt, *logger_);

    EXPECT_EQ(session_manager_.GetSessionCount(), 3);

    // Remove sessions inactive for 50ms (should be id1 and id2)
    size_t removed = session_manager_.CleanupStaleSession(std::chrono::milliseconds(50));
    EXPECT_EQ(removed, 2);
    EXPECT_EQ(session_manager_.GetSessionCount(), 1);

    // Only id3 should remain
    auto *found = session_manager_.FindSession(id3);
    EXPECT_NE(found, nullptr);
}

// Test: Packet ID sequencing across multiple sessions
TEST_F(VpnServerIntegrationTest, PacketIdSequencingPerSession)
{
    auto session_id_1 = SessionId::Generate();
    auto session_id_2 = SessionId::Generate();

    auto &session_1 = session_manager_.GetOrCreateSession(session_id_1, CreateEndpoint(0xC0A80050, 5500), true, std::nullopt, *logger_);
    auto &session_2 = session_manager_.GetOrCreateSession(session_id_2, CreateEndpoint(0xC0A80051, 5501), true, std::nullopt, *logger_);

    // Each session should have independent packet ID sequences
    auto id_1a = session_1.GetControlChannel().GetNextPacketId();
    auto id_2a = session_2.GetControlChannel().GetNextPacketId();
    auto id_1b = session_1.GetControlChannel().GetNextPacketId();
    auto id_2b = session_2.GetControlChannel().GetNextPacketId();

    // Packet IDs should be strictly increasing within each session
    EXPECT_LT(id_1a, id_1b);
    EXPECT_LT(id_2a, id_2b);

    // Different sessions can have interleaved packet IDs
    // (no ordering guarantee between sessions)
}

// Test: Hard reset handling with session ID conflict resolution
TEST_F(VpnServerIntegrationTest, ClientSessionIdGeneration)
{
    // Create multiple clients, verify they get unique session IDs
    std::unordered_set<uint64_t> session_ids_set;

    for (int i = 0; i < 5; ++i)
    {
        auto session_id = SessionId::Generate();
        EXPECT_EQ(session_ids_set.count(session_id.value), 0) << "Duplicate session ID generated!";
        session_ids_set.insert(session_id.value);
    }

    EXPECT_EQ(session_ids_set.size(), 5);
}

// Test: Session endpoint isolation (different clients don't interfere)
TEST_F(VpnServerIntegrationTest, SessionEndpointIsolation)
{
    auto id1 = SessionId::Generate();
    auto id2 = SessionId::Generate();
    auto endpoint1 = CreateEndpoint(0xC0A80060, 5600);
    auto endpoint2 = CreateEndpoint(0xC0A80061, 5601);

    auto &session1 = session_manager_.GetOrCreateSession(id1, endpoint1, true, std::nullopt, *logger_);
    auto &session2 = session_manager_.GetOrCreateSession(id2, endpoint2, true, std::nullopt, *logger_);

    // Verify endpoints are correctly stored
    EXPECT_EQ(session1.GetEndpoint().addr, endpoint1.addr);
    EXPECT_EQ(session1.GetEndpoint().port, endpoint1.port);
    EXPECT_EQ(session2.GetEndpoint().addr, endpoint2.addr);
    EXPECT_EQ(session2.GetEndpoint().port, endpoint2.port);

    // Modifying one session should not affect the other
    session1.UpdateLastActivity();
    auto time1 = session1.GetLastActivity();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto time2_before = session2.GetLastActivity();
    session2.UpdateLastActivity();
    auto time2_after = session2.GetLastActivity();

    EXPECT_GT(time1, time2_before);
    EXPECT_GT(time2_after, time2_before);
}

// ============================================================================
// IP Address Allocation Integration Tests
// ============================================================================

// Test: IP allocation after TLS handshake simulation
TEST_F(VpnServerIntegrationTest, IpAllocationAfterHandshake)
{
    IpPoolManager ip_pool("10.8.0.0/24", true);

    auto session_id = SessionId::Generate();
    auto endpoint = CreateEndpoint(0xC0A80070, 5700);
    auto &session = session_manager_.GetOrCreateSession(session_id, endpoint, true, std::nullopt, *logger_);

    // Session should not have IP initially
    EXPECT_FALSE(session.GetAssignedIpv4().has_value());

    // Allocate IP
    auto ip_opt = ip_pool.AllocateIpv4(session_id.value);
    ASSERT_TRUE(ip_opt.has_value());

    session.SetAssignedIpv4(*ip_opt);

    // Verify IP is assigned
    EXPECT_TRUE(session.GetAssignedIpv4().has_value());
    EXPECT_EQ(session.GetAssignedIpv4().value(), *ip_opt);

    // Add route
    routing_table_.AddRoute(*ip_opt, 32, session_id.value);
    auto routed = routing_table_.Lookup(*ip_opt);
    EXPECT_TRUE(routed.has_value());
    EXPECT_EQ(*routed, session_id.value);
}

// Test: Multiple client IP allocation
TEST_F(VpnServerIntegrationTest, MultipleClientIpAllocation)
{
    IpPoolManager ip_pool("10.8.0.0/24", true);
    std::vector<SessionId> session_ids;
    std::vector<uint32_t> allocated_ips;

    // Allocate IPs to 5 clients
    for (int i = 0; i < 5; ++i)
    {
        auto session_id = SessionId::Generate();
        auto endpoint = CreateEndpoint(0xC0A80080 + i, static_cast<uint16_t>(5800 + i));
        auto &session = session_manager_.GetOrCreateSession(session_id, endpoint, true, std::nullopt, *logger_);

        auto ip_opt = ip_pool.AllocateIpv4(session_id.value);
        ASSERT_TRUE(ip_opt.has_value());

        session.SetAssignedIpv4(*ip_opt);
        routing_table_.AddRoute(*ip_opt, 32, session_id.value);

        session_ids.push_back(session_id);
        allocated_ips.push_back(*ip_opt);
    }

    // Verify all IPs are unique
    std::set<uint32_t> unique_ips(allocated_ips.begin(), allocated_ips.end());
    EXPECT_EQ(unique_ips.size(), 5);

    // Verify all routes work
    for (size_t i = 0; i < session_ids.size(); ++i)
    {
        auto routed = routing_table_.Lookup(allocated_ips[i]);
        EXPECT_TRUE(routed.has_value());
        EXPECT_EQ(*routed, session_ids[i].value);
    }
}

// Test: IP release and reallocation
TEST_F(VpnServerIntegrationTest, IpReleaseAndReallocation)
{
    IpPoolManager ip_pool("192.168.1.0/30", false); // Only 2 usable IPs

    auto id1 = SessionId::Generate();
    auto id2 = SessionId::Generate();
    auto id3 = SessionId::Generate();

    // Allocate both IPs
    auto ip1 = ip_pool.AllocateIpv4(id1.value);
    auto ip2 = ip_pool.AllocateIpv4(id2.value);
    EXPECT_TRUE(ip1.has_value());
    EXPECT_TRUE(ip2.has_value());

    // Try to allocate third - should fail (pool exhausted)
    auto ip3 = ip_pool.AllocateIpv4(id3.value);
    EXPECT_FALSE(ip3.has_value());

    // Release first IP
    ip_pool.ReleaseIpv4(id1.value);
    routing_table_.RemoveRoute(*ip1, 32);

    // Now third client can get an IP
    ip3 = ip_pool.AllocateIpv4(id3.value);
    EXPECT_TRUE(ip3.has_value());
}

// Test: IP pool cleanup on session removal
TEST_F(VpnServerIntegrationTest, IpPoolCleanupOnSessionRemoval)
{
    IpPoolManager ip_pool("10.8.0.0/24", true);

    auto id1 = SessionId::Generate();
    auto id2 = SessionId::Generate();
    auto endpoint1 = CreateEndpoint(0xC0A80090, 5900);
    auto endpoint2 = CreateEndpoint(0xC0A80091, 5901);

    session_manager_.GetOrCreateSession(id1, endpoint1, true, std::nullopt, *logger_);
    session_manager_.GetOrCreateSession(id2, endpoint2, true, std::nullopt, *logger_);

    // Allocate IPs
    auto ip1 = ip_pool.AllocateIpv4(id1.value);
    auto ip2 = ip_pool.AllocateIpv4(id2.value);
    ASSERT_TRUE(ip1.has_value());
    ASSERT_TRUE(ip2.has_value());

    EXPECT_EQ(ip_pool.AllocatedCount(), 2);
    EXPECT_EQ(session_manager_.GetSessionCount(), 2);

    // Remove first session
    session_manager_.RemoveSession(id1);
    ip_pool.ReleaseIpv4(id1.value);

    EXPECT_EQ(ip_pool.AllocatedCount(), 1);
    EXPECT_EQ(ip_pool.AvailableCount(), ip_pool.TotalCount() - 1);

    // Verify second session still has its IP
    EXPECT_TRUE(ip_pool.IsIpv4Allocated(*ip2));
    EXPECT_FALSE(ip_pool.IsIpv4Allocated(*ip1));
}

// Test: IP assignment with routing integration
TEST_F(VpnServerIntegrationTest, IpAssignmentWithRoutingIntegration)
{
    IpPoolManager ip_pool("10.8.0.0/24", true);

    auto id1 = SessionId::Generate();
    auto endpoint1 = CreateEndpoint(0xC0A800A0, 6000);
    auto &session = session_manager_.GetOrCreateSession(id1, endpoint1, true, std::nullopt, *logger_);

    // Allocate IP and add route
    auto ip = ip_pool.AllocateIpv4(id1.value);
    ASSERT_TRUE(ip.has_value());

    session.SetAssignedIpv4(*ip);
    routing_table_.AddRoute(*ip, 32, id1.value);

    // Convert IP to string for verification
    struct in_addr addr;
    addr.s_addr = htonl(*ip);
    std::string ip_str = inet_ntoa(addr);

    // Should be within the 10.8.0.0/24 usable range (.2 .. .254)
    EXPECT_GE(*ip, 0x0A080002u); // 10.8.0.2
    EXPECT_LE(*ip, 0x0A0800FEu); // 10.8.0.254

    // Verify routing works
    auto routed = routing_table_.Lookup(*ip);
    ASSERT_TRUE(routed.has_value());
    EXPECT_EQ(*routed, id1.value);
}
