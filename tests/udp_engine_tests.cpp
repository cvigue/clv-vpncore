// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "udp_worker_thread.h"
#include "udp_engine_types.h"
#include "cpu_affinity.h"
#include "data_path_stats.h"
#include "openvpn/connection.h"
#include "openvpn/data_channel.h"
#include "openvpn/session_manager.h"
#include "p2p_policy.h"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <gtest/gtest.h>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <latch>
#include <thread>

using namespace clv::vpn;
using namespace std::chrono_literals;

namespace {

spdlog::logger &TestLogger()
{
    static auto sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    static spdlog::logger logger("test_udp_engine", sink);
    return logger;
}

} // namespace

// --- Lifecycle tests ---

TEST(UdpWorkerThread, ConstructDestruct)
{
    UdpWorkerThread sd("test", kAffinityOff, TestLogger());
    EXPECT_FALSE(sd.running());
}

TEST(UdpWorkerThread, StartStop)
{
    UdpWorkerThread sd("test", kAffinityOff, TestLogger());
    sd.Start();
    EXPECT_TRUE(sd.running());
    sd.Stop();
    EXPECT_FALSE(sd.running());
}

TEST(UdpWorkerThread, DoubleStartIsNoop)
{
    UdpWorkerThread sd("test", kAffinityOff, TestLogger());
    sd.Start();
    sd.Start(); // second call should be harmless
    EXPECT_TRUE(sd.running());
    sd.Stop();
}

TEST(UdpWorkerThread, DoubleStopIsNoop)
{
    UdpWorkerThread sd("test", kAffinityOff, TestLogger());
    sd.Start();
    sd.Stop();
    sd.Stop(); // second call should be harmless
    EXPECT_FALSE(sd.running());
}

TEST(UdpWorkerThread, DestructorStops)
{
    auto sd = std::make_unique<UdpWorkerThread>("test", kAffinityOff, TestLogger());
    sd->Start();
    EXPECT_TRUE(sd->running());
    sd.reset(); // destructor should call Stop
}

// --- Work execution tests ---

TEST(UdpWorkerThread, PostRunsOnWorkerThread)
{
    UdpWorkerThread sd("test", kAffinityOff, TestLogger());
    sd.Start();

    std::thread::id worker_tid;
    std::latch done(1);

    asio::post(sd.context(), [&]
    {
        worker_tid = std::this_thread::get_id();
        done.count_down();
    });

    done.wait();
    EXPECT_NE(worker_tid, std::this_thread::get_id());

    sd.Stop();
}

TEST(UdpWorkerThread, CoroutineRunsOnWorkerThread)
{
    UdpWorkerThread sd("test", kAffinityOff, TestLogger());
    sd.Start();

    std::thread::id worker_tid;
    std::latch done(1);

    asio::co_spawn(
        sd.context(),
        [&]() -> asio::awaitable<void>
    {
        worker_tid = std::this_thread::get_id();
        done.count_down();
        co_return;
    },
        asio::detached);

    done.wait();
    EXPECT_NE(worker_tid, std::this_thread::get_id());

    sd.Stop();
}

TEST(UdpWorkerThread, MultiplePostsExecuteInOrder)
{
    UdpWorkerThread sd("test", kAffinityOff, TestLogger());
    sd.Start();

    constexpr int kCount = 1000;
    std::vector<int> results;
    results.reserve(kCount);
    std::latch done(1);

    for (int i = 0; i < kCount; ++i)
    {
        asio::post(sd.context(), [&results, i]
        { results.push_back(i); });
    }
    asio::post(sd.context(), [&done]
    { done.count_down(); });

    done.wait();
    ASSERT_EQ(results.size(), kCount);
    for (int i = 0; i < kCount; ++i)
        EXPECT_EQ(results[i], i);

    sd.Stop();
}

TEST(UdpWorkerThread, WorkerStaysAliveWithoutWork)
{
    // Work guard keeps the context alive even with no pending work.
    UdpWorkerThread sd("test", kAffinityOff, TestLogger());
    sd.Start();

    std::this_thread::sleep_for(50ms);
    EXPECT_TRUE(sd.running());

    // Post work after the idle period.
    std::atomic<bool> executed{false};
    std::latch done(1);

    asio::post(sd.context(), [&]
    {
        executed.store(true, std::memory_order_release);
        done.count_down();
    });

    done.wait();
    EXPECT_TRUE(executed.load(std::memory_order_acquire));

    sd.Stop();
}

TEST(UdpWorkerThread, TimerWorksOnTxContext)
{
    UdpWorkerThread sd("test", kAffinityOff, TestLogger());
    sd.Start();

    std::atomic<bool> fired{false};
    std::latch done(1);

    asio::co_spawn(
        sd.context(),
        [&]() -> asio::awaitable<void>
    {
        asio::steady_timer timer(co_await asio::this_coro::executor, 10ms);
        co_await timer.async_wait(asio::use_awaitable);
        fired.store(true, std::memory_order_release);
        done.count_down();
    },
        asio::detached);

    done.wait();
    EXPECT_TRUE(fired.load(std::memory_order_acquire));

    sd.Stop();
}

// --- Thread isolation test ---

TEST(UdpWorkerThread, TxContextIsSeparateFromCallerContext)
{
    asio::io_context rx_ctx;
    UdpWorkerThread sd("test", kAffinityOff, TestLogger());
    sd.Start();

    std::thread::id rx_tid;
    std::thread::id tx_tid;
    std::latch done(2);

    asio::post(sd.context(), [&]
    {
        tx_tid = std::this_thread::get_id();
        done.count_down();
    });

    asio::post(rx_ctx, [&]
    {
        rx_tid = std::this_thread::get_id();
        done.count_down();
    });

    // Drive rx_ctx from this thread.
    rx_ctx.run();
    done.wait();

    EXPECT_NE(tx_tid, rx_tid);

    sd.Stop();
}

// --- DataPathStats Merge tests ---

TEST(DataPathStatsMerge, MergeReconstructsUnifiedStats)
{
    DataPathStats::RxCounters rx;
    rx.packetsReceived = 1000;
    rx.bytesReceived = 500000;
    rx.batchHist[0] = 10;
    rx.batchHist[1] = 5;
    rx.batchSaturations = 3;
    rx.packetsDecrypted = 990;
    rx.decryptFailures = 10;
    rx.tunWrites = 990;

    DataPathStats::TxCounters tx;
    tx.tunReads = 800;
    tx.packetsEncrypted = 800;
    tx.packetsSent = 795;
    tx.bytesSent = 400000;
    tx.sendErrors = 5;
    tx.routeLookupMisses = 3;

    auto merged = DataPathStats::Merge(rx, tx);

    // RX fields
    EXPECT_EQ(merged.packetsReceived, 1000);
    EXPECT_EQ(merged.bytesReceived, 500000);
    EXPECT_EQ(merged.batchHist[0], 10);
    EXPECT_EQ(merged.batchHist[1], 5);
    EXPECT_EQ(merged.batchSaturations, 3);
    EXPECT_EQ(merged.packetsDecrypted, 990);
    EXPECT_EQ(merged.decryptFailures, 10);
    EXPECT_EQ(merged.tunWrites, 990);

    // TX fields
    EXPECT_EQ(merged.tunReads, 800);
    EXPECT_EQ(merged.packetsEncrypted, 800);
    EXPECT_EQ(merged.packetsSent, 795);
    EXPECT_EQ(merged.bytesSent, 400000);
    EXPECT_EQ(merged.sendErrors, 5);
    EXPECT_EQ(merged.routeLookupMisses, 3);
}

TEST(DataPathStatsMerge, MergeOfDefaultsIsZero)
{
    DataPathStats::RxCounters rx;
    DataPathStats::TxCounters tx;
    auto merged = DataPathStats::Merge(rx, tx);

    EXPECT_EQ(merged.packetsReceived, 0);
    EXPECT_EQ(merged.bytesSent, 0);
    EXPECT_EQ(merged.routeLookupMisses, 0);
}

TEST(DataPathStatsMerge, RecordBatchHelpers)
{
    DataPathStats::RxCounters rx;
    rx.RecordRecvBatch(512, 4096);  // bin 1, not saturated
    rx.RecordRecvBatch(4096, 4096); // bin 7, saturated

    EXPECT_EQ(rx.batchHist[1], 1);
    EXPECT_EQ(rx.batchHist[7], 1);
    EXPECT_EQ(rx.batchSaturations, 1);
}

TEST(DataPathStatsMerge, DeltaWorksWithMergedStats)
{
    DataPathStats::RxCounters rx1;
    rx1.packetsReceived = 100;
    DataPathStats::TxCounters tx1;
    tx1.packetsSent = 80;
    auto snap1 = DataPathStats::Merge(rx1, tx1);

    DataPathStats::RxCounters rx2;
    rx2.packetsReceived = 250;
    DataPathStats::TxCounters tx2;
    tx2.packetsSent = 200;
    auto snap2 = DataPathStats::Merge(rx2, tx2);

    auto delta = DataPathStats::Delta(snap2, snap1);
    EXPECT_EQ(delta.packetsReceived, 150);
    EXPECT_EQ(delta.packetsSent, 120);
}

// ============================================================================
// SessionIndex tests
// ============================================================================

using namespace clv::vpn;
using namespace clv::vpn::openvpn;

TEST(SessionIndex, FindReturnsNullptrForMissing)
{
    SessionIndex idx;
    EXPECT_EQ(idx.Find(SessionId{42}), nullptr);
    EXPECT_EQ(idx.size(), 0u);
}

TEST(SessionIndex, FindReturnsEntryForKnownSession)
{
    SessionIndex idx;
    SessionEntry entry;
    entry.key_id = 3;
    idx.entries[100] = entry;

    auto *found = idx.Find(SessionId{100});
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->key_id, 3);
}

TEST(SessionIndex, SizeReflectsEntries)
{
    SessionIndex idx;
    idx.entries[1] = {};
    idx.entries[2] = {};
    idx.entries[3] = {};
    EXPECT_EQ(idx.size(), 3u);
}

TEST(SessionIndex, CopyableForQsbrPublish)
{
    SessionIndex idx1;
    idx1.entries[42] = SessionEntry{.key_id = 7};
    SessionIndex idx2 = idx1;
    ASSERT_NE(idx2.Find(SessionId{42}), nullptr);
    EXPECT_EQ(idx2.Find(SessionId{42})->key_id, 7);
}

// ============================================================================
// TxEncryptState tests
// ============================================================================

static EncryptionKey MakeTestKey()
{
    EncryptionKey key;
    key.cipher_algorithm = CipherAlgorithm::AES_128_GCM;
    key.cipher_key.resize(16, 0xAB);
    key.cipher_iv.resize(8, 0xCD);
    key.hmac_algorithm = HmacAlgorithm::NONE;
    key.is_valid = true;
    key.key_id = 1;
    return key;
}

TEST(TxEncryptState, NeedsReinitWhenInvalid)
{
    TxEncryptState tx;
    EXPECT_TRUE(tx.NeedsReinit(0));
    EXPECT_TRUE(tx.NeedsReinit(1));
}

TEST(TxEncryptState, NeedsReinitWhenKeyIdChanged)
{
    TxEncryptState tx;
    auto key = MakeTestKey();
    tx.ApplySnapshot(key, 1);
    EXPECT_FALSE(tx.NeedsReinit(1));
    EXPECT_TRUE(tx.NeedsReinit(2));
}

TEST(TxEncryptState, ApplySnapshotInitializesContext)
{
    TxEncryptState tx;
    EXPECT_FALSE(tx.valid);

    auto key = MakeTestKey();
    tx.ApplySnapshot(key, 3);

    EXPECT_TRUE(tx.valid);
    EXPECT_EQ(tx.current_key_id, 3);
    EXPECT_TRUE(tx.encrypt_ctx.has_value());
    EXPECT_EQ(tx.cipher_iv, key.cipher_iv);
}

TEST(TxEncryptState, ApplySnapshotDoesNotResetPacketId)
{
    TxEncryptState tx;
    tx.outbound_packet_id = 1000;
    auto key = MakeTestKey();
    tx.ApplySnapshot(key, 1);
    EXPECT_EQ(tx.outbound_packet_id, 1000u);
}

TEST(TxEncryptState, EncryptInPlaceProducesValidWirePacket)
{
    TxEncryptState tx;
    auto key = MakeTestKey();
    tx.ApplySnapshot(key, 2);

    SessionId session{0x00ABCDEF};

    // Set up buffer: plaintext at offset kDataV2Overhead
    std::vector<std::uint8_t> buf(kDataV2Overhead + 64, 0);
    // Write some plaintext IP-like data at offset 24
    buf[kDataV2Overhead] = 0x45; // IPv4 header
    buf[kDataV2Overhead + 1] = 0x00;

    auto wire_len = tx.EncryptInPlace(buf, 64, session);
    ASSERT_GT(wire_len, 0u);
    EXPECT_EQ(wire_len, kDataV2Overhead + 64);

    // Verify P_DATA_V2 header
    uint8_t opcode_byte = buf[0];
    EXPECT_EQ(GetOpcode(opcode_byte), Opcode::P_DATA_V2);
    EXPECT_EQ(GetKeyId(opcode_byte), 2);

    // Verify peer_id (lower 24 bits of session)
    uint32_t peer_id = (static_cast<uint32_t>(buf[1]) << 16)
                       | (static_cast<uint32_t>(buf[2]) << 8)
                       | static_cast<uint32_t>(buf[3]);
    EXPECT_EQ(peer_id, 0x00ABCDEFu & PEER_ID_MASK);
}

TEST(TxEncryptState, EncryptInPlaceIncrementsPacketId)
{
    TxEncryptState tx;
    auto key = MakeTestKey();
    tx.ApplySnapshot(key, 0);

    EXPECT_EQ(tx.outbound_packet_id, 1u);

    std::vector<std::uint8_t> buf(kDataV2Overhead + 16, 0);
    SessionId session{1};

    auto w1 = tx.EncryptInPlace(buf, 16, session);
    EXPECT_GT(w1, 0u);
    EXPECT_EQ(tx.outbound_packet_id, 2u);

    auto w2 = tx.EncryptInPlace(buf, 16, session);
    EXPECT_GT(w2, 0u);
    EXPECT_EQ(tx.outbound_packet_id, 3u);
}

TEST(TxEncryptState, EncryptInPlaceReturnsZeroWhenInvalid)
{
    TxEncryptState tx;
    std::vector<std::uint8_t> buf(kDataV2Overhead + 16, 0);
    EXPECT_EQ(tx.EncryptInPlace(buf, 16, SessionId{1}), 0u);
}

TEST(TxEncryptState, EncryptInPlaceReturnsZeroForSmallBuffer)
{
    TxEncryptState tx;
    auto key = MakeTestKey();
    tx.ApplySnapshot(key, 0);

    std::vector<std::uint8_t> buf(10); // too small
    EXPECT_EQ(tx.EncryptInPlace(buf, 64, SessionId{1}), 0u);
}

TEST(TxEncryptState, EncryptInPlaceDecryptibleByDataChannel)
{
    // Verify wire compatibility: TxEncryptState encrypt → DataChannel decrypt
    auto key = MakeTestKey();
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    spdlog::logger logger("compat_test", null_sink);

    // Set up DataChannel with the same key
    DataChannel dc(logger);
    dc.InstallNewKeys(key, key, 1);

    // Encrypt with TxEncryptState
    TxEncryptState tx;
    tx.ApplySnapshot(key, 1);

    SessionId session{0x000001};
    constexpr std::size_t pt_len = 32;
    std::vector<std::uint8_t> buf(kDataV2Overhead + pt_len, 0);
    // Plaintext: IP-like data
    for (std::size_t i = 0; i < pt_len; ++i)
        buf[kDataV2Overhead + i] = static_cast<uint8_t>(i + 1);

    auto wire_len = tx.EncryptInPlace(buf, pt_len, session);
    ASSERT_EQ(wire_len, kDataV2Overhead + pt_len);

    // Decrypt with DataChannel
    auto plaintext = dc.DecryptPacketInPlace(std::span<uint8_t>(buf.data(), wire_len));
    ASSERT_FALSE(plaintext.empty());
    EXPECT_EQ(plaintext.size(), pt_len);
    for (std::size_t i = 0; i < pt_len; ++i)
        EXPECT_EQ(plaintext[i], static_cast<uint8_t>(i + 1));
}

// ============================================================================
// UdpEngineContext tests
// ============================================================================

TEST(UdpEngineContext, ConstructsWithEmptyState)
{
    UdpEngineContext ctx;
    EXPECT_NE(ctx.core, nullptr);

    auto rv4 = ctx.routes_v4.read();
    EXPECT_EQ(rv4->GetRouteCount(), 0u);

    auto sv = ctx.sessions.read();
    EXPECT_EQ(sv->size(), 0u);
}

TEST(UdpEngineContext, PublishRoutesUpdatesSnapshot)
{
    UdpEngineContext ctx;

    RoutingTableIpv4 v4;
    v4.AddRoute(0x0A000100, 24, 42); // 10.0.1.0/24 → session 42

    RoutingTableIpv6 v6;

    ctx.PublishRoutes(v4, v6);

    auto view = ctx.routes_v4.read();
    EXPECT_EQ(view->GetRouteCount(), 1u);
    auto sid = view->Lookup(0x0A000105); // 10.0.1.5
    ASSERT_TRUE(sid.has_value());
    EXPECT_EQ(*sid, 42u);
}

TEST(UdpEngineContext, PublishSessionsUpdatesSnapshot)
{
    UdpEngineContext ctx;

    SessionIndex idx;
    idx.entries[100] = SessionEntry{.key_id = 5};
    idx.entries[200] = SessionEntry{.key_id = 7};

    ctx.PublishSessions(idx);

    auto view = ctx.sessions.read();
    EXPECT_EQ(view->size(), 2u);
    auto *e = view->Find(SessionId{100});
    ASSERT_NE(e, nullptr);
    EXPECT_EQ(e->key_id, 5);
}

TEST(UdpEngineContext, QuiescedViewReadsCurrentSnapshot)
{
    UdpEngineContext ctx;

    // Register thread for QSBR
    ctx.core->register_thread();

    SessionIndex idx;
    idx.entries[1] = SessionEntry{.key_id = 3};
    ctx.PublishSessions(idx);

    // Quiesced read (zero-overhead)
    auto view = ctx.sessions.read_quiesced();
    ASSERT_NE(view->Find(SessionId{1}), nullptr);
    EXPECT_EQ(view->Find(SessionId{1})->key_id, 3);

    ctx.core->unregister_thread();
}

TEST(UdpEngineContext, ReclaimDeferredEmptyIsNoOp)
{
    UdpEngineContext ctx;
    ctx.ReclaimDeferred(); // should not crash
    EXPECT_TRUE(ctx.deferred.empty());
    ctx.ForceReclaimAll(); // clean up qsbr_register allocation
}

TEST(UdpEngineContext, SharedCoreAdvancesAllEpochs)
{
    UdpEngineContext ctx;

    // All QsbrType members share the same core
    EXPECT_EQ(ctx.routes_v4.core(), ctx.core);
    EXPECT_EQ(ctx.routes_v6.core(), ctx.core);
    EXPECT_EQ(ctx.sessions.core(), ctx.core);
}

// ============================================================================
// SessionIndex::FindByEndpoint tests
// ============================================================================

static transport::PeerEndpoint MakeEndpoint(const char *ip, std::uint16_t port)
{
    return {asio::ip::make_address(ip), port};
}

TEST(SessionIndex, FindByEndpointReturnsNullptrForEmpty)
{
    SessionIndex idx;
    auto ep = MakeEndpoint("10.0.0.1", 1194);
    EXPECT_EQ(idx.FindByEndpoint(ep), nullptr);
}

TEST(SessionIndex, FindByEndpointReturnsEntryForKnownEndpoint)
{
    SessionIndex idx;
    auto ep = MakeEndpoint("10.0.0.1", 1194);
    SessionEntry entry;
    entry.key_id = 5;
    idx.entries[99] = entry;
    idx.by_endpoint[ep] = 99;

    auto *found = idx.FindByEndpoint(ep);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->key_id, 5);
}

TEST(SessionIndex, FindByEndpointDistinguishesByPort)
{
    SessionIndex idx;
    auto ep1 = MakeEndpoint("10.0.0.1", 1194);
    auto ep2 = MakeEndpoint("10.0.0.1", 5000); // same IP, different port
    SessionEntry entry;
    entry.key_id = 7;
    idx.entries[1] = entry;
    idx.by_endpoint[ep1] = 1;

    EXPECT_NE(idx.FindByEndpoint(ep1), nullptr);
    EXPECT_EQ(idx.FindByEndpoint(ep2), nullptr);
}

TEST(SessionIndex, FindByEndpointDistinguishesByAddress)
{
    SessionIndex idx;
    auto ep1 = MakeEndpoint("10.0.0.1", 1194);
    auto ep2 = MakeEndpoint("10.0.0.2", 1194); // different IP, same port
    idx.entries[1] = SessionEntry{.key_id = 2};
    idx.by_endpoint[ep1] = 1;

    EXPECT_NE(idx.FindByEndpoint(ep1), nullptr);
    EXPECT_EQ(idx.FindByEndpoint(ep2), nullptr);
}

TEST(SessionIndex, FindByEndpointWithOrphanedReverseEntry)
{
    // by_endpoint points to a session_id with no matching entry
    SessionIndex idx;
    auto ep = MakeEndpoint("192.168.1.1", 4242);
    idx.by_endpoint[ep] = 999; // no entry for 999

    EXPECT_EQ(idx.FindByEndpoint(ep), nullptr);
}

TEST(SessionIndex, FindByEndpointWithIpv6Endpoint)
{
    SessionIndex idx;
    auto ep = MakeEndpoint("2001:db8::1", 1194);
    idx.entries[7] = SessionEntry{.key_id = 11};
    idx.by_endpoint[ep] = 7;

    auto *found = idx.FindByEndpoint(ep);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->key_id, 11);
}

TEST(SessionIndex, FindByEndpointMultiplePeers)
{
    // Ensure multiple endpoints map to distinct entries independently
    SessionIndex idx;
    auto ep1 = MakeEndpoint("10.0.0.1", 1194);
    auto ep2 = MakeEndpoint("10.0.0.2", 1194);
    idx.entries[1] = SessionEntry{.key_id = 1};
    idx.entries[2] = SessionEntry{.key_id = 2};
    idx.by_endpoint[ep1] = 1;
    idx.by_endpoint[ep2] = 2;

    ASSERT_NE(idx.FindByEndpoint(ep1), nullptr);
    ASSERT_NE(idx.FindByEndpoint(ep2), nullptr);
    EXPECT_EQ(idx.FindByEndpoint(ep1)->key_id, 1);
    EXPECT_EQ(idx.FindByEndpoint(ep2)->key_id, 2);
}

// ============================================================================
// P2PPolicy state machine tests
// ============================================================================

TEST(P2PPolicy, DefaultState_TxReadyFalse)
{
    P2PPolicy policy{TestLogger()};
    EXPECT_FALSE(policy.TxReady());
}

TEST(P2PPolicy, SetPeer_ValidFd_TxReadyTrue)
{
    P2PPolicy policy{TestLogger()};
    auto ep = MakeEndpoint("10.0.0.1", 1194);
    policy.SetPeer(ep, SessionId{1}, /*socket_fd=*/5);
    EXPECT_TRUE(policy.TxReady());
    EXPECT_EQ(policy.TxSocketFd(), 5);
}

TEST(P2PPolicy, SetPeer_InvalidFd_TxReadyFalse)
{
    P2PPolicy policy{TestLogger()};
    auto ep = MakeEndpoint("10.0.0.1", 1194);
    policy.SetPeer(ep, SessionId{1}, /*socket_fd=*/-1);
    EXPECT_FALSE(policy.TxReady());
}

TEST(P2PPolicy, ApplyEncryptKey_AfterSetPeer_TxReadyTrue)
{
    P2PPolicy policy{TestLogger()};
    auto ep = MakeEndpoint("10.0.0.1", 1194);
    policy.SetPeer(ep, SessionId{1}, 5);

    auto key = MakeTestKey();
    policy.ApplyEncryptKey(key, 3);

    EXPECT_TRUE(policy.TxReady());
    EXPECT_EQ(policy.tx_snapshot.key_id, 3);
}

TEST(P2PPolicy, ApplyEncryptKey_WithoutPeer_TxReadyFalse)
{
    // valid flag is gated on socket_fd — no SetPeer means socket_fd stays -1
    P2PPolicy policy{TestLogger()};
    auto key = MakeTestKey();
    policy.ApplyEncryptKey(key, 2);
    EXPECT_FALSE(policy.TxReady());
}

TEST(P2PPolicy, Reset_ClearsAllState)
{
    P2PPolicy policy{TestLogger()};
    auto ep = MakeEndpoint("10.0.0.1", 1194);
    policy.SetPeer(ep, SessionId{1}, 5);
    policy.ApplyEncryptKey(MakeTestKey(), 1);
    EXPECT_TRUE(policy.TxReady());

    policy.Reset();

    EXPECT_FALSE(policy.TxReady());
    EXPECT_EQ(policy.TxSocketFd(), -1);
    EXPECT_FALSE(policy.tx_encrypt.valid);
}

TEST(P2PPolicy, SetPeer_UpdatesDestAndSession)
{
    P2PPolicy policy{TestLogger()};
    auto ep = MakeEndpoint("172.16.0.1", 4242);
    SessionId sid{0xDEAD};
    policy.SetPeer(ep, sid, 7);

    EXPECT_EQ(policy.tx_snapshot.peer, ep);
    EXPECT_EQ(policy.tx_snapshot.session_id.value, sid.value);
    EXPECT_EQ(policy.tx_snapshot.socket_fd, 7);
}

TEST(P2PPolicy, EncryptSlot_ReturnsWireLen)
{
    P2PPolicy policy{TestLogger()};
    auto ep = MakeEndpoint("10.0.0.1", 1194);
    SessionId sid{42};
    policy.SetPeer(ep, sid, 5);
    policy.ApplyEncryptKey(MakeTestKey(), 3);
    policy.tx_snapshot.valid = true;

    constexpr std::size_t pt_len = 64;
    std::vector<uint8_t> slot_buf(kDataV2Overhead + pt_len, 0);
    transport::SendEntry out;
    Connection *conn = nullptr;
    auto wire_len = policy.EncryptSlot(slot_buf, pt_len, out, conn);
    EXPECT_GT(wire_len, 0u);
    EXPECT_EQ(out.dest, ep);
    EXPECT_EQ(conn, nullptr); // P2P always returns null conn
}

TEST(P2PPolicy, EncryptSlot_IncrementsPacketIdEachCall)
{
    P2PPolicy policy{TestLogger()};
    policy.SetPeer(MakeEndpoint("10.0.0.1", 1194), SessionId{1}, 5);
    policy.ApplyEncryptKey(MakeTestKey(), 0);
    policy.tx_snapshot.valid = true;

    constexpr std::size_t pt_len = 64;
    std::vector<uint8_t> slot_buf(kDataV2Overhead + pt_len, 0);
    transport::SendEntry out;
    Connection *conn = nullptr;

    // Each call must encrypt successfully (wire_len > 0) and use a unique packet_id.
    // We can't inspect the packet_id directly but can verify all three succeed.
    auto w1 = policy.EncryptSlot(slot_buf, pt_len, out, conn);
    auto w2 = policy.EncryptSlot(slot_buf, pt_len, out, conn);
    auto w3 = policy.EncryptSlot(slot_buf, pt_len, out, conn);

    EXPECT_GT(w1, 0u);
    EXPECT_GT(w2, 0u);
    EXPECT_GT(w3, 0u);
}

// ============================================================================
// cpu_affinity error paths (previously dead)
// ============================================================================

TEST(CpuAffinity, SetThreadAffinity_OffIsNoop)
{
    // kAffinityOff is a no-op and must always return true.
    EXPECT_TRUE(SetThreadAffinity(kAffinityOff, TestLogger(), "test"));
}

TEST(CpuAffinity, SetThreadAffinity_OutOfRangeReturnsFalse)
{
    // An out-of-range core (very large) must be rejected.
    EXPECT_FALSE(SetThreadAffinity(999999, TestLogger(), "test"));
}

TEST(CpuAffinity, SetThreadAffinity_NegativeCoreReturnsFalse)
{
    // A negative value that is not a sentinel must be rejected.
    // Any negative value other than kAffinityOff (-1) and kAffinityAuto (-2)
    // falls through to the range check: (core < 0) → false. Use -3.
    EXPECT_FALSE(SetThreadAffinity(-3, TestLogger(), "test"));
}

TEST(CpuAffinity, AffinityModeString_Off)
{
    EXPECT_EQ("off", AffinityModeString(kAffinityOff));
}

TEST(CpuAffinity, AffinityModeString_Auto)
{
    EXPECT_EQ("auto", AffinityModeString(kAffinityAuto));
}

TEST(CpuAffinity, AffinityModeString_Numeric)
{
    EXPECT_EQ("2", AffinityModeString(2));
    EXPECT_EQ("0", AffinityModeString(0));
}

TEST(CpuAffinity, GetCurrentCpu_ReturnsValidCore)
{
    // sched_getcpu() must succeed in a normal test environment.
    int cpu = GetCurrentCpu();
    EXPECT_GE(cpu, 0);
}

TEST(CpuAffinity, SetThreadAffinity_Core0_Succeeds)
{
    // Pinning to CPU 0 must always succeed (every machine has CPU 0).
    // This exercises the actual sched_setaffinity syscall path.
    EXPECT_TRUE(SetThreadAffinity(0, TestLogger(), "test"));
}

TEST(CpuAffinity, SetThreadAffinity_Auto_Pins_ToCurrentCore)
{
    // kAffinityAuto queries sched_getcpu() and pins there — covers the auto branch
    // and the success path through sched_setaffinity.
    EXPECT_TRUE(SetThreadAffinity(kAffinityAuto, TestLogger(), "test"));
}

TEST(CpuAffinity, ClearThreadAffinity_Succeeds)
{
    // Restoring full CPU mask should always succeed.
    EXPECT_TRUE(ClearThreadAffinity(TestLogger()));
}

// ============================================================================
// CpuCoreAllocator
// ============================================================================

TEST(CpuCoreAllocator, Claim_Off_ReturnsOff)
{
    CpuCoreAllocator::ResetForTesting();
    EXPECT_EQ(CpuCoreAllocator::Claim(kAffinityOff), kAffinityOff);
}

TEST(CpuCoreAllocator, Claim_Auto_ReturnsValidCore)
{
    CpuCoreAllocator::ResetForTesting();
    int core = CpuCoreAllocator::Claim(kAffinityAuto);
    EXPECT_GE(core, 0);
    CpuCoreAllocator::Release(core);
}

TEST(CpuCoreAllocator, Claim_ExplicitCore_ReturnsThatCore)
{
    CpuCoreAllocator::ResetForTesting();
    int core = CpuCoreAllocator::Claim(0);
    EXPECT_EQ(core, 0);
    CpuCoreAllocator::Release(core);
}

TEST(CpuCoreAllocator, Claim_AlreadyClaimed_PicksDifferentCore)
{
    CpuCoreAllocator::ResetForTesting();
    if (std::thread::hardware_concurrency() < 2)
        GTEST_SKIP() << "Need >= 2 logical cores";

    int first = CpuCoreAllocator::Claim(0);
    ASSERT_EQ(first, 0);

    int second = CpuCoreAllocator::Claim(0);
    EXPECT_GE(second, 0);
    EXPECT_NE(second, first);

    CpuCoreAllocator::Release(first);
    CpuCoreAllocator::Release(second);
}

TEST(CpuCoreAllocator, Release_AllowsReclaim)
{
    CpuCoreAllocator::ResetForTesting();

    int core = CpuCoreAllocator::Claim(0);
    ASSERT_EQ(core, 0);

    CpuCoreAllocator::Release(core);

    int reclaimed = CpuCoreAllocator::Claim(0);
    EXPECT_EQ(reclaimed, 0);
    CpuCoreAllocator::Release(reclaimed);
}

TEST(CpuCoreAllocator, Release_Negative_IsNoop)
{
    CpuCoreAllocator::ResetForTesting();
    // Must not crash or corrupt state.
    CpuCoreAllocator::Release(kAffinityOff);
    CpuCoreAllocator::Release(-2);
    EXPECT_EQ(CpuCoreAllocator::Claim(0), 0);
    CpuCoreAllocator::Release(0);
}

TEST(CpuCoreAllocator, ConcurrentAutoClaimsYieldDistinctCores)
{
    CpuCoreAllocator::ResetForTesting();
    if (std::thread::hardware_concurrency() < 2)
        GTEST_SKIP() << "Need >= 2 logical cores";

    std::atomic<int> core_a{-1};
    std::atomic<int> core_b{-1};
    std::latch ready{2};

    auto t1 = std::jthread([&](std::stop_token)
    {
        ready.arrive_and_wait();
        core_a.store(CpuCoreAllocator::Claim(kAffinityAuto));
    });
    auto t2 = std::jthread([&](std::stop_token)
    {
        ready.arrive_and_wait();
        core_b.store(CpuCoreAllocator::Claim(kAffinityAuto));
    });
    t1.join();
    t2.join();

    EXPECT_GE(core_a.load(), 0);
    EXPECT_GE(core_b.load(), 0);
    EXPECT_NE(core_a.load(), core_b.load());

    CpuCoreAllocator::Release(core_a.load());
    CpuCoreAllocator::Release(core_b.load());
}

// ============================================================================
// TxEncryptState – explicit packet_id overload (4-param)
// ============================================================================

TEST(TxEncryptState, EncryptInPlace_WithExplicitPacketId)
{
    TxEncryptState tx;
    auto key = MakeTestKey();
    tx.ApplySnapshot(key, 1);

    SessionId session{0x000001};
    constexpr std::size_t pt_len = 16;
    std::vector<uint8_t> buf(kDataV2Overhead + pt_len, 0);
    for (std::size_t i = 0; i < pt_len; ++i)
        buf[kDataV2Overhead + i] = static_cast<uint8_t>(i + 0x10);

    // 4-param overload with an explicit packet_id
    auto wire_len = tx.EncryptInPlace(buf, pt_len, session, /*packet_id=*/42u);
    ASSERT_EQ(wire_len, kDataV2Overhead + pt_len);

    // packet_id must appear at bytes [4..8) (big-endian)
    uint32_t pkt_id = (static_cast<uint32_t>(buf[4]) << 24)
                      | (static_cast<uint32_t>(buf[5]) << 16)
                      | (static_cast<uint32_t>(buf[6]) << 8)
                      | static_cast<uint32_t>(buf[7]);
    EXPECT_EQ(pkt_id, 42u);

    // The internal counter must NOT be incremented by the 4-param overload
    EXPECT_EQ(tx.outbound_packet_id, 1u);
}

// ============================================================================
// RxDecryptState tests
// ============================================================================

namespace {

static RxDecryptSnapshot MakeRxSnapshot(uint8_t key_id, uint8_t key_byte = 0xAB)
{
    EncryptionKey key;
    key.cipher_algorithm = CipherAlgorithm::AES_128_GCM;
    key.cipher_key.resize(16, key_byte);
    key.cipher_iv.resize(8, 0xCD);
    key.hmac_algorithm = HmacAlgorithm::NONE;
    key.is_valid = true;
    key.key_id = key_id;
    return RxDecryptSnapshot{.decrypt_key = key, .key_id = key_id, .valid = true};
}

} // namespace

TEST(RxDecryptState, NeedsReinit_WhenInvalid)
{
    RxDecryptState rx;
    EXPECT_TRUE(rx.NeedsReinit(0));
    EXPECT_TRUE(rx.NeedsReinit(1));
}

TEST(RxDecryptState, NeedsReinit_AfterApply_SameAndDifferentKeyId)
{
    RxDecryptState rx;
    rx.ApplySnapshot(MakeRxSnapshot(3));
    EXPECT_FALSE(rx.NeedsReinit(3));
    EXPECT_TRUE(rx.NeedsReinit(4));
}

TEST(RxDecryptState, ApplySnapshot_InstallsPrimaryKey)
{
    RxDecryptState rx;
    EXPECT_FALSE(rx.valid);
    rx.ApplySnapshot(MakeRxSnapshot(2));
    EXPECT_TRUE(rx.valid);
    EXPECT_EQ(rx.current_key_id, 2);
    EXPECT_FALSE(rx.lame_duck.has_value());
}

TEST(RxDecryptState, ApplySnapshot_InvalidSnapIsNoOp)
{
    RxDecryptState rx;
    RxDecryptSnapshot bad;
    bad.valid = false;
    rx.ApplySnapshot(bad);
    EXPECT_FALSE(rx.valid);
}

TEST(RxDecryptState, ApplySnapshot_SecondCallMovesToLameDuck)
{
    RxDecryptState rx;
    rx.ApplySnapshot(MakeRxSnapshot(1));
    EXPECT_FALSE(rx.lame_duck.has_value());

    rx.ApplySnapshot(MakeRxSnapshot(2, 0xEF));
    EXPECT_TRUE(rx.lame_duck.has_value());
    EXPECT_EQ(rx.current_key_id, 2);
}

TEST(RxDecryptState, DecryptPacketInPlace_BufferTooSmallReturnsEmpty)
{
    RxDecryptState rx;
    rx.ApplySnapshot(MakeRxSnapshot(1));
    std::vector<uint8_t> buf(4); // < kDataV2Overhead (24)
    EXPECT_TRUE(rx.DecryptPacketInPlace(buf).empty());
}

TEST(RxDecryptState, DecryptPacketInPlace_NonDataOpcodeReturnsEmpty)
{
    RxDecryptState rx;
    rx.ApplySnapshot(MakeRxSnapshot(1));
    std::vector<uint8_t> buf(kDataV2Overhead + 4, 0);
    buf[0] = 0x20; // P_CONTROL_V1 opcode byte (4 << 3)
    EXPECT_TRUE(rx.DecryptPacketInPlace(buf).empty());
}

TEST(RxDecryptState, DecryptPacketInPlace_NoKeyInstalledReturnsEmpty)
{
    // No ApplySnapshot → valid=false; key lookup always fails
    RxDecryptState rx;
    TxEncryptState tx;
    tx.ApplySnapshot(MakeTestKey(), 1);
    std::vector<uint8_t> buf(kDataV2Overhead + 16, 0);
    auto wire_len = tx.EncryptInPlace(buf, 16, SessionId{1});
    ASSERT_GT(wire_len, 0u);
    EXPECT_TRUE(rx.DecryptPacketInPlace(std::span<uint8_t>(buf.data(), wire_len)).empty());
}

TEST(RxDecryptState, DecryptPacketInPlace_UnsupportedCipherReturnsEmpty)
{
    // Install a NONE-cipher key → slot found but IsSupportedAead = false
    EncryptionKey none_key;
    none_key.cipher_algorithm = CipherAlgorithm::NONE;
    none_key.is_valid = true;
    none_key.key_id = 1;
    RxDecryptSnapshot snap{.decrypt_key = none_key, .key_id = 1, .valid = true};

    RxDecryptState rx;
    rx.ApplySnapshot(snap);
    EXPECT_TRUE(rx.valid);

    TxEncryptState tx;
    tx.ApplySnapshot(MakeTestKey(), 1); // valid AEAD encryption
    std::vector<uint8_t> buf(kDataV2Overhead + 16, 0);
    auto wire_len = tx.EncryptInPlace(buf, 16, SessionId{1});
    ASSERT_GT(wire_len, 0u);

    // RxDecryptState saw key_id=1 but cipher is NONE → empty
    EXPECT_TRUE(rx.DecryptPacketInPlace(std::span<uint8_t>(buf.data(), wire_len)).empty());
}

TEST(RxDecryptState, DecryptPacketInPlace_RoundtripWithTxEncrypt)
{
    TxEncryptState tx;
    tx.ApplySnapshot(MakeTestKey(), 1);

    RxDecryptState rx;
    rx.ApplySnapshot(MakeRxSnapshot(1));

    SessionId session{0xABCD};
    constexpr std::size_t pt_len = 32;
    std::vector<uint8_t> buf(kDataV2Overhead + pt_len, 0);
    for (std::size_t i = 0; i < pt_len; ++i)
        buf[kDataV2Overhead + i] = static_cast<uint8_t>(i + 1);

    auto wire_len = tx.EncryptInPlace(buf, pt_len, session);
    ASSERT_GT(wire_len, 0u);

    auto plaintext = rx.DecryptPacketInPlace(std::span<uint8_t>(buf.data(), wire_len));
    ASSERT_EQ(plaintext.size(), pt_len);
    for (std::size_t i = 0; i < pt_len; ++i)
        EXPECT_EQ(plaintext[i], static_cast<uint8_t>(i + 1));
}

TEST(RxDecryptState, DecryptPacketInPlace_LameDuckKeyDecrypts)
{
    // Encrypt with key1, then rotate to key2 → key1 becomes lame_duck → must still decrypt
    auto key1 = MakeTestKey(); // key_id=1, cipher=0xAB

    TxEncryptState tx;
    tx.ApplySnapshot(key1, 1);

    constexpr std::size_t pt_len = 16;
    std::vector<uint8_t> wire(kDataV2Overhead + pt_len, 0);
    wire[kDataV2Overhead] = 0x45; // IPv4 first byte as canary
    auto wire_len = tx.EncryptInPlace(wire, pt_len, SessionId{0x1234}, /*packet_id=*/10u);
    ASSERT_GT(wire_len, 0u);
    std::vector<uint8_t> saved(wire.begin(), wire.begin() + wire_len);

    // RX: install key1 (primary), then key2 (primary) → key1 → lame_duck
    auto key2 = MakeTestKey();
    key2.cipher_key.assign(16, 0xEF);
    key2.key_id = 2;

    RxDecryptState rx;
    rx.ApplySnapshot(MakeRxSnapshot(1, 0xAB));
    rx.ApplySnapshot(RxDecryptSnapshot{.decrypt_key = key2, .key_id = 2, .valid = true});

    ASSERT_TRUE(rx.lame_duck.has_value());

    std::vector<uint8_t> copy(saved);
    auto pt = rx.DecryptPacketInPlace(std::span<uint8_t>(copy.data(), wire_len));
    ASSERT_FALSE(pt.empty());
    EXPECT_EQ(copy[kDataV2Overhead], 0x45u); // canary intact after decrypt
}

TEST(RxDecryptState, DecryptPacketInPlace_AuthFailureReturnsEmpty)
{
    TxEncryptState tx;
    tx.ApplySnapshot(MakeTestKey(), 1);
    RxDecryptState rx;
    rx.ApplySnapshot(MakeRxSnapshot(1));

    std::vector<uint8_t> buf(kDataV2Overhead + 16, 0);
    auto wire_len = tx.EncryptInPlace(buf, 16, SessionId{0x1});
    ASSERT_GT(wire_len, 0u);

    buf[8] ^= 0xFF; // corrupt tag byte at offset 8

    EXPECT_TRUE(rx.DecryptPacketInPlace(std::span<uint8_t>(buf.data(), wire_len)).empty());
}

TEST(RxDecryptState, DecryptPacketInPlace_TooOldPacketIdReturnsEmpty)
{
    // kBits = 32*64 = 2048. Advance highest to 2049, then pkt_id=1 → diff=2048 → TooOld
    RxDecryptState rx;
    rx.ApplySnapshot(MakeRxSnapshot(1));

    TxEncryptState tx;
    tx.ApplySnapshot(MakeTestKey(), 1);
    SessionId session{0x1};
    constexpr std::size_t pt_len = 16;

    auto tryDecrypt = [&](uint32_t pkt_id) -> bool
    {
        std::vector<uint8_t> buf(kDataV2Overhead + pt_len, 0);
        auto w = tx.EncryptInPlace(buf, pt_len, session, pkt_id);
        if (w == 0)
            return false;
        return !rx.DecryptPacketInPlace(std::span<uint8_t>(buf.data(), w)).empty();
    };

    ASSERT_TRUE(tryDecrypt(1));    // accepted → highest=1
    ASSERT_TRUE(tryDecrypt(2049)); // accepted → highest=2049

    // pkt_id=1: diff = 2049-1 = 2048 ≥ kBits(2048) → TooOld
    EXPECT_FALSE(tryDecrypt(1));
}

TEST(RxDecryptState, DecryptPacketInPlace_DuplicatePacketIdReturnsEmpty)
{
    RxDecryptState rx;
    rx.ApplySnapshot(MakeRxSnapshot(1));

    TxEncryptState tx;
    tx.ApplySnapshot(MakeTestKey(), 1);
    constexpr std::size_t pt_len = 16;

    // Encrypt once, save wire bytes
    std::vector<uint8_t> wire(kDataV2Overhead + pt_len, 0);
    auto wire_len = tx.EncryptInPlace(wire, pt_len, SessionId{0x1}, /*packet_id=*/100u);
    ASSERT_GT(wire_len, 0u);
    std::vector<uint8_t> saved(wire.begin(), wire.begin() + wire_len);

    // First decrypt → success (Accept called → replay window records pkt_id=100)
    ASSERT_FALSE(rx.DecryptPacketInPlace(std::span<uint8_t>(wire.data(), wire_len)).empty());

    // Second decrypt of same packet_id → Duplicate → empty
    std::vector<uint8_t> copy(saved);
    EXPECT_TRUE(rx.DecryptPacketInPlace(std::span<uint8_t>(copy.data(), wire_len)).empty());
}

// ============================================================================
// DataPathStats – standalone RecordRecvBatch
// ============================================================================

TEST(DataPathStats, RecordRecvBatch_StandaloneCounters)
{
    DataPathStats s;
    s.RecordRecvBatch(512, 4096);  // bin 1, not saturated
    s.RecordRecvBatch(4096, 4096); // bin 7, saturated

    EXPECT_EQ(s.batchHist[1], 1u);
    EXPECT_EQ(s.batchHist[7], 1u);
    EXPECT_EQ(s.batchSaturations, 1u);
}

// ============================================================================
// StatsObserver tests
// ============================================================================

TEST(StatsObserver, Elapsed_ReturnsZeroOnFirstCallWithDefaultStats)
{
    DataPathStats live;
    StatsObserver obs(live);

    auto delta = obs.Elapsed();
    EXPECT_EQ(delta.packetsReceived, 0u);
    EXPECT_EQ(delta.bytesSent, 0u);
}

TEST(StatsObserver, Elapsed_ReturnsDelta_AfterLiveCounterUpdate)
{
    DataPathStats live;
    StatsObserver obs(live);

    live.packetsReceived = 500;
    live.bytesSent = 20000;

    auto delta = obs.Elapsed();
    EXPECT_EQ(delta.packetsReceived, 500u);
    EXPECT_EQ(delta.bytesSent, 20000u);

    // Second call: no new activity → delta is zero
    auto delta2 = obs.Elapsed();
    EXPECT_EQ(delta2.packetsReceived, 0u);
}

TEST(StatsObserver, RecordRxBatchHistogram_AccumulatesInWindow)
{
    DataPathStats live;
    StatsObserver obs(live);

    obs.RecordRxBatchHistogram(512); // bin 1
    obs.RecordRxBatchHistogram(512); // bin 1 again

    auto delta = obs.Elapsed();
    EXPECT_EQ(delta.batchHist[1], 2u);
    // Histogram is reset after Elapsed()
    auto delta2 = obs.Elapsed();
    EXPECT_EQ(delta2.batchHist[1], 0u);
}

// ============================================================================
// TxBurstAvgWindow tests
// ============================================================================

TEST(TxBurstAvgWindow, RecordAndSnapshot)
{
    TxBurstAvgWindow w;
    w.Record(10);
    w.Record(20);
    w.Record(30);
    auto [total, count] = w.SnapshotAndReset();
    EXPECT_EQ(total, 60u);
    EXPECT_EQ(count, 3u);
    // Reset clears counters
    auto [t2, c2] = w.SnapshotAndReset();
    EXPECT_EQ(t2, 0u);
    EXPECT_EQ(c2, 0u);
}

TEST(TxBurstAvgWindow, EmptySnapshot)
{
    TxBurstAvgWindow w;
    auto [total, count] = w.SnapshotAndReset();
    EXPECT_EQ(total, 0u);
    EXPECT_EQ(count, 0u);
    EXPECT_EQ(FormatAvgBurst(total, count), "---");
}

// ============================================================================
// RingOccHistWindow tests
// ============================================================================

TEST(RingOccHistWindow, BinMapping)
{
    // depth=32: occ=0 → bin 0, occ=1 (3%) → bin 1, occ=12 (37%) → bin 2, occ=28 (87%) → bin 3
    EXPECT_EQ(RingOccHistWindow::OccBin(0, 32), 0u);
    EXPECT_EQ(RingOccHistWindow::OccBin(1, 32), 1u);
    EXPECT_EQ(RingOccHistWindow::OccBin(8, 32), 1u);  // 25%
    EXPECT_EQ(RingOccHistWindow::OccBin(9, 32), 2u);  // 28%
    EXPECT_EQ(RingOccHistWindow::OccBin(24, 32), 2u); // 75%
    EXPECT_EQ(RingOccHistWindow::OccBin(25, 32), 3u); // 78%
    EXPECT_EQ(RingOccHistWindow::OccBin(31, 32), 3u); // 97%
}

TEST(RingOccHistWindow, RecordAndSnapshot)
{
    RingOccHistWindow w;
    w.Record(0, 32);  // bin 0
    w.Record(4, 32);  // bin 1 (12%)
    w.Record(16, 32); // bin 2 (50%)
    w.Record(30, 32); // bin 3 (93%)
    auto hist = w.SnapshotAndReset();
    EXPECT_EQ(hist[0], 1u);
    EXPECT_EQ(hist[1], 1u);
    EXPECT_EQ(hist[2], 1u);
    EXPECT_EQ(hist[3], 1u);
    // Reset
    auto hist2 = w.SnapshotAndReset();
    for (auto v : hist2)
        EXPECT_EQ(v, 0u);
}

TEST(RingOccHistWindow, FormatRingOccHistIdle)
{
    std::array<uint64_t, DataPathStats::kRingOccBins> hist{};
    EXPECT_EQ(FormatRingOccHist(hist), "idle");
}

TEST(RingOccHistWindow, FormatRingOccHistAllEmpty)
{
    std::array<uint64_t, DataPathStats::kRingOccBins> hist{};
    hist[0] = 100;
    auto s = FormatRingOccHist(hist);
    EXPECT_EQ(s, "[100,00,00,00]");
}

// ============================================================================
// ComputeStatsRates tests
// ============================================================================

TEST(ComputeStatsRates, ZeroElapsedReturnsZero)
{
    DataPathStats delta;
    delta.bytesReceived = 1000000;
    delta.bytesSent = 500000;

    auto rates = ComputeStatsRates(delta, /*elapsedSec=*/0.0, /*rcvBuf=*/212992, /*sndBuf=*/212992);
    EXPECT_DOUBLE_EQ(rates.rxMbps, 0.0);
    EXPECT_DOUBLE_EQ(rates.txMbps, 0.0);
}

TEST(ComputeStatsRates, NonZeroElapsed_ComputesMbps)
{
    DataPathStats delta;
    delta.bytesReceived = 1250000; // 10 Mbps over 1s
    delta.bytesSent = 625000;      // 5 Mbps over 1s

    auto rates = ComputeStatsRates(delta, /*elapsedSec=*/1.0, /*rcvBuf=*/212992, /*sndBuf=*/212992);
    EXPECT_NEAR(rates.rxMbps, 10.0, 0.1);
    EXPECT_NEAR(rates.txMbps, 5.0, 0.1);
    EXPECT_GT(rates.rxBufMs, 0.0);
    EXPECT_GT(rates.txBufMs, 0.0);
}

TEST(ComputeStatsRates, ZeroBytesGivesInfiniteBufMs)
{
    DataPathStats delta; // all zeros
    auto rates = ComputeStatsRates(delta, /*elapsedSec=*/1.0, /*rcvBuf=*/65536, /*sndBuf=*/65536);
    EXPECT_TRUE(std::isinf(rates.rxBufMs));
    EXPECT_TRUE(std::isinf(rates.txBufMs));
}

// ============================================================================
// FormatBatchHist tests
// ============================================================================

TEST(FormatBatchHist, AllZeroReturnsIdle)
{
    std::array<uint64_t, DataPathStats::kBatchHistBins> hist{};
    EXPECT_EQ(FormatBatchHist(hist, 0), "idle");
}

TEST(FormatBatchHist, NonZeroFormatsCorrectly)
{
    // 100 observations all in bin 0 → 100% in bin 0, 0% elsewhere
    std::array<uint64_t, DataPathStats::kBatchHistBins> hist{};
    hist[0] = 100;

    std::string result = FormatBatchHist(hist, /*sat=*/3);
    // Should start with '[' and end with "]-3"
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result, "idle");
    EXPECT_NE(result.find("]-3"), std::string::npos);
}

TEST(FormatBatchHist, DefaultBracketsWithSaturation)
{
    std::array<uint64_t, DataPathStats::kBatchHistBins> hist{};
    hist[3] = 50;
    hist[4] = 50;

    auto s = FormatBatchHist(hist, /*sat=*/0, /*open=*/'[', /*close=*/']');
    EXPECT_EQ(s.front(), '[');
    EXPECT_NE(s.find(']'), std::string::npos);
}

// ============================================================================
// BatchHistWindow tests
// ============================================================================

TEST(BatchHistWindow, RecordAndSnapshot)
{
    BatchHistWindow win;
    win.Record(512);  // bin 1
    win.Record(512);  // bin 1 again
    win.Record(1024); // bin 2

    auto snap = win.SnapshotAndReset();
    EXPECT_EQ(snap[1], 2u);
    EXPECT_EQ(snap[2], 1u);

    // After reset, bins are zero
    auto snap2 = win.SnapshotAndReset();
    for (auto v : snap2)
        EXPECT_EQ(v, 0u);
}

// ============================================================================
// P2PPolicy – uncovered methods
// ============================================================================

TEST(P2PPolicy, EncryptSlot_ProducesWirePacket)
{
    P2PPolicy policy{TestLogger()};
    auto ep = MakeEndpoint("10.0.0.1", 1194);
    SessionId sid{0xABCD};
    policy.SetPeer(ep, sid, 5);
    policy.ApplyEncryptKey(MakeTestKey(), 1);
    policy.tx_snapshot.valid = true;

    constexpr std::size_t pt_len = 32;
    std::vector<uint8_t> slot_buf(kDataV2Overhead + pt_len, 0);
    for (std::size_t i = 0; i < pt_len; ++i)
        slot_buf[kDataV2Overhead + i] = static_cast<uint8_t>(i + 1);

    transport::SendEntry out;
    Connection *conn = nullptr;
    auto wire_len = policy.EncryptSlot(slot_buf, pt_len, out, conn);
    EXPECT_GT(wire_len, 0u);
    EXPECT_EQ(wire_len, kDataV2Overhead + pt_len);
    EXPECT_EQ(out.dest, ep);
}

TEST(P2PPolicy, ApplyDecryptSnapshot_InstallsKey)
{
    // Verify the behavioural contract: after ApplyDecryptSnapshot a packet
    // encrypted with the matching key decrypts successfully.  rx_decrypt is
    // lazily applied on the first DecryptInPlace call, so we test via
    // round-trip rather than inspecting internal state directly.
    P2PPolicy policy{TestLogger()};
    policy.ApplyDecryptSnapshot(MakeRxSnapshot(2));

    EncryptionKey tx_key;
    tx_key.cipher_algorithm = CipherAlgorithm::AES_128_GCM;
    tx_key.cipher_key.resize(16, 0xAB); // matches MakeRxSnapshot default key_byte
    tx_key.cipher_iv.resize(8, 0xCD);
    tx_key.hmac_algorithm = HmacAlgorithm::NONE;
    tx_key.is_valid = true;
    tx_key.key_id = 2;

    TxEncryptState tx;
    tx.ApplySnapshot(tx_key, 2);

    constexpr std::size_t pt_len = 16;
    std::vector<uint8_t> backing(kDataV2Overhead + pt_len, 0);
    backing[kDataV2Overhead] = 0xBB; // canary
    auto wire_len = tx.EncryptInPlace(backing, pt_len, SessionId{0x1});
    ASSERT_GT(wire_len, 0u);

    transport::IncomingSlot slot;
    slot.buf = backing.data();
    slot.capacity = backing.size();
    slot.len = wire_len;

    auto pt = policy.DecryptInPlace(slot);
    ASSERT_FALSE(pt.empty());
    EXPECT_EQ(backing[kDataV2Overhead], 0xBBu);
}

TEST(P2PPolicy, DecryptInPlace_RoundtripWithTxEncryptState)
{
    auto key = MakeTestKey();

    P2PPolicy policy{TestLogger()};
    policy.ApplyDecryptSnapshot(MakeRxSnapshot(1));

    TxEncryptState tx;
    tx.ApplySnapshot(key, 1);

    constexpr std::size_t pt_len = 16;
    transport::IncomingSlot slot;
    std::vector<uint8_t> backing(kDataV2Overhead + pt_len, 0);
    backing[kDataV2Overhead] = 0x99; // canary
    auto wire_len = tx.EncryptInPlace(backing, pt_len, SessionId{0x1});
    ASSERT_GT(wire_len, 0u);
    slot.buf = backing.data();
    slot.capacity = backing.size();
    slot.len = wire_len;

    auto pt = policy.DecryptInPlace(slot);
    ASSERT_FALSE(pt.empty());
    EXPECT_EQ(backing[kDataV2Overhead], 0x99u);
}

TEST(P2PPolicy, Constructor_SetsLogger)
{
    P2PPolicy policy{TestLogger()};
    EXPECT_EQ(policy.rx_decrypt.logger, &TestLogger());
}

TEST(P2PPolicy, LifecycleCallbacks_AreNoOps)
{
    P2PPolicy policy{TestLogger()};
    policy.OnTxStart();
    policy.OnTxStop();
    policy.OnRxStart();
    policy.OnRxStop();
    policy.OnPostRecvBatch(0);
    policy.OnBatchSent(0);
    // Reaching here without crash is the assertion
    SUCCEED();
}

// ============================================================================
// UdpEngineContext – DeferDestruction and non-empty ReclaimDeferred
// ============================================================================

TEST(UdpEngineContext, DeferDestructionAddsToQueue)
{
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    auto log = std::make_unique<spdlog::logger>("ue_test", null_sink);

    UdpEngineContext ctx;
    Connection::Endpoint ep{asio::ip::address_v4(0xC0A80001), 1194};
    auto conn = std::make_unique<Connection>(
        openvpn::SessionId::Generate(), ep, true, std::nullopt, *log);

    ctx.DeferDestruction(std::move(conn));
    EXPECT_EQ(ctx.deferred.size(), 1u);
}

TEST(UdpEngineContext, ReclaimDeferred_NonEmpty_RegistrationAndReclaim)
{
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    auto log = std::make_unique<spdlog::logger>("ue_test2", null_sink);

    UdpEngineContext ctx;
    Connection::Endpoint ep{asio::ip::address_v4(0xC0A80002), 1194};
    auto conn = std::make_unique<Connection>(
        openvpn::SessionId::Generate(), ep, false, std::nullopt, *log);

    ctx.DeferDestruction(std::move(conn));
    EXPECT_EQ(ctx.deferred.size(), 1u);

    // ReclaimDeferred will register the CP thread and check QSBR epochs
    ctx.ReclaimDeferred();
    // No crash and the function ran → DeferredConnection lifecycle fully covered
    EXPECT_TRUE(ctx.cp_registered_);
    ctx.ForceReclaimAll(); // clean up qsbr_register allocation
}

TEST(SessionIndex, BuildFrom_EmptyManagerReturnsEmptyIndex)
{
    SessionManager sm;
    auto idx = SessionIndex::BuildFrom(sm);
    EXPECT_EQ(idx.size(), 0u);
}

TEST(SessionIndex, BuildFrom_SkipsSessionsWithoutKeys)
{
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    auto log = std::make_unique<spdlog::logger>("buildtest", null_sink);

    Connection::Endpoint ep{asio::ip::address_v4(0xC0A80001), 1194};
    auto session_id = openvpn::SessionId::Generate();

    SessionManager sm;
    // Session exists but has no keys installed → BuildFrom must skip it
    auto &conn = sm.GetOrCreateSession(session_id, ep, true, std::nullopt, *log);
    ASSERT_FALSE(conn.GetDataChannel().HasValidKeys());

    auto idx = SessionIndex::BuildFrom(sm);
    EXPECT_EQ(idx.size(), 0u); // skipped because no valid keys
}

TEST(UdpEngineContext, PublishSessions_FromManager_EmptyManagerPublishesEmptyIndex)
{
    UdpEngineContext ctx;
    SessionManager sm; // no sessions

    ctx.PublishSessions(sm); // exercises PublishSessions(const SessionManager&)

    auto view = ctx.sessions.read();
    EXPECT_EQ(view->size(), 0u);
}
