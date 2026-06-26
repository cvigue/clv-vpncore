// Copyright (c) 2025- Charlie Vigue. All rights reserved.

/**
 * @file server_helpers_tests.cpp
 * @brief Unit tests for newly-modular helper functions in the server control
 *        adapters and shared data-path stats utilities.
 *
 * Covers:
 *   - DeriveServerIp            (openvpn/push_exchange_helpers.h)
 *   - DeriveServerIpv6          (openvpn/push_exchange_helpers.h)
 *   - BuildKeyMethod2Options   (openvpn/control_plane_helpers.h)
 *   - ComputeStatsRates        (data_path_stats.h)
 *   - FormatBatchHist          (data_path_stats.h)
 *
 * All of these are pure inline functions exposed by the modularization
 * refactor.  None require a live network, kernel module, or TLS stack.
 */

#include "data_path_stats.h"
#include "openvpn/control_plane_helpers.h"
#include "openvpn/key_derivation.h"
#include "openvpn/push_exchange_helpers.h"
#include "openvpn/tls_crypt_v2.h"
#include "openvpn/vpn_config.h"
#include "server_control_base.h"

#include <algorithm>
#include <asio/co_spawn.hpp>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>

#include <array>
#include <cmath>
#include <initializer_list>
#include <optional>
#include <spdlog/sinks/null_sink.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace clv::vpn;

// ============================================================================
// DeriveServerIp
// ============================================================================

// Helper to build a minimal ServerConfig with just the fields DeriveServerIp touches.
static VpnConfig::ServerConfig MakeServerCfg(const std::string &network,
                                             const std::string &bridge_ip = {})
{
    VpnConfig::ServerConfig cfg;
    cfg.network = network;
    cfg.bridge_ip = bridge_ip;
    return cfg;
}

TEST(DeriveServerIp, Cidr24_NetworkPlusOne)
{
    // 10.8.0.0/24 → network addr 10.8.0.0, gateway = 10.8.0.1
    auto ip = DeriveServerIp(MakeServerCfg("10.8.0.0/24"));
    EXPECT_EQ(ip, "10.8.0.1");
}

TEST(DeriveServerIp, Cidr8_NetworkPlusOne)
{
    // 10.0.0.0/8 → 10.0.0.1
    auto ip = DeriveServerIp(MakeServerCfg("10.0.0.0/8"));
    EXPECT_EQ(ip, "10.0.0.1");
}

TEST(DeriveServerIp, Cidr16_NetworkPlusOne)
{
    // 192.168.1.0/16 → 192.168.0.1
    // ParseCidr masks the host bits: network = 192.168.0.0
    auto ip = DeriveServerIp(MakeServerCfg("192.168.0.0/16"));
    EXPECT_EQ(ip, "192.168.0.1");
}

TEST(DeriveServerIp, BridgeIpTakesPrecedence)
{
    // When bridge_ip is set, that value is returned directly (no CIDR math)
    auto ip = DeriveServerIp(MakeServerCfg("10.8.0.0/24", "172.16.0.254"));
    EXPECT_EQ(ip, "172.16.0.254");
}

TEST(DeriveServerIp, BridgeIpUsedEvenWithEmptyNetwork)
{
    auto ip = DeriveServerIp(MakeServerCfg("", "192.168.99.1"));
    EXPECT_EQ(ip, "192.168.99.1");
}

TEST(DeriveServerIp, InvalidCidrThrows)
{
    EXPECT_THROW(DeriveServerIp(MakeServerCfg("not-a-cidr")), std::invalid_argument);
}

TEST(DeriveServerIp, EmptyNetworkThrows)
{
    // No bridge_ip and empty network → ParseCidr fails
    EXPECT_THROW(DeriveServerIp(MakeServerCfg("")), std::invalid_argument);
}

// ============================================================================
// DeriveServerIpv6
// ============================================================================

static VpnConfig::ServerConfig MakeServerCfgV6(const std::string &network_v6)
{
    VpnConfig::ServerConfig cfg;
    cfg.network_v6 = network_v6;
    return cfg;
}

TEST(DeriveServerIpv6, LoopbackPrefix_LastByteIncrement)
{
    // fd00::/8 → network = fd00::, server = fd00::1
    auto ip = DeriveServerIpv6(MakeServerCfgV6("fd00::/8"));
    EXPECT_EQ(ip, "fd00::1");
}

TEST(DeriveServerIpv6, Slash64_NetworkPlusOne)
{
    auto ip = DeriveServerIpv6(MakeServerCfgV6("fd12:3456::/64"));
    EXPECT_EQ(ip, "fd12:3456::1");
}

TEST(DeriveServerIpv6, AllZeroNetwork_GivesOne)
{
    // ::/128 → ::1
    auto ip = DeriveServerIpv6(MakeServerCfgV6("::/128"));
    EXPECT_EQ(ip, "::1");
}

TEST(DeriveServerIpv6, InvalidCidrThrows)
{
    EXPECT_THROW(DeriveServerIpv6(MakeServerCfgV6("not-an-ipv6")),
                 std::invalid_argument);
}

TEST(DeriveServerIpv6, EmptyCidrThrows)
{
    EXPECT_THROW(DeriveServerIpv6(MakeServerCfgV6("")), std::invalid_argument);
}

// ============================================================================
// BuildKeyMethod2Options
// ============================================================================

// Helper: check all of these substrings appear in the option string.
static void ExpectContains(const std::string &s, std::initializer_list<std::string_view> tokens)
{
    for (auto tok : tokens)
        EXPECT_NE(s.find(tok), std::string::npos)
            << "  option string: \"" << s << "\"\n"
            << "  missing token: \"" << tok << "\"";
}

static void ExpectAbsent(const std::string &s, std::initializer_list<std::string_view> tokens)
{
    for (auto tok : tokens)
        EXPECT_EQ(s.find(tok), std::string::npos)
            << "  option string: \"" << s << "\"\n"
            << "  unexpected token: \"" << tok << "\"";
}

TEST(BuildKeyMethod2Options, ServerUdp_HasUdpv4AndTlsServer)
{
    auto opts = BuildKeyMethod2Options(openvpn::PeerRole::Server, "udp", "AES-256-GCM");
    ExpectContains(opts, {"proto UDPv4", "tls-server", "cipher AES-256-GCM"});
    ExpectAbsent(opts, {"tls-client", "TCPv4"});
}

TEST(BuildKeyMethod2Options, ClientUdp_HasUdpv4AndTlsClient)
{
    auto opts = BuildKeyMethod2Options(openvpn::PeerRole::Client, "udp", "AES-256-GCM");
    ExpectContains(opts, {"proto UDPv4", "tls-client", "cipher AES-256-GCM"});
    ExpectAbsent(opts, {"tls-server", "TCPv4", "auth [null-digest]"});
}

TEST(BuildKeyMethod2Options, ServerTcp_HasTcpServerLabel)
{
    auto opts = BuildKeyMethod2Options(openvpn::PeerRole::Server, "tcp", "AES-256-GCM");
    ExpectContains(opts, {"proto TCPv4_SERVER", "tls-server"});
    ExpectAbsent(opts, {"TCPv4_CLIENT", "UDPv4"});
}

TEST(BuildKeyMethod2Options, ClientTcp_HasTcpClientLabel)
{
    auto opts = BuildKeyMethod2Options(openvpn::PeerRole::Client, "tcp", "AES-256-GCM");
    ExpectContains(opts, {"proto TCPv4_CLIENT", "tls-client"});
    ExpectAbsent(opts, {"TCPv4_SERVER", "UDPv4"});
}

TEST(BuildKeyMethod2Options, UdpIpv6Only_HasUdpv6)
{
    auto opts = BuildKeyMethod2Options(openvpn::PeerRole::Client, "udp", "AES-256-GCM", 1500, true);
    ExpectContains(opts, {"proto UDPv6", "tls-client"});
    ExpectAbsent(opts, {"UDPv4", "TCP"});
}

TEST(BuildKeyMethod2Options, ServerWithNullCipher_GetsDefaultAes256)
{
    // Server role + empty cipher → default AES-256-GCM inserted
    auto opts = BuildKeyMethod2Options(openvpn::PeerRole::Server, "udp", "");
    ExpectContains(opts, {"cipher AES-256-GCM", "tls-server"});
}

TEST(BuildKeyMethod2Options, ClientWithNullCipher_NoCipherInOutput)
{
    // Client role + empty cipher → no cipher entry
    auto opts = BuildKeyMethod2Options(openvpn::PeerRole::Client, "udp", "");
    ExpectAbsent(opts, {"cipher"});
}

TEST(BuildKeyMethod2Options, ServerHasAuthAndKeysize)
{
    auto opts = BuildKeyMethod2Options(openvpn::PeerRole::Server, "udp", "AES-256-GCM");
    ExpectContains(opts, {"auth [null-digest]", "keysize 256"});
}

TEST(BuildKeyMethod2Options, ClientLacksAuthAndKeysize)
{
    auto opts = BuildKeyMethod2Options(openvpn::PeerRole::Client, "udp", "AES-256-GCM");
    ExpectAbsent(opts, {"auth [null-digest]", "keysize 256"});
}

TEST(BuildKeyMethod2Options, LinkMtuIsDerivation)
{
    // link-mtu = tun-mtu + 49
    auto opts = BuildKeyMethod2Options(openvpn::PeerRole::Server, "udp", "AES-256-GCM", 1400);
    ExpectContains(opts, {"link-mtu 1449", "tun-mtu 1400"});
}

TEST(BuildKeyMethod2Options, DefaultTunMtu1500_GivesLinkMtu1549)
{
    auto opts = BuildKeyMethod2Options(openvpn::PeerRole::Server, "udp", "AES-256-GCM");
    ExpectContains(opts, {"link-mtu 1549", "tun-mtu 1500"});
}

TEST(BuildKeyMethod2Options, StartsWithV4DevTypeTun)
{
    // Option string must start with "V4,dev-type tun,..."
    auto opts = BuildKeyMethod2Options(openvpn::PeerRole::Server, "udp", "AES-256-GCM");
    EXPECT_EQ(opts.rfind("V4,dev-type tun,", 0), 0u);
}

// ============================================================================
// ComputeStatsRates
// ============================================================================

static DataPathStats MakeStats(std::uint64_t bytes_recv, std::uint64_t bytes_sent)
{
    DataPathStats s{};
    s.bytesReceived = bytes_recv;
    s.bytesSent = bytes_sent;
    return s;
}

TEST(ComputeStatsRates, BasicMbpsCalculation)
{
    // 10 MB received, 5 MB sent over 1 second = 80 Mbps rx, 40 Mbps tx
    auto rates = ComputeStatsRates(MakeStats(10'000'000, 5'000'000), 1.0, 0, 0);
    EXPECT_NEAR(rates.rxMbps, 80.0, 0.1);
    EXPECT_NEAR(rates.txMbps, 40.0, 0.1);
}

TEST(ComputeStatsRates, ScalesByElapsedTime)
{
    // Same bytes over 2 seconds = half the rate
    auto r1 = ComputeStatsRates(MakeStats(10'000'000, 0), 1.0, 0, 0);
    auto r2 = ComputeStatsRates(MakeStats(10'000'000, 0), 2.0, 0, 0);
    EXPECT_NEAR(r1.rxMbps, r2.rxMbps * 2, 0.01);
}

TEST(ComputeStatsRates, ZeroElapsed_GivesZeroRates)
{
    auto rates = ComputeStatsRates(MakeStats(10'000'000, 5'000'000), 0.0, 0, 0);
    EXPECT_EQ(rates.rxMbps, 0.0);
    EXPECT_EQ(rates.txMbps, 0.0);
}

TEST(ComputeStatsRates, ZeroBytes_GivesZeroMbps)
{
    auto rates = ComputeStatsRates(MakeStats(0, 0), 1.0, 0, 0);
    EXPECT_EQ(rates.rxMbps, 0.0);
    EXPECT_EQ(rates.txMbps, 0.0);
}

TEST(ComputeStatsRates, BufferHeadroomMs_Rx)
{
    // rcvBuf=100000 bytes at 100000 bytes/s → 1000 ms headroom
    auto rates = ComputeStatsRates(MakeStats(100'000, 0), 1.0, /*rcvBuf=*/100'000, 0);
    EXPECT_NEAR(rates.rxBufMs, 1000.0, 1.0);
}

TEST(ComputeStatsRates, BufferHeadroomMs_Tx)
{
    // sndBuf=50000 bytes at 50000 bytes/s → 1000 ms headroom
    auto rates = ComputeStatsRates(MakeStats(0, 50'000), 1.0, 0, /*sndBuf=*/50'000);
    EXPECT_NEAR(rates.txBufMs, 1000.0, 1.0);
}

TEST(ComputeStatsRates, ZeroRxRate_GivesInfiniteRxBufMs)
{
    // Zero recv rate → infinite headroom (buffer never fills)
    auto rates = ComputeStatsRates(MakeStats(0, 100), 1.0, /*rcvBuf=*/65536, 0);
    EXPECT_TRUE(std::isinf(rates.rxBufMs));
}

TEST(ComputeStatsRates, ZeroTxRate_GivesInfiniteTxBufMs)
{
    auto rates = ComputeStatsRates(MakeStats(100, 0), 1.0, 0, /*sndBuf=*/65536);
    EXPECT_TRUE(std::isinf(rates.txBufMs));
}

// ============================================================================
// FormatBatchHist
// ============================================================================

using Hist = std::array<std::uint64_t, DataPathStats::kBatchHistBins>;

TEST(FormatBatchHist, AllZero_ReturnsIdle)
{
    Hist h{};
    EXPECT_EQ(FormatBatchHist(h, 0), "idle");
}

TEST(FormatBatchHist, AllInFirstBin_100Percent)
{
    Hist h{};
    h[0] = 1; // 100% in bin 0
    auto s = FormatBatchHist(h, 0);
    // Should start with '[', contain "100", end with "]-0"
    EXPECT_EQ(s[0], '[');
    EXPECT_NE(s.find("100"), std::string::npos);
    EXPECT_TRUE(s.rfind("-0") == s.size() - 2);
}

TEST(FormatBatchHist, AllInLastBin)
{
    Hist h{};
    h[DataPathStats::kBatchHistBins - 1] = 10;
    auto s = FormatBatchHist(h, 0);
    EXPECT_NE(s.find("100"), std::string::npos);
}

TEST(FormatBatchHist, SaturationCounterAppended)
{
    Hist h{};
    h[0] = 5;
    auto s = FormatBatchHist(h, /*sat=*/42);
    // Should end with "-42"
    EXPECT_NE(s.rfind("-42"), std::string::npos);
}

TEST(FormatBatchHist, CustomBrackets)
{
    Hist h{};
    h[0] = 1;
    auto s = FormatBatchHist(h, 0, '{', '}');
    EXPECT_EQ(s[0], '{');
    auto close_pos = s.rfind('}');
    EXPECT_NE(close_pos, std::string::npos);
}

TEST(FormatBatchHist, TwoBinsEqualSplit_FiftyPercent)
{
    Hist h{};
    h[0] = 50;
    h[1] = 50; // equal split
    auto s = FormatBatchHist(h, 0);
    // Both visible bins should show "50"
    auto first = s.find("50");
    ASSERT_NE(first, std::string::npos);
    auto second = s.find("50", first + 1);
    EXPECT_NE(second, std::string::npos);
}

TEST(FormatBatchHist, BinCountMatchesKBatchHistBins)
{
    // Each bin is separated by a comma; count commas → kBatchHistBins - 1
    Hist h{};
    h[3] = 1;
    auto s = FormatBatchHist(h, 0);
    // Strip brackets and saturation suffix; count commas
    std::size_t comma_count = std::count(s.begin(), s.end(), ',');
    EXPECT_EQ(comma_count, DataPathStats::kBatchHistBins - 1);
}

// ============================================================================
// detail::ExtractV3WKcLength
// ============================================================================

namespace {

// Build a packet of `total_size` bytes with the last two bytes encoding
// `wkc_len` in big-endian, and the rest filled with a dummy byte.
std::vector<std::uint8_t> MakeV3Packet(std::size_t total_size, std::uint16_t wkc_len)
{
    std::vector<std::uint8_t> pkt(total_size, 0xAB);
    if (total_size >= 2)
    {
        pkt[total_size - 2] = static_cast<std::uint8_t>(wkc_len >> 8);
        pkt[total_size - 1] = static_cast<std::uint8_t>(wkc_len & 0xFF);
    }
    return pkt;
}

constexpr std::size_t kMin = openvpn::TLS_CRYPT_V2_MIN_WKC_LEN; // 290
constexpr std::size_t kMax = openvpn::TLS_CRYPT_V2_MAX_WKC_LEN; // 1024

} // namespace

TEST(ExtractV3WKcLength, EmptyPacket_ReturnsNullopt)
{
    EXPECT_FALSE(detail::ExtractV3WKcLength({}).has_value());
}

TEST(ExtractV3WKcLength, TooShort_OneLessThanMinimum_ReturnsNullopt)
{
    // Minimum valid total size is kMin + 1 (= 291). One byte below is rejected.
    auto pkt = MakeV3Packet(kMin, static_cast<std::uint16_t>(kMin));
    EXPECT_FALSE(detail::ExtractV3WKcLength(pkt).has_value());
}

TEST(ExtractV3WKcLength, ExactlyMinimumSize_ValidWkcLen_ReturnsLen)
{
    // total = kMin + 1 (291 bytes), wkc_len = kMin (290) → split = 1 (valid prefix).
    auto pkt = MakeV3Packet(kMin + 1, static_cast<std::uint16_t>(kMin));
    auto result = detail::ExtractV3WKcLength(pkt);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, static_cast<std::uint16_t>(kMin));
}

TEST(ExtractV3WKcLength, WkcLenBelowMinimum_ReturnsNullopt)
{
    // wkc_len = kMin - 1 is below the minimum WKc blob size.
    auto pkt = MakeV3Packet(kMin + 1, static_cast<std::uint16_t>(kMin - 1));
    EXPECT_FALSE(detail::ExtractV3WKcLength(pkt).has_value());
}

TEST(ExtractV3WKcLength, WkcLenAboveMaximum_ReturnsNullopt)
{
    // wkc_len > kMax (1024) must be rejected even if the buffer is large enough.
    auto pkt = MakeV3Packet(kMax + 2, static_cast<std::uint16_t>(kMax + 1));
    EXPECT_FALSE(detail::ExtractV3WKcLength(pkt).has_value());
}

TEST(ExtractV3WKcLength, WkcLenAtMaximum_ValidPacket_ReturnsLen)
{
    // total = kMax + 1 (1025 bytes), wkc_len = kMax (1024) → split = 1.
    auto pkt = MakeV3Packet(kMax + 1, static_cast<std::uint16_t>(kMax));
    auto result = detail::ExtractV3WKcLength(pkt);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, static_cast<std::uint16_t>(kMax));
}

TEST(ExtractV3WKcLength, WkcLenEqualsPacketSize_NoPrefix_ReturnsNullopt)
{
    // wkc_len == data.size() → split = 0 (no packet prefix); must be rejected.
    auto pkt = MakeV3Packet(kMin + 1, static_cast<std::uint16_t>(kMin + 1));
    EXPECT_FALSE(detail::ExtractV3WKcLength(pkt).has_value());
}

TEST(ExtractV3WKcLength, WkcLenExceedsPacketSize_ReturnsNullopt)
{
    // wkc_len > data.size() would underflow the split calculation; must be rejected.
    auto pkt = MakeV3Packet(kMin + 1, static_cast<std::uint16_t>(kMin + 2));
    EXPECT_FALSE(detail::ExtractV3WKcLength(pkt).has_value());
}

TEST(ExtractV3WKcLength, LargeValidPacket_CorrectSplitPosition)
{
    // 500-byte packet, wkc_len = 300 → split = 200, result = 300.
    constexpr std::uint16_t wkc = 300;
    auto pkt = MakeV3Packet(500, wkc);
    auto result = detail::ExtractV3WKcLength(pkt);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, wkc);
}

// ============================================================================
// HandleClientPushReply — concept constraints + behavioural unit tests
// ============================================================================

namespace {

// Records every action call so tests can assert what the handler invoked.
struct MockClientActions
{
    int derive_count = 0;
    bool network_configured = false;
    bool connected = false;
    std::optional<std::pair<std::uint32_t, std::uint64_t>> rekey_args;

    void DeriveAndInstallKeys()
    {
        ++derive_count;
    }
    void ApplyNetworkConfig()
    {
        network_configured = true;
    }
    void MarkConnected()
    {
        connected = true;
    }
    void ScheduleRekey(std::uint32_t r, std::uint64_t g)
    {
        rekey_args = {r, g};
    }
};

struct MockServerActions
{
    Connection *derived_keys_for = nullptr;
    std::optional<std::pair<openvpn::SessionId, std::uint32_t>> rekey_args;

    void DeriveAndInstallKeys(Connection *c)
    {
        derived_keys_for = c;
    }
    void ScheduleRekey(openvpn::SessionId sid, std::uint32_t sec)
    {
        rekey_args = {sid, sec};
    }
};

} // namespace

// Compile-time concept satisfaction checks.
static_assert(ClientPushActions<MockClientActions>,
              "MockClientActions must satisfy ClientPushActions");
static_assert(!ClientPushActions<MockServerActions>, // lacks ApplyNetworkConfig/MarkConnected
              "MockServerActions must NOT satisfy ClientPushActions");
static_assert(ServerPushActions<MockServerActions>,
              "MockServerActions must satisfy ServerPushActions");
static_assert(!ServerPushActions<MockClientActions>, // DeriveAndInstallKeys takes no arg
              "MockClientActions must NOT satisfy ServerPushActions");

// Runs a no-wait coroutine synchronously on a temporary io_context.
// Re-throws any exception the coroutine propagates.
static void RunSync(asio::awaitable<void> coro)
{
    asio::io_context ctx;
    std::exception_ptr ep;
    asio::co_spawn(ctx, std::move(coro), [&ep](std::exception_ptr e)
    { ep = e; });
    ctx.run();
    if (ep)
        std::rethrow_exception(ep);
}

// Owns the storage that ClientPushReplyData borrows by reference.
struct ClientPushFixture
{
    openvpn::ConfigExchange exchange;
    std::vector<std::string> allowed_ciphers = {"AES-256-GCM", "AES-128-GCM"};
    std::string current_cipher = "AES-256-GCM";
    std::uint32_t client_reneg_sec = 0;
    std::string negotiated_cipher;
    std::uint32_t server_peer_id = 0;
    bool is_connected = false;
    bool rekey_timer_armed = false;
    std::uint64_t rekey_generation = 7;
    // Two-step init: sink outlives logger.
    std::shared_ptr<spdlog::sinks::null_sink_mt> sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    spdlog::logger logger{"cpr_test", sink};

    ClientPushReplyData MakeData()
    {
        return ClientPushReplyData{
            .config_exchange = exchange,
            .allowed_ciphers = allowed_ciphers,
            .current_cipher = current_cipher,
            .client_renegotiate_seconds = client_reneg_sec,
            .negotiated_cipher = negotiated_cipher,
            .server_peer_id = server_peer_id,
            .is_connected = is_connected,
            .rekey_timer_armed = rekey_timer_armed,
            .rekey_generation = rekey_generation,
            .logger = logger,
        };
    }
};

TEST(HandleClientPushReply, FirstConnect_NetworkConfiguredAndMarkedConnected)
{
    ClientPushFixture fx;
    MockClientActions actions;

    RunSync(HandleClientPushReply("", fx.MakeData(), actions));

    EXPECT_TRUE(actions.network_configured);
    EXPECT_TRUE(actions.connected);
    EXPECT_EQ(actions.derive_count, 0);
    EXPECT_FALSE(actions.rekey_args.has_value());
}

TEST(HandleClientPushReply, AlreadyConnected_EarlyReturn_SkipsNetworkConfig)
{
    ClientPushFixture fx;
    fx.is_connected = true;
    MockClientActions actions;

    RunSync(HandleClientPushReply("", fx.MakeData(), actions));

    EXPECT_FALSE(actions.network_configured);
    EXPECT_FALSE(actions.connected);
    EXPECT_EQ(actions.derive_count, 0);
    EXPECT_FALSE(actions.rekey_args.has_value());
}

TEST(HandleClientPushReply, NcpCipherOverride_UpdatesCipherAndDerivesKeys)
{
    ClientPushFixture fx;
    fx.current_cipher = "AES-256-GCM";
    MockClientActions actions;

    RunSync(HandleClientPushReply("cipher AES-128-GCM", fx.MakeData(), actions));

    EXPECT_EQ(fx.negotiated_cipher, "AES-128-GCM");
    EXPECT_EQ(actions.derive_count, 1);
}

TEST(HandleClientPushReply, NcpCipher_MatchesCurrent_NoDeriveKeys)
{
    ClientPushFixture fx;
    fx.current_cipher = "AES-256-GCM";
    MockClientActions actions;

    // Server echoes the cipher already in use — no re-derivation needed.
    RunSync(HandleClientPushReply("cipher AES-256-GCM", fx.MakeData(), actions));

    EXPECT_EQ(actions.derive_count, 0);
}

TEST(HandleClientPushReply, DisallowedCipher_ThrowsRuntimeError)
{
    ClientPushFixture fx;
    MockClientActions actions;

    // BF-CBC is not in allowed_ciphers = {"AES-256-GCM", "AES-128-GCM"}.
    EXPECT_THROW(
        RunSync(HandleClientPushReply("cipher BF-CBC", fx.MakeData(), actions)),
        std::runtime_error);
}

TEST(HandleClientPushReply, PeerId_UpdatedFromPushReply)
{
    ClientPushFixture fx;
    MockClientActions actions;

    // Use Serialize to produce a valid options string containing peer-id 42.
    openvpn::NegotiatedConfig cfg;
    cfg.peer_id = 42;
    std::string opts = openvpn::ConfigExchange::Serialize(cfg);
    constexpr auto kPrefix = std::string_view{"PUSH_REPLY,"};
    if (opts.starts_with(kPrefix))
        opts.erase(0, kPrefix.size());

    RunSync(HandleClientPushReply(opts, fx.MakeData(), actions));

    EXPECT_EQ(fx.server_peer_id, 42u);
}

TEST(HandleClientPushReply, RekeyTimer_ArmedOnFirstConnect_WithPushedRenegSec)
{
    ClientPushFixture fx;
    fx.rekey_generation = 3;
    MockClientActions actions;

    RunSync(HandleClientPushReply("reneg-sec 3600", fx.MakeData(), actions));

    ASSERT_TRUE(actions.rekey_args.has_value());
    EXPECT_EQ(actions.rekey_args->first, 3600u);
    EXPECT_EQ(actions.rekey_args->second, 3u); // rekey_generation passed through
    EXPECT_TRUE(fx.rekey_timer_armed);
}

TEST(HandleClientPushReply, RekeyTimer_FallsBackToClientRenegSec)
{
    ClientPushFixture fx;
    fx.client_reneg_sec = 1800;
    MockClientActions actions;

    // No reneg-sec in the push — handler uses client's configured value.
    RunSync(HandleClientPushReply("", fx.MakeData(), actions));

    ASSERT_TRUE(actions.rekey_args.has_value());
    EXPECT_EQ(actions.rekey_args->first, 1800u);
}

TEST(HandleClientPushReply, RekeyTimer_NotReArmed_WhenAlreadySet)
{
    ClientPushFixture fx;
    fx.client_reneg_sec = 3600;
    fx.rekey_timer_armed = true; // guard flag already set
    MockClientActions actions;

    RunSync(HandleClientPushReply("", fx.MakeData(), actions));

    EXPECT_FALSE(actions.rekey_args.has_value());
}

TEST(HandleClientPushReply, RekeyTimer_ZeroReneg_NeverArmed)
{
    ClientPushFixture fx;
    fx.client_reneg_sec = 0; // no client fallback either
    MockClientActions actions;

    RunSync(HandleClientPushReply("", fx.MakeData(), actions));

    EXPECT_FALSE(actions.rekey_args.has_value());
    EXPECT_FALSE(fx.rekey_timer_armed);
}

// ============================================================================
// HandleServerPushRequest — concept constraints (above) + smoke test
// ============================================================================

TEST(HandleServerPushRequest, NoTransport_EarlyReturn_NoActionsTriggered)
{
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    spdlog::logger logger("spr_test", null_sink);

    auto sid = openvpn::SessionId::Generate();
    Connection::Endpoint ep{asio::ip::address_v4(0xC0A80001u), 1194};
    Connection session(sid, ep, true, std::nullopt, logger);

    VpnConfig::ServerConfig srv;
    srv.network = "10.8.0.0/24";
    std::optional<openvpn::TlsCrypt> no_crypt;

    MockServerActions actions;
    // Session has no transport → handler should co_return without calling any action.
    RunSync(HandleServerPushRequest(&session, srv, no_crypt, logger, actions));

    EXPECT_EQ(actions.derived_keys_for, nullptr);
    EXPECT_FALSE(actions.rekey_args.has_value());
}
