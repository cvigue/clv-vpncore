// Copyright (c) 2025- Charlie Vigue. All rights reserved.
// TX drain-loop unit tests (replaces old TxSpsc tests after Section 31 rewrite).

#include "data_path_stats.h"
#include "openvpn/vpn_config.h"

#include <nlohmann/json.hpp>
#include <gtest/gtest.h>

using namespace clv::vpn;

// ---------------------------------------------------------------------------
// VpnConfig::PerformanceConfig — drain-loop field defaults and validation
// ---------------------------------------------------------------------------

TEST(TxDrainConfig, DefaultValues)
{
    VpnConfig::PerformanceConfig p;
    EXPECT_EQ(p.tx_drain_depth, 1024);
    EXPECT_EQ(p.tx_send_batch, 64);
    EXPECT_EQ(p.tx_small_pkt_flush, 384);
}

TEST(TxDrainConfig, ParseFromJson)
{
    auto json = nlohmann::json{
        {"performance", {
                            {"tx_drain_depth", 128},
                            {"tx_send_batch", 32},
                            {"tx_small_pkt_flush", 256},
                        }}};
    auto cfg = VpnConfigParser::ParseJson(json);
    EXPECT_EQ(cfg.performance.tx_drain_depth, 128);
    EXPECT_EQ(cfg.performance.tx_send_batch, 32);
    EXPECT_EQ(cfg.performance.tx_small_pkt_flush, 256);
}

TEST(TxDrainConfig, ValidationClampsInvalidDepth)
{
    auto json = nlohmann::json{
        {"performance", {{"tx_drain_depth", 0}}}};
    auto cfg = VpnConfigParser::ParseJson(json);
    EXPECT_GE(cfg.performance.tx_drain_depth, 1);
}

TEST(TxDrainConfig, ValidationClampsNegativeSendBatch)
{
    auto json = nlohmann::json{
        {"performance", {{"tx_send_batch", -5}}}};
    auto cfg = VpnConfigParser::ParseJson(json);
    EXPECT_EQ(cfg.performance.tx_send_batch, 0);
}

TEST(TxDrainConfig, ValidationClampsNegativeSmallPktFlush)
{
    auto json = nlohmann::json{
        {"performance", {{"tx_small_pkt_flush", -1}}}};
    auto cfg = VpnConfigParser::ParseJson(json);
    EXPECT_EQ(cfg.performance.tx_small_pkt_flush, 0);
}

// ---------------------------------------------------------------------------
// DataPathStats::TxCounters — drain-loop counter fields
// ---------------------------------------------------------------------------

TEST(TxDrainStats, NewCounterFields)
{
    DataPathStats::TxCounters c;
    // txSmallPktFlush replaces txSmallPacketInline; txRingFullEvents removed
    c.txSmallPktFlush = 7;
    EXPECT_EQ(c.txSmallPktFlush, 7u);
}

TEST(TxDrainStats, MergePreservesSmallPktFlush)
{
    DataPathStats::RxCounters rx{};
    DataPathStats::TxCounters tx{};
    tx.txSmallPktFlush = 42;
    auto merged = DataPathStats::Merge(rx, tx);
    EXPECT_EQ(merged.txSmallPktFlush, 42u);
}

TEST(TxDrainStats, DeltaCalculation)
{
    DataPathStats a{};
    a.txSmallPktFlush = 100;
    a.packetsSent = 1000;
    DataPathStats b{};
    b.txSmallPktFlush = 130;
    b.packetsSent = 1500;
    auto d = DataPathStats::Delta(b, a);
    EXPECT_EQ(d.txSmallPktFlush, 30u);
    EXPECT_EQ(d.packetsSent, 500u);
}
