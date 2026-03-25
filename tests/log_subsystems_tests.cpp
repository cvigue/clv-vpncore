// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "log_subsystems.h"

#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <string>

namespace clv::vpn::logging {
namespace {

class SubsystemLoggerManagerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Drop all loggers registered by previous tests to avoid name
        // collisions — SubsystemLoggerManager registers global loggers.
        spdlog::drop_all();
    }

    void TearDown() override
    {
        spdlog::drop_all();
    }
};

// ── Construction ────────────────────────────────────────────────────

TEST_F(SubsystemLoggerManagerTest, ConstructionCreatesAllLoggers)
{
    SubsystemLoggerManager mgr;

    EXPECT_NE(mgr.GetLogger(Subsystem::keepalive), nullptr);
    EXPECT_NE(mgr.GetLogger(Subsystem::sessions), nullptr);
    EXPECT_NE(mgr.GetLogger(Subsystem::control), nullptr);
    EXPECT_NE(mgr.GetLogger(Subsystem::dataio), nullptr);
    EXPECT_NE(mgr.GetLogger(Subsystem::routing), nullptr);
    EXPECT_NE(mgr.GetLogger(Subsystem::general), nullptr);
}

TEST_F(SubsystemLoggerManagerTest, LoggerNamesAreCorrect)
{
    SubsystemLoggerManager mgr;

    EXPECT_EQ(mgr.GetLogger(Subsystem::keepalive)->name(), "vpn:keepalive");
    EXPECT_EQ(mgr.GetLogger(Subsystem::sessions)->name(), "vpn:sessions");
    EXPECT_EQ(mgr.GetLogger(Subsystem::control)->name(), "vpn:control");
    EXPECT_EQ(mgr.GetLogger(Subsystem::dataio)->name(), "vpn:dataio");
    EXPECT_EQ(mgr.GetLogger(Subsystem::routing)->name(), "vpn:routing");
    EXPECT_EQ(mgr.GetLogger(Subsystem::general)->name(), "vpn");
}

TEST_F(SubsystemLoggerManagerTest, DefaultLevelIsInfo)
{
    SubsystemLoggerManager mgr;

    // Without env overrides the default is info (from SPDLOG_LEVEL or fallback)
    for (int i = 0; i < 6; ++i)
    {
        auto logger = mgr.GetLogger(static_cast<Subsystem>(i));
        EXPECT_EQ(logger->level(), spdlog::level::info)
            << "subsystem " << i << " should default to info";
    }
}

// ── SetDefaultLevel ─────────────────────────────────────────────────

TEST_F(SubsystemLoggerManagerTest, SetDefaultLevelChangesAllLoggers)
{
    SubsystemLoggerManager mgr;
    mgr.SetDefaultLevel(spdlog::level::debug);

    for (int i = 0; i < 6; ++i)
    {
        auto logger = mgr.GetLogger(static_cast<Subsystem>(i));
        EXPECT_EQ(logger->level(), spdlog::level::debug)
            << "subsystem " << i << " should be debug after SetDefaultLevel";
    }
}

TEST_F(SubsystemLoggerManagerTest, SetDefaultLevelToWarn)
{
    SubsystemLoggerManager mgr;
    mgr.SetDefaultLevel(spdlog::level::warn);

    for (int i = 0; i < 6; ++i)
    {
        EXPECT_EQ(mgr.GetLogger(static_cast<Subsystem>(i))->level(),
                  spdlog::level::warn);
    }
}

// ── SetSubsystemLevel ───────────────────────────────────────────────

TEST_F(SubsystemLoggerManagerTest, SetSubsystemLevelChangesOnlyTarget)
{
    SubsystemLoggerManager mgr;
    mgr.SetSubsystemLevel(Subsystem::dataio, spdlog::level::trace);

    EXPECT_EQ(mgr.GetLogger(Subsystem::dataio)->level(), spdlog::level::trace);

    // Others remain at default
    EXPECT_EQ(mgr.GetLogger(Subsystem::keepalive)->level(), spdlog::level::info);
    EXPECT_EQ(mgr.GetLogger(Subsystem::sessions)->level(), spdlog::level::info);
    EXPECT_EQ(mgr.GetLogger(Subsystem::control)->level(), spdlog::level::info);
    EXPECT_EQ(mgr.GetLogger(Subsystem::routing)->level(), spdlog::level::info);
    EXPECT_EQ(mgr.GetLogger(Subsystem::general)->level(), spdlog::level::info);
}

TEST_F(SubsystemLoggerManagerTest, SetDefaultThenOverrideSubsystem)
{
    SubsystemLoggerManager mgr;
    mgr.SetDefaultLevel(spdlog::level::warn);
    mgr.SetSubsystemLevel(Subsystem::control, spdlog::level::debug);

    EXPECT_EQ(mgr.GetLogger(Subsystem::control)->level(), spdlog::level::debug);
    EXPECT_EQ(mgr.GetLogger(Subsystem::dataio)->level(), spdlog::level::warn);
}

TEST_F(SubsystemLoggerManagerTest, SetSubsystemThenDefaultOverwrites)
{
    SubsystemLoggerManager mgr;
    mgr.SetSubsystemLevel(Subsystem::routing, spdlog::level::trace);
    mgr.SetDefaultLevel(spdlog::level::err);

    // SetDefaultLevel is a blanket override — replaces all levels
    EXPECT_EQ(mgr.GetLogger(Subsystem::routing)->level(), spdlog::level::err);
}

// ── SubsystemFromString / SubsystemToString ─────────────────────────

TEST_F(SubsystemLoggerManagerTest, SubsystemFromStringKnownNames)
{
    EXPECT_EQ(SubsystemFromString("keepalive"), Subsystem::keepalive);
    EXPECT_EQ(SubsystemFromString("sessions"), Subsystem::sessions);
    EXPECT_EQ(SubsystemFromString("control"), Subsystem::control);
    EXPECT_EQ(SubsystemFromString("dataio"), Subsystem::dataio);
    EXPECT_EQ(SubsystemFromString("routing"), Subsystem::routing);
    EXPECT_EQ(SubsystemFromString("general"), Subsystem::general);
}

TEST_F(SubsystemLoggerManagerTest, SubsystemFromStringUnknownFallsBackToGeneral)
{
    EXPECT_EQ(SubsystemFromString("unknown_subsystem"), Subsystem::general);
    EXPECT_EQ(SubsystemFromString(""), Subsystem::general);
    EXPECT_EQ(SubsystemFromString("KEEPALIVE"), Subsystem::general); // case-sensitive
}

TEST_F(SubsystemLoggerManagerTest, SubsystemToStringKnownValues)
{
    EXPECT_EQ(SubsystemToString(Subsystem::keepalive), "keepalive");
    EXPECT_EQ(SubsystemToString(Subsystem::sessions), "sessions");
    EXPECT_EQ(SubsystemToString(Subsystem::control), "control");
    EXPECT_EQ(SubsystemToString(Subsystem::dataio), "dataio");
    EXPECT_EQ(SubsystemToString(Subsystem::routing), "routing");
    EXPECT_EQ(SubsystemToString(Subsystem::general), "general");
}

TEST_F(SubsystemLoggerManagerTest, SubsystemRoundTrip)
{
    for (int i = 0; i < 6; ++i)
    {
        auto subsys = static_cast<Subsystem>(i);
        auto name = SubsystemToString(subsys);
        EXPECT_EQ(SubsystemFromString(name), subsys)
            << "round-trip failed for " << name;
    }
}

// ── GetLogger returns distinct loggers ──────────────────────────────

TEST_F(SubsystemLoggerManagerTest, EachSubsystemHasDistinctLogger)
{
    SubsystemLoggerManager mgr;

    auto keepalive = mgr.GetLogger(Subsystem::keepalive);
    auto sessions = mgr.GetLogger(Subsystem::sessions);
    auto control = mgr.GetLogger(Subsystem::control);
    auto dataio = mgr.GetLogger(Subsystem::dataio);
    auto routing = mgr.GetLogger(Subsystem::routing);
    auto general = mgr.GetLogger(Subsystem::general);

    EXPECT_NE(keepalive, sessions);
    EXPECT_NE(sessions, control);
    EXPECT_NE(control, dataio);
    EXPECT_NE(dataio, routing);
    EXPECT_NE(routing, general);
}

} // namespace
} // namespace clv::vpn::logging
