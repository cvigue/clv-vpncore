// Copyright (c) 2025- Charlie Vigue. All rights reserved.
//
// HexDump tests live in clv-base/Core/tests/log_utils_tests.cpp.
// This file covers the OpenSSL-specific helpers that require the OpenSSL error queue.

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <log_utils.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

// =============================================================================
// DrainOpenSslErrors / ForEachOpenSslError
// =============================================================================

namespace clv {
namespace {

TEST(DrainOpenSslErrorsTest, EmptyQueue_ReturnsEmptyVector)
{
    ERR_clear_error();
    auto errors = DrainOpenSslErrors();
    EXPECT_TRUE(errors.empty());
}

TEST(DrainOpenSslErrorsTest, PushedError_Appears)
{
    ERR_clear_error();
    ERR_put_error(ERR_LIB_USER, 0, ERR_R_INTERNAL_ERROR, __FILE__, __LINE__);
    auto errors = DrainOpenSslErrors();
    ASSERT_EQ(errors.size(), 1u);
    EXPECT_FALSE(errors[0].empty());
}

TEST(DrainOpenSslErrorsTest, QueueDrainedAfterCall)
{
    ERR_clear_error();
    ERR_put_error(ERR_LIB_USER, 0, ERR_R_INTERNAL_ERROR, __FILE__, __LINE__);
    auto first = DrainOpenSslErrors();
    EXPECT_EQ(first.size(), 1u);
    auto second = DrainOpenSslErrors();
    EXPECT_TRUE(second.empty());
}

TEST(DrainOpenSslErrorsTest, MultipleErrors_AllCaptured)
{
    ERR_clear_error();
    ERR_put_error(ERR_LIB_USER, 0, ERR_R_INTERNAL_ERROR, __FILE__, __LINE__);
    ERR_put_error(ERR_LIB_USER, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
    auto errors = DrainOpenSslErrors();
    EXPECT_EQ(errors.size(), 2u);
}

TEST(ForEachOpenSslErrorTest, EmptyQueue_CallbackNeverInvoked)
{
    ERR_clear_error();
    int count = 0;
    ForEachOpenSslError([&count](const std::string &)
    { ++count; });
    EXPECT_EQ(count, 0);
}

TEST(ForEachOpenSslErrorTest, PushedError_CallbackInvoked)
{
    ERR_clear_error();
    ERR_put_error(ERR_LIB_USER, 0, ERR_R_INTERNAL_ERROR, __FILE__, __LINE__);
    std::vector<std::string> captured;
    ForEachOpenSslError([&captured](const std::string &s)
    { captured.push_back(s); });
    ASSERT_EQ(captured.size(), 1u);
    EXPECT_FALSE(captured[0].empty());
}

TEST(ForEachOpenSslErrorTest, QueueDrainedAfterCall)
{
    ERR_clear_error();
    ERR_put_error(ERR_LIB_USER, 0, ERR_R_INTERNAL_ERROR, __FILE__, __LINE__);
    ForEachOpenSslError([](const std::string &) {});
    int count = 0;
    ForEachOpenSslError([&count](const std::string &)
    { ++count; });
    EXPECT_EQ(count, 0);
}

TEST(ForEachOpenSslErrorTest, MultipleErrors_AllDelivered)
{
    ERR_clear_error();
    ERR_put_error(ERR_LIB_USER, 0, ERR_R_INTERNAL_ERROR, __FILE__, __LINE__);
    ERR_put_error(ERR_LIB_USER, 0, ERR_R_MALLOC_FAILURE, __FILE__, __LINE__);
    int count = 0;
    ForEachOpenSslError([&count](const std::string &)
    { ++count; });
    EXPECT_EQ(count, 2);
}

} // namespace
} // namespace clv
