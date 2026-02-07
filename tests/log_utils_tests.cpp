// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <log_utils.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

namespace clv::vpn {
namespace {

class HexDumpTest : public ::testing::Test
{
  protected:
    // Common test data
    const std::vector<std::uint8_t> empty_data{};
    const std::vector<std::uint8_t> single_byte{0xAB};
    const std::vector<std::uint8_t> sample_data{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67};
    const std::vector<std::uint8_t> zeros{0x00, 0x00, 0x00};
    const std::vector<std::uint8_t> max_values{0xFF, 0xFF, 0xFF};
};

TEST_F(HexDumpTest, EmptyDataReturnsEmptyString)
{
    auto result = HexDump(empty_data);
    EXPECT_EQ(result, "");
}

TEST_F(HexDumpTest, SingleByteFormatted)
{
    auto result = HexDump(single_byte);
    EXPECT_EQ(result, "ab");
}

TEST_F(HexDumpTest, MultipleBytesSeparatedBySpace)
{
    auto result = HexDump(sample_data);
    EXPECT_EQ(result, "de ad be ef 01 23 45 67");
}

TEST_F(HexDumpTest, ZerosFormattedCorrectly)
{
    auto result = HexDump(zeros);
    EXPECT_EQ(result, "00 00 00");
}

TEST_F(HexDumpTest, MaxValuesFormattedCorrectly)
{
    auto result = HexDump(max_values);
    EXPECT_EQ(result, "ff ff ff");
}

TEST_F(HexDumpTest, TruncatesWithEllipsisWhenExceedsMaxBytes)
{
    // Default max_bytes is 60, create data larger than that
    std::vector<std::uint8_t> large_data(100, 0xAA);

    auto result = HexDump(large_data, 5);
    EXPECT_EQ(result, "aa aa aa aa aa...");
}

TEST_F(HexDumpTest, NoEllipsisWhenExactlyMaxBytes)
{
    auto result = HexDump(sample_data, 8);
    EXPECT_EQ(result, "de ad be ef 01 23 45 67");
    // No ellipsis because we have exactly 8 bytes
}

TEST_F(HexDumpTest, NoEllipsisWhenLessThanMaxBytes)
{
    auto result = HexDump(sample_data, 100);
    EXPECT_EQ(result, "de ad be ef 01 23 45 67");
}

TEST_F(HexDumpTest, CustomSeparatorEmpty)
{
    auto result = HexDump(sample_data, 60, "");
    EXPECT_EQ(result, "deadbeef01234567");
}

TEST_F(HexDumpTest, CustomSeparatorColon)
{
    auto result = HexDump(sample_data, 60, ":");
    EXPECT_EQ(result, "de:ad:be:ef:01:23:45:67");
}

TEST_F(HexDumpTest, CustomSeparatorMultiChar)
{
    std::vector<std::uint8_t> short_data{0xAA, 0xBB, 0xCC};
    auto result = HexDump(short_data, 60, " | ");
    EXPECT_EQ(result, "aa | bb | cc");
}

TEST_F(HexDumpTest, NullSeparatorNoSeparation)
{
    auto result = HexDump(sample_data, 60, nullptr);
    EXPECT_EQ(result, "deadbeef01234567");
}

TEST_F(HexDumpTest, UnlimitedBytesWithZeroMaxBytes)
{
    std::vector<std::uint8_t> large_data(100, 0xBB);

    auto result = HexDump(large_data, 0, "");

    // Should contain all 100 bytes with no ellipsis
    EXPECT_EQ(result.size(), 200); // 2 hex chars per byte, no separators
    EXPECT_TRUE(result.find("...") == std::string::npos);
}

TEST_F(HexDumpTest, SpanOverloadWorks)
{
    std::span<const std::uint8_t> span_data(sample_data);
    auto result = HexDump(span_data);
    EXPECT_EQ(result, "de ad be ef 01 23 45 67");
}

TEST_F(HexDumpTest, VectorOverloadWorks)
{
    auto result = HexDump(sample_data);
    EXPECT_EQ(result, "de ad be ef 01 23 45 67");
}

TEST_F(HexDumpTest, LowercaseHexOutput)
{
    std::vector<std::uint8_t> data{0xAB, 0xCD, 0xEF};
    auto result = HexDump(data);

    // Verify lowercase hex
    EXPECT_EQ(result, "ab cd ef");
    EXPECT_TRUE(result.find('A') == std::string::npos);
    EXPECT_TRUE(result.find('B') == std::string::npos);
}

TEST_F(HexDumpTest, MaxBytesOneShowsOneByte)
{
    auto result = HexDump(sample_data, 1);
    EXPECT_EQ(result, "de...");
}

TEST_F(HexDumpTest, LargeDataDefaultMaxBytes)
{
    std::vector<std::uint8_t> large_data(100, 0x42);

    auto result = HexDump(large_data); // Uses default max_bytes=60

    // Count spaces to verify 60 bytes (59 spaces for 60 bytes, plus "...")
    size_t space_count = std::count(result.begin(), result.end(), ' ');
    EXPECT_EQ(space_count, 59); // 59 separators between 60 bytes
    EXPECT_TRUE(result.ends_with("..."));
}

} // namespace
} // namespace clv::vpn
