// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_TEST_LOG_UTIL_H
#define CLV_VPN_TEST_LOG_UTIL_H

#include <spdlog/logger.h>
#include <spdlog/sinks/null_sink.h>

namespace clv::vpn::test {

inline spdlog::logger &NullLogger()
{
    static auto sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    static auto logger = std::make_shared<spdlog::logger>("test", sink);
    return *logger;
}

} // namespace clv::vpn::test

#endif // CLV_VPN_TEST_LOG_UTIL_H
