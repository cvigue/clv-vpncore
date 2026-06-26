// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_KEEPALIVE_LOOP_H
#define CLV_VPN_KEEPALIVE_LOOP_H

/**
 * @file keepalive_loop.h
 * @brief Unified timer-driven keepalive loop for client and server channels.
 *
 * KeepaliveLoop works with any session type S satisfying the KeepaliveSession
 * concept: HasValidKeys(), GetLastActivity(), GetLastOutbound(),
 * UpdateLastOutbound().  Client and server pass different thin session
 * wrappers; the loop body is identical.
 *
 * @par Timeout handling
 * - @p timeout == 0 disables dead-peer detection (matches client behaviour
 *   when keepalive_timeout is unset in config).
 * - After dead_fn(s) is called the session is skipped (continue).
 *   For the client the dead_fn clears *running_, so the outer while exits
 *   on the next iteration.
 *
 * @par TX-idle guard
 * If now - s.GetLastOutbound() < interval the loop skips the PING.
 * GetLastOutbound() must be updated by the *data* TX path (not only by pings)
 * for this guard to be useful.  All server channels and the client UDP/TCP
 * channels satisfy this — see Connection::UpdateLastOutbound() and
 * P2PPolicy::OnBatchSent().
 */

#include <asio/awaitable.hpp>
#include <asio/error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <spdlog/logger.h>

#include <atomic>
#include <chrono>
#include <concepts>
#include <exception>
#include <string_view>

namespace clv::vpn {

/**
 * @brief Minimum interface required of a session passed to KeepaliveLoop.
 */
template <typename S>
concept KeepaliveSession = requires(const S &cs, S &ms) {
    { cs.HasValidKeys() } -> std::convertible_to<bool>;
    { cs.GetLastActivity() } -> std::convertible_to<std::chrono::steady_clock::time_point>;
    { cs.GetLastOutbound() } -> std::convertible_to<std::chrono::steady_clock::time_point>;
    { ms.UpdateLastOutbound() };
};

/**
 * @brief Unified timer-driven keepalive loop.
 *
 * @tparam GetSessions  () -> range<S>   where S satisfies KeepaliveSession.
 * @tparam PingFn       (S&) -> asio::awaitable<void>
 * @tparam DeadFn       (S&) -> void
 */
template <typename GetSessions, typename PingFn, typename DeadFn>
asio::awaitable<void> KeepaliveLoop(std::string_view name,
                                    const std::atomic<bool> &running,
                                    asio::steady_timer &timer,
                                    std::chrono::seconds interval,
                                    std::chrono::seconds timeout,
                                    spdlog::logger &logger,
                                    GetSessions get_sessions,
                                    PingFn ping_fn,
                                    DeadFn dead_fn)
{
    logger.info("{} keepalive started: interval={}s timeout={}s",
                name,
                interval.count(),
                timeout.count());

    auto last_tick = std::chrono::steady_clock::now();

    while (running)
    {
        timer.expires_after(interval);
        try
        {
            co_await timer.async_wait(asio::use_awaitable);
        }
        catch (const asio::system_error &e)
        {
            if (e.code() == asio::error::operation_aborted)
                break;
            throw;
        }

        if (!running)
            break;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration<double>(now - last_tick).count();
        last_tick = now;

        auto sessions = get_sessions();
        logger.debug("Keepalive tick ({:.2f}s): {} session(s)", elapsed, std::size(sessions));

        for (auto &s : sessions)
        {
            if (!s.HasValidKeys())
                continue;

            auto since_rx = now - s.GetLastActivity();
            if (timeout.count() > 0 && since_rx >= timeout)
            {
                logger.warn("{} keepalive timeout ({:.1f}s since last RX)",
                            name,
                            std::chrono::duration<double>(since_rx).count());
                dead_fn(s);
                continue;
            }

            if (now - s.GetLastOutbound() >= interval)
            {
                try
                {
                    co_await ping_fn(s);
                    s.UpdateLastOutbound();
                }
                catch (const std::exception &e)
                {
                    logger.warn("{} keepalive PING failed: {}", name, e.what());
                }
            }
        }
    }
}

} // namespace clv::vpn

#endif // CLV_VPN_KEEPALIVE_LOOP_H
