// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SOCKET_UTILS_H
#define CLV_VPN_SOCKET_UTILS_H

/**
 * @file socket_utils.h
 * @brief Shared socket utility functions for VPN client and server.
 */

#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include <unistd.h>

namespace clv::vpn {

/**
 * @brief Apply a socket buffer size, trying SO_*FORCE first then regular.
 *
 * @details Attempts the FORCE variant (bypasses rmem_max/wmem_max when
 *          running with CAP_NET_ADMIN), falls back to the regular variant
 *          otherwise. Logs the requested vs actual value.
 *
 * @param fd         Socket file descriptor
 * @param force_opt  SO_RCVBUFFORCE or SO_SNDBUFFORCE
 * @param regular_opt SO_RCVBUF or SO_SNDBUF
 * @param requested  Desired buffer size in bytes (<=0 is a no-op)
 * @param label      Human-readable name for logging (e.g. "SO_RCVBUF")
 * @param logger     spdlog logger for status messages
 */
inline void ApplySocketBuffer(int fd, int force_opt, int regular_opt,
                              int requested, const char *label,
                              spdlog::logger &logger)
{
    if (requested <= 0)
        return;

    int val = requested;
    if (setsockopt(fd, SOL_SOCKET, force_opt, &val, sizeof(val)) != 0)
    {
        // FORCE requires CAP_NET_ADMIN — fall back to regular option
        val = requested;
        setsockopt(fd, SOL_SOCKET, regular_opt, &val, sizeof(val));
    }

    int actual = 0;
    socklen_t len = sizeof(actual);
    getsockopt(fd, SOL_SOCKET, regular_opt, &actual, &len);
    logger.info("UDP {}: requested={} actual={}", label, requested, actual);
}

} // namespace clv::vpn

#endif // CLV_VPN_SOCKET_UTILS_H
