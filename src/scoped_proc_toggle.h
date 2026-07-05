// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_SCOPED_PROC_TOGGLE_H
#define CLV_VPN_SCOPED_PROC_TOGGLE_H

#include <not_null.h>
#include <scoped_ownership.h>

#include <spdlog/logger.h>

#include <fstream>
#include <stdexcept>
#include <string>

namespace clv::vpn {

// ---------------------------------------------------------------------------
// Policy structs — each one provides a proc path and a human-readable label.
// ---------------------------------------------------------------------------

/** @brief Policy for IPv4 forwarding (/proc/sys/net/ipv4/ip_forward). */
struct Ipv4ForwardPolicy
{
    static constexpr const char *proc_path = "/proc/sys/net/ipv4/ip_forward";
    static constexpr const char *label = "IPv4 forwarding";
};

/** @brief Policy for IPv6 forwarding (/proc/sys/net/ipv6/conf/all/forwarding). */
struct Ipv6ForwardPolicy
{
    static constexpr const char *proc_path = "/proc/sys/net/ipv6/conf/all/forwarding";
    static constexpr const char *label = "IPv6 forwarding";
};

// ---------------------------------------------------------------------------
// ScopedProcToggle<Policy>
// ---------------------------------------------------------------------------

/**
 * @brief RAII guard that enables a boolean proc toggle on construction and
 *        restores the previous value on destruction.
 *
 * @tparam Policy  A struct providing:
 *   - @c static @c constexpr @c const @c char* @c proc_path  — sysfs/procfs path
 *   - @c static @c constexpr @c const @c char* @c label       — human-readable name for logs
 *
 * Reads the proc path, enables it if not already set, and restores the
 * original value when the guard is destroyed.
 *
 * If the toggle was already enabled, destruction is a no-op.
 *
 * @note Requires root / CAP_NET_ADMIN.
 *
 * @par Testing
 * This class directly manipulates /proc and is not unit-testable in
 * isolation without root privileges. It is exercised via integration
 * tests (e.g., vpn_server_integration_tests) that run the full server
 * lifecycle as root. If fine-grained unit testing is needed in the
 * future, inject a virtual interface for the proc read/write operations.
 */
template <typename Policy>
class ScopedProcToggle
{
  public:
    /**
     * @brief Enable the proc toggle
     * @param logger Logger for diagnostics
     * @throws std::runtime_error if the proc path cannot be read or written
     */
    explicit ScopedProcToggle(spdlog::logger &logger)
        : logger_(&logger)
    {
        // Read current state
        std::ifstream in(Policy::proc_path);
        if (!in.is_open())
        {
            throw std::runtime_error(
                "Cannot read " + std::string(Policy::proc_path) + " (root required)");
        }

        int value = 0;
        in >> value;

        if (value != 0)
        {
            logger_->info("{} already enabled", Policy::label);
            return;
        }

        // Enable toggle
        std::ofstream out(Policy::proc_path);
        if (!out.is_open())
        {
            throw std::runtime_error(
                "Cannot write " + std::string(Policy::proc_path) + " (root required)");
        }
        out << "1";
        out.flush();

        if (!out.good())
        {
            throw std::runtime_error(
                std::string("Failed to enable ") + Policy::label);
        }

        ownership_.set_owns(true);
        logger_->info("{} enabled (was disabled, will restore on shutdown)", Policy::label);
    }

    /**
     * @brief Restore original state
     */
    ~ScopedProcToggle() noexcept
    {
        Revert();
    }

    // Non-copyable
    ScopedProcToggle(const ScopedProcToggle &) = delete;
    ScopedProcToggle &operator=(const ScopedProcToggle &) = delete;

    // Movable
    ScopedProcToggle(ScopedProcToggle &&other) noexcept
        : logger_(other.logger_),
          ownership_(std::move(other.ownership_))
    {
    }

    ScopedProcToggle &operator=(ScopedProcToggle &&other) noexcept
    {
        if (this != &other)
        {
            Revert();
            logger_ = other.logger_;
            ownership_ = std::move(other.ownership_);
        }
        return *this;
    }

  private:
    /** Restore the toggle to disabled if this instance owns it (noexcept). */
    void Revert() noexcept
    {
        if (!ownership_.owns())
            return;
        ownership_.release();

        try
        {
            std::ofstream out(Policy::proc_path);
            if (!out.is_open())
            {
                logger_->warn("Cannot open {} to restore {}", Policy::proc_path, Policy::label);
                return;
            }
            out << "0";
            out.flush();
            if (!out.good())
            {
                logger_->warn("Failed to restore {} to disabled", Policy::label);
                return;
            }
            logger_->info("{} restored to disabled", Policy::label);
        }
        catch (...)
        {
            // Must not throw (used from destructor / move-assign)
        }
    }

    not_null<spdlog::logger *> logger_;
    clv::ScopedOwnership ownership_;
};

// ---------------------------------------------------------------------------
// Convenience aliases — drop-in replacements for the old class names.
// ---------------------------------------------------------------------------

/** @brief RAII guard for IPv4 forwarding (was ScopedIpForward). */
using ScopedIpForward = ScopedProcToggle<Ipv4ForwardPolicy>;

/** @brief RAII guard for IPv6 forwarding (was ScopedIpv6Forward). */
using ScopedIpv6Forward = ScopedProcToggle<Ipv6ForwardPolicy>;

} // namespace clv::vpn

#endif // CLV_VPN_SCOPED_PROC_TOGGLE_H
