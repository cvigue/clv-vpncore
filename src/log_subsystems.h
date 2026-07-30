#ifndef CLV_VPN_LOG_SUBSYSTEMS_H
#define CLV_VPN_LOG_SUBSYSTEMS_H

#include <spdlog/common.h>

#include <array>
#include <memory>
#include <string>

namespace spdlog {
class logger;
}

namespace clv::vpn::logging {

// Subsystem identifiers
/** @brief Named logging channels for VPN server subsystems. */
enum class Subsystem
{
    keepalive, ///< KeepAliveLoop, PING sends/receives
    sessions,  ///< Session creation, cleanup, timeouts
    control,   ///< TLS handshakes, control packets, PUSH_REPLY
    dataio,    ///< Data packet encryption/decryption
    routing,   ///< Routing table, TUN packet processing
    general    ///< Catch-all for other messages
};

// Manager for subsystem loggers. Owns all logger instances and provides access via enum indexing.
// Environment variables:
//   SPDLOG_LEVEL=level — sets global default level (default: info)
//   SPDLOG_LEVEL_vpn_keepalive=debug — per-subsystem level override
/**
 * @brief Manager for per-subsystem spdlog loggers.
 *
 * Owns logger instances and applies SPDLOG_LEVEL / per-subsystem overrides.
 */
class SubsystemLoggerManager
{
  private:
    static constexpr int SUBSYSTEM_COUNT = 6;
    // spdlog::register_logger() requires shared_ptr, and the global registry
    // holds its own copy. We keep a shared_ptr per slot so the logger is not
    // destroyed if something calls spdlog::drop() externally. All callers
    // borrow via GetLogger(), which returns a plain reference.
    std::array<std::shared_ptr<spdlog::logger>, SUBSYSTEM_COUNT> loggers_;

  public:
    /**
     * @brief Create subsystem loggers and apply SPDLOG_LEVEL overrides.
     *
     * Reads SPDLOG_LEVEL (global default) and SPDLOG_LEVEL_vpn_<name>
     * per-subsystem overrides from the environment.
     */
    SubsystemLoggerManager();

    /**
     * @brief Set the default log level for all subsystem loggers that don't have
     * a per-subsystem environment variable override.
     * @param level spdlog level to apply
     */
    void SetDefaultLevel(spdlog::level::level_enum level);

    /**
     * @brief Set the level for a single subsystem logger.
     * @param subsystem Target channel
     * @param level spdlog level to apply
     */
    void SetSubsystemLevel(Subsystem subsystem, spdlog::level::level_enum level);

    /**
     * @brief Borrow a subsystem logger by enum.
     * @param subsystem Channel to retrieve
     * @return Reference to the registered spdlog logger
     */
    spdlog::logger &GetLogger(Subsystem subsystem) const
    {
        return *loggers_[static_cast<int>(subsystem)];
    }
};

/**
 * @brief Parse a subsystem name string.
 * @param name Lowercase name (e.g. "keepalive", "control")
 * @return Matching Subsystem value
 * @throws std::invalid_argument if name is unknown
 */
Subsystem SubsystemFromString(const std::string &name);

/**
 * @brief Convert a subsystem enum to its canonical name.
 * @param subsystem Value to stringify
 * @return Lowercase name (e.g. "routing")
 */
std::string SubsystemToString(Subsystem subsystem);

} // namespace clv::vpn::logging

#endif // CLV_VPN_LOG_SUBSYSTEMS_H
