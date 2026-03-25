#ifndef CLV_VPN_LOG_SUBSYSTEMS_H
#define CLV_VPN_LOG_SUBSYSTEMS_H

#include <array>
#include <memory>
#include <string>

#include <spdlog/common.h>

namespace spdlog {
class logger;
}

namespace clv::vpn::logging {

// Subsystem identifiers
enum class Subsystem
{
    keepalive, // KeepAliveLoop, PING sends/receives
    sessions,  // Session creation, cleanup, timeouts
    control,   // TLS handshakes, control packets, PUSH_REPLY
    dataio,    // Data packet encryption/decryption
    routing,   // Routing table, TUN packet processing
    general    // Catch-all for other messages
};

// Manager for subsystem loggers. Owns all logger instances and provides access via enum indexing.
// Environment variables:
//   SPDLOG_LEVEL=level — sets global default level (default: info)
//   SPDLOG_LEVEL_vpn_keepalive=debug — per-subsystem level override
class SubsystemLoggerManager
{
  private:
    static constexpr int SUBSYSTEM_COUNT = 6;
    std::array<std::shared_ptr<spdlog::logger>, SUBSYSTEM_COUNT> loggers_;

  public:
    SubsystemLoggerManager();

    /**
     * Set the default log level for all subsystem loggers that don't have
     * a per-subsystem environment variable override.
     */
    void SetDefaultLevel(spdlog::level::level_enum level);

    /** Set the level for a single subsystem logger. */
    void SetSubsystemLevel(Subsystem subsystem, spdlog::level::level_enum level);

    std::shared_ptr<spdlog::logger> GetLogger(Subsystem subsystem) const
    {
        return loggers_[static_cast<int>(subsystem)];
    }
};

// Convenience: convert string to Subsystem
Subsystem SubsystemFromString(const std::string &name);

// Convenience: convert Subsystem to string
std::string SubsystemToString(Subsystem subsystem);

} // namespace clv::vpn::logging

#endif // CLV_VPN_LOG_SUBSYSTEMS_H
