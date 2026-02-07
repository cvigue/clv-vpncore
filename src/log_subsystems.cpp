#include "log_subsystems.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

namespace clv::vpn::logging {

namespace {

spdlog::level::level_enum GetLevelFromEnv(const char *env_var, spdlog::level::level_enum default_level)
{
    const char *level_str = std::getenv(env_var);
    if (!level_str)
        return default_level;

    try
    {
        return spdlog::level::from_str(level_str);
    }
    catch (...)
    {
        return default_level;
    }
}

// Convert logger name "vpn:xxx" to env var format "SPDLOG_LEVEL_vpn_xxx"
std::string LoggerNameToEnvVar(const std::string &name)
{
    std::string result = "SPDLOG_LEVEL_" + name;
    // Replace colons with underscores in the name part
    for (auto &ch : result)
        if (ch == ':')
            ch = '_';
    return result;
}

} // anonymous namespace

SubsystemLoggerManager::SubsystemLoggerManager()
{
    // Create shared sink (console output with colors)
    auto sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

    // Define loggers with their names
    struct LoggerDef
    {
        Subsystem subsys;
        const char *name;
    };

    const std::vector<LoggerDef> loggers = {
        {Subsystem::keepalive, "vpn:keepalive"},
        {Subsystem::sessions, "vpn:sessions"},
        {Subsystem::control, "vpn:control"},
        {Subsystem::dataio, "vpn:dataio"},
        {Subsystem::routing, "vpn:routing"},
        {Subsystem::general, "vpn"}};

    // Get global default level from SPDLOG_LEVEL
    auto default_level = GetLevelFromEnv("SPDLOG_LEVEL", spdlog::level::info);

    // Create all loggers and apply environment-based levels
    for (const auto &def : loggers)
    {
        auto logger = std::make_shared<spdlog::logger>(def.name, sink);

        // Check for per-logger level override (e.g., SPDLOG_LEVEL_vpn_keepalive)
        std::string env_var = LoggerNameToEnvVar(def.name);
        auto level = GetLevelFromEnv(env_var.c_str(), default_level);
        logger->set_level(level);

        loggers_[static_cast<int>(def.subsys)] = logger;
        spdlog::register_logger(logger);
    }
}

void SubsystemLoggerManager::SetDefaultLevel(spdlog::level::level_enum level)
{
    for (auto &logger : loggers_)
    {
        if (logger)
            logger->set_level(level);
    }
}

void SubsystemLoggerManager::SetSubsystemLevel(Subsystem subsystem, spdlog::level::level_enum level)
{
    auto &logger = loggers_[static_cast<int>(subsystem)];
    if (logger)
        logger->set_level(level);
}

Subsystem SubsystemFromString(const std::string &name)
{
    if (name == "keepalive")
        return Subsystem::keepalive;
    if (name == "sessions")
        return Subsystem::sessions;
    if (name == "control")
        return Subsystem::control;
    if (name == "dataio")
        return Subsystem::dataio;
    if (name == "routing")
        return Subsystem::routing;
    return Subsystem::general;
}

std::string SubsystemToString(Subsystem subsystem)
{
    switch (subsystem)
    {
    case Subsystem::keepalive:
        return "keepalive";
    case Subsystem::sessions:
        return "sessions";
    case Subsystem::control:
        return "control";
    case Subsystem::dataio:
        return "dataio";
    case Subsystem::routing:
        return "routing";
    case Subsystem::general:
        return "general";
    }
    return "unknown";
}

} // namespace clv::vpn::logging
