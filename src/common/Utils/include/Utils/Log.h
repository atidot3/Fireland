#pragma once

// ============================================================================
// Log — Configurable, coloured logging system
//
// Initialization:
//   Fireland::Utils::Log::Init("authserver.conf");      // from config file
//   Fireland::Utils::Log::Init();                       // defaults: console, INFO
//
// Usage (std::format syntax — first argument is the logger tag):
//   FL_LOG_INFO("TcpListener", "Listening on {}:{}", addr, port);
//   FL_LOG_ERROR("AuthServer", "Login failed for user {}", username);
//
// Config file format (inspired by TrinityCore):
//
//   Appender.<name> = <Type>,<LogLevel>,<Flags>[,<Colors>|<File>,<Mode>]
//   Flags: 1=Timestamp 2=LogLevel 4=LoggerName 8=SourceLocation (bitwise OR)
//   Logger.<name>   = <LogLevel>,<Appender1> [<Appender2> ...]
//
// See authserver.conf.dist / worldserver.conf.dist for full documentation.
// ============================================================================

#include <cstdint>
#include <format>
#include <source_location>
#include <string>
#include <string_view>
#include <utility>

#include "Describe.hpp"

namespace Fireland::Utils::Log
{
    // ---- Severity levels (matches TrinityCore convention) ----------------------
    // Lower value = more critical.  A logger configured at level N accepts
    // all messages with level <= N.
    enum class Level : uint8_t
    {
        Disabled = 0,
        Fatal    = 1,
        Error    = 2,
        Warning  = 3,
        Info     = 4,
        Debug    = 5,
        Trace    = 6,
    };
	BOOST_DESCRIBE_ENUM(Level, Disabled, Fatal, Error, Warning, Info, Debug, Trace);

    /// Initialise from a config file.  Falls back to defaults if not found.
    void Init(const std::string& configFile);

    /// Initialise with a default console appender at the given level.
    void Init(Level defaultLevel = Level::Info);

    /// Check if a logger would accept a message at the given level.
    bool ShouldLog(std::string_view logger, Level level);

    /// Write a log message for a given logger and level.
    void Write(std::string_view logger, Level level, std::string_view message,
              std::source_location loc = std::source_location::current());

    /// Change the severity of an existing logger at runtime.
    void SetLevel(std::string_view logger, Level level);

    /// Disable/enable the console appender (for --quiet mode).
    void SetConsoleEnabled(bool enabled);

    /// Format helper — wraps std::format.  Called by FL_LOG_* macros.
    template <typename... Args>
    std::string Format(std::format_string<Args...> fmt, Args&&... args)
    {
        return std::format(fmt, std::forward<Args>(args)...);
    }
} // namespace Fireland::Utils::Log

// ---- Convenience macros (std::format API with logger tag) ------------------
// The ShouldLog check avoids the Format() cost for disabled loggers.

#define FL_LOG_TRACE(tag, fmt, ...)   do { if (::Fireland::Utils::Log::ShouldLog(tag, ::Fireland::Utils::Log::Level::Trace))   ::Fireland::Utils::Log::Write(tag, ::Fireland::Utils::Log::Level::Trace,   ::Fireland::Utils::Log::Format(fmt __VA_OPT__(,) __VA_ARGS__)); } while(0)
#define FL_LOG_DEBUG(tag, fmt, ...)   do { if (::Fireland::Utils::Log::ShouldLog(tag, ::Fireland::Utils::Log::Level::Debug))   ::Fireland::Utils::Log::Write(tag, ::Fireland::Utils::Log::Level::Debug,   ::Fireland::Utils::Log::Format(fmt __VA_OPT__(,) __VA_ARGS__)); } while(0)
#define FL_LOG_INFO(tag, fmt, ...)    do { if (::Fireland::Utils::Log::ShouldLog(tag, ::Fireland::Utils::Log::Level::Info))    ::Fireland::Utils::Log::Write(tag, ::Fireland::Utils::Log::Level::Info,    ::Fireland::Utils::Log::Format(fmt __VA_OPT__(,) __VA_ARGS__)); } while(0)
#define FL_LOG_WARNING(tag, fmt, ...) do { if (::Fireland::Utils::Log::ShouldLog(tag, ::Fireland::Utils::Log::Level::Warning)) ::Fireland::Utils::Log::Write(tag, ::Fireland::Utils::Log::Level::Warning, ::Fireland::Utils::Log::Format(fmt __VA_OPT__(,) __VA_ARGS__)); } while(0)
#define FL_LOG_ERROR(tag, fmt, ...)   do { if (::Fireland::Utils::Log::ShouldLog(tag, ::Fireland::Utils::Log::Level::Error))   ::Fireland::Utils::Log::Write(tag, ::Fireland::Utils::Log::Level::Error,   ::Fireland::Utils::Log::Format(fmt __VA_OPT__(,) __VA_ARGS__)); } while(0)
#define FL_LOG_FATAL(tag, fmt, ...)   do { if (::Fireland::Utils::Log::ShouldLog(tag, ::Fireland::Utils::Log::Level::Fatal))   ::Fireland::Utils::Log::Write(tag, ::Fireland::Utils::Log::Level::Fatal,   ::Fireland::Utils::Log::Format(fmt __VA_OPT__(,) __VA_ARGS__)); } while(0)
