// ============================================================================
// Log — Configurable, coloured logging implementation
//
// Thread-safety model:
//   - Init() is called once from main() before any worker threads start.
//   - After Init(), the maps (s_appenders, s_loggers) are structurally frozen.
//   - ShouldLog() / Write() are lock-free on the hot path.
//   - SetLevel() / SetConsoleEnabled() use atomic stores (safe from any thread).
// ============================================================================

#include "Log.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#   ifndef WIN32_LEAN_AND_MEAN
#       define WIN32_LEAN_AND_MEAN
#   endif
#   include <Windows.h>
#endif

namespace Fireland::Utils::Log {

// ============================================================================
// Constants
// ============================================================================

static constexpr int LABEL_WIDTH = 7;

static const char* LabelForLevel(Level lvl)
{
    switch (lvl)
    {
        case Level::Fatal:   return "FATAL";
        case Level::Error:   return "ERROR";
        case Level::Warning: return "WARNING";
        case Level::Info:    return "INFO";
        case Level::Debug:   return "DEBUG";
        case Level::Trace:   return "TRACE";
        default:             return "???";
    }
}

// ============================================================================
// ANSI colour table (indexed 0-14, TrinityCore convention)
// ============================================================================

static constexpr const char* ANSI_RESET = "\033[0m";

static constexpr const char* ColorTable[] =
{
    "\033[30m",  //  0 - BLACK
    "\033[31m",  //  1 - RED (dark)
    "\033[32m",  //  2 - GREEN
    "\033[33m",  //  3 - BROWN
    "\033[34m",  //  4 - BLUE
    "\033[35m",  //  5 - MAGENTA
    "\033[36m",  //  6 - CYAN
    "\033[37m",  //  7 - GREY
    "\033[93m",  //  8 - YELLOW (bright)
    "\033[91m",  //  9 - LRED (bright red)
    "\033[92m",  // 10 - LGREEN
    "\033[94m",  // 11 - LBLUE
    "\033[95m",  // 12 - LMAGENTA
    "\033[96m",  // 13 - LCYAN
    "\033[97m",  // 14 - WHITE
};
static constexpr int COLOR_COUNT = 15;

static const char* AnsiColor(uint8_t index)
{
    return (index < COLOR_COUNT) ? ColorTable[index] : ANSI_RESET;
}

static constexpr std::array<uint8_t, 6> DEFAULT_COLORS = { 1, 9, 5, 2, 8, 7 };

// ============================================================================
// Appender flags (bitwise OR)
// ============================================================================

enum AppenderFlags : uint8_t
{
    FLAG_TIMESTAMP   = 1,
    FLAG_LOGLEVEL    = 2,
    FLAG_LOGGERNAME  = 4,
};

// ============================================================================
// Appender base class
// ============================================================================

class Appender
{
public:
    Appender(Level maxLevel, uint8_t flags)
        : _maxLevel(maxLevel), _flags(flags) {}
    virtual ~Appender() = default;

    bool Accepts(Level msgLevel) const
    {
        auto max = _maxLevel.load(std::memory_order_relaxed);
        return msgLevel != Level::Disabled &&
               static_cast<uint8_t>(msgLevel) <= static_cast<uint8_t>(max);
    }

    virtual void Write(Level level, std::string_view logger, std::string_view message) = 0;

    void SetMaxLevel(Level level) { _maxLevel.store(level, std::memory_order_relaxed); }

protected:
    static std::string Timestamp()
    {
        auto now  = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms   = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now.time_since_epoch()) % 1000;
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &time);
#else
        localtime_r(&time, &tm);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
            << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return oss.str();
    }

    std::atomic<Level> _maxLevel;
    uint8_t            _flags;
};

// ============================================================================
// Console Appender
// ============================================================================

class ConsoleAppender final : public Appender
{
public:
    ConsoleAppender(Level maxLevel, uint8_t flags, std::array<uint8_t, 6> colors)
        : Appender(maxLevel, flags), _colors(colors)
    {
    }

    void Write(Level level, std::string_view logger, std::string_view message) override
    {
        if (!Accepts(level))
            return;

        const char* color = AnsiColor(_colors[static_cast<uint8_t>(level) - 1]);

        std::ostringstream oss;

        if (_flags & FLAG_TIMESTAMP)
            oss << "\033[90m[" << Timestamp() << "] " << ANSI_RESET;

        if (_flags & FLAG_LOGLEVEL)
            oss << color << "[" << std::left << std::setw(LABEL_WIDTH)
                << LabelForLevel(level) << "] " << ANSI_RESET;

        if (_flags & FLAG_LOGGERNAME)
            oss << "\033[90m[" << logger << "] " << ANSI_RESET;

        oss << message;

        std::cout << oss.str() << std::endl;
    }

private:
    std::array<uint8_t, 6> _colors;
};

// ============================================================================
// File Appender
// ============================================================================

class FileAppender final : public Appender
{
public:
    FileAppender(Level maxLevel, uint8_t flags,
                 const std::string& filename, char mode)
        : Appender(maxLevel, flags)
    {
        auto openMode = (mode == 'w')
            ? (std::ios::out | std::ios::trunc)
            : (std::ios::out | std::ios::app);
        _file.open(filename, openMode);
    }

    void Write(Level level, std::string_view logger, std::string_view message) override
    {
        if (!Accepts(level) || !_file.is_open())
            return;

        std::ostringstream oss;

        if (_flags & FLAG_TIMESTAMP)
            oss << "[" << Timestamp() << "] ";

        if (_flags & FLAG_LOGLEVEL)
            oss << "[" << std::left << std::setw(LABEL_WIDTH)
                  << LabelForLevel(level) << "] ";

        if (_flags & FLAG_LOGGERNAME)
            oss << "[" << logger << "] ";

        oss << message << '\n';

        // Single write + flush
        _file << oss.str();
        _file.flush();
    }

private:
    std::ofstream _file;
};

// ============================================================================
// Logger config
// ============================================================================

struct LoggerConfig
{
    std::atomic<Level>       maxLevel{ Level::Disabled };
    std::vector<std::string> appenderNames;

    LoggerConfig() = default;
    LoggerConfig(LoggerConfig&& o) noexcept
        : maxLevel(o.maxLevel.load(std::memory_order_relaxed))
        , appenderNames(std::move(o.appenderNames))
    {}
    LoggerConfig& operator=(LoggerConfig&& o) noexcept
    {
        maxLevel.store(o.maxLevel.load(std::memory_order_relaxed), std::memory_order_relaxed);
        appenderNames = std::move(o.appenderNames);
        return *this;
    }
};

// ============================================================================
// Global state
//
// s_appenders / s_loggers are populated during Init() (single-threaded)
// and structurally immutable afterwards.  Only atomic levels change at runtime.
// ============================================================================

static std::once_flag                                             s_initFlag;
static std::atomic<bool>                                          s_initialized{ false };
static std::unordered_map<std::string, std::unique_ptr<Appender>> s_appenders;
static std::unordered_map<std::string, LoggerConfig>              s_loggers;

// ============================================================================
// Enable VT-100 escape sequences on Windows
// ============================================================================

static void EnableAnsiOnWindows()
{
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (!GetConsoleMode(hOut, &mode)) return;
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
}

// ============================================================================
// Config parsing helpers
// ============================================================================

static std::string Trim(std::string_view sv)
{
    auto start = sv.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return {};
    auto end = sv.find_last_not_of(" \t\r\n");
    return std::string(sv.substr(start, end - start + 1));
}

static std::vector<std::string> SplitConfigValue(std::string_view value)
{
    std::vector<std::string> tokens;
    std::string current;
    bool inQuotes = false;

    for (char c : value)
    {
        if (c == '"') { inQuotes = !inQuotes; continue; }
        if (c == ',' && !inQuotes)
        {
            tokens.push_back(Trim(current));
            current.clear();
            continue;
        }
        current += c;
    }
    if (!current.empty())
        tokens.push_back(Trim(current));

    return tokens;
}

static std::array<uint8_t, 6> ParseColors(const std::string& colorStr)
{
    std::array<uint8_t, 6> colors = DEFAULT_COLORS;
    std::istringstream iss(colorStr);
    for (int i = 0; i < 6 && iss; ++i)
    {
        int val = 0;
        if (iss >> val)
            colors[i] = static_cast<uint8_t>(std::clamp(val, 0, 14));
    }
    return colors;
}

static void ParseAppender(const std::string& name, const std::string& value)
{
    auto parts = SplitConfigValue(value);
    if (parts.size() < 3)
        return;

    int type    = std::stoi(parts[0]);
    int level   = std::clamp(std::stoi(parts[1]), 0, 6);
    int flags   = std::stoi(parts[2]);
    auto maxLvl = static_cast<Level>(level);
    auto fl     = static_cast<uint8_t>(flags);

    if (type == 1)
    {
        auto colors = (parts.size() >= 4) ? ParseColors(parts[3]) : DEFAULT_COLORS;
        s_appenders[name] = std::make_unique<ConsoleAppender>(maxLvl, fl, colors);
    }
    else if (type == 2)
    {
        if (parts.size() < 4) return;
        char mode = (parts.size() >= 5 && !parts[4].empty()) ? parts[4][0] : 'a';
        s_appenders[name] = std::make_unique<FileAppender>(maxLvl, fl, parts[3], mode);
    }
}

static void ParseLogger(const std::string& name, const std::string& value)
{
    auto commaPos = value.find(',');
    if (commaPos == std::string::npos) return;

    int level = std::clamp(std::stoi(Trim(value.substr(0, commaPos))), 0, 6);
    std::string appendersPart = Trim(value.substr(commaPos + 1));

    LoggerConfig cfg;
    cfg.maxLevel.store(static_cast<Level>(level), std::memory_order_relaxed);

    std::istringstream iss(appendersPart);
    std::string appName;
    while (iss >> appName)
        cfg.appenderNames.push_back(appName);

    s_loggers[name] = std::move(cfg);
}

static void LoadConfigFile(const std::string& filename)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        std::cerr << "[Log] Config file '" << filename << "' not found, using defaults\n";
        return;
    }

    std::string line;
    while (std::getline(file, line))
    {
        line = Trim(line);
        if (line.empty() || line[0] == '#')
            continue;

        auto eqPos = line.find('=');
        if (eqPos == std::string::npos)
            continue;

        std::string key   = Trim(line.substr(0, eqPos));
        std::string value = Trim(line.substr(eqPos + 1));

        if (key.starts_with("Appender."))
            ParseAppender(key.substr(9), value);
        else if (key.starts_with("Logger."))
            ParseLogger(key.substr(7), value);
    }
}

// ============================================================================
// Defaults
// ============================================================================

static void CreateDefaults(Level defaultLevel)
{
    s_appenders["Console"] = std::make_unique<ConsoleAppender>(
        Level::Trace,
        static_cast<uint8_t>(FLAG_LOGLEVEL | FLAG_LOGGERNAME),
        DEFAULT_COLORS);

    LoggerConfig root;
    root.maxLevel.store(defaultLevel, std::memory_order_relaxed);
    root.appenderNames = { "Console" };
    s_loggers["root"] = std::move(root);
}

// ============================================================================
// Logger lookup (lock-free — maps are frozen after Init)
// ============================================================================

static const LoggerConfig* FindLogger(std::string_view name)
{
    auto it = s_loggers.find(std::string(name));
    if (it != s_loggers.end())
        return &it->second;

    it = s_loggers.find("root");
    if (it != s_loggers.end())
        return &it->second;

    return nullptr;
}

// ============================================================================
// Public API — all lock-free after Init()
// ============================================================================

void Init(const std::string& configFile)
{
    std::call_once(s_initFlag, [&configFile]
    {
        EnableAnsiOnWindows();
        CreateDefaults(Level::Info);

        if (!configFile.empty())
            LoadConfigFile(configFile);

        s_initialized.store(true, std::memory_order_release);
    });
}

void Init(Level defaultLevel)
{
    std::call_once(s_initFlag, [defaultLevel]
    {
        EnableAnsiOnWindows();
        CreateDefaults(defaultLevel);
        s_initialized.store(true, std::memory_order_release);
    });
}

bool ShouldLog(std::string_view logger, Level level)
{
    if (!s_initialized.load(std::memory_order_acquire))
        return static_cast<uint8_t>(level) <= static_cast<uint8_t>(Level::Info);

    const auto* cfg = FindLogger(logger);
    if (!cfg)
        return false;

    auto max = cfg->maxLevel.load(std::memory_order_relaxed);
    return level != Level::Disabled &&
           static_cast<uint8_t>(level) <= static_cast<uint8_t>(max);
}

void Write(std::string_view logger, Level level, std::string_view message)
{
    if (!s_initialized.load(std::memory_order_acquire))
    {
        std::cout << "[" << std::left << std::setw(LABEL_WIDTH)
                  << LabelForLevel(level) << "] "
                  << "[" << logger << "] " << message << std::endl;
        return;
    }

    const auto* cfg = FindLogger(logger);
    if (!cfg) return;

    for (const auto& appName : cfg->appenderNames)
    {
        auto it = s_appenders.find(appName);
        if (it != s_appenders.end())
            it->second->Write(level, logger, message);
    }
}

void SetLevel(std::string_view logger, Level level)
{
    auto it = s_loggers.find(std::string(logger));
    if (it != s_loggers.end())
        it->second.maxLevel.store(level, std::memory_order_relaxed);
}

void SetConsoleEnabled(bool enabled)
{
    for (auto& [name, appender] : s_appenders)
    {
        if (dynamic_cast<ConsoleAppender*>(appender.get()))
            appender->SetMaxLevel(enabled ? Level::Trace : Level::Disabled);
    }
}

} // namespace Fireland::Utils::Log
