<p align="center">
  <h1 align="center">🔥 Fireland</h1>
  <p align="center">
    World of Warcraft — Cataclysm (4.3.4) Private Server Emulator
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-23-blue?logo=cplusplus" alt="C++23">
  <img src="https://img.shields.io/badge/Boost-1.90.0-orange?logo=boost" alt="Boost 1.90.0">
  <img src="https://img.shields.io/badge/CMake-3.20+-green?logo=cmake" alt="CMake 3.20+">
  <img src="https://img.shields.io/badge/Platform-Windows%2011%20|%20Debian%2013-lightgrey" alt="Platform">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Tested-Visual%20Studio%202026%20(18.4)-purple?logo=visualstudio" alt="VS 2026">
  <img src="https://img.shields.io/badge/Tested-Debian%2013%20(Trixie)-red?logo=debian" alt="Debian 13">
</p>

---

## Overview

**Fireland** is a modern WoW Cataclysm (4.3.4) server emulator written from scratch in **C++23**, leveraging **Boost.Asio** with C++20 coroutines for high-performance asynchronous networking.

### Key features

- ⚡ **Coroutine-based networking** — `co_await` everywhere, no callback spaghetti
- 🔐 **SRP6 authentication** — full challenge → proof → realm list flow (Boost.Multiprecision + Boost.UUID SHA1)
- 🎨 **Configurable coloured logging** — per-component filtering, console + file appenders, TrinityCore-style `.conf` files
- 🧩 **Modular architecture** — `Utils`, `Crypto`, `Network`, `AuthServer`, `WorldServer` as separate CMake targets
- 🔧 **Zero manual dependency management** — Boost is fetched automatically via CMake `FetchContent`
- 🖥️ **Cross-platform** — Windows (MSVC), Linux (GCC/Clang), macOS (Apple Clang)

## Project structure

```
Fireland/
├── CMakeLists.txt              # Root build configuration
├── cmake/
│   ├── Platform.cmake          # OS/arch detection
│   ├── CompilerOptions.cmake   # Warning levels, sanitizers
│   └── Macros.cmake            # Utility macros
├── 3rdParty/
│   └── boost/                  # Boost FetchContent (auto-downloaded)
├── etc/
│   ├── authserver.conf.dist    # Auth server config template
│   └── worldserver.conf.dist   # World server config template
└── src/
    ├── common/
    │   ├── Crypto/             # Cryptography primitives
    │   │   ├── BigNumber.h/cpp # boost::multiprecision::cpp_int wrapper
    │   │   ├── SHA1.h          # SHA-1 digest (boost::uuids::detail::sha1)
    │   │   └── SRP6.h/cpp      # SRP-6 authentication protocol
    │   ├── Utils/              # Shared utilities
    │   │   ├── Async.hpp       # awaitable<T> alias, async_sleep
    │   │   ├── ByteBuffer.h/cpp# Binary serialisation buffer
    │   │   ├── Describe.hpp    # Compile-time type description helpers
    │   │   ├── IoContext.h/cpp # Boost.Asio thread pool wrapper
    │   │   ├── Log.h/cpp       # Configurable logging system
    │   │   ├── ProgramOptions.h# CLI argument parsing (--config, --quiet, --help)
    │   │   └── StringUtils.h   # Trim, split, case-convert
    │   └── Network/            # Async TCP networking library
    │       ├── IoContext.h/cpp  # Network-specific io_context
    │       ├── TcpListener.h   # Coroutine accept loop (header-only, templated)
    │       ├── TcpSession.h/cpp    # Per-connection read/write coroutines
    │       ├── SessionManager.h/cpp# Thread-safe session tracking (strand-based)
    │       └── PacketBuffer.h/cpp  # WoW packet framing (opcode + payload)
    └── server/
        ├── authserver/         # Authentication server (port 3724)
        │   ├── AuthOpcode.h    # Auth protocol opcodes & packet structures
        │   ├── AuthSession.h/cpp # SRP6 auth flow (challenge → proof → realm list)
        │   └── main.cpp
        └── worldserver/        # World server (port 8085)
            └── main.cpp
```

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| **CMake** | ≥ 3.20 | Build system |
| **C++ compiler** | C++23 support | MSVC 19.40+, GCC 13+, Clang 17+ |
| **Boost** | 1.90.0 | *Auto-downloaded* via FetchContent |

### Boost components used

| Component | Purpose |
|---|---|
| `Boost.Asio` | Async I/O, TCP, coroutines, timers, signal handling |
| `Boost.System` | Error codes |
| `Boost.Log` | Logging backend (used by smoke test) |
| `Boost.ProgramOptions` | CLI argument parsing (`--config`, `--quiet`, `--help`) |
| `Boost.Regex` | Pattern matching |
| `Boost.DateTime` | Time utilities |
| `Boost.Coroutine` | Coroutine context switching |
| `Boost.URL` | URL parsing |
| `Boost.Charconv` | Fast number ↔ string conversion |
| `Boost.Test` | Unit testing framework |

> **Note**: You do **not** need to install Boost manually. CMake downloads and builds only the required components automatically on first configure.

## Tested platforms

| OS | Compiler | Status |
|---|---|---|
| **Windows 11** | Visual Studio Community 2026 (MSVC 18.4) | ✅ Builds & runs |
| **Debian 13** (Trixie) | GCC 14 / Clang 18 | ✅ Builds & runs |

## Building

### Windows 11 — Visual Studio 2026

```powershell
git clone https://github.com/atidot3/Fireland.git
cd Fireland
cmake -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Debug
```

Or open the folder directly in Visual Studio 2026 (CMake is detected automatically), then build from the IDE.

### Debian 13 (Trixie)

```bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential cmake git

# Clone & build
git clone https://github.com/atidot3/Fireland.git
cd Fireland
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

### Other platforms

The project targets standard C++23 and should build on any system with CMake ≥ 3.20 and a conforming compiler (GCC 13+, Clang 17+, Apple Clang 16+), though only the two platforms above are actively tested.

### CMake options

| Option | Default | Description |
|---|---|---|
| `FIRELAND_ENABLE_SANITIZERS` | `OFF` | Enable AddressSanitizer + UBSan in Debug builds |

## Configuration

Copy the `.dist` template and edit to your needs:

```bash
cp etc/authserver.conf.dist authserver.conf
cp etc/worldserver.conf.dist worldserver.conf
```

### Logging system

The logging system is configured via `Appender.*` and `Logger.*` entries in the `.conf` files (inspired by [TrinityCore](https://github.com/TrinityCore/TrinityCore)).

```ini
# Appender.<name> = <Type>,<LogLevel>,<Flags>[,<Colors>|<File>,<Mode>]
#   Type:     1 = Console, 2 = File
#   LogLevel: 0=Disabled 1=Fatal 2=Error 3=Warning 4=Info 5=Debug 6=Trace
#   Flags:    1=Timestamp 2=LogLevel 4=LoggerName (bitwise OR)

Appender.Console = 1,5,6,"1 9 5 2 8 7"
Appender.Auth    = 2,5,7,Auth.log,w

# Logger.<name> = <LogLevel>,<Appender1> [<Appender2> ...]
Logger.root           = 4,Console
Logger.AuthServer     = 5,Console Auth
Logger.TcpListener    = 4,Console
#Logger.SessionManager = 5,Console    # ← commented = falls back to root
```

## Usage

```bash
# Auth server
./authserver --config authserver.conf

# World server
./worldserver --config worldserver.conf

# CLI options
./authserver --help
./authserver --version
./authserver --quiet              # disable console output (file appenders still active)
./authserver -c /path/to/my.conf  # custom config path
```

## Architecture highlights

### SRP6 authentication

The auth server implements the full SRP-6 handshake as a single coroutine per client:

```cpp
async<void> AuthSession::Run()
{
    auto self = shared_from_this(); // prevent premature destruction
    while (_socket.is_open())
    {
        uint8_t cmd = co_await ReadOpcode();
        switch (static_cast<AuthOpcode>(cmd))
        {
            case AuthOpcode::CMD_AUTH_LOGON_CHALLENGE: co_await HandleLogonChallenge(); break;
            case AuthOpcode::CMD_AUTH_LOGON_PROOF:     co_await HandleLogonProof();     break;
            case AuthOpcode::CMD_REALM_LIST:           co_await HandleRealmList();      break;
        }
    }
}
```

### Coroutine networking

All network I/O uses C++20 coroutines via Boost.Asio:

```cpp
boost::asio::awaitable<void> TcpSession::ReadLoop()
{
    while (IsOpen())
    {
        auto header = co_await ReadHeader();
        auto packet = co_await ReadPayload(header);
        _packetHandler(shared_from_this(), std::move(packet));
    }
}
```

### Strand-based thread safety

`SessionManager` uses a Boost.Asio strand to serialise all session map access without mutexes:

```cpp
void SessionManager::Add(TcpSession::Ptr session)
{
    boost::asio::post(_strand, [this, session = std::move(session)]() mutable {
        _sessions[session->GetId()] = std::move(session);
    });
}
```

### Typed logging with std::format

```cpp
FL_LOG_INFO("TcpListener", "Listening on {}:{}", address, port);
FL_LOG_ERROR("TcpSession", "Session #{} read error: {}", _id, e.what());
```

## License

*To be determined.*
