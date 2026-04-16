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

**Fireland** is a modern WoW Cataclysm (4.3.4 / build 15595) server emulator written from scratch in **C++23**, leveraging **Boost.Asio** with C++20 coroutines for high-performance asynchronous networking.

### Key features

- ⚡ **Coroutine-based networking** — `co_await` everywhere, no callback spaghetti
- 🔐 **SRP6 authentication** — full challenge → proof → realm list flow
- 🌐 **World server protocol** — complete Cataclysm handshake up to character selection
- 🔒 **ARC4-drop1024 header encryption** — per-direction streams keyed via HMAC-SHA1
- 🧩 **Bit-packed packet serialisation** — `WriteBit` / `WriteBits` / `FlushBits` matching the Cata 4.x wire format
- 🎨 **Configurable coloured logging** — per-component filtering, console + file appenders, TrinityCore-style `.conf` files
- 🏗️ **Modular architecture** — `Utils`, `Crypto`, `Database`, `Network`, `AuthServer`, `WorldServer` as separate CMake targets
- 🔧 **Zero manual dependency management** — Boost is fetched automatically via CMake `FetchContent`
- 🖥️ **Cross-platform** — Windows (MSVC), Linux (GCC/Clang)

## Project structure

```
Fireland/
├── CMakeLists.txt
├── cmake/
│   ├── Platform.cmake
│   ├── CompilerOptions.cmake
│   └── Macros.cmake
├── etc/
│   ├── authserver.conf.dist
│   └── worldserver.conf.dist
└── src/
    ├── common/
    │   ├── Crypto/
    │   │   ├── include/Crypto/
    │   │   │   ├── ARC4.h          # ARC4 stream cipher
    │   │   │   ├── BigNumber.h     # boost::multiprecision::cpp_int wrapper
    │   │   │   ├── HMAC.h          # HMAC-SHA1 (Boost.UUID backend)
    │   │   │   ├── SHA1.h          # SHA-1 digest
    │   │   │   ├── SRP6.h          # SRP-6 authentication protocol
    │   │   │   └── WorldCrypt.h    # ARC4-drop1024 world packet header cipher
    │   │   └── src/
    │   │       ├── BigNumber.cpp
    │   │       └── SRP6.cpp
    │   ├── Database/
    │   │   ├── include/Database/
    │   │   │   ├── Auth/AuthWrapper.h       # Async auth DB operations
    │   │   │   └── connection_pool_wrapper.h
    │   │   └── src/
    │   │       ├── Auth/AuthWrapper.cpp
    │   │       └── connection_pool_wrapper.cpp
    │   ├── Network/
    │   │   ├── include/Network/
    │   │   │   ├── PacketBuffer.h   # Simple header+payload framing
    │   │   │   ├── SessionManager.h # Thread-safe session tracking (strand)
    │   │   │   ├── TcpListener.h    # Coroutine accept loop (header-only)
    │   │   │   └── TcpSession.h     # Per-connection read/write coroutines
    │   │   └── src/
    │   │       ├── PacketBuffer.cpp
    │   │       ├── SessionManager.cpp
    │   │       └── TcpSession.cpp
    │   └── Utils/
    │       ├── include/Utils/
    │       │   ├── Async.hpp        # awaitable<T> alias, async_sleep
    │       │   ├── ByteBuffer.h     # Binary serialisation buffer (bit I/O included)
    │       │   ├── Describe.hpp     # Boost.Describe helpers
    │       │   ├── Filesystem.h
    │       │   ├── IoContext.h      # Boost.Asio thread pool wrapper
    │       │   ├── Log.h            # Configurable logging system
    │       │   ├── ProgramOptions.h # CLI argument parsing
    │       │   └── StringUtils.h
    │       └── src/
    │           ├── Filesystem.cpp
    │           ├── IoContext.cpp
    │           └── Log.cpp
    └── server/
        ├── authserver/             # Authentication server (port 3724)
        │   ├── Network/
        │   │   ├── AuthOpcode.h    # Auth protocol opcodes & wire structures
        │   │   ├── AuthPacket.hpp  # Typed ByteBuffer for auth packets
        │   │   ├── AuthSession.h
        │   │   └── AuthSession.cpp # SRP6 auth flow (challenge → proof → realm list)
        │   ├── Realm/Realm.h
        │   └── main.cpp
        └── worldserver/            # World server (port 8085)
            ├── WorldOpcode.h       # Cata 4.3.4 opcode table + AuthResponseResult
            ├── WorldPacket.h       # Typed ByteBuffer for world packets (SMSG/CMSG)
            ├── WorldSession.h
            ├── WorldSession.cpp    # Full Cata handshake + post-auth packet loop
            └── main.cpp
```

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| **CMake** | ≥ 3.20 | Build system |
| **C++ compiler** | C++23 support | MSVC 19.40+, GCC 13+, Clang 17+ |
| **Boost** | 1.90.0 | *Auto-downloaded* via FetchContent |
| **MySQL / MariaDB** | Any recent | Auth database (credentials in `.conf`) |

### Boost components used

| Component | Purpose |
|---|---|
| `Boost.Asio` | Async I/O, TCP, coroutines, timers, signal handling |
| `Boost.System` | Error codes |
| `Boost.Log` | Logging backend |
| `Boost.ProgramOptions` | CLI argument parsing |
| `Boost.Multiprecision` | Big-integer arithmetic for SRP6 |
| `Boost.UUID` | SHA-1 implementation |
| `Boost.Describe` | Compile-time enum-to-string for opcodes |

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
sudo apt install -y build-essential cmake git libmysqlclient-dev

# Clone & build
git clone https://github.com/atidot3/Fireland.git
cd Fireland
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

### CMake options

| Option | Default | Description |
|---|---|---|
| `FIRELAND_ENABLE_SANITIZERS` | `OFF` | Enable AddressSanitizer + UBSan in Debug builds |

## Configuration

Copy the `.dist` templates and edit to your needs:

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
#   Flags:    1=Timestamp 2=LogLevel 4=LoggerName 8=SourceLocation (bitwise OR)

Appender.Console = 1,5,15,"1 9 5 2 8 7"
Appender.Auth    = 2,5,15,Auth.log,w

# Logger.<name> = <LogLevel>,<Appender1> [<Appender2> ...]
Logger.root           = 4,Console
Logger.AuthServer     = 5,Console Auth
Logger.WorldSession   = 5,Console
```

## Usage

```bash
# Auth server (port 3724)
./authserver --config authserver.conf

# World server (port 8085)
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

```
CMD_AUTH_LOGON_CHALLENGE  →  server sends B, N, g, salt
CMD_AUTH_LOGON_PROOF      →  client sends A, M1 — server verifies, sends M2
CMD_REALM_LIST            →  server sends realm list
```

After a successful proof, the 40-byte SRP session key `K` is stored in the auth database and later retrieved by the world server to initialise packet encryption.

### World server — Cataclysm 4.3.4 handshake

```
TCP connect
  ← ServerConnectionInit  ("WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT")
  → ClientConnectionInit  ("WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER")
  ← SMSG_AUTH_CHALLENGE   (server seed + 8×uint32 DOS seeds)
  → CMSG_AUTH_SESSION     (build, account, client seed, digest=SHA1(account,0,clientSeed,serverSeed,K))
  ← SMSG_AUTH_RESPONSE    (AUTH_OK + expansion info)  ← ARC4 encryption starts here
  ← SMSG_ADDON_INFO
  ← SMSG_CLIENTCACHE_VERSION
  ← SMSG_TUTORIAL_FLAGS
  → CMSG_READY_FOR_ACCOUNT_DATA_TIMES
  ← SMSG_ACCOUNT_DATA_TIMES
  → CMSG_REALM_SPLIT / CMSG_CHAR_ENUM / …
  ← SMSG_CHAR_ENUM        (character list)
```

### ARC4-drop1024 packet encryption

All world packet **headers** are encrypted after `SMSG_AUTH_RESPONSE`. Two independent ARC4 streams are used:

```
encKey = HMAC-SHA1(key = kServerEncryptSeed,  data = SessionKey K)
decKey = HMAC-SHA1(key = kClientDecryptSeed,  data = SessionKey K)
```

Each stream discards its first 1024 keystream bytes (ARC4-drop1024) before use. Header sizes:
- `SMSG` (server → client): 4 bytes `[uint16 size BE | uint16 opcode LE]`
- `CMSG` (client → server): 6 bytes `[uint16 size BE | uint32 opcode LE]`

### Bit-packed packet serialisation

Cataclysm 4.x uses a compact bit-stream format for many packets. `ByteBuffer` exposes:

```cpp
void WriteBit(uint32_t bit);          // write 1 bit (MSB-first within each byte)
void WriteBits(uint32_t value, uint32_t bits);
void FlushBits();                     // zero-pad to next byte boundary

bool    ReadBit();
uint32_t ReadBits(uint32_t n);
```

Example — `SMSG_CHAR_ENUM` empty character list:
```cpp
WorldPacket data(SMSG_CHAR_ENUM);
data.WriteBits(0, 23);   // FactionChangeRestrictions count
data.WriteBit(true);     // Success
data.WriteBits(0, 17);   // Characters count
data.FlushBits();
co_await SendPacket(data);
```

### Typed logging with std::format

```cpp
FL_LOG_INFO("WorldSession", "Client {} authenticated as '{}'", _remoteAddress, _username);
FL_LOG_ERROR("WorldSession", "CMSG_AUTH_SESSION digest mismatch for '{}'", _username);
FL_LOG_TRACE("WorldSession", "SMSG_AUTH_CHALLENGE seed = 0x{:08X}", _serverSeed);
```

## License

*To be determined.*
