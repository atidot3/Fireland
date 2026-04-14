#pragma once

// ============================================================================
// WorldCrypt — WoW Cataclysm (4.3.4 / build 15595) packet-header cipher
//
// After a successful CMSG_AUTH_SESSION handshake, all world-packet *headers*
// are encrypted with ARC4-drop1024.  Bodies are NOT encrypted.
//
// Header sizes:
//   SMSG (server → client): 4 bytes  [Size:2 BE | Opcode:2 LE]
//   CMSG (client → server): 6 bytes  [Size:2 BE | Opcode:4 LE]
//
// Two independent ARC4 streams are used — one per direction.
// Each stream is keyed with HMAC-SHA1(SessionKey, DirectionSeed) and then
// has its first 1024 keystream bytes discarded.
// ============================================================================

#include <array>
#include <cstdint>
#include <span>

#include "ARC4.h"
#include "HMAC.h"

namespace Fireland::Crypto {

class WorldCrypt
{
public:
    // Per-direction HMAC seeds (Cataclysm 4.x, build 15595).
    // These are fixed constants hardcoded in both the server and the WoW client
    // binary. They are used ONLY as HMAC keys to derive the per-session ARC4
    // cipher keys: encKey = HMAC_SHA1(K, kEncryptSeed), and similarly for dec.
    // They are NOT sent over the wire; the client already knows them.
    static constexpr std::array<uint8_t, 16> kEncryptSeed = {
        0x08, 0xF6, 0x61, 0xC1, 0xCA, 0x4C, 0x41, 0xE0,
        0xF2, 0x01, 0x99, 0xFF, 0x02, 0x15, 0x7A, 0x00,
    };
    static constexpr std::array<uint8_t, 16> kDecryptSeed = {
        0x40, 0xAD, 0x9C, 0xE3, 0x44, 0x2A, 0x9C, 0x0F,
        0x9F, 0xBE, 0x31, 0xB2, 0xAD, 0x93, 0x9B, 0x61,
    };

    /// Initialise both cipher streams from the 40-byte SRP6 session key.
    /// Must be called once after CMSG_AUTH_SESSION is verified.
    void Init(std::span<const uint8_t> sessionKey)
    {
        // Derive a 20-byte ARC4 key for each direction
        SHA1::Digest encKey = HMAC_SHA1(sessionKey, std::span<const uint8_t>(kEncryptSeed));
        SHA1::Digest decKey = HMAC_SHA1(sessionKey, std::span<const uint8_t>(kDecryptSeed));

        _encrypt.Init(std::span<const uint8_t>(encKey));
        _decrypt.Init(std::span<const uint8_t>(decKey));

        // ARC4-drop1024: discard the first 1024 keystream bytes from each stream
        _encrypt.Drop(1024);
        _decrypt.Drop(1024);

        _initialized = true;
    }

    bool IsInitialized() const { return _initialized; }

    /// Encrypt an outgoing SMSG header in-place (server → client, typically 4 bytes).
    void EncryptSend(uint8_t* header, std::size_t len)
    {
        if (_initialized)
            _encrypt.Process(header, len);
    }

    /// Decrypt an incoming CMSG header in-place (client → server, typically 6 bytes).
    void DecryptRecv(uint8_t* header, std::size_t len)
    {
        if (_initialized)
            _decrypt.Process(header, len);
    }

private:
    ARC4 _encrypt;
    ARC4 _decrypt;
    bool _initialized = false;
};

} // namespace Fireland::Crypto
