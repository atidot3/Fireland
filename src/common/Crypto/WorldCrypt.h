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
    /// Initialise both cipher streams from the SRP6 session key and the
    /// per-session random seeds that were sent in SMSG_AUTH_CHALLENGE.
    ///
    /// In Cataclysm 4.x, the two 16-byte halves of the DosChallenge field
    /// serve as HMAC keys:
    ///   encKey = HMAC-SHA1(K, encryptSeed)   — used for outgoing SMSG headers
    ///   decKey = HMAC-SHA1(K, decryptSeed)   — used for incoming CMSG headers
    ///
    /// The client derives the same keys because it received the seeds in the
    /// challenge packet. Must be called once after CMSG_AUTH_SESSION is verified.
    void Init(std::span<const uint8_t> sessionKey,
              std::span<const uint8_t> encryptSeed,
              std::span<const uint8_t> decryptSeed)
    {
        SHA1::Digest encKey = HMAC_SHA1(sessionKey, encryptSeed);
        SHA1::Digest decKey = HMAC_SHA1(sessionKey, decryptSeed);

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
