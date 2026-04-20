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
// Each stream is keyed with HMAC-SHA1(key=fixedSeed, data=SessionKey) and then
// has its first 1024 keystream bytes discarded (ARC4-drop1024).
// The fixed seeds are hardcoded in both the client and server binaries.
// ============================================================================

#include <array>
#include <cstdint>
#include <span>

#include <Crypto/ARC4.h>
#include <Crypto/HMAC.h>

namespace Firelands::Crypto {

class WorldCrypt
{
public:
    /// Initialise both cipher streams from the SRP6 session key K.
    ///
    /// Key derivation (Cataclysm 4.3.4):
    ///   encKey = HMAC-SHA1(key=kServerEncryptSeed, data=K)  — SMSG header encrypt
    ///   decKey = HMAC-SHA1(key=kClientDecryptSeed, data=K)  — CMSG header decrypt
    ///
    /// Must be called once after CMSG_AUTH_SESSION is verified.
    void Init(std::span<const uint8_t> sessionKey)
    {
        // Cataclysm 4.3.4 (build 15595) hardcoded seeds — identical to TC WorldPacketCrypt.cpp.
        // The client derives keys as: HMAC-SHA1(key=fixedSeed, data=K).
        // Seed is the HMAC *key*; session key K is the HMAC *message*.
        static const uint8_t kServerEncryptSeed[] = {
            0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA,
            0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53, 0x57};
        static const uint8_t kClientDecryptSeed[] = {
            0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5,
            0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43, 0x67, 0xCE};

        std::span<const uint8_t> encryptSeed(kServerEncryptSeed, sizeof(kServerEncryptSeed));
        std::span<const uint8_t> decryptSeed(kClientDecryptSeed, sizeof(kClientDecryptSeed));
        // HMAC(key=seed, data=K) — seed is the key, K is the message
        SHA1::Digest encKey = HMAC_SHA1(encryptSeed, sessionKey);
        SHA1::Digest decKey = HMAC_SHA1(decryptSeed, sessionKey);

        _encrypt.Init(std::span<const uint8_t>(encKey));
        _decrypt.Init(std::span<const uint8_t>(decKey));

        // ARC4-drop1024: discard the first 1024 keystream bytes from each stream
        // WoW uses ARC4-drop1024 to strengthen the cipher.
        _encrypt.Drop(1024);
        _decrypt.Drop(1024);

        _initialized = true;
    }

    bool IsInitialized() const { return _initialized; }

    /// Encrypt an outgoing SMSG header in-place (server → client, typically 4 bytes).
    void EncryptSend(uint8_t* header, std::size_t len)
    {
        if (_initialized)
        {
            _encrypt.Process(header, len);
        }
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

} // namespace Firelands::Crypto
