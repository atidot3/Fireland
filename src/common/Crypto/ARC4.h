#pragma once

// ============================================================================
// ARC4 — Alleged RC4 stream cipher (in-place XOR)
//
// Used for WoW world-packet header encryption (post-auth).
// Two independent instances are required: one for each direction.
//
// NOTE: ARC4 is a weak cipher. WoW uses it only for header bytes; packet
//       bodies are transmitted in plaintext.
// ============================================================================

#include <array>
#include <cstdint>
#include <span>

namespace Fireland::Crypto {

class ARC4
{
public:
    /// Initialise the cipher with a key (KSA phase).
    void Init(std::span<const uint8_t> key)
    {
        for (int i = 0; i < 256; ++i)
            _S[i] = static_cast<uint8_t>(i);

        int j = 0;
        const std::size_t keyLen = key.size();
        for (int i = 0; i < 256; ++i)
        {
            j = (j + _S[i] + key[i % keyLen]) & 0xFF;
            std::swap(_S[i], _S[j]);
        }

        _i = 0;
        _j = 0;
    }

    /// Discard `count` bytes from the keystream (ARC4-dropN).
    /// WoW Cataclysm requires dropping 1024 bytes after key setup.
    void Drop(std::size_t count)
    {
        for (std::size_t n = 0; n < count; ++n)
        {
            _i = (_i + 1) & 0xFF;
            _j = (_j + _S[_i]) & 0xFF;
            std::swap(_S[_i], _S[_j]);
            // keystream byte consumed but discarded
        }
    }

    /// Encrypt or decrypt data in-place (XOR with the keystream).
    void Process(std::span<uint8_t> data)
    {
        for (uint8_t& byte : data)
        {
            _i = (_i + 1) & 0xFF;
            _j = (_j + _S[_i]) & 0xFF;
            std::swap(_S[_i], _S[_j]);
            byte ^= _S[(_S[_i] + _S[_j]) & 0xFF];
        }
    }

    void Process(uint8_t* data, std::size_t len)
    {
        Process(std::span<uint8_t>(data, len));
    }

private:
    std::array<uint8_t, 256> _S{};
    int _i = 0;
    int _j = 0;
};

} // namespace Fireland::Crypto
