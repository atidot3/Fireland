#pragma once

// ============================================================================
// HMAC-SHA1 — RFC 2104 keyed-hash message authentication code
//
// Implemented on top of Fireland::Crypto::SHA1 (Boost-based); no external
// crypto library required.
// ============================================================================

#include <array>
#include <cstdint>
#include <span>

#include "SHA1.h"

namespace Fireland::Crypto {

/// Compute HMAC-SHA1(key, data).
/// Both key and data are arbitrary byte spans.
inline SHA1::Digest HMAC_SHA1(std::span<const uint8_t> key,
                               std::span<const uint8_t> data)
{
    static constexpr std::size_t BLOCK = 64; // SHA1 block size in bytes

    // If key is longer than the block size, hash it first (RFC 2104 §3)
    std::array<uint8_t, BLOCK> k{};
    if (key.size() > BLOCK)
    {
        SHA1::Digest hashed = SHA1::Hash(key);
        std::copy(hashed.begin(), hashed.end(), k.begin());
    }
    else
    {
        std::copy(key.begin(), key.end(), k.begin());
    }

    // Build ipad (0x36) and opad (0x5C) keys
    std::array<uint8_t, BLOCK> ipad{};
    std::array<uint8_t, BLOCK> opad{};
    for (std::size_t i = 0; i < BLOCK; ++i)
    {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    // inner = SHA1(ipad || data)
    SHA1 inner;
    inner.Update(std::span<const uint8_t>(ipad));
    inner.Update(data);
    SHA1::Digest innerHash = inner.Finalize();

    // outer = SHA1(opad || inner)
    SHA1 outer;
    outer.Update(std::span<const uint8_t>(opad));
    outer.Update(std::span<const uint8_t>(innerHash));
    return outer.Finalize();
}

} // namespace Fireland::Crypto
