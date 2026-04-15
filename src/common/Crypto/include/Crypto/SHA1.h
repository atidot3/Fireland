#pragma once

// ============================================================================
// SHA1 — Thin wrapper around boost::uuids::detail::sha1
// ============================================================================

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <iostream>
#include <boost/uuid/detail/sha1.hpp>

namespace Fireland::Crypto {

class SHA1
{
public:
    static constexpr std::size_t DIGEST_SIZE = 20;
    using Digest = std::array<uint8_t, DIGEST_SIZE>;

    void Update(std::span<const uint8_t> data)
    {
        _ctx.process_bytes(data.data(), data.size());
    }

    void Update(std::string_view str)
    {
        _ctx.process_bytes(str.data(), str.size());
    }

    Digest Finalize()
    {
        boost::uuids::detail::sha1::digest_type raw;
        _ctx.get_digest(raw);

        Digest result{};

        for (int i = 0; i < 5; ++i)
        {
            uint32_t v = raw[i];

            // 🔥 FIX ENDIAN BOOST SHA1 (CRUCIAL)
            v =
                ((v & 0x000000FF) << 24) |
                ((v & 0x0000FF00) << 8)  |
                ((v & 0x00FF0000) >> 8)  |
                ((v & 0xFF000000) >> 24);

            result[i * 4 + 0] = (v >> 24) & 0xFF;
            result[i * 4 + 1] = (v >> 16) & 0xFF;
            result[i * 4 + 2] = (v >> 8)  & 0xFF;
            result[i * 4 + 3] = (v >> 0)  & 0xFF;
        }

        return result;
    }

    static Digest Hash(std::span<const uint8_t> data)
    {
        SHA1 sha;
        sha.Update(data);
        return sha.Finalize();
    }

    static Digest Hash(std::string_view str)
    {
        SHA1 sha;
        sha.Update(str);
        return sha.Finalize();
    }

private:
    boost::uuids::detail::sha1 _ctx;
};

} // namespace Fireland::Crypto
