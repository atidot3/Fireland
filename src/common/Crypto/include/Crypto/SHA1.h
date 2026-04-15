#pragma once

// ============================================================================
// SHA1 — Thin wrapper around boost::uuids::detail::sha1
// ============================================================================

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <boost/uuid/detail/sha1.hpp>

namespace Fireland::Crypto {

    class SHA1
    {
    public:
        static constexpr std::size_t DIGEST_SIZE = 20;
        using Digest = std::array<uint8_t, DIGEST_SIZE>;

        SHA1() = default;
        SHA1(const SHA1&) = delete;
        SHA1& operator=(const SHA1&) = delete;
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
            std::memcpy(result.data(), raw, DIGEST_SIZE);
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
