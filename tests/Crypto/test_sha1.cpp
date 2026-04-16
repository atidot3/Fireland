// ============================================================================
// Tests unitaires Crypto::SHA1
// ============================================================================
#include <boost/test/unit_test.hpp>
#include <Crypto/SHA1.h>

using namespace Fireland::Crypto;

BOOST_AUTO_TEST_CASE(sha1_empty_string_test)
{
    // SHA1 of empty string
    auto digest = SHA1::Hash(std::span<const uint8_t>());
    
    // Expected: DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
    uint8_t expected[] = {
        0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D,
        0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90,
        0xAF, 0xD8, 0x07, 0x09
    };

    for (size_t i = 0; i < SHA1::DIGEST_SIZE; ++i)
        BOOST_TEST(digest[i] == expected[i]);
}

BOOST_AUTO_TEST_CASE(sha1_string_test)
{
    // SHA1 of "abc"
    std::string input = "abc";
    auto digest = SHA1::Hash(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(input.data()), input.size()
    ));

    // Expected: A9993E364706816ABA3E25717850C26C9CD0D89D
    uint8_t expected[] = {
        0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
        0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
        0x9C, 0xD0, 0xD8, 0x9D
    };

    for (size_t i = 0; i < SHA1::DIGEST_SIZE; ++i)
        BOOST_TEST(digest[i] == expected[i]);
}

BOOST_AUTO_TEST_CASE(sha1_long_string_test)
{
    // SHA1 of "The quick brown fox jumps over the lazy dog"
    std::string input = "The quick brown fox jumps over the lazy dog";
    auto digest = SHA1::Hash(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(input.data()), input.size()
    ));

    // Expected: 2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12
    uint8_t expected[] = {
        0x2F, 0xD4, 0xE1, 0xC6, 0x7A, 0x2D, 0x28, 0xFC,
        0xED, 0x84, 0x9E, 0xE1, 0xBB, 0x76, 0xE7, 0x39,
        0x1B, 0x93, 0xEB, 0x12
    };

    for (size_t i = 0; i < SHA1::DIGEST_SIZE; ++i)
        BOOST_TEST(digest[i] == expected[i]);
}

BOOST_AUTO_TEST_CASE(sha1_incremental_test)
{
    // Test incremental Update + Finalize
    SHA1 sha;
    
    std::string part1 = "Hello ";
    std::string part2 = "World!";
    
    sha.Update(part1);
    sha.Update(part2);
    
    auto digest = sha.Finalize();
    
    // Verify digest is valid (non-zero)
    BOOST_TEST(digest.size() == SHA1::DIGEST_SIZE);
    
    // Compute the same thing in one go
    std::string combined = part1 + part2;
    auto digest2 = SHA1::Hash(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(combined.data()), combined.size()
    ));
    
    for (size_t i = 0; i < SHA1::DIGEST_SIZE; ++i)
        BOOST_TEST(digest[i] == digest2[i]);
}

BOOST_AUTO_TEST_CASE(sha1_digest_size_test)
{
    // Verify digest size
    BOOST_TEST(SHA1::DIGEST_SIZE == 20U);
    
    auto digest = SHA1::Hash(std::span<const uint8_t>());
    BOOST_TEST(digest.size() == 20U);
}
