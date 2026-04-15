#include "SRP6.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace Fireland::Crypto {

// WoW's 256-bit safe prime (little-endian)
static constexpr uint8_t N_BYTES[] = {
    0xB7, 0x9B, 0x3E, 0x2A, 0x87, 0x82, 0x3C, 0xAB,
    0x8F, 0x5E, 0xBF, 0xBF, 0x8E, 0xB1, 0x01, 0x08,
    0x53, 0x50, 0x06, 0x29, 0x8B, 0x5B, 0xAD, 0xBD,
    0x5B, 0x53, 0xE1, 0x89, 0x5E, 0x64, 0x4B, 0x89,
};

static BigNumber MakeN()
{
    BigNumber n;
    n.SetBinary(N_BYTES);
    return n;
}

const BigNumber SRP6::N = MakeN();
const BigNumber SRP6::g = BigNumber(7);

static std::string ToUpper(std::string_view sv)
{
    std::string result(sv);
    for (auto& c : result)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return result;
}

void SRP6::ComputeVerifier(std::string_view username, std::string_view password)
{
    _username = ToUpper(username);
    _salt.SetRandom(32);

    // x = SHA1(salt | SHA1(UPPER(username) : UPPER(password)))
    std::string authString = _username + ":" + ToUpper(password);
    auto innerHash = SHA1::Hash(authString);

    auto saltBytes = _salt.AsByteArray(32);
    SHA1 sha;
    sha.Update(std::span<const uint8_t>(saltBytes));
    sha.Update(std::span<const uint8_t>(innerHash));
    auto xDigest = sha.Finalize();

    BigNumber x;
    x.SetBinary(xDigest);

    // v = g^x mod N
    _verifier = g.ModExp(x, N);
}

void SRP6::SetVerifier(std::string_view username,
                       const BigNumber& salt, const BigNumber& verifier)
{
    _username = ToUpper(username);
    _salt     = salt;
    _verifier = verifier;
}

void SRP6::GenerateChallenge()
{
    // b = random 19 bytes (server secret ephemeral)
    _b.SetRandom(19);

    // B = (3*v + g^b mod N) % N
    auto gmod = g.ModExp(_b, N);
    _B = (_verifier * BigNumber(3) + gmod) % N;
}

bool SRP6::VerifyClientProof(const BigNumber& A, const SHA1::Digest& clientM1)
{
    // Reject A == 0 (security check)
    if (A.IsZero())
        return false;

    auto A_bytes = A.AsByteArray(32);
    auto B_bytes = _B.AsByteArray(32);

    // u = SHA1(A | B)
    SHA1 uHash;
    uHash.Update(std::span<const uint8_t>(A_bytes));
    uHash.Update(std::span<const uint8_t>(B_bytes));
    auto uDigest = uHash.Finalize();

    BigNumber u;
    u.SetBinary(uDigest);
    if (u.IsZero())
        return false;

    // S = (A * v^u mod N)^b mod N
    auto S = (A * _verifier.ModExp(u, N)).ModExp(_b, N);

    // K = interleaved session key (40 bytes)
    _K = InterleaveHash(S);

    // --- Verify M1 ---
    auto N_bytes    = N.AsByteArray(32);
    auto g_bytes    = g.AsByteArray(1);
    auto salt_bytes = _salt.AsByteArray(32);

    // t3 = SHA1(N) XOR SHA1(g)
    auto nHash = SHA1::Hash(std::span<const uint8_t>(N_bytes));
    auto gHash = SHA1::Hash(std::span<const uint8_t>(g_bytes));
    SHA1::Digest t3{};
    for (std::size_t i = 0; i < SHA1::DIGEST_SIZE; ++i)
        t3[i] = nHash[i] ^ gHash[i];

    auto usernameHash = SHA1::Hash(_username);

    // M1_expected = SHA1(t3 | H(username) | salt | A | B | K)
    SHA1 m1Hash;
    m1Hash.Update(std::span<const uint8_t>(t3));
    m1Hash.Update(std::span<const uint8_t>(usernameHash));
    m1Hash.Update(std::span<const uint8_t>(salt_bytes));
    m1Hash.Update(std::span<const uint8_t>(A_bytes));
    m1Hash.Update(std::span<const uint8_t>(B_bytes));
    m1Hash.Update(std::span<const uint8_t>(_K));
    auto M1_expected = m1Hash.Finalize();

    if (M1_expected != clientM1)
        return false;

    // M2 = SHA1(A | M1 | K)
    SHA1 m2Hash;
    m2Hash.Update(std::span<const uint8_t>(A_bytes));
    m2Hash.Update(std::span<const uint8_t>(clientM1));
    m2Hash.Update(std::span<const uint8_t>(_K));
    _M2 = m2Hash.Finalize();

    return true;
}

std::array<uint8_t, 40> SRP6::InterleaveHash(const BigNumber& S)
{
    auto S_bytes = S.AsByteArray(32);

    // Skip leading zero bytes, keep even count
    std::size_t p = 0;
    while (p < S_bytes.size() && S_bytes[p] == 0)
        ++p;
    if ((S_bytes.size() - p) % 2 != 0)
        ++p;

    std::size_t remaining = S_bytes.size() - p;
    std::size_t half = remaining / 2;

    // Split into even and odd indexed bytes
    std::vector<uint8_t> part1(half), part2(half);
    for (std::size_t i = 0; i < half; ++i)
    {
        part1[i] = S_bytes[p + i * 2];
        part2[i] = S_bytes[p + i * 2 + 1];
    }

    auto hash1 = SHA1::Hash(std::span<const uint8_t>(part1));
    auto hash2 = SHA1::Hash(std::span<const uint8_t>(part2));

    // Interleave the two SHA1 results
    std::array<uint8_t, 40> K{};
    for (std::size_t i = 0; i < 20; ++i)
    {
        K[i * 2]     = hash1[i];
        K[i * 2 + 1] = hash2[i];
    }
    return K;
}

} // namespace Fireland::Crypto
