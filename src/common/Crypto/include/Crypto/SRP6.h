#pragma once

// ============================================================================
// SRP6 — Secure Remote Password protocol (WoW variant)
//
// Implements the server side of WoW's SRP6-based authentication.
// Reference: http://srp.stanford.edu/design.html (WoW uses k=3, SHA1)
// ============================================================================

#include <array>
#include <string_view>

#include <Crypto/BigNumber.h>
#include <Crypto/SHA1.h>

namespace Firelands::Crypto {

class SRP6
{
public:
    static const BigNumber N;   // Safe prime (256-bit)
    static const BigNumber g;   // Generator (7)

    /// Compute salt + verifier from plaintext credentials.
    /// In production this would be stored in the database.
    void ComputeVerifier(std::string_view username, std::string_view password);

    /// Use a pre-existing salt and verifier (e.g. loaded from DB).
    void SetVerifier(std::string_view username,
                     const BigNumber& salt, const BigNumber& verifier);

    /// Generate the server challenge (B, salt) for this login attempt.
    void GenerateChallenge();

    /// Verify the client's proof.  Returns true on success.
    bool VerifyClientProof(const BigNumber& A, const SHA1::Digest& clientM1);

    // --- Accessors (valid after GenerateChallenge) --------------------------
    const BigNumber& GetB()    const { return _B; }
    const BigNumber& GetSalt() const { return _salt; }
    const BigNumber& GetVerifier() const { return _verifier; }

    // --- Accessors (valid after VerifyClientProof succeeds) -----------------
    const SHA1::Digest&            GetServerProof() const { return _M2; }
    const std::array<uint8_t, 40>& GetSessionKey()  const { return _K; }

private:
    static std::array<uint8_t, 40> InterleaveHash(const BigNumber& S);

    std::string _username;
    BigNumber   _salt;
    BigNumber   _verifier;

    BigNumber   _b;     // server secret ephemeral
    BigNumber   _B;     // server public ephemeral

    SHA1::Digest            _M2{};
    std::array<uint8_t, 40> _K{};
};

} // namespace Firelands::Crypto
