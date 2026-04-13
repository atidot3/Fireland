#pragma once

// ============================================================================
// WorldOpcode — Cataclysm 4.3.4 (build 15595) world server opcodes
//
// Only the authentication handshake opcodes are defined here.
// TODO: Complete opcode table for Cata 4.3.4
// ============================================================================

#include <cstdint>

#include <Utils/Describe.hpp>

namespace Fireland::World {

// Server → Client opcodes (2-byte opcode in header)
constexpr uint16_t SMSG_AUTH_CHALLENGE = 0x4542;
constexpr uint16_t SMSG_AUTH_RESPONSE  = 0x0EC4;

// Client → Server opcodes (4-byte opcode in header)
constexpr uint32_t CMSG_AUTH_SESSION = 0x04CF;

// Expansion constant
constexpr uint8_t EXPANSION_CATACLYSM = 3;

// Cataclysm expected build number
constexpr uint16_t EXPECTED_BUILD = 15595;

// ---- Auth response result codes (used in SMSG_AUTH_RESPONSE) ---------------

enum class AuthResponseResult : uint8_t
{
    AUTH_OK                  = 0x0C,
    AUTH_FAILED              = 0x01,
    AUTH_REJECT              = 0x0E,
    AUTH_BAD_SERVER_PROOF    = 0x02,
    AUTH_UNAVAILABLE         = 0x03,
    AUTH_SYSTEM_ERROR        = 0x04,
    AUTH_BILLING_ERROR       = 0x05,
    AUTH_BILLING_EXPIRED     = 0x06,
    AUTH_VERSION_MISMATCH    = 0x07,
    AUTH_UNKNOWN_ACCOUNT     = 0x08,
    AUTH_INCORRECT_PASSWORD  = 0x09,
    AUTH_SESSION_EXPIRED     = 0x0A,
    AUTH_SERVER_SHUTTING_DOWN = 0x0B,
    AUTH_WAIT_QUEUE          = 0x1B,
};
BOOST_DESCRIBE_ENUM(AuthResponseResult,
    AUTH_OK,
    AUTH_FAILED,
    AUTH_REJECT,
    AUTH_BAD_SERVER_PROOF,
    AUTH_UNAVAILABLE,
    AUTH_SYSTEM_ERROR,
    AUTH_BILLING_ERROR,
    AUTH_BILLING_EXPIRED,
    AUTH_VERSION_MISMATCH,
    AUTH_UNKNOWN_ACCOUNT,
    AUTH_INCORRECT_PASSWORD,
    AUTH_SESSION_EXPIRED,
    AUTH_SERVER_SHUTTING_DOWN,
    AUTH_WAIT_QUEUE);

// ---- Cata digest byte order in CMSG_AUTH_SESSION ---------------------------
// The WoW 4.3.4 client sends the 20-byte SHA1 digest in shuffled order.

constexpr uint8_t DIGEST_ORDER[20] = {
    18, 14, 3, 4, 0, 9, 12, 10, 7, 13, 5, 6, 17, 8, 19, 1, 16, 11, 2, 15
};

} // namespace Fireland::World
