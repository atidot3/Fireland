#pragma once

// ============================================================================
// AuthOpcode — WoW authentication protocol opcodes & structures
// ============================================================================

#include <cstdint>

#include <Utils/Describe.hpp>

namespace Fireland::Auth {

enum class AuthOpcode : uint8_t
{
    CMD_AUTH_LOGON_CHALLENGE  = 0x00,
    CMD_AUTH_LOGON_PROOF      = 0x01,
    CMD_REALM_LIST            = 0x10,
};
BOOST_DESCRIBE_ENUM(AuthOpcode,
    CMD_AUTH_LOGON_CHALLENGE,
    CMD_AUTH_LOGON_PROOF,
    CMD_REALM_LIST);

enum class AuthResult : uint8_t
{
    SUCCESS                   = 0x00,
    FAIL_UNKNOWN_ACCOUNT      = 0x04,
    FAIL_INCORRECT_PASSWORD   = 0x05,
    FAIL_BANNED               = 0x03,
    FAIL_SUSPENDED            = 0x0C,
    FAIL_VERSION_INVALID      = 0x09,
};
BOOST_DESCRIBE_ENUM(AuthResult,
    SUCCESS,
    FAIL_UNKNOWN_ACCOUNT,
    FAIL_INCORRECT_PASSWORD,
    FAIL_BANNED,
    FAIL_SUSPENDED,
    FAIL_VERSION_INVALID);

// ---- Wire structures (packed, little-endian) -------------------------------

#pragma pack(push, 1)

struct AuthLogonChallenge_C
{
    uint8_t  cmd;              // 0x00
    uint8_t  error;            // 0x08 for Cataclysm
    uint16_t size;             // remaining size
    uint8_t  gamename[4];      // "WoW\0"
    uint8_t  version1;         // 4
    uint8_t  version2;         // 3
    uint8_t  version3;         // 4
    uint16_t build;            // 15595
    uint8_t  platform[4];
    uint8_t  os[4];
    uint8_t  locale[4];
    uint32_t timezone_bias;
    uint32_t ip;
    uint8_t  account_len;
    //uint8_t  I[1];
};

struct AuthLogonProof_C
{
    uint8_t cmd;               // 0x01
    uint8_t A[32];             // client public ephemeral
    uint8_t M1[20];            // client proof
    uint8_t crc_hash[20];
    uint8_t number_of_keys;
    uint8_t security_flags;
};

#pragma pack(pop)

} // namespace Fireland::Auth
