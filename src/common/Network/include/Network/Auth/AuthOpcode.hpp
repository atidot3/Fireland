#pragma once

// ============================================================================
// AuthOpcode — WoW authentication protocol opcodes & structures
// ============================================================================

#include <cstdint>

#include <Utils/ByteBuffer.h>
#include <Utils/Asio/Describe.hpp>

namespace Fireland::Auth
{
    enum class AuthOpcode : uint8_t
    {
        CMD_AUTH_LOGON_CHALLENGE      = 0x00,
        CMD_AUTH_LOGON_PROOF          = 0x01,
        CMD_AUTH_RECONNECT_CHALLENGE  = 0x02,
        CMD_AUTH_RECONNECT_PROOF      = 0x03,
        CMD_REALM_LIST                = 0x10,

        NONE                          = 0x20,
    };
    BOOST_DESCRIBE_ENUM(AuthOpcode,
        CMD_AUTH_LOGON_CHALLENGE,
        CMD_AUTH_LOGON_PROOF,
        CMD_AUTH_RECONNECT_CHALLENGE,
        CMD_AUTH_RECONNECT_PROOF,
        CMD_REALM_LIST,
        NONE);

    // ---- Wire structures (packed, little-endian) -------------------------------

    #pragma pack(push, 1)

    struct AuthLogonChallenge_C
    {
        uint8_t  error;                     // 0x08 for Cataclysm
        uint16_t size;                      // remaining size
        std::array<uint8_t, 4>  gamename;   // "WoW\0"
        uint8_t  version1;                  // 4
        uint8_t  version2;                  // 3
        uint8_t  version3;                  // 4
        uint16_t build;                     // 15595
        std::array<uint8_t, 4>  platform;
        std::array<uint8_t, 4>  os;
        std::array<uint8_t, 4>  locale;
        uint32_t timezone_bias;
        uint32_t ip;
        uint8_t  account_len;
        std::string account_name;

        AuthLogonChallenge_C() = default;
        AuthLogonChallenge_C(Fireland::Utils::ByteBuffer& buffer)
        {
            if (buffer.Size() <= 0)
                throw std::runtime_error("Buffer too small for AuthLogonChallenge_C");
            
            buffer>> error >> size;
            buffer>> gamename;
            buffer>> version1 >> version2 >> version3 >> build;
            buffer>> platform;
            buffer>> os;
            buffer>> locale;
            buffer>> timezone_bias >> ip >> account_len;
            account_name = buffer.ReadString(account_len);
        }
        AuthLogonChallenge_C& operator<<(Fireland::Utils::ByteBuffer& buffer)
        {
            if (buffer.Size() <= 0)
                throw std::runtime_error("Buffer too small for AuthLogonChallenge_C");
            buffer>> error >> size;
            buffer>> gamename;
            buffer>> version1 >> version2 >> version3 >> build;
            buffer>> platform;
            buffer>> os;
            buffer>> locale;
            buffer>> timezone_bias >> ip >> account_len;
            account_name = buffer.ReadString(account_len);
            return *this;
        }
    };

    struct AuthLogonProof_C
    {
        std::array<uint8_t, 32> A;            // client public ephemeral
        std::array<uint8_t, 20> M1;           // client proof
        std::array<uint8_t, 20> crc_hash;     // client CRC hash (unused)
        uint8_t number_of_keys;
        uint8_t security_flags;

        AuthLogonProof_C() = default;
        AuthLogonProof_C(Fireland::Utils::ByteBuffer& buffer)
        {
            if (buffer.Size() <= 0)
                throw std::runtime_error("Buffer too small for AuthLogonProof_C");
            
            buffer>> A >> M1 >> crc_hash;
            buffer>> number_of_keys >> security_flags;
        }
        AuthLogonProof_C& operator<<(Fireland::Utils::ByteBuffer& buffer)
        {        if (buffer.Size() <= 0)
                throw std::runtime_error("Buffer too small for AuthLogonProof_C");
            buffer>> A >> M1 >> crc_hash;
            buffer>> number_of_keys >> security_flags;
            return *this;
        }
    };

    struct AuthReconnectProof_C
    {
        std::array<uint8_t, 16> R1;            // client random
        std::array<uint8_t, 20> R2;            // client proof: SHA1(username, R1, reconnect_rand, K)
        std::array<uint8_t, 20> R3;            // client checksum (unused)
        uint8_t number_of_keys;

        AuthReconnectProof_C() = default;
        AuthReconnectProof_C(Fireland::Utils::ByteBuffer& buffer)
        {
            if (buffer.Size() <= 0)
                throw std::runtime_error("Buffer too small for AuthReconnectProof_C");
            buffer >> R1 >> R2 >> R3;
            buffer>> number_of_keys;
        }
        AuthReconnectProof_C& operator<<(Fireland::Utils::ByteBuffer& buffer)
        {
            if (buffer.Size() <= 0)
                throw std::runtime_error("Buffer too small for AuthReconnectProof_C");
            buffer >> R1 >> R2 >> R3;
            buffer>> number_of_keys;
            return *this;
        }
    };

    #pragma pack(pop)

} // namespace Fireland::Auth
