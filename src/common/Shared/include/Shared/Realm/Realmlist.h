#pragma once

#include <string>
#include <cstdint>

#include <Utils/Describe.hpp>

enum realm_type : uint8_t
{
    Normal   = 0,
    PvP      = 1,
    Normal2  = 4,
    RP       = 6,
    RPPvP    = 8,
    FFA_PvP  = 16,
};
BOOST_DESCRIBE_ENUM(realm_type, Normal, PvP, Normal2, RP, RPPvP, FFA_PvP)

enum realm_flag : uint8_t
{
    None             = 0x00,
    VersionMismatch  = 0x01,
    Offline          = 0x02,
    SpecifyBuild     = 0x04,
    Unk1             = 0x08,
    Unk2             = 0x10,
    Recommended      = 0x20,
    NewPlayers       = 0x40,
    Full             = 0x80,
};
BOOST_DESCRIBE_ENUM(realm_flag, None, VersionMismatch, Offline, SpecifyBuild, Unk1, Unk2, Recommended, NewPlayers, Full)

enum realm_timezone : uint8_t
{
    Development    = 1,
    America        = 2,
    Oceanic        = 3,
    LatinAmerica   = 4,
    Tournament     = 5,
    Korea          = 6,
    English        = 8,
    German         = 9,
    French         = 10,
    Spanish        = 11,
    Russian        = 12,
    Taiwan         = 14,
    China          = 16,
};
BOOST_DESCRIBE_ENUM(realm_timezone, Development, America, Oceanic, LatinAmerica, Tournament, Korea, English, German, French, Spanish, Russian, Taiwan, China)

enum realm_security_level : uint8_t
{
    Player = 0,
    GM     = 1,
    Admin  = 2,
};
BOOST_DESCRIBE_ENUM(realm_security_level, Player, GM, Admin)

struct realmlist
{
    uint32_t    id;
    std::string name;
    std::string address;
    uint16_t    port;
    uint8_t     type;
    uint8_t     timezone;
    uint8_t     allowedSecurityLevel;
    float       population;
};
BOOST_DESCRIBE_STRUCT(realmlist, (), (id, name, address, port, type, timezone, allowedSecurityLevel, population))
