#include "WorldSession.h"

#include <cctype>
#include <cstring>
#include <format>
#include <random>
#include <stdexcept>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include <Utils/ByteBuffer.h>
#include <Utils/Log.h>
#include <Utils/StringUtils.h>

#include <Database/Auth/AuthWrapper.h>

using namespace Fireland::World;
using namespace Fireland::Utils;
using namespace Fireland::Utils::Async;
using ByteBuffer = Fireland::Utils::ByteBuffer;

// ---- Construction ----------------------------------------------------------

WorldSession::WorldSession(boost::asio::ip::tcp::socket socket) noexcept
    : _socket(std::move(socket))
    , _remoteAddress{"<unknown>"}
    , _username{}
    , _accountId{0}
    , _serverSeed{0}
    , _authenticated{false}
{
    boost::system::error_code ec;
    auto ep = _socket.remote_endpoint(ec);
    _remoteAddress = ec ? "<unknown>"
                        : std::format("{}:{}", ep.address().to_string(), ep.port());
}

WorldSession::~WorldSession() noexcept
{
    FL_LOG_INFO("WorldSession", "[{}] Client disconnected", _remoteAddress);
}

// ---- Main coroutine --------------------------------------------------------

void WorldSession::Start()
{
    auto self = shared_from_this();
    boost::asio::co_spawn(_socket.get_executor(), self->Run(), boost::asio::detached);
}

async<void> WorldSession::Run()
{
    auto self = shared_from_this();
    FL_LOG_INFO("WorldSession", "[{}] Client connected", _remoteAddress);

    try
    {
        co_await SendConnectionInit();
        co_await ReadConnectionInit();
        co_await SendAuthChallenge();
        co_await HandleAuthSession();

        if (_authenticated)
            co_await PacketLoop();
    }
    catch (const boost::system::system_error& e)
    {
        if (e.code() != boost::asio::error::eof &&
            e.code() != boost::asio::error::operation_aborted &&
            e.code() != boost::asio::error::connection_reset)
        {
            FL_LOG_ERROR("WorldSession", "[{}] Error: {}", _remoteAddress, e.what());
        }
    }

    FL_LOG_INFO("WorldSession", "[{}] Disconnected", _remoteAddress);
}

// ---- Connection initialization (Cata 4.3.4) --------------------------------

async<void> WorldSession::SendConnectionInit()
{
    // Non-standard frame: [uint16_be size][string] -- no opcode field.
    auto len = static_cast<uint16_t>(SERVER_CONNECTION_INIT.size());

    ByteBuffer packet(2 + len);
    packet << static_cast<uint8_t>(len >> 8)
           << static_cast<uint8_t>(len & 0xFF);
    packet.Append(SERVER_CONNECTION_INIT.data(), SERVER_CONNECTION_INIT.size());

    FL_LOG_DEBUG("WorldSession", "[{}] Sending connection init ({} bytes)",
        _remoteAddress, packet.Size());

    co_await boost::asio::async_write(_socket, boost::asio::buffer(packet.Storage()), boost::asio::use_awaitable);
}

async<void> WorldSession::ReadConnectionInit()
{
    std::array<uint8_t, 2> sizeBuf{};
    co_await boost::asio::async_read(_socket, boost::asio::buffer(sizeBuf), boost::asio::use_awaitable);

    uint16_t size = (uint16_t{sizeBuf[0]} << 8) | sizeBuf[1];

    std::vector<uint8_t> payload(size);
    co_await boost::asio::async_read(_socket, boost::asio::buffer(payload), boost::asio::use_awaitable);

    auto compareLen = std::min(static_cast<std::size_t>(size), CLIENT_CONNECTION_INIT.size());
    std::string_view initStr(reinterpret_cast<const char*>(payload.data()), compareLen);

    if (initStr != CLIENT_CONNECTION_INIT)
    {
        FL_LOG_ERROR("WorldSession", "[{}] Invalid connection init: '{}'", _remoteAddress, initStr);
        _socket.close();
        co_return;
    }

    FL_LOG_DEBUG("WorldSession", "[{}] Connection init handshake completed", _remoteAddress);
}

// ---- SMSG_AUTH_CHALLENGE ----------------------------------------------------

async<void> WorldSession::SendAuthChallenge()
{
    // Payload layout (37 bytes):
    //   uint8[16]  encryptSeed   — DosChallenge bytes  0-15 (random)
    //   uint8[16]  decryptSeed   — DosChallenge bytes 16-31 (random)
    //   uint32     serverSeed    — used by client to compute CMSG_AUTH_SESSION digest
    //   uint8      DosZeroBits   — leading-zero PoW requirement (1 = minimal)

    WorldPacket packet(SMSG_AUTH_CHALLENGE, 37);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis(0, 0xFF);
    _serverSeed = dis(gen);
    for (int i = 0; i < 32; ++i)
        packet << static_cast<uint8_t>(dis(gen));

    packet << _serverSeed << uint8_t(1);

    FL_LOG_DEBUG("WorldSession", "[{}] Sending SMSG_AUTH_CHALLENGE (seed=0x{:08X})", _remoteAddress, _serverSeed);

    co_await SendPacket(packet);
}

// ---- CMSG_AUTH_SESSION ------------------------------------------------------

async<void> WorldSession::HandleAuthSession()
{
    auto packet = co_await ReadClientPacket();

    FL_LOG_DEBUG("WorldSession", "[{}] Received {} (payload={} bytes)", _remoteAddress, packet.opcodeName(), packet.Size());
    FL_LOG_DEBUG("WorldSession", "[{}] Raw payload: {}", _remoteAddress, StringUtils::HexStr(packet.Data()));

    if (!packet.is(CMSG_AUTH_SESSION))
    {
        FL_LOG_WARNING("WorldSession", "[{}] Expected CMSG_AUTH_SESSION (0x{:04X}), got {}", _remoteAddress, static_cast<uint32_t>(CMSG_AUTH_SESSION), packet.opcodeName());
        co_return;
    }

    // ---- Cata 4.3.4 CMSG_AUTH_SESSION — scattered / interleaved format ------
    // Digest bytes are NOT sent contiguously: they are shuffled in between
    // other fixed-size fields.  Layout (verified against build 15595 capture):
    //
    //   [0-3]   uint32  ServerId      (skip — GRUNT protocol only)
    //   [4-7]   uint32  Battlegroup   (skip)
    //   [8]     uint8   LoginServerType
    //   [9-35]  scattered block A: digest[10,18,12,5] dosResponse(8)
    //                              digest[15,9,19,4,7,16,3] build(2) digest[8] realmId(4) buildType(1)
    //   [36-51] scattered block B: digest[17,6,0,1,11] localChallenge(4)
    //                              digest[2] region(4,skip) digest[14,13]
    //   [52-55] uint32  addonSize
    //   [56..]  addonSize bytes  zlib-compressed addon list
    //   [..]    bit section: useIPv6(1 bit) nameLen(12 bits)
    //   [..]    account name (nameLen bytes, no null terminator)

    std::array<uint8_t, 20> digest{};
    uint16_t build{};
    uint32_t realmId{}, localChallenge{};

    // Fluent scattered reader — mirrors the wire layout line by line.
    // .skip(n)  — advance n bytes without storing
    // .dg(i)    — read one digest byte into digest[i]
    // .read(v)  — read sizeof(v) bytes into v
    struct ScatteredReader {
        WorldPacket& pkt;
        std::array<uint8_t, 20>& digest;
        ScatteredReader& skip(std::size_t n)  { pkt.Skip(n);                           return *this; }
        ScatteredReader& dg(uint8_t i)        { digest[i] = pkt.Read<uint8_t>();       return *this; }
        ScatteredReader& read(uint16_t& v)    { v = pkt.Read<uint16_t>();              return *this; }
        ScatteredReader& read(uint32_t& v)    { v = pkt.Read<uint32_t>();              return *this; }
    } sr{packet, digest};

    sr.skip(9)                                              // ServerId + Battlegroup + LoginServerType
      .dg(10).dg(18).dg(12).dg(5)
      .skip(8)                                              // dosResponse (uint64)
      .dg(15).dg(9).dg(19).dg(4).dg(7).dg(16).dg(3)
      .read(build).dg(8).read(realmId).skip(1)             // build, digest[8], realmId, buildType
      .dg(17).dg(6).dg(0).dg(1).dg(11)
      .read(localChallenge).dg(2).skip(4)                  // localChallenge, digest[2], region(skip)
      .dg(14).dg(13);

    // Addon data block
    uint32_t addonSize = packet.Read<uint32_t>();
    constexpr uint32_t MAX_ADDON_SIZE = 0xFFFFF; // 1 MB sanity cap
    if (addonSize > MAX_ADDON_SIZE)
    {
        FL_LOG_WARNING("WorldSession", "[{}] CMSG_AUTH_SESSION: addon size too large ({})", _remoteAddress, addonSize);
        co_return;
    }
    packet.Skip(addonSize);

    // Bit section — bits read MSB-first within each byte:
    //   bit 0       → useIPv6
    //   bits 1..12  → nameLen (12 bits, MSB first)
    bool     useIPv6 = packet.ReadBit();
    uint32_t nameLen = packet.ReadBits(12);
    packet.FlushBits();   // align to next byte boundary

    // Account name: nameLen bytes, no null terminator
    std::string account = packet.ReadString(nameLen);
    _username = StringUtils::ToUpper(account);

    FL_LOG_INFO("WorldSession", "[{}] Auth session for '{}' (build={}, realm={}, useIPv6={})", _remoteAddress, _username, build, realmId, useIPv6);
    FL_LOG_DEBUG("WorldSession", "[{}] localChallenge: 0x{:08X}", _remoteAddress, localChallenge);
    FL_LOG_DEBUG("WorldSession", "[{}] Client digest: {}", _remoteAddress, StringUtils::HexStr(std::span<const uint8_t>(digest)));

    // Find in DB: look up the session key for this account, which should have been stored by the authserver.
    auto accountOpt = co_await sAuthDB.GetAccountByUsername(_username);
    if (!accountOpt)    {
        FL_LOG_WARNING("WorldSession", "[{}] No account found for '{}'", _remoteAddress, _username);
        co_await SendAuthResponse(ResponseCodes::AUTH_UNKNOWN_ACCOUNT);
        co_return;
    }
    auto K = co_await sAuthDB.LookupSessionKey(accountOpt->id);
    if (!K || K->size() != 40)
    {
        FL_LOG_WARNING("WorldSession", "[{}] No session key for '{}' — ensure authserver stored the key", _remoteAddress, _username);
        co_await SendAuthResponse(ResponseCodes::AUTH_UNKNOWN_ACCOUNT);
        co_return;
    }

    // Verify: SHA1(account || t[4] || localChallenge[4] || serverSeed[4] || K)
    // `t` is always zero — it was the client timestamp field, since deprecated.
    Crypto::SHA1 sha;
    const uint32_t t = 0;
    sha.Update(std::string_view(_username));
    sha.Update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&t), 4));
    sha.Update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&localChallenge), 4));
    sha.Update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&_serverSeed), 4));
    sha.Update(std::span<const uint8_t>(*K));

    auto expected = sha.Finalize();
    FL_LOG_DEBUG("WorldSession", "[{}] Expected digest: {}", _remoteAddress, StringUtils::HexStr(std::span<const uint8_t>(expected)));

    if (digest != expected)
    {
        FL_LOG_WARNING("WorldSession", "[{}] Auth digest mismatch for '{}'", _remoteAddress, _username);
        co_await SendAuthResponse(ResponseCodes::AUTH_INCORRECT_PASSWORD);
        co_return;
    }

    FL_LOG_INFO("WorldSession", "[{}] '{}' authenticated successfully", _remoteAddress, _username);
    _authenticated = true;
    _accountId = accountOpt->id;

    // Init ARC4 with the per-session seeds sent in SMSG_AUTH_CHALLENGE.
    _crypt.Init(std::span<const uint8_t>(*K));
    FL_LOG_DEBUG("WorldSession", "[{}] ARC4 encryption initialised", _remoteAddress);

    // 5. Send Authentication Handshake Sequence for 4.3.4 (15595)
    // Precise order and content in 4.3.4 is critical for the client to proceed to
    // Character Enum.
    co_await SendAuthResponse(ResponseCodes::AUTH_OK);
    /*co_await SendAddonInfo();
    co_await SendClientCacheVersion();
    co_await SendTutorialFlags();
    co_await SendAccountRestrictedUpdate();
    co_await SendRealmSplit(realmId);
    co_await SendSetTimeZoneInformation();
    co_await SendFeatureSystemStatus();
    co_await SendMotd();
    co_await SendLearnedDanceMoves();
    co_await SendInitialRaidGroupError();
    co_await SendSetDfFastLaunchResources();*/

    // Note: SMSG_ACCOUNT_DATA_TIMES, SMSG_REALM_SPLIT, and
    // SMSG_FEATURE_SYSTEM_STATUS are now sent reactively when the client requests
    // them (via CMSG_READY_FOR_ACCOUNT_DATA_TIMES, etc.) Sending them proactively
    // here can cause some 15595 clients to hang.
}

async<void> WorldSession::SendAuthResponse(ResponseCodes result)
{
    WorldPacket response(SMSG_AUTH_RESPONSE);

    // Cata 4.3.4 (15595) SMSG_AUTH_RESPONSE bit-packed format (mirrors TC AuthResponse::Write):
    //   bit 0: hasWaitInfo
    //   [bit 1: HasFCM — only present when hasWaitInfo]
    //   bit N: hasSuccessInfo
    //   FlushBits()
    //   [SuccessInfo fields — only present when hasSuccessInfo]
    //   uint8 Result
    //   [uint32 WaitCount — only present when hasWaitInfo]
    bool hasSuccessInfo = (result == ResponseCodes::AUTH_OK);
    bool hasWaitInfo    = false; // queue not implemented

    response.WriteBit(hasWaitInfo);
    response.WriteBit(hasSuccessInfo);
    response.FlushBits();

    if (hasSuccessInfo)
    {
        // Field order must match TC: TimeRemain, ActiveExpansionLevel,
        // TimeSecondsUntilPCKick, AccountExpansionLevel, TimeRested, TimeOptions
        response << uint32_t(0); // TimeRemain
        response << uint8_t(EXPANSION_CATACLYSM);  // ActiveExpansionLevel (Cataclysm = 3 if needed)
        response << uint32_t(0); // TimeSecondsUntilPCKick
        response << uint8_t(EXPANSION_CATACLYSM);  // AccountExpansionLevel
        response << uint32_t(0); // TimeRested
        response << uint8_t(0);  // TimeOptions
    }

    response << result;

    FL_LOG_DEBUG("WorldSession", "[{}] Sending SMSG_AUTH_RESPONSE (result=0x{:02X})", _remoteAddress, static_cast<uint8_t>(result));
    FL_LOG_DEBUG("WorldSession", "[{}] AUTH_RESPONSE RAW: {}", _remoteAddress, Fireland::Utils::StringUtils::HexStr(response.Data()));

    co_await SendPacket(response);
}

async<void> WorldSession::SendAddonInfo()
{
    WorldPacket response(SMSG_ADDON_INFO);

    // No secure addon info entries (zero addons sent by client or all known-good).
    // Followed by uint32 banned-addon count = 0.
    response << uint32_t(0); // bannedAddonCount

    co_await SendPacket(response);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_ADDON_INFO sent", _remoteAddress);
}

async<void> WorldSession::SendClientCacheVersion()
{
    WorldPacket cacheVer(SMSG_CLIENTCACHE_VERSION);
    cacheVer << uint32_t(0); // version (uint32)
    co_await SendPacket(cacheVer);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_CLIENTCACHE_VERSION sent", _remoteAddress);
}

async<void> WorldSession::SendTutorialFlags()
{
    WorldPacket tutorials(SMSG_TUTORIAL_FLAGS);
    for (int i = 0; i < 8; ++i)
        tutorials << uint32_t(0xFFFFFFFF);
    co_await SendPacket(tutorials);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_TUTORIAL_FLAGS sent", _remoteAddress);
}

async<void> WorldSession::SendAccountRestrictedUpdate()
{
    WorldPacket data(SMSG_ACCOUNT_RESTRICTED_UPDATE);
    
    data.WriteBit(false); // isRestricted
    data.FlushBits();
    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_ACCOUNT_RESTRICTED_UPDATE sent", _remoteAddress);
}

async<void> WorldSession::SendSetDfFastLaunchResources()
{
    WorldPacket data(SMSG_SET_DF_FAST_LAUNCH_RESOURCES);
    
    data.WriteBits(0, 32); // Count (32 bits for bits count?)
    data.FlushBits();
    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_SET_DF_FAST_LAUNCH_RESOURCES sent", _remoteAddress);
}

async<void> WorldSession::SendInitialRaidGroupError()
{
    WorldPacket data(SMSG_INITIAL_RAID_GROUP_ERROR);
    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_INITIAL_RAID_GROUP_ERROR sent", _remoteAddress);
}

async<void> WorldSession::SendAccountDataTimes()
{
    WorldPacket data(SMSG_ACCOUNT_DATA_TIMES);
    data << static_cast<uint32_t>(std::time(nullptr)); // ServerTime
    data << uint8_t(1);                                // Unk
    data << uint32_t(0);                               // Mask (0 means no per-type times)
    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_ACCOUNT_DATA_TIMES sent", _remoteAddress);
}

async<void> WorldSession::SendFeatureSystemStatus()
{
    WorldPacket features(SMSG_FEATURE_SYSTEM_STATUS);

    // Cata 4.3.4 (15595) fields
    features << uint8_t(0);  // ScrollOfResurrectionDailyLimit
    features << uint8_t(0);  // ScrollOfResurrectionDailyLimitTotal
    features << uint32_t(0); // ScrollOfResurrectionMaxLevel

    features.WriteBit(false); // QuestHotfixesEnabled
    features.WriteBit(false); // EuropaEnabled
    features.WriteBit(false); // EquipmentManagerEnabled
    features.WriteBit(false); // CanPurchaseLevel
    features.WriteBit(false); // VoiceChatEnabled
    features.WriteBit(false); // ScrollOfResurrectionEnabled
    features.WriteBit(false); // ComplaintEnabled
    features.WriteBit(false); // SessionTimerEnabled
    features.WriteBit(false); // KioskModeEnabled
    features.FlushBits();
    co_await SendPacket(features);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_FEATURE_SYSTEM_STATUS sent (4.3.4 format)", _remoteAddress);
}

async<void> WorldSession::SendRealmSplit(uint32_t realmId)
{
    WorldPacket split(SMSG_REALM_SPLIT);
    std::string splitDate = "01/01/01";

    split << uint32_t(realmId); // Realm ID
    split << uint32_t(0);       // State (0 = Normal)

    split.WriteBits(static_cast<uint32_t>(splitDate.size()), 7);
    split.FlushBits();
    split.Append(splitDate.data(), splitDate.size());

    co_await SendPacket(split);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_REALM_SPLIT sent (Bit-packed 4.3.4)", _remoteAddress);
}

async<void> WorldSession::SendSetTimeZoneInformation()
{
    WorldPacket data(SMSG_SET_TIME_ZONE_INFORMATION);
    std::string serverTz = "UTC";
    std::string localTz = "UTC";

    data.WriteBits(static_cast<uint32_t>(serverTz.length()), 7);
    data.WriteBits(static_cast<uint32_t>(localTz.length()), 7);
    data.FlushBits();

    data.Append(serverTz.data(), serverTz.size());
    data.Append(localTz.data(), localTz.size());

    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_SET_TIME_ZONE_INFORMATION sent (Bit-packed 4.3.4)", _remoteAddress);
}

async<void> WorldSession::SendLearnedDanceMoves()
{
    WorldPacket data(SMSG_LEARNED_DANCE_MOVES);

    data.WriteBits(0, 23); // Count (23 bits in Cata 4.3.4)
    data.FlushBits();
    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_LEARNED_DANCE_MOVES sent (0 moves, bit-packed)", _remoteAddress);
}

async<void> WorldSession::SendMotd()
{
    WorldPacket motd(SMSG_MOTD);
    std::vector<std::string> lines = {"Bo0p !"};

    motd.WriteBits(static_cast<uint32_t>(lines.size()), 4);
    for (auto const &line : lines)
        motd.WriteBits(static_cast<uint32_t>(line.length()), 11);
    
    motd.FlushBits();

    for (auto const &line : lines)
        motd.Append(line.data(), line.size());

    co_await SendPacket(motd);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_MOTD sent (4.3.4 15595 Bit-packed)", _remoteAddress);
}

// ---- Packet loop (post-auth) ------------------------------------------------

async<void> WorldSession::PacketLoop()
{
    FL_LOG_INFO("WorldSession", "[{}] '{}' entering packet loop", _remoteAddress, _username);

    while (_socket.is_open())
    {
        auto packet = co_await ReadClientPacket();
		WorldServerOpcodes opcode = static_cast<WorldServerOpcodes>(packet.opcode());

        FL_LOG_DEBUG("WorldSession", "[{}] [{}]:{} (payload={} bytes)", _remoteAddress, Fireland::Utils::Describe::to_string(opcode), packet.opcodeName(), packet.Size());

        switch (opcode)
        {
            case CMSG_READY_FOR_ACCOUNT_DATA_TIMES:
                co_await HandleReadyForAccountDataTimes(packet);
                break;
            case CMSG_CHAR_ENUM:
                co_await HandleCharEnum(packet);
                break;
            case CMSG_REALM_SPLIT:
                co_await HandleRealmSplit(packet);
                break;
            case CMSG_PING:
                co_await HandlePing(packet);
                break;
            case CMSG_LOG_DISCONNECT:
                co_return;
            case CMSG_CHAR_CREATE:
                co_await HandleCharCreate(packet);
				break;
            case CMSG_CHAR_DELETE:
                co_await HandleCharDelete(packet);
                break;
            case CMSG_PLAYER_LOGIN:
                co_await HandlePlayerLogin(packet);
                break;
            default:
                FL_LOG_DEBUG("WorldSession", "[{}] Unhandled opcode {} ({} bytes)",
                    _remoteAddress, packet.opcodeName(), packet.Size());
                break;
        }
    }
}

// ---- Post-auth packet handlers -----------------------------------------------

async<void> WorldSession::HandleReadyForAccountDataTimes(WorldPacket& /*packet*/)
{
    co_await SendAccountDataTimes();
}

async<void> WorldSession::HandleCharEnum(WorldPacket& /*packet*/)
{
    co_await SendCharEnum();
}

async<void> WorldSession::HandleRealmSplit(WorldPacket& packet)
{
    uint32_t realmId = 0;
    if (packet.Size() >= 4)
        realmId = packet.Read<uint32_t>();
    co_await SendRealmSplit(realmId);
}

async<void> WorldSession::HandlePing(WorldPacket& packet)
{
    if (packet.Size() < 8)
        co_return;

    uint32_t serial  = packet.Read<uint32_t>();
    uint32_t latency = packet.Read<uint32_t>();
    FL_LOG_DEBUG("WorldSession", "[{}] CMSG_PING serial={} latency={}ms", _remoteAddress, serial, latency);

    WorldPacket pong(SMSG_PONG);
    pong << serial;
    co_await SendPacket(pong);
}

async<void> WorldSession::SendCharEnum()
{
    // SMSG_CHAR_ENUM (Cata 4.3.4 bit-packed format, 0 characters).
    // Layout mirrors TC EnumCharactersResult::Write():
    //   WriteBits(restrictionCount, 23)
    //   WriteBit(success)
    //   WriteBits(charCount, 17)
    //   FlushBits()
    //   [per-character data — omitted when charCount=0]
    WorldPacket data(SMSG_CHAR_ENUM);
    data.WriteBits(0, 23);   // FactionChangeRestrictions count
    data.WriteBit(true);     // Success
    data.WriteBits(0, 17);   // Characters count
    data.FlushBits();

    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_CHAR_ENUM sent (empty list)", _remoteAddress);
}

async<void> WorldSession::HandleCharCreate(WorldPacket& packet)
{
    try
    {
        std::string name = packet.ReadString();
        uint8_t race, _class, gender, skin, face, hairStyle, hairColor, facialHair, outfitId;
        packet >> race >> _class >> gender >> skin >> face >> hairStyle >> hairColor >> facialHair >> outfitId;

        FL_LOG_INFO("WorldSession", "[{}] CMSG_CHAR_CREATE for '{}' (Race: {}, Class: {})", _remoteAddress, name, race, _class);

        //bool success = _charService->CreateCharacter(_accountId, name, race, klass, gender, skin, face, hairStyle, hairColor, facialHair);
        bool success = true;

        WorldPacket response(SMSG_CHAR_CREATE);
        // 4.3.4 SMSG_CHAR_CREATE Response

        // CHAR_CREATE_SUCCESS=0x31,
        // CHAR_CREATE_ERROR=0x32 (Cata 4.3.4)
        ResponseCodes resultCode = success ? ResponseCodes::CHAR_CREATE_SUCCESS : ResponseCodes::CHAR_CREATE_ERROR;
        response << resultCode;

        co_await SendPacket(response);
        FL_LOG_INFO("WorldSession", "[{}] SMSG_CHAR_CREATE sent result: {}", _remoteAddress, success ? "SUCCESS" : "FAIL");
    }
    catch (const std::exception& e)
    {
        FL_LOG_ERROR("WorldSession", "[{}] Error handling CMSG_CHAR_CREATE: {}", _remoteAddress, e.what());
	}
}

async<void> WorldSession::HandleCharDelete(WorldPacket& packet)
{
	uint64_t guid = packet.Read<uint64_t>();

    FL_LOG_DEBUG("WorldSession", "[{}] CMSG_CHAR_DELETE for GUID: {}", _remoteAddress, guid);

    //bool success = _charService->DeleteCharacter(static_cast<uint32>(guid), _accountId);
    bool success = true;

    WorldPacket response(SMSG_CHAR_DELETE);
    // 4.3.4 SMSG_CHAR_DELETE Response
    // Success = 0x47,
    // Error = 0x48 (Legacy but usually works)
    response << static_cast<uint8_t>(success ? 0x47 : 0x48);

    co_await SendPacket(response);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_CHAR_DELETE sent result: {}", _remoteAddress, success ? "SUCCESS" : "FAIL");
}

async<void> WorldSession::HandlePlayerLogin(WorldPacket& packet)
{
    uint64_t guid = packet.Read<uint64_t>();
    FL_LOG_INFO("WorldSession", "[{}] CMSG_PLAYER_LOGIN for GUID: {}", _remoteAddress, guid);
    //_playerGuid = guid;

    // 1. Send SMSG_LOGIN_VERIFY_WORLD
    WorldPacket verify(SMSG_LOGIN_VERIFY_WORLD);
    verify << static_cast<uint32_t>(0);   // Map ID (0 = Azeroth)
    verify << static_cast<float>(0.0f); // X
    verify << static_cast<float>(0.0f); // Y
    verify << static_cast<float>(0.0f); // Z
    verify << static_cast<float>(0.0f); // O
    co_await SendPacket(verify);

    // 2. Send SMSG_TUTORIAL_FLAGS (all zero)
    co_await SendTutorialFlags();

    // 3. Send SMSG_TIME_SYNC_REQ
    WorldPacket timeSync(SMSG_TIME_SYNC_REQ);
    timeSync << static_cast<uint32_t>(0); // Counter
    co_await SendPacket(timeSync);

    // 4. Send Initial Object Update
    //SendInitialObjectUpdate(guid);

    // 5. Send Account Data Times
    co_await SendAccountDataTimes();

    // 6. Set Time Speed
    //SendLoginSetTimeSpeed();

    // 7. Send MOTD (Correct bit-packed format)
    co_await SendMotd();

    FL_LOG_INFO("WorldSession", "[{}] Handshake for Player Login completed for GUID: {}", _remoteAddress, guid);
}

// ---- Helpers ---------------------------------------------------------------

async<WorldPacket> WorldSession::ReadClientPacket()
{
    // 1. Read and decrypt the 6-byte CMSG wire header.
    std::array<uint8_t, WorldPacket::CMSG_HEADER_SIZE> headerBuf{};
    auto readed = co_await boost::asio::async_read(_socket, boost::asio::buffer(headerBuf), boost::asio::use_awaitable);
    FL_LOG_DEBUG("WorldSession", "[{}] Read {} bytes for CMSG header", _remoteAddress, readed);

    _crypt.DecryptRecv(headerBuf.data(), headerBuf.size());

    // 2. Parse opcode and payload size; build an empty WorldPacket.
    WorldPacket packet = WorldPacket::FromCmsgHeader(headerBuf);
    FL_LOG_DEBUG("WorldSession", "[{}] Parsed opcode {} with payload size {} bytes", _remoteAddress, packet.opcodeName(), packet.Size());

    // 3. Read the payload (if any) directly into the packet.
    uint16_t wireSize = (uint16_t{headerBuf[0]} << 8) | headerBuf[1];
    if (wireSize > 4)
    {
        std::size_t payloadSize = wireSize - 4;
        constexpr std::size_t MAX_PAYLOAD = 64 * 1024;
        if (payloadSize > MAX_PAYLOAD)
            throw std::runtime_error(std::format("Packet {}: payload too large ({} bytes)", packet.opcodeName(), payloadSize));

        std::vector<uint8_t> payloadBuf(payloadSize);
        auto readedPayload = co_await boost::asio::async_read(_socket, boost::asio::buffer(payloadBuf), boost::asio::use_awaitable);
        FL_LOG_DEBUG("WorldSession", "[{}] Read {} bytes for CMSG payload", _remoteAddress, readedPayload);

        packet.Append(payloadBuf.data(), payloadBuf.size());
    }

    co_return packet;
}

async<void> WorldSession::SendPacket(const WorldPacket& packet)
{
    auto frame = packet.Serialize();
    
    if (packet.opcode() == NULL_OPCODE)
    {
        FL_LOG_ERROR("Network", "Prevented sending of NULL_OPCODE");
        co_return;
    }
    else if (packet.opcode() == UNKNOWN_OPCODE)
    {
        FL_LOG_ERROR("Network", "Prevented sending of UNKNOWN_OPCODE");
        co_return;
    }

    // Encrypt the 4-byte SMSG header in-place.
    // WorldCrypt::EncryptSend is a no-op until Init() has been called.
    FL_LOG_DEBUG("WorldSession", "[{}] SendPacket RAW: {}", _remoteAddress, Fireland::Utils::StringUtils::HexStr(frame));
    _crypt.EncryptSend(frame.data(), WorldPacket::SMSG_HEADER_SIZE);
    FL_LOG_DEBUG("WorldSession", "[{}] SendPacket CRYPT: {}", _remoteAddress, Fireland::Utils::StringUtils::HexStr(frame));
    co_await boost::asio::async_write(_socket, boost::asio::buffer(frame), boost::asio::use_awaitable);
}
