#include "WorldSession.h"

#include <cctype>
#include <chrono>
#include <cstring>
#include <ctime>
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
#include <Database/Char/CharWrapper.h>

#include <Game/Objects/UpdateData.h>

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
    WorldPacket data(SMSG_ACCOUNT_RESTRICTED_WARNING);
    
    data.WriteBit(false); // isRestricted
    data.FlushBits();
    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_ACCOUNT_RESTRICTED_UPDATE sent", _remoteAddress);
}

async<void> WorldSession::SendSetDfFastLaunchResources()
{
    WorldPacket data(SMSG_SET_DF_FAST_LAUNCH_RESULT);
    
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

    // TC 4.3.4 SystemPackets.cpp FeatureSystemStatus::Write()
    features << int8_t(2);    // ComplaintStatus (2 = enabled)
    features << int32_t(1);   // ScrollOfResurrectionRequestsRemaining
    features << int32_t(1);   // ScrollOfResurrectionMaxRequestsPerDay
    features << int32_t(1);   // CfgRealmID
    features << int32_t(0);   // CfgRealmRecID
    features.WriteBit(false); // ItemRestorationButtonEnabled
    features.WriteBit(false); // TravelPassEnabled
    features.WriteBit(false); // ScrollOfResurrectionEnabled
    features.WriteBit(false); // EuropaTicketSystemStatus present
    features.WriteBit(false); // SessionAlert present
    features.WriteBit(false); // VoiceEnabled
    features.FlushBits();
    co_await SendPacket(features);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_FEATURE_SYSTEM_STATUS sent", _remoteAddress);
}

async<void> WorldSession::SendHotfixNotify()
{
    WorldPacket data(SMSG_HOTFIX_NOTIFY_BLOB);
    data.WriteBits(0, 22); // hotfix count = 0
    data.FlushBits();
    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_HOTFIX_NOTIFY_BLOB sent (0 hotfixes)", _remoteAddress);
}

async<void> WorldSession::SendBindPointUpdate(float x, float y, float z, uint32_t mapId, uint32_t zoneId)
{
    WorldPacket data(SMSG_BIND_POINT_UPDATE);
    data << x << y << z << mapId << zoneId;
    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_BIND_POINT_UPDATE sent", _remoteAddress);
}

async<void> WorldSession::SendWorldServerInfo()
{
    // TC 4.3.4 MiscPackets.cpp WorldServerInfo::Write()
    WorldPacket data(SMSG_WORLD_SERVER_INFO);
    data.WriteBit(false); // RestrictedAccountMaxLevel present
    data.WriteBit(false); // RestrictedAccountMaxMoney present
    data.WriteBit(false); // IneligibleForLootMask present
    data.FlushBits();
    data << uint8_t(0);  // IsTournamentRealm
    data << uint32_t(static_cast<uint32_t>(std::time(nullptr))); // WeeklyReset
    data << uint32_t(0); // DifficultyID (0 = normal)
    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_WORLD_SERVER_INFO sent", _remoteAddress);
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
    WorldPacket data(SMSG_LEARNED_DANCE_MOVES, 8);
    data << uint64_t(0);
    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_LEARNED_DANCE_MOVES sent (0 moves)", _remoteAddress);
}

async<void> WorldSession::SendMotd()
{
    WorldPacket motd(SMSG_MOTD);
    std::vector<std::string> lines = {"Bo0p !"};

    motd << static_cast<int32_t>(lines.size());
    for (auto const& line : lines)
        motd << line; // WriteCString (null-terminated)

    co_await SendPacket(motd);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_MOTD sent", _remoteAddress);
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
            case CMSG_TIME_SYNC_RESP:
                break; // acknowledged, no reply needed
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
            case CMSG_MESSAGECHAT:
                co_await HandleMessageChat(packet);
                break;
            case CMSG_SET_ACTIVE_MOVER:
                break; // client ACK of SMSG_MOVE_SET_ACTIVE_MOVER, no reply needed
            case MSG_MOVE_HEARTBEAT:
            case MSG_MOVE_START_FORWARD:
            case MSG_MOVE_START_BACKWARD:
            case MSG_MOVE_STOP:
            case MSG_MOVE_SET_FACING:
                co_await HandleMovement(packet);
                break;
            case CMSG_LOADING_SCREEN_NOTIFY:
				co_await HandleLoadingScreenNotify(packet);
                break;
            case CMSG_VIOLENCE_LEVEL:
				co_await HandleViolenceLevel(packet);
                break;
            case CMSG_QUERY_QUESTS_COMPLETED:
				co_await HandleQueryQuestsCompleted(packet);
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
    WorldPacket data(SMSG_CHAR_ENUM);
    
    const auto characters = co_await sCharDB.GetCharactersForAccount(_accountId);
	const auto charCount = static_cast<uint32_t>(characters.size());

	FL_LOG_DEBUG("WorldSession", "[{}] Sending SMSG_CHAR_ENUM with {} characters", _remoteAddress, charCount);

    struct GuidData {
        uint8_t g[8];
        uint8_t gg[8];
    };
    std::vector<GuidData> guidData(charCount);
    for (uint32_t i = 0; const auto& it : characters)
    {
        uint64_t guid = it.guid;
        uint64_t guildGuid = 0; // Guilds not implemented yet

        for (int b = 0; b < 8; ++b)
        {
            guidData[i].g[b] = static_cast<uint8_t>((guid >> (b * 8)) & 0xFF);
            guidData[i].gg[b] = static_cast<uint8_t>((guildGuid >> (b * 8)) & 0xFF);
        }
        ++i;
    }

    // SMSG_CHAR_ENUM (Cata 4.3.4 bit-packed format, 0 characters).
    // Layout mirrors TC EnumCharactersResult::Write():
    //   WriteBits(restrictionCount, 23)
    //   WriteBit(success)
    //   WriteBits(charCount, 17)
    //   FlushBits()
    //   [per-character data — omitted when charCount=0]
    data.WriteBits(0, 23);         // FactionChangeRestrictions count
    data.WriteBit(true);           // Success
    data.WriteBits(charCount, 17); // Characters count
    for (uint32_t i = 0; const auto& ch : characters)
    {
        auto& gd = guidData[i];

        // Scrambled GUID bits (Exact order from TCPP CharacterPackets.cpp)
        data.WriteBit(gd.g[3] != 0);
        data.WriteBit(gd.gg[1] != 0);
        data.WriteBit(gd.gg[7] != 0);
        data.WriteBit(gd.gg[2] != 0);
        data.WriteBits(static_cast<uint32_t>(ch.name.length()), 7);
        data.WriteBit(gd.g[4] != 0);
        data.WriteBit(gd.g[7] != 0);
        data.WriteBit(gd.gg[3] != 0);
        data.WriteBit(gd.g[5] != 0);
        data.WriteBit(gd.gg[6] != 0);
        data.WriteBit(gd.g[1] != 0);
        data.WriteBit(gd.gg[5] != 0);
        data.WriteBit(gd.gg[4] != 0);
        data.WriteBit(ch.firstLogin);
        data.WriteBit(gd.g[0] != 0);
        data.WriteBit(gd.g[2] != 0);
        data.WriteBit(gd.g[6] != 0);
        data.WriteBit(gd.gg[0] != 0);
        ++i;
    }
    data.FlushBits();

    for (uint32_t i = 0; const auto& ch : characters)
    {
        auto& gd = guidData[i];

        data << ch.char_class;
        // Equipment: 23 visual item slots
        for (int slot = 0; slot < 23; ++slot)
        {
            data<< uint8_t(0);  // InvType
            data<< uint32_t(0); // DisplayID
            data<< uint32_t(0); // DisplayEnchantID
        }

        data << uint32_t(0);                // PetCreatureFamilyID
        data.WriteByteSeq(gd.gg[2]);        // GuildGUID[2]
        data << uint8_t(0);                 // ListPosition
        data << uint8_t(ch.hairStyle);
        data.WriteByteSeq(gd.gg[3]);        // GuildGUID[3]
        data << uint32_t(0);                // PetCreatureDisplayID
        data << uint32_t(ch.characterFlags);
        data << uint8_t(ch.hairColor);
        data.WriteByteSeq(gd.g[4]);         // Guid[4]
        data << int32_t(ch.mapId);
        data.WriteByteSeq(gd.gg[5]);        // GuildGUID[5]
        data << float(ch.z);
        data.WriteByteSeq(gd.gg[6]);        // GuildGUID[6]
        data << uint32_t(0);                // PetExperienceLevel
        data.WriteByteSeq(gd.g[3]);         // Guid[3]
        data << float(ch.y);
        data << uint32_t(ch.customizationFlags);
        data << uint8_t(ch.facialHair);
        data.WriteByteSeq(gd.g[7]);         // Guid[7]
        data << uint8_t(ch.gender);
        data.Append(ch.name.data(), ch.name.size());
        data << uint8_t(ch.face);
        data.WriteByteSeq(gd.g[0]);         // Guid[0]
        data.WriteByteSeq(gd.g[2]);         // Guid[2]
        data.WriteByteSeq(gd.gg[1]);        // GuildGUID[1]
        data.WriteByteSeq(gd.gg[7]);        // GuildGUID[7]
        data << float(ch.x);
        data << uint8_t(ch.skin);
        data << uint8_t(ch.race);
        data << uint8_t(ch.level);
        data.WriteByteSeq(gd.g[6]);         // Guid[6]
        data.WriteByteSeq(gd.gg[4]);        // GuildGUID[4]
        data.WriteByteSeq(gd.gg[0]);        // GuildGUID[0]
        data.WriteByteSeq(gd.g[5]);         // Guid[5]
        data.WriteByteSeq(gd.g[1]);         // Guid[1]
        data << int32_t(ch.zoneId);
        ++i;
    }

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

        auto SendCharCreateResponse = [this](ResponseCodes code) -> async<void>
        {
            WorldPacket response(SMSG_CHAR_CREATE);
            response << code;
            co_await SendPacket(response);
        };

        auto name_free = co_await sCharDB.IsNameAvailable(name);
        if (!name_free)
        {
            FL_LOG_WARNING("WorldSession", "[{}] Character name '{}' is already taken", _remoteAddress, name);
            co_return co_await SendCharCreateResponse(ResponseCodes::CHAR_CREATE_NAME_IN_USE);
		}

		characters character{0, _accountId, name, race, _class, gender, skin, face, hairStyle, hairColor, facialHair, 1, 12, 0, -8949.95f, -132.493f, 83.5312f, 0, 0, 0, true};
		auto opt_created_character = co_await sCharDB.CreateCharacter(character);
        if (!opt_created_character)
        {
            FL_LOG_ERROR("WorldSession", "[{}] Failed to create character '{}' in database", _remoteAddress, name);
            co_return co_await SendCharCreateResponse(ResponseCodes::CHAR_CREATE_FAILED);
		}

        //bool success = _charService->CreateCharacter(_accountId, name, race, klass, gender, skin, face, hairStyle, hairColor, facialHair);
		co_return co_await SendCharCreateResponse(ResponseCodes::CHAR_CREATE_SUCCESS);
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

    bool success = co_await sCharDB.DeleteCharacter(guid, _accountId);

    WorldPacket response(SMSG_CHAR_DELETE);
    // 4.3.4 SMSG_CHAR_DELETE Response
    response << static_cast<uint8_t>(success ? ResponseCodes::CHAR_DELETE_SUCCESS : ResponseCodes::CHAR_DELETE_FAILED);

    co_await SendPacket(response);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_CHAR_DELETE sent result: {}", _remoteAddress, success ? "SUCCESS" : "FAIL");
}

async<void> WorldSession::HandlePlayerLogin(WorldPacket& packet)
{
    // CMSG_PLAYER_LOGIN sends a scrambled packed GUID (order: 2,3,0,6,4,5,1,7)
    std::array<bool, 8> hasByte{};
    hasByte[2] = packet.ReadBit();
    hasByte[3] = packet.ReadBit();
    hasByte[0] = packet.ReadBit();
    hasByte[6] = packet.ReadBit();
    hasByte[4] = packet.ReadBit();
    hasByte[5] = packet.ReadBit();
    hasByte[1] = packet.ReadBit();
    hasByte[7] = packet.ReadBit();

    uint64_t rawGuid = 0;
    auto* guidBytes = reinterpret_cast<uint8_t*>(&rawGuid);
    if (hasByte[2]) guidBytes[2] = packet.Read<uint8_t>() ^ 1;
    if (hasByte[3]) guidBytes[3] = packet.Read<uint8_t>() ^ 1;
    if (hasByte[0]) guidBytes[0] = packet.Read<uint8_t>() ^ 1;
    if (hasByte[6]) guidBytes[6] = packet.Read<uint8_t>() ^ 1;
    if (hasByte[4]) guidBytes[4] = packet.Read<uint8_t>() ^ 1;
    if (hasByte[5]) guidBytes[5] = packet.Read<uint8_t>() ^ 1;
    if (hasByte[1]) guidBytes[1] = packet.Read<uint8_t>() ^ 1;
    if (hasByte[7]) guidBytes[7] = packet.Read<uint8_t>() ^ 1;

    uint32_t charGuid = static_cast<uint32_t>(rawGuid);
    FL_LOG_INFO("WorldSession", "[{}] CMSG_PLAYER_LOGIN for GUID: {}", _remoteAddress, charGuid);

    auto charOpt = co_await sCharDB.GetCharacterByGuid(charGuid);
    if (!charOpt)
    {
        FL_LOG_ERROR("WorldSession", "[{}] Character GUID {} not found", _remoteAddress, charGuid);
        co_return;
    }
    const auto& ch = *charOpt;
    uint64_t guid = ch.guid;

    // Use Northshire starting position if character has no valid position
    float spawnX = (ch.x == 0.0f && ch.y == 0.0f) ? -8949.95f : ch.x;
    float spawnY = (ch.x == 0.0f && ch.y == 0.0f) ? -132.493f : ch.y;
    float spawnZ = (ch.x == 0.0f && ch.y == 0.0f) ? 83.5312f  : ch.z;

	FL_LOG_DEBUG("WorldSession", "[{}] Player '{}' login: GUID={}, Map={}, Pos=({:.2f}, {:.2f}, {:.2f}), FirstLogin={}", _remoteAddress, ch.name, guid, ch.mapId, spawnX, spawnY, spawnZ, ch.firstLogin);

    // 1. Initial account data (TC: first thing in HandlePlayerLogin)
    co_await SendAccountDataTimes();
    co_await SendLearnedDanceMoves();
    co_await SendHotfixNotify();

    // 2. Before-map packets (TC: SendInitialPacketsBeforeAddToMap)
    co_await SendClientControlUpdate(guid, true);
    co_await SendBindPointUpdate(spawnX, spawnY, spawnZ, ch.mapId, ch.zoneId);
    co_await SendWorldServerInfo();
    co_await SendInitialSpells();
    co_await SendUnlearnSpells();
    co_await SendActionButtons();
    co_await SendInitializeFactions();
    co_await SendMotd();
    co_await SendFeatureSystemStatus();

    // 3. "AddToMap" — sends CREATE_OBJECT2 to client
    co_await SendCreatePlayerObject(ch, spawnX, spawnY, spawnZ);

    // 4. Post-map packets (TC: SendInitialPacketsAfterAddToMap)
    //    MoveSetActiveMover MUST come after CREATE_OBJECT2; the client ignores it
    //    if the player GUID is not yet in the object manager.
    co_await SendMoveSetActiveMover(guid);

    // 5. LOGIN_VERIFY_WORLD must come AFTER CREATE_OBJECT2 + MoveSetActiveMover
    WorldPacket verify(SMSG_LOGIN_VERIFY_WORLD, 20);
    verify << uint32_t(ch.mapId) << spawnX << spawnY << spawnZ << float(0.0f);
    co_await SendPacket(verify);

    co_await SendLoginSetTimeSpeed();

    WorldPacket timeSync(SMSG_TIME_SYNC_REQ);
    timeSync << uint32_t(0);
    co_await SendPacket(timeSync);

    co_await SendTutorialFlags();

    FL_LOG_INFO("WorldSession", "[{}] Player login complete for '{}'", _remoteAddress, ch.name);
}

async<void> WorldSession::HandleMessageChat(WorldPacket& packet)
{
    uint32_t type = packet.Read<uint32_t>();
    uint32_t language = packet.Read<uint32_t>();

    std::string target;
    static const uint32_t CHAT_MSG_WHISPER = 6;
    static const uint32_t CHAT_MSG_CHANNEL = 15;
    if (type == CHAT_MSG_WHISPER || type == CHAT_MSG_CHANNEL)
    {
        target = packet.ReadString();
    }

    std::string message = packet.ReadString();
	auto _playerGuid = 1; // Placeholder GUID for the player sending the message
    FL_LOG_DEBUG("WorldSession", "[{}] Chat from {} : [{}] {}", _remoteAddress, _playerGuid, type, message);

    // Echo back to nearby players (spatial chat base)
    // For now, only send back to the sender
    WorldPacket response(SMSG_MESSAGECHAT);
    response << static_cast<uint8_t>(type);
    response << static_cast<uint32_t>(language);
    response << static_cast<uint64_t>(_playerGuid);
    response << static_cast<uint32_t>(0);           // Unk
    response << static_cast<uint64_t>(_playerGuid); // Target? or Sender? depends on type
    response << static_cast<uint32_t>(message.length() + 1);
    response << message;
    response << static_cast<uint8_t>(0); // Tag

    co_await SendPacket(response);
}

async<void> WorldSession::HandleMovement(WorldPacket& packet)
{
    auto ReadMovementInfo = [](WorldPacket& packet, MovementInfo& move)
    {
        if (packet.Size() >= 26)
        {
            // Basic structure: Flags(4), Flags2(2), Time(4), X, Y, Z, O (16) = 26 bytes
			packet >> move.flags >> move.flags2 >> move.time >> move.x >> move.y >> move.z >> move.orientation;
        }
    };
    MovementInfo move;
    ReadMovementInfo(packet, move);

    // Update internal state
	auto _playerGuid = 1; // Placeholder GUID for the player moving
    FL_LOG_DEBUG("WorldSession", "[{}] Player {} moved to ({:.2f}, {:.2f}, {:.2f}) O:{:.2f}", _remoteAddress, _playerGuid, move.x, move.y, move.z, move.orientation);

    // Broadcast movement (Echo back to client for now, or broadcast to others if
    // any) In WoW, we typically echo back the movement packet if it's an MSG
    // opcode

    // Rough check for MSG opcodes if needed,
    if (packet.opcode() >= 0x2000)
    {
        
        // but we listed them explicitly
        // echo back
        WorldPacket echo(packet.opcode(), packet.Size());
        echo << packet.Storage();
        co_await SendPacket(echo);
    }
}

// ---- Player login helpers --------------------------------------------------

async<void> WorldSession::SendInitialSpells()
{
    WorldPacket data(SMSG_INITIAL_SPELLS, 5);
    data << uint8_t(0);   // initial login flag
    data << uint16_t(0);  // spell count
    data << uint16_t(0);  // cooldown count
    co_await SendPacket(data);
}

async<void> WorldSession::SendUnlearnSpells()
{
    WorldPacket data(SMSG_SEND_UNLEARN_SPELLS, 4);
    data << uint32_t(0);  // count = 0
    co_await SendPacket(data);
}

async<void> WorldSession::SendInitializeFactions()
{
    // TC sends exactly 256 entries: flags (uint8) + standing (uint32) per entry
    WorldPacket data(SMSG_INITIALIZE_FACTIONS, 4 + 256 * 5);
    data << uint32_t(256);
    for (uint32_t i = 0; i < 256; ++i)
    {
        data << uint8_t(0);  // flags
        data << uint32_t(0); // standing
    }
    co_await SendPacket(data);
}

async<void> WorldSession::SendActionButtons()
{
    // TC order: reason byte first, then 144 buttons (uint32 each)
    WorldPacket data(SMSG_ACTION_BUTTONS, 1 + 144 * 4);
    data << uint8_t(0);  // 0 = initial login
    for (int i = 0; i < 144; ++i)
        data << uint32_t(0);
    co_await SendPacket(data);
}

async<void> WorldSession::SendLoginSetTimeSpeed()
{
    // TC format: AppendPackedTime(GameTime) + float(speed) + uint32(HolidayOffset)
    // AppendPackedTime packs: (year-100)<<24 | mon<<20 | (mday-1)<<14 | wday<<11 | hour<<6 | min
    time_t now = std::time(nullptr);
    struct tm lt{};
#if defined(_WIN32) || defined(_WIN64)
    localtime_s(&lt, &now);
#else
    // POSIX: use localtime_r for thread-safe conversion
    localtime_r(&now, &lt);
#endif
    uint32_t packedTime = static_cast<uint32_t>(
        ((lt.tm_year - 100) << 24) | (lt.tm_mon << 20) |
        ((lt.tm_mday - 1)   << 14) | (lt.tm_wday << 11) |
        (lt.tm_hour          << 6)  |  lt.tm_min);

    WorldPacket data(SMSG_LOGIN_SET_TIME_SPEED, 12);
    data << packedTime;
    data << float(0.01666667f);
    data << uint32_t(0); // GameTimeHolidayOffset
    co_await SendPacket(data);
}

// Display ID lookup for playable races in Cata 4.3.4 (gender: 0=male, 1=female)
static uint32_t GetDisplayId(uint8_t race, uint8_t gender)
{
    static const uint32_t ids[25][2] = {
        {0,     0    }, // 0 unused
        {49,    50   }, // 1 Human
        {51,    52   }, // 2 Orc
        {53,    54   }, // 3 Dwarf
        {55,    56   }, // 4 Night Elf
        {57,    58   }, // 5 Undead
        {59,    60   }, // 6 Tauren
        {1563,  1564 }, // 7 Gnome
        {1478,  1479 }, // 8 Troll
        {0,     0    }, // 9 unused
        {15476, 15475}, // 10 Blood Elf
        {16125, 16126}, // 11 Draenei
        {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0}, // 12-20 unused
        {20578, 20579}, // 21 Goblin
        {24389, 24390}, // 22 Worgen
        {0,     0    }, // 23 unused
        {0,     0    }, // 24 unused
    };
    if (race >= 25) return 49;
    uint32_t id = ids[race][gender & 1];
    return id ? id : 49;
}

async<void> WorldSession::SendCreatePlayerObject(const characters& ch, float x, float y, float z)
{
    UpdateData data(static_cast<uint16_t>(ch.mapId));
    MovementInfo info;
    info.x = x;
    info.y = y;
    info.z = z;
    info.orientation = 0.0f;

    uint64_t guid = ch.guid;

    // Power type: warrior/dk=1(rage/runic), hunter=2(focus), rogue=3(energy), rest=0(mana)
    static const uint8_t classPower[] = {0, 1, 0, 2, 0, 3, 0, 0, 0, 0, 0, 0, 6, 0};
    uint8_t powerType = (ch.char_class < 14) ? classPower[ch.char_class] : 0;

    // Faction template IDs per race
    static const uint32_t factions[] = {0, 1, 2, 3, 4, 5, 6, 115, 116, 0, 1610, 1629,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 2101, 2100, 0, 0};
    uint32_t faction = (ch.race < 23) ? factions[ch.race] : 1;

    uint32_t displayId = GetDisplayId(ch.race, ch.gender);

    std::map<uint16_t, uint32_t> fields;

    fields[OBJECT_FIELD_GUID]          = static_cast<uint32_t>(guid & 0xFFFFFFFF);
    fields[OBJECT_FIELD_GUID + 1]      = static_cast<uint32_t>(guid >> 32);
    fields[OBJECT_FIELD_TYPE]          = (1 << TYPEID_OBJECT) | (1 << TYPEID_UNIT) | (1 << TYPEID_PLAYER);
    fields[OBJECT_FIELD_SCALE_X]       = 0x3F800000u; // 1.0f as bits

    fields[UNIT_FIELD_BYTES_0]         = static_cast<uint32_t>(ch.race)
                                       | (static_cast<uint32_t>(ch.char_class) << 8)
                                       | (static_cast<uint32_t>(ch.gender) << 16)
                                       | (static_cast<uint32_t>(powerType) << 24);
    fields[UNIT_FIELD_FLAGS]           = 0x00000008u; // UNIT_FLAG_PLAYER_CONTROLLED
    fields[UNIT_FIELD_HEALTH]          = 100;
    fields[UNIT_FIELD_MAXHEALTH]       = 100;
    fields[UNIT_FIELD_BASE_HEALTH]     = 100;
    fields[UNIT_FIELD_BYTES_1]         = 0; // stand state = UNIT_STAND_STATE_STAND
    fields[UNIT_FIELD_LEVEL]           = ch.level ? ch.level : 1;
    fields[UNIT_FIELD_FACTIONTEMPLATE] = faction;
    fields[UNIT_FIELD_DISPLAYID]       = displayId;
    fields[UNIT_FIELD_NATIVEDISPLAYID] = displayId;

    fields[PLAYER_BYTES]               = static_cast<uint32_t>(ch.skin)
                                       | (static_cast<uint32_t>(ch.face) << 8)
                                       | (static_cast<uint32_t>(ch.hairStyle) << 16)
                                       | (static_cast<uint32_t>(ch.hairColor) << 24);
    fields[PLAYER_BYTES_2]             = static_cast<uint32_t>(ch.facialHair);
    fields[PLAYER_BYTES_3]             = static_cast<uint32_t>(ch.gender);

    data.AddCreateObject(guid, TYPEID_PLAYER, info, fields, /*isSelf=*/true);

    WorldPacket packet(SMSG_UPDATE_OBJECT);
    data.Build(packet);
    co_await SendPacket(packet);
}

async<void> WorldSession::SendClientControlUpdate(uint64_t guid, bool allowMove)
{
    // TC: data << target->GetPackGUID() << uint8(allowMove ? 1 : 0)
    WorldPacket data(SMSG_CLIENT_CONTROL_UPDATE);
    data.WritePackedGuid(guid);
    data << uint8_t(allowMove ? 1 : 0);
    co_await SendPacket(data);
}

async<void> WorldSession::SendMoveSetActiveMover(uint64_t guid)
{
    // TC: MoveSetActiveMover::Write() — bit-packed GUID in order 5,7,3,6,0,4,1,2
    uint8_t g[8];
    for (int i = 0; i < 8; ++i)
        g[i] = static_cast<uint8_t>((guid >> (i * 8)) & 0xFF);

    WorldPacket data(SMSG_MOVE_SET_ACTIVE_MOVER);
    data.WriteBit(g[5]);
    data.WriteBit(g[7]);
    data.WriteBit(g[3]);
    data.WriteBit(g[6]);
    data.WriteBit(g[0]);
    data.WriteBit(g[4]);
    data.WriteBit(g[1]);
    data.WriteBit(g[2]);
    data.FlushBits();
    data.WriteByteSeq(g[6]);
    data.WriteByteSeq(g[2]);
    data.WriteByteSeq(g[3]);
    data.WriteByteSeq(g[0]);
    data.WriteByteSeq(g[5]);
    data.WriteByteSeq(g[7]);
    data.WriteByteSeq(g[1]);
    data.WriteByteSeq(g[4]);
    co_await SendPacket(data);
}

async<void> WorldSession::HandleLoadingScreenNotify(WorldPacket& packet)
{
    uint32_t mapId = packet.Read<uint32_t>();
    bool loadingScreenState = packet.ReadBit();

    FL_LOG_DEBUG("WorldSession", "Loading screen for map '{}' is {}.", mapId, loadingScreenState ? "started" : "finished");
    co_return;
}

async<void> WorldSession::HandleViolenceLevel(WorldPacket& /*recvData*/)
{
	// Client is notifying us of its violence level setting, which may affect what content we can show it. For now, just log it.
    co_return;
}


async<void> WorldSession::HandleQueryQuestsCompleted(WorldPacket& /*recvData*/)
{
    size_t rew_count = 0;

    WorldPacket data(SMSG_QUERY_QUESTS_COMPLETED_RESPONSE, 4 + 4 * rew_count);
    data << uint32_t(rew_count);

    co_await SendPacket(data);
}


// ---- Helpers ---------------------------------------------------------------

async<WorldPacket> WorldSession::ReadClientPacket()
{
    // 1. Read and decrypt the 6-byte CMSG wire header.
    std::array<uint8_t, WorldPacket::CMSG_HEADER_SIZE> headerBuf{};
    [[maybe_unused]] auto readed = co_await boost::asio::async_read(_socket, boost::asio::buffer(headerBuf), boost::asio::use_awaitable);
    //FL_LOG_DEBUG("WorldSession", "[{}] Read {} bytes for CMSG header", _remoteAddress, readed);

    _crypt.DecryptRecv(headerBuf.data(), headerBuf.size());

    // 2. Parse opcode and payload size; build an empty WorldPacket.
    WorldPacket packet = WorldPacket::FromCmsgHeader(headerBuf);
    //FL_LOG_DEBUG("WorldSession", "[{}] Parsed opcode {} with payload size {} bytes", _remoteAddress, packet.opcodeName(), packet.Size());

    // 3. Read the payload (if any) directly into the packet.
    uint16_t wireSize = (uint16_t{headerBuf[0]} << 8) | headerBuf[1];
    if (wireSize > 4)
    {
        std::size_t payloadSize = wireSize - 4;
        constexpr std::size_t MAX_PAYLOAD = 64 * 1024;
        if (payloadSize > MAX_PAYLOAD)
            throw std::runtime_error(std::format("Packet {}: payload too large ({} bytes)", packet.opcodeName(), payloadSize));

        std::vector<uint8_t> payloadBuf(payloadSize);
        readed = co_await boost::asio::async_read(_socket, boost::asio::buffer(payloadBuf), boost::asio::use_awaitable);
        //FL_LOG_DEBUG("WorldSession", "[{}] Read {} bytes for CMSG payload", _remoteAddress, readed);

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
	WorldServerOpcodes opcode = static_cast<WorldServerOpcodes>(packet.opcode());
    auto packet_name = Describe::to_string(opcode);
    FL_LOG_DEBUG("WorldSession", "[{}] {} SendPacket: {}", _remoteAddress, packet_name, Fireland::Utils::StringUtils::HexStr(frame));
    _crypt.EncryptSend(frame.data(), WorldPacket::SMSG_HEADER_SIZE);
    co_await boost::asio::async_write(_socket, boost::asio::buffer(frame), boost::asio::use_awaitable);
}
