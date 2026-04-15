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

#include <Utils/Bytes/ByteBuffer.h>
#include <Utils/Bytes/ByteHelper.hpp>
#include <Utils/Log.h>
#include <Utils/StringUtils.h>

using namespace Fireland::World;
using namespace Fireland::Utils;
using namespace Fireland::Utils::Async;

// ---- Construction ----------------------------------------------------------

WorldSession::WorldSession(boost::asio::ip::tcp::socket socket,
                           Fireland::Database::Auth::AuthWrapper& authdbPool) noexcept
    : _socket(std::move(socket))
    , _authdbPool(authdbPool)
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
    auto accountOpt = co_await _authdbPool.GetAccountByUsername(_username);
    if (!accountOpt)    {
        FL_LOG_WARNING("WorldSession", "[{}] No account found for '{}'", _remoteAddress, _username);
        co_await SendAuthResponse(AuthResponseResult::AUTH_UNKNOWN_ACCOUNT);
        co_return;
    }
    auto K = co_await _authdbPool.LookupSessionKey(accountOpt->id);
    if (!K || K->size() != 40)
    {
        FL_LOG_WARNING("WorldSession", "[{}] No session key for '{}' — ensure authserver stored the key", _remoteAddress, _username);
        co_await SendAuthResponse(AuthResponseResult::AUTH_UNKNOWN_ACCOUNT);
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
        co_await SendAuthResponse(AuthResponseResult::AUTH_INCORRECT_PASSWORD);
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
    co_await SendAuthResponse(AuthResponseResult::AUTH_OK);
    co_await SendAddonInfo();
    co_await SendClientCacheVersion();
    co_await SendTutorialFlags();
    co_await SendAccountRestrictedUpdate();
    co_await SendRealmSplit(realmId);
    co_await SendSetTimeZoneInformation();
    co_await SendFeatureSystemStatus();
    co_await SendMotd();
    co_await SendLearnedDanceMoves();
    co_await SendInitialRaidGroupError();
    co_await SendSetDfFastLaunchResources();

    // Note: SMSG_ACCOUNT_DATA_TIMES, SMSG_REALM_SPLIT, and
    // SMSG_FEATURE_SYSTEM_STATUS are now sent reactively when the client requests
    // them (via CMSG_READY_FOR_ACCOUNT_DATA_TIMES, etc.) Sending them proactively
    // here can cause some 15595 clients to hang.
}

async<void> WorldSession::SendAuthResponse(AuthResponseResult result)
{
    WorldPacket response(SMSG_AUTH_RESPONSE);

    if (result == AuthResponseResult::AUTH_OK)
    {
        ByteHelper helper(response);
        helper.WriteBit(false); // isQueued
        helper.WriteBit(true);  // hasSuccessInfo

        helper.WriteBit(false); // isBattleNetAccount
        helper.WriteBit(false); // isTrialAccount
        helper.WriteBit(true);  // isExpansionStandard

        helper.FlushBits();

        response << uint32_t(0xFFFFFFFF);          // TimeRemain
        response << uint8_t(EXPANSION_CATACLYSM);  // activeExpansionLevel
        response << uint32_t(0);                   // TimeSecondsUntilPCKick
        response << uint8_t(EXPANSION_CATACLYSM);  // accountExpansionLevel
        response << uint32_t(0);                   // TimeRested
        response << uint8_t(0);                    // TimeOptions
    }
    else
    {
        ByteHelper helper(response);
        helper.WriteBit(false); // isQueued
        helper.WriteBit(false); // hasSuccessInfo
        helper.FlushBits();     // → 1 byte: 0x00
    }
    response << result;

    FL_LOG_DEBUG("WorldSession", "[{}] Sending SMSG_AUTH_RESPONSE (result=0x{:02X})", _remoteAddress, static_cast<uint8_t>(result));
    FL_LOG_DEBUG("WorldSession", "[{}] AUTH_RESPONSE RAW: {}", _remoteAddress, Fireland::Utils::StringUtils::HexStr(response.Data()));

    co_await SendPacket(response);
}

async<void> WorldSession::SendAddonInfo()
{
    WorldPacket response(SMSG_ADDON_INFO);

    // Cata 4.3.4 (15595) uses bit-packed counts (23 bits each)
    ByteHelper helper(response);
    helper.WriteBits(0, 23);// addonCount
    helper.WriteBits(0, 23);// bannedAddonCount
    helper.FlushBits(); // align to byte boundary after writing bit-packed counts

    co_await SendPacket(response);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_ADDON_INFO sent (4.3.4 15595 bit-packed format)", _remoteAddress);
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
    ByteHelper helper(data);
    helper.WriteBit(false); // isRestricted
    helper.FlushBits();
    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_ACCOUNT_RESTRICTED_UPDATE sent", _remoteAddress);
}

async<void> WorldSession::SendSetDfFastLaunchResources()
{
    WorldPacket data(SMSG_SET_DF_FAST_LAUNCH_RESOURCES);
    ByteHelper helper(data);
    helper.WriteBits(0, 32); // Count (32 bits for bits count?)
    helper.FlushBits();
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

    ByteHelper helper(features);
    helper.WriteBit(false); // QuestHotfixesEnabled
    helper.WriteBit(false); // EuropaEnabled
    helper.WriteBit(false); // EquipmentManagerEnabled
    helper.WriteBit(false); // CanPurchaseLevel
    helper.WriteBit(false); // VoiceChatEnabled
    helper.WriteBit(false); // ScrollOfResurrectionEnabled
    helper.WriteBit(false); // ComplaintEnabled
    helper.WriteBit(false); // SessionTimerEnabled
    helper.WriteBit(false); // KioskModeEnabled
    helper.FlushBits();

    co_await SendPacket(features);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_FEATURE_SYSTEM_STATUS sent (4.3.4 format)", _remoteAddress);
}

async<void> WorldSession::SendRealmSplit(uint32_t realmId)
{
    WorldPacket split(SMSG_REALM_SPLIT);
    std::string splitDate = "01/01/01";

    split << uint32_t(realmId); // Realm ID
    split << uint32_t(0);       // State (0 = Normal)
    
    ByteHelper helper(split);
    helper.WriteBits(static_cast<uint32_t>(splitDate.size()), 7);
    helper.FlushBits();
    split.WriteString(splitDate);

    co_await SendPacket(split);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_REALM_SPLIT sent (Bit-packed 4.3.4)", _remoteAddress);
}

async<void> WorldSession::SendSetTimeZoneInformation()
{
    WorldPacket data(SMSG_SET_TIME_ZONE_INFORMATION);
    std::string serverTz = "UTC";
    std::string localTz = "UTC";

    ByteHelper helper(data);
    helper.WriteBits(static_cast<uint32_t>(serverTz.length()), 7);
    helper.WriteBits(static_cast<uint32_t>(localTz.length()), 7);
    helper.FlushBits();

    data.WriteString(serverTz);
    data.WriteString(localTz);

    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_SET_TIME_ZONE_INFORMATION sent (Bit-packed 4.3.4)", _remoteAddress);
}

async<void> WorldSession::SendLearnedDanceMoves()
{
    WorldPacket data(SMSG_LEARNED_DANCE_MOVES);
    ByteHelper helper(data);
    helper.WriteBits(0, 23); // Count (23 bits in Cata 4.3.4)
    helper.FlushBits();
    co_await SendPacket(data);
    FL_LOG_INFO("WorldSession", "[{}] SMSG_LEARNED_DANCE_MOVES sent (0 moves, bit-packed)", _remoteAddress);
}

async<void> WorldSession::SendMotd()
{
    WorldPacket motd(SMSG_MOTD);
    std::vector<std::string> lines = {"Bo0p !"};

    ByteHelper helper(motd);
    helper.WriteBits(static_cast<uint32_t>(lines.size()), 4);
    for (auto const &line : lines)
        helper.WriteBits(static_cast<uint32_t>(line.length()), 11);
    
    helper.FlushBits();

    for (auto const &line : lines)
    {
        motd.WriteString(line);
    }

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

        FL_LOG_DEBUG("WorldSession", "[{}] {} (payload={} bytes)",
            _remoteAddress, packet.opcodeName(), packet.Size());

        if (!packet.Empty())
        {
            FL_LOG_TRACE("WorldSession", "[{}] Payload: {}",
                _remoteAddress, StringUtils::HexStr(packet.Data()));
        }

        // TODO: Dispatch world opcodes (CMSG_CHAR_ENUM, CMSG_PLAYER_LOGIN, etc.)
    }
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
            throw std::runtime_error(
                std::format("Packet {}: payload too large ({} bytes)",
                    packet.opcodeName(), payloadSize));

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
    
    // Encrypt the 4-byte SMSG header in-place.
    // WorldCrypt::EncryptSend is a no-op until Init() has been called.
    FL_LOG_DEBUG("WorldSession", "[{}] SendPacket RAW: {}", _remoteAddress, Fireland::Utils::StringUtils::HexStr(frame));
    _crypt.EncryptSend(frame.data(), WorldPacket::SMSG_HEADER_SIZE);
    FL_LOG_DEBUG("WorldSession", "[{}] SendPacket CRYPT: {}", _remoteAddress, Fireland::Utils::StringUtils::HexStr(frame));
    co_await boost::asio::async_write(_socket, boost::asio::buffer(frame), boost::asio::use_awaitable);
}
