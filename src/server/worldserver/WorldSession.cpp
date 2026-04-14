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

#include <Utils/Log.h>
#include <Utils/ByteBuffer.h>
#include <Utils/StringUtils.h>

using namespace Fireland::World;
using namespace Fireland::Utils;
using namespace Fireland::Utils::Async;

// ---- Construction ----------------------------------------------------------

WorldSession::WorldSession(boost::asio::ip::tcp::socket socket,
                           Network::SessionKeyStore& keyStore) noexcept
    : _socket(std::move(socket))
    , _keyStore(keyStore)
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
    std::mt19937 rng{std::random_device{}()};
    _serverSeed = std::uniform_int_distribution<uint32_t>{}(rng);

    // Generate per-session random seeds (Cata 4.x: these are both the DosChallenge
    // bytes AND the HMAC keys used later to derive the per-session ARC4 keys).
    std::uniform_int_distribution<unsigned> byteDist(0, 255);
    for (auto& b : _encryptSeed) b = static_cast<uint8_t>(byteDist(rng));
    for (auto& b : _decryptSeed) b = static_cast<uint8_t>(byteDist(rng));

    // Payload layout (37 bytes):
    //   uint8[16]  encryptSeed   — DosChallenge bytes  0-15 (random)
    //   uint8[16]  decryptSeed   — DosChallenge bytes 16-31 (random)
    //   uint32     serverSeed    — used by client to compute CMSG_AUTH_SESSION digest
    //   uint8      DosZeroBits   — leading-zero PoW requirement (1 = minimal)
    WorldPacket packet(SMSG_AUTH_CHALLENGE, 37);
    packet.Append(_encryptSeed.data(), _encryptSeed.size());
    packet.Append(_decryptSeed.data(), _decryptSeed.size());
    packet << _serverSeed;
    packet << uint8_t(1);

    FL_LOG_DEBUG("WorldSession", "[{}] Sending SMSG_AUTH_CHALLENGE (seed=0x{:08X})",
        _remoteAddress, _serverSeed);

    co_await SendPacket(packet);
}

// ---- CMSG_AUTH_SESSION ------------------------------------------------------

async<void> WorldSession::HandleAuthSession()
{
    auto packet = co_await ReadClientPacket();

    FL_LOG_DEBUG("WorldSession", "[{}] Received {} (payload={} bytes)",
        _remoteAddress, packet.opcodeName(), packet.Size());
    FL_LOG_TRACE("WorldSession", "[{}] Raw payload: {}",
        _remoteAddress, StringUtils::HexStr(packet.Data()));

    if (!packet.is(CMSG_AUTH_SESSION))
    {
        FL_LOG_WARNING("WorldSession",
            "[{}] Expected CMSG_AUTH_SESSION (0x{:04X}), got {}",
            _remoteAddress, CMSG_AUTH_SESSION, packet.opcodeName());
        co_return;
    }

    // ---- Cata 4.3.4 bit-packed CMSG_AUTH_SESSION parsing -------------------
    // Bits are stored MSB-first within each byte. After the bit block the
    // reader is flushed to the next byte boundary before sequential reads.

    uint8_t bitByte = 0;
    int32_t bitPos  = -1;   // -1 means "load next byte on first access"

    auto readBit = [&]() -> bool {
        if (bitPos < 0) {
            bitByte = packet.Read<uint8_t>();
            bitPos  = 7;
        }
        return (bitByte >> bitPos--) & 1;
    };
    auto readBits = [&](uint32_t n) -> uint32_t {
        uint32_t result = 0;
        for (uint32_t i = n; i-- > 0;)
            result |= (readBit() ? 1u : 0u) << i;
        return result;
    };

    // Bit fields
    uint32_t nameLen      = readBits(12);
    bool     useIPv6      = readBit();
    bool     hasAddonData = readBit();
    bitPos = -1;    // flush remaining bits of the current byte

    // Byte-aligned sequential fields
    std::array<uint8_t, 4> localChallenge{};
    packet.ReadBytes(localChallenge.data(), 4);

    std::array<uint8_t, 20> digest{};
    for (uint8_t idx : DIGEST_ORDER)
        packet >> digest[idx];

    uint64_t dosResponse{};
    packet >> dosResponse;

    uint32_t realmId{}, loginServerId{};
    packet >> realmId >> loginServerId;

    uint16_t build{};
    packet >> build;

    // Account name: nameLen bytes, no null terminator
    std::string account = packet.ReadString(nameLen);

    _username = StringUtils::ToUpper(account);

    FL_LOG_INFO("WorldSession",
        "[{}] Auth session for '{}' (build={}, realm={}, loginServer={}, useIPv6={})",
        _remoteAddress, _username, build, realmId, loginServerId, useIPv6);
    FL_LOG_TRACE("WorldSession", "[{}] localChallenge: {}",
        _remoteAddress, StringUtils::HexStr(std::span<const uint8_t>(localChallenge)));
    FL_LOG_TRACE("WorldSession", "[{}] Client digest: {}",
        _remoteAddress, StringUtils::HexStr(std::span<const uint8_t>(digest)));

    auto storedKey = co_await _keyStore.Lookup(_username);
    if (!storedKey)
    {
        FL_LOG_WARNING("WorldSession",
            "[{}] No session key for '{}' — ensure authserver stored the key",
            _remoteAddress, _username);
        co_await SendAuthResponse(AuthResponseResult::AUTH_UNKNOWN_ACCOUNT);
        co_return;
    }

    // Verify: SHA1(account, loginServerId[4], localChallenge[4], serverSeed[4], K)
    Crypto::SHA1 sha;
    sha.Update(std::string_view(_username));
    sha.Update(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&loginServerId), 4));
    sha.Update(std::span<const uint8_t>(localChallenge.data(), 4));
    sha.Update(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&_serverSeed), 4));
    sha.Update(std::span<const uint8_t>(*storedKey));

    auto expected = sha.Finalize();
    FL_LOG_TRACE("WorldSession", "[{}] Expected digest: {}",
        _remoteAddress, StringUtils::HexStr(std::span<const uint8_t>(expected)));

    if (digest != expected)
    {
        FL_LOG_WARNING("WorldSession", "[{}] Auth digest mismatch for '{}'",
            _remoteAddress, _username);
        co_await SendAuthResponse(AuthResponseResult::AUTH_INCORRECT_PASSWORD);
        co_return;
    }

    FL_LOG_INFO("WorldSession", "[{}] '{}' authenticated successfully",
        _remoteAddress, _username);
    _authenticated = true;

    // Init ARC4 with the per-session seeds sent in SMSG_AUTH_CHALLENGE.
    _crypt.Init(std::span<const uint8_t>(*storedKey),
                std::span<const uint8_t>(_encryptSeed),
                std::span<const uint8_t>(_decryptSeed));
    FL_LOG_DEBUG("WorldSession", "[{}] ARC4 encryption initialised", _remoteAddress);

    co_await SendAuthResponse(AuthResponseResult::AUTH_OK);
}

// ---- SMSG_AUTH_RESPONSE -----------------------------------------------------

async<void> WorldSession::SendAuthResponse(AuthResponseResult result)
{
    WorldPacket response(SMSG_AUTH_RESPONSE);

    if (result == AuthResponseResult::AUTH_OK)
    {
        // Cata bit-packed: isQueued(0), hasSuccessInfo(1), addonPrefixRulesCount(0, 21 bits)
        // Byte 0: [0][1][000000] = 0x40
        // Byte 1: [00000000]     = 0x00
        // Byte 2: [0000000x]     = 0x00  (flush: last bit padded)
        response << uint8_t(0x40) << uint8_t(0x00) << uint8_t(0x00);
        response << uint32_t(0)            // billingTimeRemaining
                 << EXPANSION_CATACLYSM    // expansion
                 << uint32_t(0)            // billingTimeRested
                 << EXPANSION_CATACLYSM    // expansion
                 << uint32_t(0);           // billingPlanFlags
    }
    else
    {
        // Bit-packed: isQueued(0), hasSuccessInfo(0)
        response << uint8_t(0x00);
    }
    response << std::to_underlying(result);

    FL_LOG_DEBUG("WorldSession", "[{}] Sending SMSG_AUTH_RESPONSE (result=0x{:02X})",
        _remoteAddress, std::to_underlying(result));

    co_await SendPacket(response);
}

// ---- Packet loop (post-auth) ------------------------------------------------

async<void> WorldSession::PacketLoop()
{
    FL_LOG_INFO("WorldSession", "[{}] '{}' entering packet loop",
        _remoteAddress, _username);

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
    co_await boost::asio::async_read(_socket, boost::asio::buffer(headerBuf), boost::asio::use_awaitable);

    _crypt.DecryptRecv(headerBuf.data(), headerBuf.size());

    // 2. Parse opcode and payload size; build an empty WorldPacket.
    WorldPacket packet = WorldPacket::FromCmsgHeader(headerBuf);

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
        co_await boost::asio::async_read(_socket, boost::asio::buffer(payloadBuf), boost::asio::use_awaitable);

        packet.Append(payloadBuf.data(), payloadBuf.size());
    }

    co_return packet;
}

async<void> WorldSession::SendPacket(const WorldPacket& packet)
{
    auto frame = packet.Serialize();
    
    // Encrypt the 4-byte SMSG header in-place.
    // WorldCrypt::EncryptSend is a no-op until Init() has been called.
    _crypt.EncryptSend(frame.data(), WorldPacket::SMSG_HEADER_SIZE);

    co_await boost::asio::async_write(_socket, boost::asio::buffer(frame), boost::asio::use_awaitable);
}
