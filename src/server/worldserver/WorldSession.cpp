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
    // Generate random server seed
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> seedDist;
    _serverSeed = seedDist(gen);

    // Generate encryption seeds (for future ARC4 init)
    /*std::uniform_int_distribution<unsigned> byteDist(0, 255);
    for (auto& b : _encryptSeed) b = static_cast<uint8_t>(byteDist(gen));
    for (auto& b : _decryptSeed) b = static_cast<uint8_t>(byteDist(gen));*/

    // Payload: uint32(1) + uint32(serverSeed) + encryptSeed(16) + decryptSeed(16)
    /*challenge << uint32_t(1) << _serverSeed;
    challenge.Append(_encryptSeed.data(), _encryptSeed.size());
    challenge.Append(_decryptSeed.data(), _decryptSeed.size());*/

    ByteBuffer challenge;

    auto sz = static_cast<uint16_t>(4 + 4 + 2 + 16 + 16); // payload size: uint32(serverSeed) + encryptSeed(16) + decryptSeed(16)
    auto op = static_cast<uint16_t>(SMSG_AUTH_CHALLENGE);

    challenge << static_cast<uint8_t>(sz >> 8)  // size  high byte (BE)
            << static_cast<uint8_t>(sz & 0xFF)  // size  low  byte (BE)
            << static_cast<uint8_t>(op & 0xFF)  // opcode low  byte (LE)
            << static_cast<uint8_t>(op >> 8);   // opcode high byte (LE)

    challenge.Append(Crypto::WorldCrypt::kEncryptSeed.data(), Crypto::WorldCrypt::kEncryptSeed.size());
    challenge.Append(Crypto::WorldCrypt::kDecryptSeed.data(), Crypto::WorldCrypt::kDecryptSeed.size());
    challenge << _serverSeed << uint8_t(1);

    FL_LOG_DEBUG("WorldSession", "[{}] Sending SMSG_AUTH_CHALLENGE (seed=0x{:08X}, {} bytes)", _remoteAddress, _serverSeed, challenge.Size());

    co_await boost::asio::async_write(_socket, boost::asio::buffer(challenge.Storage()), boost::asio::use_awaitable);
}

// ---- CMSG_AUTH_SESSION ------------------------------------------------------
#include <boost/endian/arithmetic.hpp>
typedef struct AUTH_LOGON_CHALLENGE_C
{
    uint8_t   cmd;
    uint8_t   error;
    boost::endian::little_uint16_t size;
    boost::endian::little_uint32_t gamename;
    uint8_t   version1;
    uint8_t   version2;
    uint8_t   version3;
    boost::endian::little_uint16_t build;
    boost::endian::little_uint32_t platform;
    boost::endian::little_uint32_t os;
    boost::endian::little_uint32_t country;
    boost::endian::little_uint32_t timezone_bias;
    boost::endian::little_uint32_t ip;
    uint8_t   I_len;
    char    I[1];
} sAuthLogonChallenge_C;
static_assert(sizeof(sAuthLogonChallenge_C) == (1 + 1 + 2 + 4 + 1 + 1 + 1 + 2 + 4 + 4 + 4 + 4 + 4 + 1 + 1));
async<void> WorldSession::HandleAuthSession()
{
    // CMSG_AUTH_SESSION is the first encrypted packet from the client.
    auto packet = co_await ReadClientPacket();

    constexpr static auto AUTH_LOGON_CHALLENGE_INITIAL_SIZE = 4;
    const sAuthLogonChallenge_C* challenge = reinterpret_cast<const sAuthLogonChallenge_C*>(packet.Data().data());
    if (challenge->size - (sizeof(sAuthLogonChallenge_C) - AUTH_LOGON_CHALLENGE_INITIAL_SIZE - 1) != challenge->I_len)
        co_return;

    FL_LOG_DEBUG("WorldSession", "[{}] Received {} (payload={} bytes)", _remoteAddress, packet.opcodeName(), packet.Size());

    if (!packet.is(CMSG_AUTH_SESSION))
    {
        FL_LOG_WARNING("WorldSession", "[{}] Expected CMSG_AUTH_SESSION (0x{:04X}), got {}", _remoteAddress, CMSG_AUTH_SESSION, packet.opcodeName());
        co_return;
    }

    FL_LOG_DEBUG("WorldSession", "[{}] CMSG_AUTH_SESSION payload ({} bytes)", _remoteAddress, packet.Size());
    FL_LOG_TRACE("WorldSession", "[{}] Raw payload: {}", _remoteAddress, StringUtils::HexStr(packet.Data()));

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
