#include "WorldSession.h"

#include <cctype>
#include <cstring>
#include <random>

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
    if (!ec)
        _remoteAddress = std::format("{}:{}", ep.address().to_string(), ep.port());
    else
        _remoteAddress = "<unknown>";
}

WorldSession::~WorldSession() noexcept
{
    FL_LOG_INFO("WorldSession", "[{}] Client disconnected", _remoteAddress);
}

// ---- Main coroutine --------------------------------------------------------

void WorldSession::Start()
{
    auto self = shared_from_this();
    boost::asio::co_spawn(
        _socket.get_executor(),
        self->Run(),
        boost::asio::detached
    );
}

async<void> WorldSession::Run()
{
    auto self = shared_from_this();

    FL_LOG_INFO("WorldSession", "[{}] Client connected", _remoteAddress);

    try
    {
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

// ---- SMSG_AUTH_CHALLENGE ---------------------------------------------------

async<void> WorldSession::SendAuthChallenge()
{
    // Generate random server seed
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> seedDist;
    _serverSeed = seedDist(gen);

    // Generate encryption seeds (for future ARC4 init)
    std::uniform_int_distribution<unsigned> byteDist(0, 255);
    for (auto& b : _encryptSeed) b = static_cast<uint8_t>(byteDist(gen));
    for (auto& b : _decryptSeed) b = static_cast<uint8_t>(byteDist(gen));

    // Payload: uint32(1) + uint32(serverSeed) + encryptSeed(16) + decryptSeed(16)
    ByteBuffer payload(40);
    payload << uint32_t(1)
            << _serverSeed;
    payload.Append(_encryptSeed.data(), _encryptSeed.size());
    payload.Append(_decryptSeed.data(), _decryptSeed.size());

    // Build packet with server header
    ByteBuffer packet(4 + payload.Size());
    WriteServerHeader(packet, SMSG_AUTH_CHALLENGE, static_cast<uint16_t>(payload.Size()));
    packet << payload;

    FL_LOG_DEBUG("WorldSession", "[{}] Sending SMSG_AUTH_CHALLENGE (seed=0x{:08X}, {} bytes)",
        _remoteAddress, _serverSeed, packet.Size());

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(packet.Storage()),
        boost::asio::use_awaitable);
}

// ---- CMSG_AUTH_SESSION -----------------------------------------------------

async<void> WorldSession::HandleAuthSession()
{
    // Read client header
    auto header = co_await ReadClientHeader();

    FL_LOG_DEBUG("WorldSession", "[{}] Received opcode 0x{:04X} (size={})",
        _remoteAddress, header.opcode, header.size);

    if (header.opcode != CMSG_AUTH_SESSION)
    {
        FL_LOG_WARNING("WorldSession", "[{}] Expected CMSG_AUTH_SESSION (0x{:04X}), got 0x{:04X}",
            _remoteAddress, CMSG_AUTH_SESSION, header.opcode);
        co_return;
    }

    // Read payload (size includes the 4-byte opcode, which we already consumed)
    uint16_t payloadSize = header.size - 4;
    std::vector<uint8_t> rawPayload(payloadSize);
    co_await boost::asio::async_read(
        _socket, boost::asio::buffer(rawPayload),
        boost::asio::use_awaitable);

    FL_LOG_DEBUG("WorldSession", "[{}] CMSG_AUTH_SESSION payload ({} bytes)", _remoteAddress, payloadSize);
    FL_LOG_TRACE("WorldSession", "[{}] Raw payload: {}", _remoteAddress, StringUtils::HexStr(rawPayload));

    // Parse fields (Cata 4.3.4 specific order)
    ByteBuffer payload(std::move(rawPayload));

    uint32_t clientBuild{}, loginServerType{}, regionId{}, battlegroupId{}, realmId{};
    uint64_t dosResponse{};
    uint32_t clientSeed{}, unknown0{};

    payload >> clientBuild
            >> loginServerType
            >> regionId
            >> battlegroupId
            >> realmId
            >> dosResponse;

    FL_LOG_DEBUG("WorldSession", "[{}] Build={}, region={}, battlegroup={}, realm={}",
        _remoteAddress, clientBuild, regionId, battlegroupId, realmId);

    // Read shuffled digest (Cata 4.3.4 specific byte order)
    std::array<uint8_t, 20> digest{};
    for (uint8_t idx : DIGEST_ORDER)
        payload >> digest[idx];

    payload >> clientSeed
            >> unknown0;

    // Read null-terminated account name
    std::string account;
    while (payload.Remaining() > 0)
    {
        auto c = payload.Read<uint8_t>();
        if (c == 0) break;
        account += static_cast<char>(c);
    }
    // Remaining bytes are compressed addon data (ignored for now)

    _username = StringUtils::ToUpper(account);

    FL_LOG_INFO("WorldSession", "[{}] Auth session for '{}' (build={}, clientSeed=0x{:08X})",
        _remoteAddress, _username, clientBuild, clientSeed);
    FL_LOG_TRACE("WorldSession", "[{}] Client digest: {}", _remoteAddress, StringUtils::HexStr(digest));

    // Look up stored session key
    // NOTE: In production, the session key should be loaded from the database
    // (written by the authserver after successful SRP6 authentication).
    auto storedKey = co_await _keyStore.Lookup(_username);
    if (!storedKey)
    {
        FL_LOG_WARNING("WorldSession",
            "[{}] No session key found for '{}' — "
            "ensure the authserver stored the key (database integration needed)",
            _remoteAddress, _username);
        co_await SendAuthResponse(AuthResponseResult::AUTH_UNKNOWN_ACCOUNT);
        co_return;
    }

    // Verify digest: SHA1(account, uint32(0), clientSeed, serverSeed, K)
    Crypto::SHA1 sha;
    sha.Update(std::string_view(_username));

    uint32_t zero = 0;
    sha.Update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&zero), 4));
    sha.Update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&clientSeed), 4));
    sha.Update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&_serverSeed), 4));
    sha.Update(std::span<const uint8_t>(*storedKey));

    auto expected = sha.Finalize();

    FL_LOG_TRACE("WorldSession", "[{}] Expected digest: {}", _remoteAddress, StringUtils::HexStr(expected));

    if (digest != expected)
    {
        FL_LOG_WARNING("WorldSession", "[{}] Auth digest mismatch for '{}'", _remoteAddress, _username);
        co_await SendAuthResponse(AuthResponseResult::AUTH_INCORRECT_PASSWORD);
        co_return;
    }

    FL_LOG_INFO("WorldSession", "[{}] '{}' authenticated successfully", _remoteAddress, _username);
    _authenticated = true;

    // TODO: Initialise ARC4 encryption with _encryptSeed, _decryptSeed, and session key

    co_await SendAuthResponse(AuthResponseResult::AUTH_OK);
}

// ---- SMSG_AUTH_RESPONSE ----------------------------------------------------

async<void> WorldSession::SendAuthResponse(AuthResponseResult result)
{
    ByteBuffer payload(20);

    if (result == AuthResponseResult::AUTH_OK)
    {
        // Cata bit-packed: isQueued(0), hasSuccessInfo(1), addonPrefixRulesCount(0, 21 bits)
        // Byte 0: [0][1][000000] = 0x40
        // Byte 1: [00000000]     = 0x00
        // Byte 2: [0000000x]     = 0x00  (flush: last bit padded)
        payload << uint8_t(0x40) << uint8_t(0x00) << uint8_t(0x00);
        payload << uint32_t(0)             // billingTimeRemaining
                << EXPANSION_CATACLYSM     // expansion
                << uint32_t(0)             // billingTimeRested
                << EXPANSION_CATACLYSM     // expansion
                << uint32_t(0);            // billingPlanFlags
    }
    else
    {
        // Bit-packed: isQueued(0), hasSuccessInfo(0)
        // Byte 0: [00000000] = 0x00
        payload << uint8_t(0x00);
    }

    payload << std::to_underlying(result);

    ByteBuffer packet(4 + payload.Size());
    WriteServerHeader(packet, SMSG_AUTH_RESPONSE, static_cast<uint16_t>(payload.Size()));
    packet << payload;

    FL_LOG_DEBUG("WorldSession", "[{}] Sending SMSG_AUTH_RESPONSE (result=0x{:02X}, {} bytes)",
        _remoteAddress, std::to_underlying(result), packet.Size());

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(packet.Storage()),
        boost::asio::use_awaitable);
}

// ---- Packet loop (post-auth placeholder) -----------------------------------

async<void> WorldSession::PacketLoop()
{
    FL_LOG_INFO("WorldSession", "[{}] '{}' entering packet loop", _remoteAddress, _username);

    while (_socket.is_open())
    {
        auto header = co_await ReadClientHeader();

        FL_LOG_DEBUG("WorldSession", "[{}] Opcode 0x{:04X} (size={})",
            _remoteAddress, header.opcode, header.size);

        // Read and discard payload for now
        uint16_t payloadSize = header.size > 4 ? header.size - 4 : 0;
        if (payloadSize > 0)
        {
            std::vector<uint8_t> buf(payloadSize);
            co_await boost::asio::async_read(
                _socket, boost::asio::buffer(buf),
                boost::asio::use_awaitable);

            FL_LOG_TRACE("WorldSession", "[{}] Payload ({} bytes): {}",
                _remoteAddress, payloadSize, StringUtils::HexStr(buf));
        }

        // TODO: Dispatch world opcodes (CMSG_CHAR_ENUM, CMSG_PLAYER_LOGIN, etc.)
    }
}

// ---- Header helpers --------------------------------------------------------

void WorldSession::WriteServerHeader(ByteBuffer& buf, uint16_t opcode, uint16_t payloadSize)
{
    // Server → Client header: [uint16 size (big-endian)][uint16 opcode (little-endian)]
    // size = opcode_size(2) + payload_size
    uint16_t size = 2 + payloadSize;
    buf << static_cast<uint8_t>(size >> 8)
        << static_cast<uint8_t>(size & 0xFF);
    buf << opcode;
}

async<WorldSession::ClientHeader> WorldSession::ReadClientHeader()
{
    // Client → Server header: [uint16 size (big-endian)][uint32 opcode (little-endian)]
    std::array<uint8_t, 6> headerBuf{};
    co_await boost::asio::async_read(
        _socket, boost::asio::buffer(headerBuf),
        boost::asio::use_awaitable);

    ClientHeader hdr{};
    hdr.size = (static_cast<uint16_t>(headerBuf[0]) << 8) | headerBuf[1];
    std::memcpy(&hdr.opcode, headerBuf.data() + 2, 4);

    co_return hdr;
}
