#include "AuthSession.h"
#include "../Realm/Realm.h"

#include <Network/Auth/AuthOpcode.hpp>
#include <Network/Auth/AuthPacket.hpp>

#include <array>
#include <bit>
#include <cctype>
#include <random>
#include <ranges>
#include <span>
#include <vector>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include <Utils/Log.h>
#include <Utils/StringUtils.h>
#include <Utils/ByteBuffer.h>

#include <Database/Auth/AuthWrapper.h>

using namespace Fireland::Auth;
using namespace Fireland::Utils::Async;
using namespace Fireland::Utils;
using ByteBuffer = Fireland::Utils::ByteBuffer;

// ---- Construction ----------------------------------------------------------

AuthSession::AuthSession(boost::asio::ip::tcp::socket socket) noexcept
    : _socket{std::move(socket)}
	, _status{ AuthSessionStatus::LOGON_CHALLENGE }
    , _remoteAddress{"<unknown>"}
    , _handlers{}
    , _srp{}
    , _username{}
    , _accountId{0}
    , _authenticated{false}
{
    boost::system::error_code ec;
    auto ep = _socket.remote_endpoint(ec);
    if (!ec)
        _remoteAddress = std::format("{}:{}", ep.address().to_string(), ep.port());
    else
        _remoteAddress = "<unknown>";

    _handlers[AuthOpcode::CMD_AUTH_LOGON_CHALLENGE] = {AuthSessionStatus::LOGON_CHALLENGE, [this](AuthPacket packet) { return HandleLogonChallenge(std::move(packet)); }};
	_handlers[AuthOpcode::CMD_AUTH_LOGON_PROOF] = { AuthSessionStatus::LOGON_PROOF, [this](AuthPacket packet) { return HandleLogonProof(std::move(packet)); } };
	//_handlers[AuthOpcode::CMD_AUTH_RECONNECT_CHALLENGE] = { AuthSessionStatus::LOGON_CHALLENGE, [this](AuthPacket packet) { return HandleReconnectChallenge(std::move(packet)); } };
	_handlers[AuthOpcode::CMD_AUTH_RECONNECT_PROOF] = { AuthSessionStatus::RECONNECT_PROOF, [this](AuthPacket packet) { return HandleReconnectProof(std::move(packet)); } };
	_handlers[AuthOpcode::CMD_REALM_LIST] = { AuthSessionStatus::WAIT_FOR_REALM_LIST, [this](AuthPacket packet) { return HandleRealmList(std::move(packet)); } };
}

AuthSession::~AuthSession() noexcept
{
    FL_LOG_INFO("AuthSession", "Client disconnected from {}", _remoteAddress);
}

// ---- Main coroutine --------------------------------------------------------

void AuthSession::Start()
{
    auto self = shared_from_this();
    boost::asio::co_spawn(_socket.get_executor(), self->Run(), boost::asio::detached);
}

async<void> AuthSession::Run()
{
    auto self = shared_from_this(); // prevent premature destruction

    FL_LOG_INFO("AuthSession", "Client connected from {}", _remoteAddress);

    try
    {
        while (_socket.is_open())
        {
            // 1. Read the first byte to get the opcode
            AuthOpcode opcode = AuthOpcode::NONE;
            auto readed_bytes = co_await boost::asio::async_read(_socket, boost::asio::buffer(&opcode, 1), boost::asio::use_awaitable);
            FL_LOG_DEBUG("AuthSession", "Read packetdata for opcode {} ({} bytes)", Utils::Describe::to_string(opcode), readed_bytes);

            // 2. Read the rest of the packet based on opcode
            std::vector<uint8_t> buffer(1024);
            readed_bytes = co_await _socket.async_read_some(boost::asio::buffer(buffer.data(), 1024), boost::asio::use_awaitable);
            FL_LOG_DEBUG("AuthSession", "Packetdata read complete ({} bytes)", readed_bytes);

            // 3. Dispatch to handler
            AuthPacket packet(opcode, 1024);
            packet.Append(buffer.data(), readed_bytes);

            if (readed_bytes == 0)
            {
                FL_LOG_INFO("AuthSession", "[{}] Connection closed by peer", _remoteAddress);
                co_return;
            }

			auto handlerIt = _handlers.find(opcode);
			if (handlerIt == _handlers.end())
            {
                FL_LOG_WARNING("AuthSession", "[{}] No handler for opcode {} (0x{:02X})", _remoteAddress, Utils::Describe::to_string(opcode), uint8_t(opcode));
                co_return;
			}
			if (_status != handlerIt->second.status)
            {
                FL_LOG_WARNING("AuthSession", "[{}] Received opcode {} (0x{:02X}) in invalid state (current: {}, required: {})", _remoteAddress, Utils::Describe::to_string(opcode), uint8_t(opcode), Utils::Describe::to_string(_status), Utils::Describe::to_string(handlerIt->second.status));
                co_return;
            }
            co_await handlerIt->second.handler(std::move(packet));
        }
    }
    catch (const boost::system::system_error& e)
    {
        if (e.code() != boost::asio::error::eof &&
            e.code() != boost::asio::error::operation_aborted &&
            e.code() != boost::asio::error::connection_reset)
        {
            FL_LOG_ERROR("AuthSession", "[{}] Error: {}", _remoteAddress, e.what());
        }
    }
    catch (const std::exception& e)
    {
        FL_LOG_ERROR("AuthSession", "[{}] Exception: {}", _remoteAddress, e.what());
    }

    FL_LOG_INFO("AuthSession", "[{}] Disconnected", _remoteAddress);
}

// ---- LOGON_CHALLENGE -------------------------------------------------------

async<void> AuthSession::HandleLogonChallenge(AuthPacket packet)
{
    AuthLogonChallenge_C auth_c(packet);
    
    FL_LOG_DEBUG("AuthSession", "[{}] Challenge fields: error=0x{:02X}, size={}, build={}, account_len={}", _remoteAddress, auth_c.error, auth_c.size, auth_c.build, auth_c.account_len);

    _username = StringUtils::ToUpper(auth_c.account_name);
    FL_LOG_INFO("AuthSession", "[{}] Logon challenge for '{}' (raw: '{}', len={})", _remoteAddress, _username, auth_c.account_name, auth_c.account_len);

    auto account = co_await sAuthDB.GetAccountByUsername(_username);
    if (!account)
    {
        FL_LOG_WARNING("AuthSession", "[{}] Unknown account '{}'", _remoteAddress, _username);
        co_await SendChallengeError(ResponseCodes::AUTH_UNKNOWN_ACCOUNT);
        co_return;
    }

    // Validate stored credentials before using them in SRP6
    if (account->salt.size() != 32 || account->verifier.empty())
    {
        FL_LOG_ERROR("AuthSession", "[{}] account '{}' has invalid credentials in DB (salt={} bytes, verifier={} bytes)", _remoteAddress, _username, account->salt.size(), account->verifier.size());
        co_await SendChallengeError(ResponseCodes::AUTH_UNKNOWN_ACCOUNT);
        co_return;
    }

    FL_LOG_DEBUG("AuthSession", "[{}] Account matched, setting up SRP6 challenge...", _remoteAddress);
    _accountId = account->id; // store account ID for later use

    // Compute SRP6 verifier and generate challenge
    Crypto::BigNumber salt, verifier;
    salt.SetBinary(account->salt);
    verifier.SetBinary(account->verifier);
    _srp.SetVerifier(_username, salt, verifier);
    _srp.GenerateChallenge();
    auto& B = _srp.GetB();
    auto& g = Crypto::SRP6::g;
    auto& N = Crypto::SRP6::N;
    auto g_bytes = g.AsByteArray(1);
    auto N_bytes = N.AsByteArray(32);

    ByteBuffer response(119);
    response << AuthOpcode::CMD_AUTH_LOGON_CHALLENGE                     // cmd
             << uint8_t(0x00)                                            // unk
             << std::to_underlying(ResponseCodes::RESPONSE_SUCCESS)      // error
             << B.AsByteArray(32)                                        // B (32 bytes)
             << static_cast<uint8_t>(g_bytes.size()) << g_bytes          // g_len + g
             << static_cast<uint8_t>(N_bytes.size()) << N_bytes          // N_len + N
             << salt.AsByteArray(32);                                    // salt (32 bytes)
    response.Pad(16);                                                    // CRC salt (16 zero bytes)
    response << uint8_t(0x00);                                           // security_flags

    FL_LOG_DEBUG("AuthSession", "[{}] Sending challenge response ({} bytes)", _remoteAddress, response.Size());
    FL_LOG_TRACE("AuthSession", "[{}] Challenge response: {}", _remoteAddress, StringUtils::HexStr(response.Data()));

	_status = AuthSessionStatus::LOGON_PROOF;
    co_await boost::asio::async_write(_socket, boost::asio::buffer(response.Storage()), boost::asio::use_awaitable);
    FL_LOG_DEBUG("AuthSession", "[{}] Challenge response sent, waiting for proof...", _remoteAddress);
}

// ---- LOGON_PROOF -----------------------------------------------------------

async<void> AuthSession::HandleLogonProof(AuthPacket packet)
{
    AuthLogonProof_C proof_c(packet);

    FL_LOG_DEBUG("AuthSession", "[{}] Logon proof received ({} bytes)", _remoteAddress, packet.Size());
    FL_LOG_TRACE("AuthSession", "[{}] Proof raw: {}", _remoteAddress, StringUtils::HexStr(packet.Data()));

    // Parse A and M1
    Crypto::BigNumber A;
    A.SetBinary(proof_c.A);

    Crypto::SHA1::Digest clientM1{};
    std::ranges::copy_n(proof_c.M1.data(), 20, clientM1.begin());

    FL_LOG_TRACE("AuthSession", "[{}] Client A ({} bytes): {}", _remoteAddress, 32, StringUtils::HexStr(proof_c.A));
    FL_LOG_TRACE("AuthSession", "[{}] Client M1 (20 bytes): {}", _remoteAddress, StringUtils::HexStr(clientM1));

    if (!_srp.VerifyClientProof(A, clientM1))
    {
        FL_LOG_WARNING("AuthSession", "[{}] Invalid logon proof (SRP6 verification failed) for '{}'", _remoteAddress, _username);

        ByteBuffer fail(4);
        fail << AuthOpcode::CMD_AUTH_LOGON_PROOF
             << std::to_underlying(ResponseCodes::AUTH_INCORRECT_PASSWORD)
             << uint8_t(0x03) << uint8_t(0x00);

        co_await boost::asio::async_write(_socket, boost::asio::buffer(fail.Storage()), boost::asio::use_awaitable);
        co_return;
    }

    FL_LOG_INFO("AuthSession", "[{}] '{}' authenticated successfully", _remoteAddress, _username);
    _authenticated = true;

    // Store session key for future reconnects and world server handoff
    co_await sAuthDB.StoreSessionKey(_accountId, _srp.GetSessionKey());

    // Build success response
    auto& M2 = _srp.GetServerProof();

    ByteBuffer response(32);
    response << AuthOpcode::CMD_AUTH_LOGON_PROOF // cmd
             << std::to_underlying(ResponseCodes::RESPONSE_SUCCESS)  // error
             << M2;                              // M2 (20 bytes)
    response.Pad(10); // account_flags (uint32) + survey_id (uint32) + login_flags (uint16)

    FL_LOG_DEBUG("AuthSession", "[{}] Sending proof success response ({} bytes)", _remoteAddress, response.Size());
    FL_LOG_TRACE("AuthSession", "[{}] Proof response: {}",
        _remoteAddress, StringUtils::HexStr(response.Data()));

	_status = AuthSessionStatus::WAIT_FOR_REALM_LIST;
    co_await boost::asio::async_write(_socket, boost::asio::buffer(response.Storage()), boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Proof response sent, waiting for realm list request...", _remoteAddress);
}

// ---- RECONNECT_CHALLENGE ---------------------------------------------------

async<void> AuthSession::HandleReconnectChallenge(AuthPacket packet)
{
    // Same header format as logon challenge (minus the cmd byte we already consumed)
    constexpr std::size_t HEADER_REMAINING = sizeof(AuthLogonChallenge_C) - 1;

    std::array<uint8_t, HEADER_REMAINING> headerBuf{};
    co_await boost::asio::async_read(
        _socket, boost::asio::buffer(headerBuf),
        boost::asio::use_awaitable);

    // account_len is the last byte of the fixed header
    uint8_t accountLen = headerBuf[HEADER_REMAINING - 1];

    // Read the account name
    std::vector<uint8_t> accountBuf(accountLen);
    co_await boost::asio::async_read(
        _socket, boost::asio::buffer(accountBuf),
        boost::asio::use_awaitable);

    std::string rawAccount(accountBuf.begin(), accountBuf.end());
    _username = StringUtils::ToUpper(rawAccount);

    FL_LOG_INFO("AuthSession", "[{}] Reconnect challenge for '{}'", _remoteAddress, _username);

    // Look up stored session key
    auto storedKey = co_await sAuthDB.LookupSessionKey(_accountId);
    if (!storedKey)
    {
        FL_LOG_WARNING("AuthSession", "[{}] Reconnect failed: no session key stored for '{}'",
            _remoteAddress, _username);

        ByteBuffer fail(3);
        fail << AuthOpcode::CMD_AUTH_RECONNECT_CHALLENGE
             << std::to_underlying(ResponseCodes::AUTH_UNKNOWN_ACCOUNT);
        co_await boost::asio::async_write(
            _socket, boost::asio::buffer(fail.Storage()),
            boost::asio::use_awaitable);
        co_return;
    }

    // Generate 16 random bytes for the reconnect proof
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned> dist(0, 255);
    for (auto& byte : _reconnectRand)
        byte = static_cast<uint8_t>(dist(gen));

    FL_LOG_DEBUG("AuthSession", "[{}] Sending reconnect challenge (16 random bytes)", _remoteAddress);
    FL_LOG_TRACE("AuthSession", "[{}] Reconnect rand: {}",
        _remoteAddress, StringUtils::HexStr(_reconnectRand));

    // Response: cmd(1) + error(1) + reconnect_rand(16) + zeros(16)
    ByteBuffer response(34);
    response << AuthOpcode::CMD_AUTH_RECONNECT_CHALLENGE
             << std::to_underlying(ResponseCodes::RESPONSE_SUCCESS);
    response.Append(_reconnectRand.data(), _reconnectRand.size());
    response.Pad(16);  // 16 zero bytes

    co_await boost::asio::async_write(_socket, boost::asio::buffer(response.Storage()), boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Reconnect challenge sent, waiting for reconnect proof...", _remoteAddress);
}

// ---- RECONNECT_PROOF -------------------------------------------------------

async<void> AuthSession::HandleReconnectProof(AuthPacket packet)
{
    // Read the rest of AuthReconnectProof_C (cmd already consumed)
    constexpr std::size_t PROOF_REMAINING = sizeof(AuthReconnectProof_C) - 1;

    std::array<uint8_t, PROOF_REMAINING> proofBuf{};
    co_await boost::asio::async_read(
        _socket, boost::asio::buffer(proofBuf),
        boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Reconnect proof received ({} bytes)", _remoteAddress, PROOF_REMAINING);

    // Parse R1 (16 bytes) and R2 (20 bytes)
    std::span<const uint8_t> R1(proofBuf.data(), 16);
    std::span<const uint8_t> R2(proofBuf.data() + 16, 20);

    FL_LOG_TRACE("AuthSession", "[{}] R1: {}", _remoteAddress, StringUtils::HexStr(R1));
    FL_LOG_TRACE("AuthSession", "[{}] R2: {}", _remoteAddress, StringUtils::HexStr(R2));

    // Look up stored session key
    auto storedKey = co_await sAuthDB.LookupSessionKey(_accountId);
    if (!storedKey)
    {
        FL_LOG_WARNING("AuthSession", "[{}] Reconnect proof failed: no session key for '{}'",
            _remoteAddress, _username);

        ByteBuffer fail(2);
        fail << AuthOpcode::CMD_AUTH_RECONNECT_PROOF
             << std::to_underlying(ResponseCodes::AUTH_UNKNOWN_ACCOUNT);
        co_await boost::asio::async_write(
            _socket, boost::asio::buffer(fail.Storage()),
            boost::asio::use_awaitable);
        co_return;
    }

    // Verify: R2 == SHA1(username, R1, reconnect_rand, K)
    Crypto::SHA1 sha;
    sha.Update(_username);
    sha.Update(R1);
    sha.Update(std::span<const uint8_t>(_reconnectRand));
    sha.Update(std::span<const uint8_t>(*storedKey));
    auto expected = sha.Finalize();

    if (!std::ranges::equal(R2, expected))
    {
        FL_LOG_WARNING("AuthSession", "[{}] Reconnect proof verification failed for '{}'",
            _remoteAddress, _username);

        ByteBuffer fail(2);
        fail << AuthOpcode::CMD_AUTH_RECONNECT_PROOF
             << std::to_underlying(ResponseCodes::AUTH_INCORRECT_PASSWORD);
        co_await boost::asio::async_write(
            _socket, boost::asio::buffer(fail.Storage()),
            boost::asio::use_awaitable);
        co_return;
    }

    FL_LOG_INFO("AuthSession", "[{}] '{}' reconnected successfully", _remoteAddress, _username);
    _authenticated = true;

    // Response: cmd(1) + error(1) + padding(2)
    ByteBuffer response(4);
    response << AuthOpcode::CMD_AUTH_RECONNECT_PROOF
             << std::to_underlying(ResponseCodes::RESPONSE_SUCCESS);
    response.Pad(2);

	_status = AuthSessionStatus::WAIT_FOR_REALM_LIST;
    co_await boost::asio::async_write(_socket, boost::asio::buffer(response.Storage()), boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Reconnect proof accepted, waiting for realm list...", _remoteAddress);
}

// ---- REALM_LIST ------------------------------------------------------------

async<void> AuthSession::HandleRealmList(AuthPacket packet)
{
    FL_LOG_DEBUG("AuthSession", "[{}] Realm list requested", _remoteAddress);

    // Build realm entries
    ByteBuffer realmData;
    auto realms = sRealm.GetRealms();
    for (auto const& realm : *realms)
    {
        std::string address = std::format("{}:{}", realm.address, realm.port);
        FL_LOG_DEBUG("AuthSession", "[{}] Realm '{}' -> {} for client", _remoteAddress, realm.name, address);

        realmData << static_cast<uint8_t>(realm.type)
                  << static_cast<uint8_t>(realm.allowedSecurityLevel)
                  << static_cast<uint8_t>(realm.flag)
                  << realm.name
                  << address
                  << realm.population
                  << uint8_t(0) // characters count
                  << static_cast<uint8_t>(realm.timezone)
                  << static_cast<uint8_t>(realm.id);
    }

    // Build full response
    // body = uint32 padding(0) + uint16 realm_count + realm data + uint16 footer(0x0010)
    ByteBuffer body;
    body.Pad(4);                  // padding
    body << static_cast<uint16_t>(realms->size())
         << realmData             // realm data
         << uint8_t(0x10)         // footer
         << uint8_t(0x00);

    // Header: opcode + uint16 body size
    ByteBuffer response;
    response << AuthOpcode::CMD_REALM_LIST
             << static_cast<uint16_t>(body.Size())
             << body;

    FL_LOG_DEBUG("AuthSession", "[{}] Sending realm list response ({} bytes, body={} bytes)",
        _remoteAddress, response.Size(), body.Size());
    FL_LOG_TRACE("AuthSession", "[{}] Realm list response: {}",
        _remoteAddress, StringUtils::HexStr(response.Data()));

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(response.Storage()),
        boost::asio::use_awaitable);
}

// ---- Error helpers ---------------------------------------------------------

async<void> AuthSession::SendChallengeError(ResponseCodes error)
{
    ByteBuffer response(3);
    response << AuthOpcode::CMD_AUTH_LOGON_CHALLENGE
             << uint8_t(0x00)
             << std::to_underlying(error);

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(response.Storage()),
        boost::asio::use_awaitable);
}
