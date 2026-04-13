#include "AuthSession.h"
#include "AuthOpcode.h"

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
#include <Utils/ByteBuffer.h>

namespace Fireland::Auth {

using Utils::Async::async;
using Utils::ByteBuffer;

// ---- Hardcoded test account ------------------------------------------------
static constexpr std::string_view HARDCODED_USERNAME = "ATIDOTE";
static constexpr std::string_view HARDCODED_PASSWORD = "ATIDOTE";

static std::string ToUpper(std::string_view sv)
{
    return sv
        | std::views::transform([](unsigned char c) -> char {
            return static_cast<char>(std::toupper(c));
          })
        | std::ranges::to<std::string>();
}

static std::string HexStr(std::span<const uint8_t> data)
{
    return data
        | std::views::transform([](uint8_t b) { return std::format("{:02X}", b); })
        | std::views::join_with(' ')
        | std::ranges::to<std::string>();
}

// ---- Construction ----------------------------------------------------------

AuthSession::AuthSession(boost::asio::ip::tcp::socket socket, Network::SessionKeyStore& keyStore) noexcept
    : _socket(std::move(socket))
    , _keyStore(keyStore)
{
    boost::system::error_code ec;
    auto ep = _socket.remote_endpoint(ec);
    if (!ec)
        _remoteAddress = std::format("{}:{}", ep.address().to_string(), ep.port());
    else
        _remoteAddress = "<unknown>";

    InitRealms();
}

AuthSession::~AuthSession() noexcept
{
    FL_LOG_INFO("AuthSession", "Client disconnected from {}", _remoteAddress);
}

// ---- Main coroutine --------------------------------------------------------

void AuthSession::Start()
{
    auto self = shared_from_this();
    boost::asio::co_spawn(
        _socket.get_executor(),
        self->Run(),
        boost::asio::detached
    );
}

async<void> AuthSession::Run()
{
    auto self = shared_from_this(); // prevent premature destruction

    FL_LOG_INFO("AuthSession", "Client connected from {}", _remoteAddress);

    try
    {
        while (_socket.is_open())
        {
            // Read the opcode byte
            uint8_t cmd = 0;
            co_await boost::asio::async_read(
                _socket, boost::asio::buffer(&cmd, 1),
                boost::asio::use_awaitable);

            switch (static_cast<AuthOpcode>(cmd))
            {
                case AuthOpcode::CMD_AUTH_LOGON_CHALLENGE:
                    co_await HandleLogonChallenge();
                    break;

                case AuthOpcode::CMD_AUTH_LOGON_PROOF:
                    co_await HandleLogonProof();
                    break;

                case AuthOpcode::CMD_AUTH_RECONNECT_CHALLENGE:
                    co_await HandleReconnectChallenge();
                    break;

                case AuthOpcode::CMD_AUTH_RECONNECT_PROOF:
                    co_await HandleReconnectProof();
                    break;

                case AuthOpcode::CMD_REALM_LIST:
                    co_await HandleRealmList();
                    break;

                default:
                    FL_LOG_WARNING("AuthSession", "[{}] Unknown opcode 0x{:02x}", _remoteAddress, cmd);
                    co_return;
            }
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

    FL_LOG_INFO("AuthSession", "[{}] Disconnected", _remoteAddress);
}

// ---- LOGON_CHALLENGE -------------------------------------------------------

async<void> AuthSession::HandleLogonChallenge()
{
    // Read the rest of the fixed-size header (we already consumed the cmd byte)
    // AuthLogonChallenge_C minus the cmd byte = sizeof(AuthLogonChallenge_C) - 1
    constexpr std::size_t HEADER_REMAINING = sizeof(AuthLogonChallenge_C) - 1;

    std::array<uint8_t, HEADER_REMAINING> headerBuf{};
    co_await boost::asio::async_read(
        _socket, boost::asio::buffer(headerBuf),
        boost::asio::use_awaitable);

    FL_LOG_TRACE("AuthSession", "[{}] Challenge header ({} bytes): {}",
        _remoteAddress, HEADER_REMAINING, HexStr(headerBuf));

    // Parse key fields from header for logging
    uint8_t  errorField = headerBuf[0];
    uint16_t sizeField  = headerBuf[1] | (headerBuf[2] << 8);
    uint16_t buildField = headerBuf[10] | (headerBuf[11] << 8);

    // account_len is the last byte of the fixed header
    uint8_t accountLen = headerBuf[HEADER_REMAINING - 1];

    FL_LOG_DEBUG("AuthSession", "[{}] Challenge fields: error=0x{:02X}, size={}, build={}, account_len={}",
        _remoteAddress, errorField, sizeField, buildField, accountLen);

    // Read the account name
    std::vector<uint8_t> accountBuf(accountLen);
    co_await boost::asio::async_read(
        _socket, boost::asio::buffer(accountBuf),
        boost::asio::use_awaitable);

    std::string rawAccount(accountBuf.begin(), accountBuf.end());
    _username = ToUpper(rawAccount);
    FL_LOG_INFO("AuthSession", "[{}] Logon challenge for '{}' (raw: '{}', len={})",
        _remoteAddress, _username, rawAccount, accountLen);

    // Check if account exists (hardcoded)
    if (_username != HARDCODED_USERNAME)
    {
        FL_LOG_WARNING("AuthSession", "[{}] Unknown account '{}' (expected '{}')",
            _remoteAddress, _username, HARDCODED_USERNAME);
        co_await SendChallengeError(std::to_underlying(AuthResult::FAIL_UNKNOWN_ACCOUNT));
        co_return;
    }

    FL_LOG_DEBUG("AuthSession", "[{}] Account matched, computing SRP6 verifier...", _remoteAddress);

    // Compute SRP6 verifier and generate challenge
    _srp.ComputeVerifier(_username, HARDCODED_PASSWORD);
    _srp.GenerateChallenge();

    // Build response
    auto B_bytes    = _srp.GetB().AsByteArray(32);
    auto N_bytes    = Crypto::SRP6::N.AsByteArray(32);
    auto g_bytes    = Crypto::SRP6::g.AsByteArray(1);
    auto salt_bytes = _srp.GetSalt().AsByteArray(32);

    FL_LOG_TRACE("AuthSession", "[{}] SRP6 B ({} bytes): {}",
        _remoteAddress, B_bytes.size(), HexStr(B_bytes));
    FL_LOG_TRACE("AuthSession", "[{}] SRP6 salt ({} bytes): {}",
        _remoteAddress, salt_bytes.size(), HexStr(salt_bytes));

    ByteBuffer response(119);
    response << std::to_underlying(AuthOpcode::CMD_AUTH_LOGON_CHALLENGE) // cmd
             << uint8_t(0x00)                                           // unk
             << std::to_underlying(AuthResult::SUCCESS)                  // error
             << B_bytes                                                  // B (32 bytes)
             << static_cast<uint8_t>(g_bytes.size()) << g_bytes          // g_len + g
             << static_cast<uint8_t>(N_bytes.size()) << N_bytes          // N_len + N
             << salt_bytes;                                              // salt (32 bytes)
    response.Pad(16);                                                    // CRC salt (16 zero bytes)
    response << uint8_t(0x00);                                           // security_flags

    FL_LOG_DEBUG("AuthSession", "[{}] Sending challenge response ({} bytes)", _remoteAddress, response.Size());
    FL_LOG_TRACE("AuthSession", "[{}] Challenge response: {}",
        _remoteAddress, HexStr(response.Data()));

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(response.Storage()),
        boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Challenge response sent, waiting for proof...", _remoteAddress);
}

// ---- LOGON_PROOF -----------------------------------------------------------

async<void> AuthSession::HandleLogonProof()
{
    // Read the rest of AuthLogonProof_C (cmd byte already consumed)
    constexpr std::size_t PROOF_REMAINING = sizeof(AuthLogonProof_C) - 1;

    std::array<uint8_t, PROOF_REMAINING> proofBuf{};
    co_await boost::asio::async_read(
        _socket, boost::asio::buffer(proofBuf),
        boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Logon proof received ({} bytes)", _remoteAddress, PROOF_REMAINING);
    FL_LOG_TRACE("AuthSession", "[{}] Proof raw: {}",
        _remoteAddress, HexStr(proofBuf));

    // Parse A and M1
    Crypto::BigNumber A;
    A.SetBinary(std::span<const uint8_t>(proofBuf.data(), 32));

    Crypto::SHA1::Digest clientM1{};
    std::ranges::copy_n(proofBuf.data() + 32, 20, clientM1.begin());

    FL_LOG_TRACE("AuthSession", "[{}] Client A ({} bytes): {}",
        _remoteAddress, 32, HexStr(std::span{proofBuf}.first(32)));
    FL_LOG_TRACE("AuthSession", "[{}] Client M1 (20 bytes): {}",
        _remoteAddress, HexStr(clientM1));

    if (!_srp.VerifyClientProof(A, clientM1))
    {
        FL_LOG_WARNING("AuthSession", "[{}] Invalid logon proof (SRP6 verification failed) for '{}'", _remoteAddress, _username);

        ByteBuffer fail(4);
        fail << std::to_underlying(AuthOpcode::CMD_AUTH_LOGON_PROOF)
             << std::to_underlying(AuthResult::FAIL_INCORRECT_PASSWORD)
             << uint8_t(0x03) << uint8_t(0x00);
        co_await boost::asio::async_write(
            _socket, boost::asio::buffer(fail.Storage()),
            boost::asio::use_awaitable);
        co_return;
    }

    FL_LOG_INFO("AuthSession", "[{}] '{}' authenticated successfully", _remoteAddress, _username);
    _authenticated = true;

    // Store session key for future reconnects
    _keyStore.Store(_username, _srp.GetSessionKey());

    // Build success response
    auto& M2 = _srp.GetServerProof();

    ByteBuffer response(32);
    response << std::to_underlying(AuthOpcode::CMD_AUTH_LOGON_PROOF) // cmd
             << std::to_underlying(AuthResult::SUCCESS)              // error
             << M2;                                                  // M2 (20 bytes)
    response.Pad(10); // account_flags (uint32) + survey_id (uint32) + login_flags (uint16)

    FL_LOG_DEBUG("AuthSession", "[{}] Sending proof success response ({} bytes)", _remoteAddress, response.Size());
    FL_LOG_TRACE("AuthSession", "[{}] Proof response: {}",
        _remoteAddress, HexStr(response.Data()));

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(response.Storage()),
        boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Proof response sent, waiting for realm list request...", _remoteAddress);
}

// ---- RECONNECT_CHALLENGE ---------------------------------------------------

async<void> AuthSession::HandleReconnectChallenge()
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
    _username = ToUpper(rawAccount);

    FL_LOG_INFO("AuthSession", "[{}] Reconnect challenge for '{}'", _remoteAddress, _username);

    // Look up stored session key
    auto storedKey = co_await _keyStore.Lookup(_username);
    if (!storedKey)
    {
        FL_LOG_WARNING("AuthSession", "[{}] Reconnect failed: no session key stored for '{}'",
            _remoteAddress, _username);

        ByteBuffer fail(3);
        fail << std::to_underlying(AuthOpcode::CMD_AUTH_RECONNECT_CHALLENGE)
             << std::to_underlying(AuthResult::FAIL_UNKNOWN_ACCOUNT);
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
        _remoteAddress, HexStr(_reconnectRand));

    // Response: cmd(1) + error(1) + reconnect_rand(16) + zeros(16)
    ByteBuffer response(34);
    response << std::to_underlying(AuthOpcode::CMD_AUTH_RECONNECT_CHALLENGE)
             << std::to_underlying(AuthResult::SUCCESS);
    response.Append(_reconnectRand.data(), _reconnectRand.size());
    response.Pad(16);  // 16 zero bytes

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(response.Storage()),
        boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Reconnect challenge sent, waiting for reconnect proof...", _remoteAddress);
}

// ---- RECONNECT_PROOF -------------------------------------------------------

async<void> AuthSession::HandleReconnectProof()
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

    FL_LOG_TRACE("AuthSession", "[{}] R1: {}", _remoteAddress, HexStr(R1));
    FL_LOG_TRACE("AuthSession", "[{}] R2: {}", _remoteAddress, HexStr(R2));

    // Look up stored session key
    auto storedKey = co_await _keyStore.Lookup(_username);
    if (!storedKey)
    {
        FL_LOG_WARNING("AuthSession", "[{}] Reconnect proof failed: no session key for '{}'",
            _remoteAddress, _username);

        ByteBuffer fail(2);
        fail << std::to_underlying(AuthOpcode::CMD_AUTH_RECONNECT_PROOF)
             << std::to_underlying(AuthResult::FAIL_UNKNOWN_ACCOUNT);
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
        fail << std::to_underlying(AuthOpcode::CMD_AUTH_RECONNECT_PROOF)
             << std::to_underlying(AuthResult::FAIL_INCORRECT_PASSWORD);
        co_await boost::asio::async_write(
            _socket, boost::asio::buffer(fail.Storage()),
            boost::asio::use_awaitable);
        co_return;
    }

    FL_LOG_INFO("AuthSession", "[{}] '{}' reconnected successfully", _remoteAddress, _username);
    _authenticated = true;

    // Response: cmd(1) + error(1) + padding(2)
    ByteBuffer response(4);
    response << std::to_underlying(AuthOpcode::CMD_AUTH_RECONNECT_PROOF)
             << std::to_underlying(AuthResult::SUCCESS);
    response.Pad(2);

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(response.Storage()),
        boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Reconnect proof accepted, waiting for realm list...", _remoteAddress);
}

// ---- REALM_LIST ------------------------------------------------------------

async<void> AuthSession::HandleRealmList()
{
    // Read 4-byte padding (cmd already consumed)
    std::array<uint8_t, 4> padding{};
    co_await boost::asio::async_read(
        _socket, boost::asio::buffer(padding),
        boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Realm list requested", _remoteAddress);

    // Resolve the client IP (without port) for address selection
    boost::system::error_code ec;
    auto clientEp = _socket.remote_endpoint(ec);
    auto clientAddr = ec ? boost::asio::ip::make_address("127.0.0.1") : clientEp.address();

    // Build realm entries
    ByteBuffer realmData;
    for (auto const& realm : _realms)
    {
        std::string address = realm.GetAddressStringForClient(clientAddr);

        FL_LOG_DEBUG("AuthSession", "[{}] Realm '{}' -> {} for client {}",
            _remoteAddress, realm.Name, address, clientAddr.to_string());

        realmData << realm.Type
                  << realm.Locked
                  << realm.Flags;
        realmData << std::string_view(realm.Name);
        realmData << std::string_view(address);
        realmData << realm.Population
                  << realm.Characters
                  << realm.Timezone
                  << realm.Id;
    }

    // Build full response
    // body = uint32 padding(0) + uint16 realm_count + realm data + uint16 footer(0x0010)
    ByteBuffer body;
    body.Pad(4);                  // padding
    body << static_cast<uint16_t>(_realms.size())
         << realmData             // realm data
         << uint8_t(0x10)         // footer
         << uint8_t(0x00);

    // Header: opcode + uint16 body size
    ByteBuffer response;
    response << std::to_underlying(AuthOpcode::CMD_REALM_LIST)
             << static_cast<uint16_t>(body.Size())
             << body;

    FL_LOG_DEBUG("AuthSession", "[{}] Sending realm list response ({} bytes, body={} bytes)",
        _remoteAddress, response.Size(), body.Size());
    FL_LOG_TRACE("AuthSession", "[{}] Realm list response: {}",
        _remoteAddress, HexStr(response.Data()));

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(response.Storage()),
        boost::asio::use_awaitable);
}

// ---- Realm initialization --------------------------------------------------

void AuthSession::InitRealms()
{
    // TODO: load realms from config / database
    Realm r;
    r.Name            = "Fireland";
    r.Type            = 0;       // Normal
    r.Locked          = 0;
    r.Flags           = 0;
    r.Timezone        = 1;
    r.Id              = 1;
    r.Characters      = 0;
    r.Population      = 0.5f;
    r.Port            = 8085;
    r.LocalAddress    = boost::asio::ip::make_address("127.0.0.1");
    r.ExternalAddress = boost::asio::ip::make_address("127.0.0.1");
    r.LocalSubnetMask = boost::asio::ip::make_address_v4("255.255.255.0");

    _realms.push_back(std::move(r));
}

// ---- Error helpers ---------------------------------------------------------

async<void> AuthSession::SendChallengeError(uint8_t error)
{
    ByteBuffer response(3);
    response << std::to_underlying(AuthOpcode::CMD_AUTH_LOGON_CHALLENGE)
             << uint8_t(0x00)
             << error;

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(response.Storage()),
        boost::asio::use_awaitable);
}

} // namespace Fireland::Auth

