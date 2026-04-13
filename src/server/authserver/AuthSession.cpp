#include "AuthSession.h"
#include "AuthOpcode.h"

#include <algorithm>
#include <cctype>
#include <span>
#include <vector>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <Utils/Log.h>

namespace Fireland::Auth {

// ---- Hardcoded test account ------------------------------------------------
static constexpr const char* HARDCODED_USERNAME = "TEST";
static constexpr const char* HARDCODED_PASSWORD = "TEST";

static std::string ToUpper(std::string_view sv)
{
    std::string result(sv);
    for (auto& c : result)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return result;
}

static std::string HexStr(std::span<const uint8_t> data)
{
    std::string result;
    result.reserve(data.size() * 3);
    for (auto b : data)
        result += std::format("{:02X} ", b);
    if (!result.empty()) result.pop_back();
    return result;
}

// ---- Construction ----------------------------------------------------------

AuthSession::AuthSession(boost::asio::ip::tcp::socket socket) noexcept
    : _socket(std::move(socket))
{
    boost::system::error_code ec;
    auto ep = _socket.remote_endpoint(ec);
    if (!ec)
        _remoteAddress = std::format("{}:{}", ep.address().to_string(), ep.port());
    else
        _remoteAddress = "<unknown>";
}

AuthSession::~AuthSession() noexcept
{
    FL_LOG_INFO("AuthSession", "Client disconnected from {}", _remoteAddress);
}

// ---- Main coroutine --------------------------------------------------------

boost::asio::awaitable<void> AuthSession::Run()
{
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

boost::asio::awaitable<void> AuthSession::HandleLogonChallenge()
{
    // Read the rest of the fixed-size header (we already consumed the cmd byte)
    // AuthLogonChallenge_C minus the cmd byte = sizeof(AuthLogonChallenge_C) - 1
    constexpr std::size_t HEADER_REMAINING = sizeof(AuthLogonChallenge_C) - 1;

    std::array<uint8_t, HEADER_REMAINING> headerBuf{};
    co_await boost::asio::async_read(
        _socket, boost::asio::buffer(headerBuf),
        boost::asio::use_awaitable);

    FL_LOG_TRACE("AuthSession", "[{}] Challenge header ({} bytes): {}",
        _remoteAddress, HEADER_REMAINING, HexStr(std::span<const uint8_t>(headerBuf.data(), HEADER_REMAINING)));

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
        co_await SendChallengeError(static_cast<uint8_t>(AuthResult::FAIL_UNKNOWN_ACCOUNT));
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

    std::vector<uint8_t> response;
    response.reserve(119);

    response.push_back(static_cast<uint8_t>(AuthOpcode::CMD_AUTH_LOGON_CHALLENGE)); // cmd
    response.push_back(0x00);                                                       // unk
    response.push_back(static_cast<uint8_t>(AuthResult::SUCCESS));                  // error

    // B (32 bytes)
    response.insert(response.end(), B_bytes.begin(), B_bytes.end());

    // g_len + g
    response.push_back(static_cast<uint8_t>(g_bytes.size()));
    response.insert(response.end(), g_bytes.begin(), g_bytes.end());

    // N_len + N
    response.push_back(static_cast<uint8_t>(N_bytes.size()));
    response.insert(response.end(), N_bytes.begin(), N_bytes.end());

    // salt (32 bytes)
    response.insert(response.end(), salt_bytes.begin(), salt_bytes.end());

    // CRC salt (16 random bytes — not verified by client)
    for (int i = 0; i < 16; ++i)
        response.push_back(0);

    // security_flags
    response.push_back(0x00);

    FL_LOG_DEBUG("AuthSession", "[{}] Sending challenge response ({} bytes)", _remoteAddress, response.size());
    FL_LOG_TRACE("AuthSession", "[{}] Challenge response: {}",
        _remoteAddress, HexStr(std::span<const uint8_t>(response.data(), response.size())));

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(response),
        boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Challenge response sent, waiting for proof...", _remoteAddress);
}

// ---- LOGON_PROOF -----------------------------------------------------------

boost::asio::awaitable<void> AuthSession::HandleLogonProof()
{
    // Read the rest of AuthLogonProof_C (cmd byte already consumed)
    constexpr std::size_t PROOF_REMAINING = sizeof(AuthLogonProof_C) - 1;

    std::array<uint8_t, PROOF_REMAINING> proofBuf{};
    co_await boost::asio::async_read(
        _socket, boost::asio::buffer(proofBuf),
        boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Logon proof received ({} bytes)", _remoteAddress, PROOF_REMAINING);
    FL_LOG_TRACE("AuthSession", "[{}] Proof raw: {}",
        _remoteAddress, HexStr(std::span<const uint8_t>(proofBuf.data(), PROOF_REMAINING)));

    // Parse A and M1
    Crypto::BigNumber A;
    A.SetBinary(std::span<const uint8_t>(proofBuf.data(), 32));

    Crypto::SHA1::Digest clientM1{};
    std::copy_n(proofBuf.data() + 32, 20, clientM1.begin());

    FL_LOG_TRACE("AuthSession", "[{}] Client A ({} bytes): {}",
        _remoteAddress, 32, HexStr(std::span<const uint8_t>(proofBuf.data(), 32)));
    FL_LOG_TRACE("AuthSession", "[{}] Client M1 (20 bytes): {}",
        _remoteAddress, HexStr(std::span<const uint8_t>(clientM1.data(), 20)));

    if (!_srp.VerifyClientProof(A, clientM1))
    {
        FL_LOG_WARNING("AuthSession", "[{}] Invalid logon proof (SRP6 verification failed) for '{}'", _remoteAddress, _username);

        std::array<uint8_t, 4> fail = {
            static_cast<uint8_t>(AuthOpcode::CMD_AUTH_LOGON_PROOF),
            static_cast<uint8_t>(AuthResult::FAIL_INCORRECT_PASSWORD),
            0x03, 0x00
        };
        co_await boost::asio::async_write(
            _socket, boost::asio::buffer(fail),
            boost::asio::use_awaitable);
        co_return;
    }

    FL_LOG_INFO("AuthSession", "[{}] '{}' authenticated successfully", _remoteAddress, _username);
    _authenticated = true;

    // Build success response
    auto& M2 = _srp.GetServerProof();

    std::vector<uint8_t> response;
    response.reserve(32);

    response.push_back(static_cast<uint8_t>(AuthOpcode::CMD_AUTH_LOGON_PROOF)); // cmd
    response.push_back(static_cast<uint8_t>(AuthResult::SUCCESS));              // error

    // M2 (20 bytes)
    response.insert(response.end(), M2.begin(), M2.end());

    // account_flags (uint32) — 0x00800000 = Pro pass, 0 = normal
    response.push_back(0x00);
    response.push_back(0x00);
    response.push_back(0x00);
    response.push_back(0x00);

    // survey_id (uint32)
    response.push_back(0x00);
    response.push_back(0x00);
    response.push_back(0x00);
    response.push_back(0x00);

    // login_flags (uint16)
    response.push_back(0x00);
    response.push_back(0x00);

    FL_LOG_DEBUG("AuthSession", "[{}] Sending proof success response ({} bytes)", _remoteAddress, response.size());
    FL_LOG_TRACE("AuthSession", "[{}] Proof response: {}",
        _remoteAddress, HexStr(std::span<const uint8_t>(response.data(), response.size())));

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(response),
        boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Proof response sent, waiting for realm list request...", _remoteAddress);
}

// ---- REALM_LIST ------------------------------------------------------------

boost::asio::awaitable<void> AuthSession::HandleRealmList()
{
    // Read 4-byte padding (cmd already consumed)
    std::array<uint8_t, 4> padding{};
    co_await boost::asio::async_read(
        _socket, boost::asio::buffer(padding),
        boost::asio::use_awaitable);

    FL_LOG_DEBUG("AuthSession", "[{}] Realm list requested", _remoteAddress);

    // Build one hardcoded realm
    const std::string realmName    = "Fireland";
    const std::string realmAddress = "127.0.0.1:8085";

    // Realm entry
    std::vector<uint8_t> realmData;
    realmData.push_back(0x00);    // type: Normal
    realmData.push_back(0x00);    // locked: no
    realmData.push_back(0x00);    // flags: none

    // name (null-terminated)
    realmData.insert(realmData.end(), realmName.begin(), realmName.end());
    realmData.push_back(0x00);

    // address (null-terminated)
    realmData.insert(realmData.end(), realmAddress.begin(), realmAddress.end());
    realmData.push_back(0x00);

    // population (float, little-endian) — 0.5 = medium
    float pop = 0.5f;
    auto* popBytes = reinterpret_cast<const uint8_t*>(&pop);
    realmData.insert(realmData.end(), popBytes, popBytes + 4);

    realmData.push_back(0x00);    // characters: 0
    realmData.push_back(0x01);    // timezone: 1
    realmData.push_back(0x01);    // realm id: 1

    // Build full response
    // body = uint32 padding(0) + uint16 realm_count + realm data + uint16 footer(0x0010)
    std::vector<uint8_t> body;
    body.resize(4, 0x00);         // padding

    // realm_count (uint16, little-endian)
    uint16_t realmCount = 1;
    body.push_back(static_cast<uint8_t>(realmCount & 0xFF));
    body.push_back(static_cast<uint8_t>((realmCount >> 8) & 0xFF));

    body.insert(body.end(), realmData.begin(), realmData.end());

    // footer
    body.push_back(0x10);
    body.push_back(0x00);

    // Header: opcode + uint16 body size
    std::vector<uint8_t> response;
    response.push_back(static_cast<uint8_t>(AuthOpcode::CMD_REALM_LIST));

    uint16_t bodySize = static_cast<uint16_t>(body.size());
    response.push_back(static_cast<uint8_t>(bodySize & 0xFF));
    response.push_back(static_cast<uint8_t>((bodySize >> 8) & 0xFF));

    response.insert(response.end(), body.begin(), body.end());

    FL_LOG_DEBUG("AuthSession", "[{}] Sending realm list response ({} bytes, body={} bytes)",
        _remoteAddress, response.size(), bodySize);
    FL_LOG_TRACE("AuthSession", "[{}] Realm list response: {}",
        _remoteAddress, HexStr(std::span<const uint8_t>(response.data(), response.size())));

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(response),
        boost::asio::use_awaitable);
}

// ---- Error helpers ---------------------------------------------------------

boost::asio::awaitable<void> AuthSession::SendChallengeError(uint8_t error)
{
    std::array<uint8_t, 3> response = {
        static_cast<uint8_t>(AuthOpcode::CMD_AUTH_LOGON_CHALLENGE),
        0x00,
        error
    };

    co_await boost::asio::async_write(
        _socket, boost::asio::buffer(response),
        boost::asio::use_awaitable);
}

} // namespace Fireland::Auth
