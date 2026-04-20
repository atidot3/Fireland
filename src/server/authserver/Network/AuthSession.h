#pragma once

// ============================================================================
// AuthSession — Coroutine-based WoW auth protocol handler
//
// Handles one client connection through the full auth flow:
//   LOGON_CHALLENGE → LOGON_PROOF → REALM_LIST
// ============================================================================

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

#include <Utils/Asio/Async.hpp>
#include <Utils/Asio/Describe.hpp>
#include <Network/Auth/AuthPacket.hpp>
#include <Shared/SharedDefines.hpp>
#include <Crypto/SRP6.h>

enum class AuthSessionStatus
{
    LOGON_CHALLENGE,
    LOGON_PROOF,
    RECONNECT_PROOF,
	WAIT_FOR_REALM_LIST,
    CLOSED
};
BOOST_DESCRIBE_ENUM(AuthSessionStatus, LOGON_CHALLENGE, LOGON_PROOF, RECONNECT_PROOF, WAIT_FOR_REALM_LIST, CLOSED)

struct AuthHandler
{
    AuthSessionStatus status;
    std::function<Firelands::Utils::Async::async<void>(Firelands::Auth::AuthPacket)> handler;
};

namespace Firelands::Auth
{
    class AuthSession : public std::enable_shared_from_this<AuthSession>
    {
    public:
        explicit AuthSession(boost::asio::ip::tcp::socket socket) noexcept;
        ~AuthSession() noexcept;

        void Start();
        void Close() {}
        uint64_t GetId() const { return reinterpret_cast<uint64_t>(this); }

    private:
        Utils::Async::async<void> Run();
        Utils::Async::async<void> HandleLogonChallenge(AuthPacket packet);
        Utils::Async::async<void> HandleLogonProof(AuthPacket packet);
        Utils::Async::async<void> HandleReconnectChallenge(AuthPacket packet);
        Utils::Async::async<void> HandleReconnectProof(AuthPacket packet);
        Utils::Async::async<void> HandleRealmList(AuthPacket packet);
        Utils::Async::async<void> SendChallengeError(ResponseCodes error);

    private:
        boost::asio::ip::tcp::socket                _socket;
        AuthSessionStatus                           _status;
        std::string                                 _remoteAddress;
        std::unordered_map<AuthOpcode, AuthHandler> _handlers;

        Crypto::SRP6 _srp;
        std::string  _username;
        uint32_t     _accountId;
        bool         _authenticated = false;

        std::array<uint8_t, 16> _reconnectRand{};  // random challenge for reconnect proof
    };
} // namespace Firelands::Auth