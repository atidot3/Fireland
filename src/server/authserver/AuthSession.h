#pragma once

// ============================================================================
// AuthSession — Coroutine-based WoW auth protocol handler
//
// Handles one client connection through the full auth flow:
//   LOGON_CHALLENGE → LOGON_PROOF → REALM_LIST
// ============================================================================

#include <memory>
#include <string>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>

#include <Crypto/SRP6.h>

namespace Fireland::Auth {

class AuthSession : public std::enable_shared_from_this<AuthSession>
{
public:
    explicit AuthSession(boost::asio::ip::tcp::socket socket) noexcept;
    ~AuthSession() noexcept;
    boost::asio::awaitable<void> Run();

private:
    boost::asio::awaitable<void> HandleLogonChallenge();
    boost::asio::awaitable<void> HandleLogonProof();
    boost::asio::awaitable<void> HandleRealmList();

    boost::asio::awaitable<void> SendChallengeError(uint8_t error);

    boost::asio::ip::tcp::socket _socket;
    std::string                  _remoteAddress;

    Crypto::SRP6 _srp;
    std::string  _username;
    bool         _authenticated = false;
};

} // namespace Fireland::Auth
