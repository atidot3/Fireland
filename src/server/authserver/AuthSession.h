#pragma once

// ============================================================================
// AuthSession — Coroutine-based WoW auth protocol handler
//
// Handles one client connection through the full auth flow:
//   LOGON_CHALLENGE → LOGON_PROOF → REALM_LIST
// ============================================================================

#include <cstdint>
#include <memory>
#include <string>

#include <boost/asio/ip/tcp.hpp>

#include <Crypto/SRP6.h>
#include <Utils/Async.hpp>

namespace Fireland::Auth {

class AuthSession : public std::enable_shared_from_this<AuthSession>
{
public:
    explicit AuthSession(boost::asio::ip::tcp::socket socket) noexcept;
    ~AuthSession() noexcept;

    void Start();

private:
    Utils::Async::async<void> Run();
    Utils::Async::async<void> HandleLogonChallenge();
    Utils::Async::async<void> HandleLogonProof();
    Utils::Async::async<void> HandleRealmList();
    Utils::Async::async<void> SendChallengeError(uint8_t error);

    boost::asio::ip::tcp::socket _socket;
    std::string                  _remoteAddress;

    Crypto::SRP6 _srp;
    std::string  _username;
    bool         _authenticated = false;
};

} // namespace Fireland::Auth