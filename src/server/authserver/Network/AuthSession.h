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

#include <Database/Auth/AuthWrapper.h>
#include <Crypto/SRP6.h>
#include <Utils/Async.hpp>

#include "AuthPacket.hpp"
#include "../Realm/Realm.h"

namespace Fireland::Auth {

class AuthSession : public std::enable_shared_from_this<AuthSession>
{
public:
    explicit AuthSession(boost::asio::ip::tcp::socket socket, Fireland::Database::Auth::AuthWrapper& dbPool) noexcept;
    ~AuthSession() noexcept;

    void Start();

private:
    Utils::Async::async<void> Run();
    Utils::Async::async<void> HandleLogonChallenge(AuthPacket packet);
    Utils::Async::async<void> HandleLogonProof(AuthPacket packet);
    Utils::Async::async<void> HandleReconnectChallenge(AuthPacket packet);
    Utils::Async::async<void> HandleReconnectProof(AuthPacket packet);
    Utils::Async::async<void> HandleRealmList(AuthPacket packet);
    Utils::Async::async<void> SendChallengeError(AuthResult error);

private:
    boost::asio::ip::tcp::socket     _socket;
    Fireland::Database::Auth::AuthWrapper& _dbPool;
    std::string                      _remoteAddress;

    Crypto::SRP6 _srp;
    std::string  _username;
    uint32_t     _accountId;
    bool         _authenticated = false;

    std::array<uint8_t, 16> _reconnectRand{};  // random challenge for reconnect proof

    std::vector<Realm> _realms;   // populated once at construction
    void InitRealms();            // builds the realm list
};

} // namespace Fireland::Auth