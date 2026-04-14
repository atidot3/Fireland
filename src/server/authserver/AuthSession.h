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

#include <Crypto/SRP6.h>
#include <Network/SessionKeyStore.h>
#include <Utils/Async.hpp>

#include "AuthPacket.hpp"
#include "Realm.h"

namespace Fireland::Auth {

class AuthSession : public std::enable_shared_from_this<AuthSession>
{
public:
    explicit AuthSession(boost::asio::ip::tcp::socket socket, Network::SessionKeyStore& keyStore) noexcept;
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

    boost::asio::ip::tcp::socket     _socket;
    Network::SessionKeyStore&        _keyStore;
    std::string                      _remoteAddress;

    Crypto::SRP6 _srp;
    std::string  _username;
    bool         _authenticated = false;

    std::array<uint8_t, 16> _reconnectRand{};  // random challenge for reconnect proof

    std::vector<Realm> _realms;   // populated once at construction
    void InitRealms();            // builds the realm list
};

} // namespace Fireland::Auth