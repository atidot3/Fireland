#pragma once

// ============================================================================
// WorldSession — Coroutine-based WoW world protocol handler
//
// Handles one client connection through the Cata 4.3.4 handshake:
//   ServerConnectionInit → ClientConnectionInit →
//   SMSG_AUTH_CHALLENGE → CMSG_AUTH_SESSION → SMSG_AUTH_RESPONSE
//
// After authentication, enters the main packet dispatch loop.
// ============================================================================

#include <array>
#include <cstdint>
#include <memory>
#include <string>

#include <boost/asio/ip/tcp.hpp>

#include <Crypto/SHA1.h>
#include <Network/SessionKeyStore.h>
#include <Utils/Async.hpp>
#include <Utils/ByteBuffer.h>

#include "WorldOpcode.h"

namespace Fireland::World {

class WorldSession : public std::enable_shared_from_this<WorldSession>
{
public:
    explicit WorldSession(boost::asio::ip::tcp::socket socket,
                          Network::SessionKeyStore& keyStore) noexcept;
    ~WorldSession() noexcept;

    void Start();

private:
    Utils::Async::async<void> Run();

    // ---- Connection initialization (Cata 4.3.4) ----
    Utils::Async::async<void> SendConnectionInit();
    Utils::Async::async<void> ReadConnectionInit();

    // ---- Auth handshake ----
    Utils::Async::async<void> SendAuthChallenge();
    Utils::Async::async<void> HandleAuthSession();
    Utils::Async::async<void> SendAuthResponse(AuthResponseResult result);

    // ---- Packet loop (post-auth) ----
    Utils::Async::async<void> PacketLoop();

    // ---- Helpers ----
    /// Write a server→client packet header: [uint16 size (BE)][uint16 opcode (LE)]
    static void WriteServerHeader(Utils::ByteBuffer& buf, uint16_t opcode, uint16_t payloadSize);

    /// Read a client→server packet header: [uint16 size (BE)][uint32 opcode (LE)]
    struct ClientHeader { uint16_t size; uint32_t opcode; };
    Utils::Async::async<ClientHeader> ReadClientHeader();

    boost::asio::ip::tcp::socket     _socket;
    Network::SessionKeyStore&        _keyStore;
    std::string                      _remoteAddress;

    std::string  _username;
    uint32_t     _serverSeed = 0;
    bool         _authenticated = false;

    // Encryption seeds (used for ARC4 init after auth — TODO: implement encryption)
    std::array<uint8_t, 16> _encryptSeed{};
    std::array<uint8_t, 16> _decryptSeed{};
};

} // namespace Fireland::World
