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
#include <Crypto/WorldCrypt.h>
#include <Network/SessionKeyStore.h>
#include <Utils/Async.hpp>
#include <Utils/ByteBuffer.h>

#include "WorldOpcode.h"
#include "WorldPacket.h"

namespace Fireland::World
{
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

        // ---- Send / receive helpers ----

        /// Read a complete CMSG (header + payload) from the socket.
        /// Decrypts the header in-place; payload is appended to the returned packet.
        Utils::Async::async<WorldPacket> ReadClientPacket();

        /// Serialise, encrypt the SMSG header, and write the packet to the socket.
        Utils::Async::async<void> SendPacket(const WorldPacket& packet);

        boost::asio::ip::tcp::socket     _socket;
        Network::SessionKeyStore&        _keyStore;
        std::string                      _remoteAddress;

        std::string  _username;
        uint32_t     _serverSeed = 0;
        bool         _authenticated = false;

        // Per-session random seeds sent in SMSG_AUTH_CHALLENGE DosChallenge.
        // Stored here so WorldCrypt::Init() can use them after auth succeeds.
        std::array<uint8_t, 16> _encryptSeed{};  // DosChallenge bytes  0-15
        std::array<uint8_t, 16> _decryptSeed{};  // DosChallenge bytes 16-31
        Crypto::WorldCrypt _crypt;
    };
} // namespace Fireland::World
