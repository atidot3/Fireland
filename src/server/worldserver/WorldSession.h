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

#include <Utils/Async.hpp>
#include <Utils/ByteBuffer.h>

#include <Shared/SharedDefines.hpp>
#include <Shared/Char/Characters.h>

#include <Network/World/WorldOpcode.hpp>
#include <Network/World/WorldPacket.hpp>

namespace Fireland::World
{
    class WorldSession : public std::enable_shared_from_this<WorldSession>
    {
    public:
        explicit WorldSession(boost::asio::ip::tcp::socket socket) noexcept;
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
        Utils::Async::async<void> SendAuthResponse(ResponseCodes result);
        Utils::Async::async<void> SendAddonInfo();
        Utils::Async::async<void> SendClientCacheVersion();
        Utils::Async::async<void> SendTutorialFlags();
        Utils::Async::async<void> SendAccountDataTimes();
        Utils::Async::async<void> SendFeatureSystemStatus();
        Utils::Async::async<void> SendRealmSplit(uint32_t realmId);
        Utils::Async::async<void> SendSetTimeZoneInformation();
        Utils::Async::async<void> SendLearnedDanceMoves();
        Utils::Async::async<void> SendMotd();
        Utils::Async::async<void> SendAccountRestrictedUpdate();
        Utils::Async::async<void> SendInitialRaidGroupError();
        Utils::Async::async<void> SendSetDfFastLaunchResources();

        // ---- Packet loop (post-auth) ----
        Utils::Async::async<void> PacketLoop();

        // ---- Post-auth packet handlers ----
        Utils::Async::async<void> HandleReadyForAccountDataTimes(WorldPacket& packet);
        Utils::Async::async<void> HandleCharEnum(WorldPacket& packet);
        Utils::Async::async<void> HandleRealmSplit(WorldPacket& packet);
        Utils::Async::async<void> SendCharEnum();
        Utils::Async::async<void> HandlePing(WorldPacket& packet);

        // ---- Characters ----
		Utils::Async::async<void> HandleCharCreate(WorldPacket& packet);
        Utils::Async::async<void> HandleCharDelete(WorldPacket& packet);
        Utils::Async::async<void> HandlePlayerLogin(WorldPacket& packet);
        Utils::Async::async<void> SendInitialSpells();
        Utils::Async::async<void> SendUnlearnSpells();
        Utils::Async::async<void> SendInitializeFactions();
        Utils::Async::async<void> SendActionButtons();
        Utils::Async::async<void> SendLoginSetTimeSpeed();
        Utils::Async::async<void> SendCreatePlayerObject(const characters& ch, float x, float y, float z);
		Utils::Async::async<void> HandleMessageChat(WorldPacket& packet);
		Utils::Async::async<void> HandleMovement(WorldPacket& packet);
        Utils::Async::async<void> SendClientControlUpdate(uint64_t guid, bool allowMove);
        Utils::Async::async<void> SendMoveSetActiveMover(uint64_t guid);
        Utils::Async::async<void> SendBindPointUpdate(float x, float y, float z, uint32_t mapId, uint32_t zoneId);
        Utils::Async::async<void> SendWorldServerInfo();
        Utils::Async::async<void> SendHotfixNotify();
        Utils::Async::async<void> HandleLoadingScreenNotify(WorldPacket& packet);
        Utils::Async::async<void> HandleViolenceLevel(WorldPacket& packet);
        Utils::Async::async<void> HandleQueryQuestsCompleted(WorldPacket& packet);

        // ---- Send / receive helpers ----

        /// Read a complete CMSG (header + payload) from the socket.
        /// Decrypts the header in-place; payload is appended to the returned packet.
        Utils::Async::async<WorldPacket> ReadClientPacket();

        /// Serialise, encrypt the SMSG header, and write the packet to the socket.
        Utils::Async::async<void> SendPacket(const WorldPacket& packet);

        boost::asio::ip::tcp::socket     _socket;
        std::string                      _remoteAddress;

        std::string  _username;
        uint32_t     _accountId;
        uint32_t     _serverSeed;
        bool         _authenticated;
        Crypto::WorldCrypt _crypt;
    };
} // namespace Fireland::World
