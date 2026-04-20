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

#include <Utils/Asio/Async.hpp>
#include <Utils/Asio/AsyncQueue.hpp>
#include <Utils/ByteBuffer.h>

#include <Shared/SharedDefines.hpp>
#include <Shared/Char/Characters.h>

#include <Network/World/WorldOpcode.hpp>
#include <Network/World/WorldPacket.hpp>

namespace Fireland::World
{
    enum class WorldSessionStatus : uint32_t
    {
        AWAIT_INITIALIZE = 0,
        CONNECTION_INITIALIZED = 1,
        AUTH_CHALLENGE = 2,
        AUTHED = 3
    };
    BOOST_DESCRIBE_ENUM(WorldSessionStatus, AWAIT_INITIALIZE, CONNECTION_INITIALIZED, AUTH_CHALLENGE, AUTHED)
    using WorldPacketHandler = std::function<Fireland::Utils::Async::async<void>(Fireland::World::WorldPacket&)>;

    class WorldSession : public std::enable_shared_from_this<WorldSession>
    {
    public:
        explicit WorldSession(boost::asio::any_io_executor exec, boost::asio::ip::tcp::socket socket) noexcept;
        ~WorldSession() noexcept;

        void Start();

    private:
        Utils::Async::async<void> InitializeHandlers();
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
        Utils::Async::async<void> SendAccountDataTimes(uint32_t mask);
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
        Utils::Async::async<void> RecvLoop();
        Utils::Async::async<void> SendLoop();

        // ---- Post-auth packet handlers ----
        Utils::Async::async<void> HandleReadyForAccountDataTimes(WorldPacket& packet);
        Utils::Async::async<void> HandleRequestAccountData(WorldPacket& packet);
        Utils::Async::async<void> HandleUpdateAccountData(WorldPacket& packet);
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
        Utils::Async::async<void> HandleLogoutRequestOpcode(WorldPacket& packet);
        Utils::Async::async<void> HandlePlayerLogoutOpcode(WorldPacket& packet);
        Utils::Async::async<void> HandleLogoutCancelOpcode(WorldPacket& packet);
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

		/// Serialise, encrypt the SMSG header, and push the complete frame into the send queue.
        void SendPacket(const WorldPacket& packet);

    private:
        boost::asio::any_io_executor                       _exec;
        boost::asio::ip::tcp::socket                       _socket;
        Utils::Async::AsyncQueue<WorldPacket>              _recvQueue;
        Utils::Async::AsyncQueue<WorldPacket>              _sendQueue;
        std::string                                        _remoteAddress;
		WorldSessionStatus                                 _sessionStatus;
        std::unordered_map<uint32_t, WorldPacketHandler>   _handlers;

        std::string                                        _username;
        uint32_t                                           _accountId;
		uint32_t                                           _characterId;
        uint32_t                                           _serverSeed;
        Crypto::WorldCrypt                                 _crypt;

		// -- Logout timer: cancellable with HandleLogoutCancelOpcode; if it expires, the session is closed and the player is logged out of the world.
		boost::asio::steady_timer						   _logoutTimer;
    };
} // namespace Fireland::World
