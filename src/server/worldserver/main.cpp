// ============================================================================
// Fireland World Server — Entry point
//
// Minimal world server using Boost.Asio C++20 coroutines.
// Listens on 0.0.0.0:8085 (default WoW world port).
//
// After TCP accept, each client goes through the Cata 4.3.4 auth handshake:
//   SMSG_AUTH_CHALLENGE → CMSG_AUTH_SESSION → SMSG_AUTH_RESPONSE
// ============================================================================

#include <cstdlib>
#include <iostream>

#include <Utils/Async.hpp>
#include <Utils/StringUtils.h>
#include <Utils/Log.h>
#include <Utils/ProgramOptions.h>
#include <Utils/IoContext.h>

#include <Network/TcpListener.h>

#include <Database/connection_pool_wrapper.h>

#include "WorldSession.h"

auto initiate_database(boost::asio::any_io_executor exec)
{
    Fireland::Database::connection_pool_wrapper_options opts;
    opts.database = "FirelandAuth";
    opts.hostname = "127.0.0.1";
    opts.port = 3306;
    opts.username = "root";
    opts.password = "password";

    auto db = std::make_shared<Fireland::Database::connection_pool_wrapper>(exec);
    db->start(opts);

    return db;
}

Fireland::Utils::Async::async<void> async_main(Fireland::Utils::IoContext& thread_pool)
{
    constexpr const char* BIND_ADDRESS = "0.0.0.0";
    constexpr uint16_t    BIND_PORT = 8085;

    // ---- TEST SHA1 
    auto hash = Fireland::Crypto::SHA1::Hash("abc");
    auto string_hash = Fireland::Utils::StringUtils::HexStrCompact(hash);

    std::cout << "SHA1 = " << string_hash << std::endl;

    if (string_hash == "a9993e364706816aba3e25717850c26c9cd0d89d")
    {
        FL_LOG_INFO("WorldSession", "SHA1 Check: SUCCESS !");
    }
    else
    {
        FL_LOG_ERROR("WorldSession",
            "SHA1 Check: FAILED ! {} != expected",
            string_hash);
    }

    // --- TEST SHA1 MULTI-UPDATE (sanity) ---
    {
        std::string part1 = "ab";
        std::string part2 = "c";
        Fireland::Crypto::SHA1 sha;
        sha.Update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(part1.data()), part1.size()));
        sha.Update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(part2.data()), part2.size()));
        auto r = sha.Finalize();
        auto s = Fireland::Utils::StringUtils::HexStrCompact(r);
        if (s == "a9993e364706816aba3e25717850c26c9cd0d89d")
            FL_LOG_INFO("WorldSession", "SHA1 multi-Update: OK");
        else
            FL_LOG_ERROR("WorldSession", "SHA1 multi-Update: FAILED — {}", s);
    }

    // --- TEST HMAC RFC 2202 ---
    std::string testKey = "Jefe";
    std::string testData = "what do ya want for nothing?";

    // Conversion en spans d'octets
    auto keySpan = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(testKey.data()), testKey.size());
    auto dataSpan = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(testData.data()), testData.size());

    // Calcul
    Fireland::Crypto::SHA1::Digest result = Fireland::Crypto::HMAC_SHA1(keySpan, dataSpan);

    // Affichage en Hexadécimal pour comparaison
    std::string hexResult;
    for (auto byte : result) {
        hexResult += std::format("{:02x}", byte);
    }

    FL_LOG_DEBUG("WorldSession", "HMAC Test Result: {}", hexResult);
    FL_LOG_DEBUG("WorldSession", "HMAC Expected:    effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");

    if (hexResult == "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79") {
        FL_LOG_INFO("WorldSession", "HMAC Check: SUCCESS ! Ta crypto est mathématiquement correcte.");
    } else {
        FL_LOG_ERROR("WorldSession", "HMAC Check: FAILED ! Ton implémentation HMAC est erronée.");
    }
    // --------------------------

    Fireland::Database::Auth::AuthWrapper authdbPool(thread_pool.Get());
    authdbPool.start();
    if (!co_await authdbPool.ping())
    {
        FL_LOG_ERROR("WorldServer", "Failed to connect to the database. Shutting down.");

        thread_pool.Stop();
        authdbPool.stop();
 
        co_return;
    }

    Fireland::Network::TcpListener<Fireland::World::WorldSession> listener(
        thread_pool,
        [&authdbPool](boost::asio::ip::tcp::socket socket) {
            return std::make_shared<Fireland::World::WorldSession>(std::move(socket), authdbPool);
        }
    );

    FL_LOG_INFO("WorldServer", "Running. Press Ctrl+C to stop.");
    co_await listener.Listen(BIND_ADDRESS, BIND_PORT);

    authdbPool.stop();
}

int main(int argc, char* argv[])
{
    Fireland::Utils::ProgramOptions opts("worldserver", "0.1.0", "worldserver.conf");
    if (!opts.Parse(argc, argv))
        return opts.ExitCode();

	// Initialize logging system
    Fireland::Utils::Log::Init(opts.ConfigFile());
    if (opts.Quiet()) Fireland::Utils::Log::SetConsoleEnabled(false);

    std::cout << "========================================\n"
              << "  Fireland World Server\n"
              << "========================================\n";

    constexpr std::size_t THREAD_COUNT = 4;

    try
    {
        // Initiate thread pool and signal handlers
        Fireland::Utils::IoContext ioContext(THREAD_COUNT);
        ioContext.InstallSignalHandlers();

        // Run the server asynchronously
        boost::asio::co_spawn(ioContext.Get(), async_main(ioContext), boost::asio::detached);

        ioContext.Join();

        FL_LOG_INFO("WorldServer", "Shutdown complete.");
    }
    catch (const std::exception& e)
    {
        FL_LOG_FATAL("WorldServer", "Fatal error: {}", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
