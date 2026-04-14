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
#include <Utils/Log.h>
#include <Utils/ProgramOptions.h>
#include <Utils/IoContext.h>

#include <Network/SessionKeyStore.h>
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

    Fireland::Network::SessionKeyStore sessionKeyStore(thread_pool.Get());
    auto dbPool = initiate_database(thread_pool.Get());

    Fireland::Network::TcpListener<Fireland::World::WorldSession> listener(
        thread_pool,
        [&sessionKeyStore, dbPool](boost::asio::ip::tcp::socket socket) {
            return std::make_shared<Fireland::World::WorldSession>(std::move(socket), sessionKeyStore);
        }
    );

    FL_LOG_INFO("WorldServer", "Running. Press Ctrl+C to stop.");
    co_await listener.Listen(BIND_ADDRESS, BIND_PORT);

    if (dbPool)
    {
        dbPool->stop();
        dbPool = nullptr;
    }
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
