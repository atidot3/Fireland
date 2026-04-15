// ============================================================================
// Fireland Auth Server — Entry point
//
// SRP6-based authentication server for WoW Cataclysm (4.3.4).
// Listens on 0.0.0.0:3724, handles LOGON_CHALLENGE, LOGON_PROOF, REALM_LIST.
//
// Hardcoded test account: TEST / TEST
// ============================================================================

#include <cstdlib>
#include <iostream>

#include <Utils/Async.hpp>
#include <Utils/Log.h>
#include <Utils/ProgramOptions.h>
#include <Utils/IoContext.h>

#include <Network/TcpListener.h>

#include <Database/Auth/AuthWrapper.h>

#include "Network/AuthSession.h"

Fireland::Utils::Async::async<void> async_main(Fireland::Utils::IoContext& thread_pool)
{
    constexpr const char* BIND_ADDRESS = "0.0.0.0";
    constexpr uint16_t    BIND_PORT = 3724;

    Fireland::Database::Auth::AuthWrapper dbPool(thread_pool.Get());
    dbPool.start();
    if (!co_await dbPool.ping())
    {
        FL_LOG_ERROR("AuthServer", "Failed to connect to the database. Shutting down.");

        thread_pool.Stop();
        dbPool.stop();
 
        co_return;
    }
    
    Fireland::Network::TcpListener<Fireland::Auth::AuthSession> listener(thread_pool, [&dbPool](boost::asio::ip::tcp::socket socket)
    {
        return std::make_shared<Fireland::Auth::AuthSession>(std::move(socket), dbPool);
    });

    FL_LOG_INFO("AuthServer", "Running. Press Ctrl+C to stop.");
    co_await listener.Listen(BIND_ADDRESS, BIND_PORT);

    dbPool.stop();
}

int main(int argc, char* argv[])
{
    constexpr std::size_t THREAD_COUNT = 2;

    Fireland::Utils::ProgramOptions opts("authserver", "0.1.0", "authserver.conf");
    if (!opts.Parse(argc, argv))
        return opts.ExitCode();

    std::string configFile = opts.ConfigFile();
    FL_LOG_INFO("AuthServer", "Using config file: {}", configFile);
	// Log configuration
    Fireland::Utils::Log::Init(configFile);
    if (opts.Quiet()) Fireland::Utils::Log::SetConsoleEnabled(false);

    std::cout << "========================================\n"
              << "  Fireland Auth Server\n"
              << "  Account: TEST / TEST\n"
              << "========================================\n";
    try
    {
		// Initiate thread pool and signal handlers
        Fireland::Utils::IoContext ioContext(THREAD_COUNT);
        ioContext.InstallSignalHandlers();

		// Run the server asynchronously
        boost::asio::co_spawn(ioContext.Get(), async_main(ioContext), boost::asio::detached);

        ioContext.Join();
        FL_LOG_INFO("AuthServer", "Shutdown complete.");
    }
    catch (const std::exception& e)
    {
        FL_LOG_FATAL("AuthServer", "Fatal error: {}", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
