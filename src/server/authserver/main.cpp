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

#include <Network/SessionKeyStore.h>
#include <Network/TcpListener.h>

#include <Database/connection_pool_wrapper.h>

#include "AuthSession.h"

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
    constexpr uint16_t    BIND_PORT = 3724;
    
    Fireland::Network::SessionKeyStore sessionKeyStore(thread_pool.Get());
    auto dbPool = initiate_database(thread_pool.Get());

    Fireland::Network::TcpListener<Fireland::Auth::AuthSession> listener(
        thread_pool,
        [&sessionKeyStore, dbPool](boost::asio::ip::tcp::socket socket) {
            return std::make_shared<Fireland::Auth::AuthSession>(std::move(socket), sessionKeyStore);
        }
    );

    FL_LOG_INFO("AuthServer", "Running. Press Ctrl+C to stop.");
    co_await listener.Listen(BIND_ADDRESS, BIND_PORT);

    if (dbPool)
    {
        dbPool->stop();
        dbPool = nullptr;
    }
}

int main(int argc, char* argv[])
{
    constexpr std::size_t THREAD_COUNT = 2;

    Fireland::Utils::ProgramOptions opts("authserver", "0.1.0", "authserver.conf");
    if (!opts.Parse(argc, argv))
        return opts.ExitCode();

	// Log configuration
    Fireland::Utils::Log::Init(opts.ConfigFile());
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
