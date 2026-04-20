// ============================================================================
// Firelands Auth Server — Entry point
//
// SRP6-based authentication server for WoW Cataclysm (4.3.4).
// Listens on 0.0.0.0:3724, handles LOGON_CHALLENGE, LOGON_PROOF, REALM_LIST.
//
// Hardcoded test account: TEST / TEST
// ============================================================================

#include <cstdlib>
#include <iostream>
#include <string>

#include <boost/asio/signal_set.hpp>

#include <Utils/Asio/Async.hpp>
#include <Utils/Asio/IoContext.h>
#include <Utils/Configuration/Configuration.h>
#include <Utils/Log.h>
#include <Utils/ProgramOptions.h>

#include <Network/TcpListener.h>

#include <Database/Auth/AuthWrapper.h>
#include <Crypto/SRP6.h>

#include "Network/AuthSession.h"
#include "Realm/Realm.h"

Firelands::Utils::Async::async<bool> initiate_database(Firelands::Utils::IoContext& thread_pool)
{
    // Load database configuration and initialize the auth wrapper
    Firelands::Database::connection_pool_wrapper_options dbOptions{
        sConfig.get<std::string>(DATABASE_USER),
        sConfig.get<std::string>(DATABASE_PASSWORD),
        sConfig.get<std::string>(DATABASE_AUTH),
        sConfig.get<std::string>(DATABASE_HOST),
        sConfig.get<uint16_t>(DATABASE_PORT)
    };
    Firelands::Database::Auth::AuthWrapper::Init(thread_pool.Get(), dbOptions);
    sAuthDB.start();
    if (!co_await sAuthDB.ping())
    {
        FL_LOG_ERROR("WorldServer", "Failed to connect to the database. Shutting down.");
        sAuthDB.Shutdown();
        thread_pool.Stop();
        co_return false;
    }

    co_return true;
}

Firelands::Utils::Async::async<void> async_main(Firelands::Utils::IoContext& thread_pool)
{
    // Initialize the database connection pool and verify connectivity before starting the server.
    if (!co_await initiate_database(thread_pool))
    {
        co_return;
    }
    
	// Initialize the realm list manager, which periodically updates the list of realms from the database.
	Realm::Init(thread_pool.Get());

    // Create the TCP listener with a session factory that constructs AuthSession instances.
    Firelands::Network::TcpListener<Firelands::Auth::AuthSession> listener(
        thread_pool,
        [](boost::asio::ip::tcp::socket socket) {
            return std::make_shared<Firelands::Auth::AuthSession>(std::move(socket));
        }
    );

    // Set up signal handling for graceful shutdown on SIGINT and SIGTERM.
    boost::asio::signal_set signals(thread_pool.Get(), SIGINT, SIGTERM);
    signals.async_wait([&listener](const boost::system::error_code& ec, int signo)
    {
        if (!ec)
        {
            FL_LOG_INFO("AuthServer", "Received signal {}, shutting down", signo);
            listener.Stop();
        }
    });

    FL_LOG_INFO("AuthServer", "Running. Press Ctrl+C to stop.");
    const std::string BIND_ADDRESS = sConfig.get<std::string>(SERVER_SERVER_IP);
    const uint16_t BIND_PORT = sConfig.get<uint16_t>(SERVER_SERVER_PORT);
    co_await listener.Listen(BIND_ADDRESS, BIND_PORT);

    signals.cancel();
    Realm::Shutdown();
    sAuthDB.Shutdown();
    thread_pool.Stop();
}

int main(int argc, char* argv[])
{
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
#endif

    Firelands::Utils::ProgramOptions opts("authserver", "0.1.0", "authserver.conf");
    if (!opts.Parse(argc, argv))
        return opts.ExitCode();

    try
    {
        Firelands::Utils::Log::Init(opts.ConfigFile());
        if (opts.Quiet()) Firelands::Utils::Log::SetConsoleEnabled(false);
        sConfig.load(opts.ConfigFile());

        // Fancy startup header
        std::cout << "\n"
            << "\033[1;31m"
            << "========================================\n"
            << "    █████╗ ██╗   ██╗████████╗██╗  ██╗    \n"
            << "   ██╔══██╗██║   ██║╚══██╔══╝██║  ██║    \n"
            << "   ███████║██║   ██║   ██║   ███████║    \n"
            << "   ██╔══██║██║   ██║   ██║   ██╔══██║    \n"
            << "   ██║  ██║╚██████╔╝   ██║   ██║  ██║    \n"
            << "   ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝    \n"
            << "========================================\n"
            << "\033[0m"
            << "  Project: Firelands Auth Server\n"
            << "  Version: 0.1.0\n"
            << "  Config : " << opts.ConfigFile() << "\n"
            << "  Threads: " << (sConfig.get<uint32_t>(SERVER_THREAD_COUNT) == 0 ? std::thread::hardware_concurrency() : sConfig.get<uint32_t>(SERVER_THREAD_COUNT)) << "\n"
            << "========================================\n\n";

        Firelands::Utils::IoContext ioContext(sConfig.get<uint32_t>(SERVER_THREAD_COUNT));
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
