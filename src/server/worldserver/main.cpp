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

#include <boost/asio/signal_set.hpp>

#include <Utils/Asio/Async.hpp>
#include <Utils/Asio/IoContext.h>
#include <Utils/Configuration/Configuration.h>
#include <Utils/StringUtils.h>
#include <Utils/Log.h>
#include <Utils/ProgramOptions.h>

#include <Network/TcpListener.h>

#include <Database/Auth/AuthWrapper.h>
#include <Database/Char/CharWrapper.h>

#include <Game/World/WorldSession.h>

Fireland::Utils::Async::async<bool> initiate_database(Fireland::Utils::IoContext& thread_pool)
{
    // Load database configuration and initialize the auth wrapper
    Fireland::Database::connection_pool_wrapper_options dbOptions{
        sConfig.get<std::string>(DATABASE_USER),
        sConfig.get<std::string>(DATABASE_PASSWORD),
        sConfig.get<std::string>(DATABASE_AUTH),
        sConfig.get<std::string>(DATABASE_HOST),
        sConfig.get<uint16_t>(DATABASE_PORT)
    };
    Fireland::Database::Auth::AuthWrapper::Init(thread_pool.Get(), dbOptions);
    sAuthDB.start();
    if (!co_await sAuthDB.ping())
    {
        FL_LOG_ERROR("WorldServer", "Failed to connect to the Auth database. Shutting down.");
        sAuthDB.Shutdown();
        thread_pool.Stop();
        co_return false;
    }

    dbOptions.database = sConfig.get<std::string>(DATABASE_CHAR);
	Fireland::Database::Char::CharWrapper::Init(thread_pool.Get(), dbOptions);
    sCharDB.start();
    if (!co_await sCharDB.ping())
    {
        FL_LOG_ERROR("WorldServer", "Failed to connect to the Characters database. Shutting down.");
        sAuthDB.Shutdown();
        sCharDB.Shutdown();
        thread_pool.Stop();
        co_return false;
    }
    co_return true;
}

Fireland::Utils::Async::async<void> async_main(Fireland::Utils::IoContext& thread_pool)
{
    // Initialize the database connection pool and verify connectivity before starting the server.
    if (!co_await initiate_database(thread_pool))
        co_return;

    // Create the TCP listener with a session factory that constructs WorldSession instances.
    Fireland::Network::TcpListener<Fireland::World::WorldSession> listener(
        thread_pool,
        [&thread_pool](boost::asio::ip::tcp::socket socket)
        {
            return std::make_shared<Fireland::World::WorldSession>(thread_pool.Get(), std::move(socket));
        }
    );

	// Set up signal handling for graceful shutdown on SIGINT and SIGTERM.
    boost::asio::signal_set signals(thread_pool.Get(), SIGINT, SIGTERM);
    signals.async_wait([&listener](const boost::system::error_code& ec, int signo)
    {
        if (!ec)
        {
            FL_LOG_INFO("WorldServer", "Received signal {}, shutting down", signo);
            listener.Stop();
        }
    });

    FL_LOG_INFO("WorldServer", "Running. Press Ctrl+C to stop.");
    const std::string BIND_ADDRESS = sConfig.get<std::string>(SERVER_SERVER_IP);
	const uint16_t BIND_PORT = sConfig.get<uint16_t>(SERVER_SERVER_PORT);
    co_await listener.Listen(BIND_ADDRESS, BIND_PORT);

    signals.cancel();
    sAuthDB.Shutdown();
	sCharDB.Shutdown();
    thread_pool.Stop();
}

int main(int argc, char* argv[])
{
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
#endif
    Fireland::Utils::ProgramOptions opts("worldserver", "0.1.0", "worldserver.conf");
    if (!opts.Parse(argc, argv))
        return opts.ExitCode();

    try
    {
        Fireland::Utils::Log::Init(opts.ConfigFile());
        if (opts.Quiet()) Fireland::Utils::Log::SetConsoleEnabled(false);
        sConfig.load(opts.ConfigFile());

        // Fancy startup header
        std::cout << "\n"
            << "\033[1;31m"
            << "========================================\n"
            << "   █████▒██╗██╗███████╗██╗      █████╗ ███╗   ██╗██████╗ \n"
            << "  ▓██   ▒██║██║██╔════╝██║     ██╔══██╗████╗  ██║██╔══██╗\n"
            << "  ▒████ ░██║██║█████╗  ██║     ███████║██╔██╗ ██║██║  ██║\n"
            << "  ░▓█▒  ░██║██║██╔══╝  ██║     ██╔══██║██║╚██╗██║██║  ██║\n"
            << "  ░▒█   ░██║██║███████╗███████╗██║  ██║██║ ╚████║██████╔╝\n"
            << "   ░    ░╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ \n"
            << "========================================\n"
            << "\033[0m"
            << "  Project: Fireland World Server\n"
            << "  Version: 0.1.0\n"
            << "  Config : " << opts.ConfigFile() << "\n"
            << "  Threads: " << (sConfig.get<uint32_t>(SERVER_THREAD_COUNT) == 0 ? std::thread::hardware_concurrency() : sConfig.get<uint32_t>(SERVER_THREAD_COUNT)) << "\n"
            << "========================================\n\n";

        Fireland::Utils::IoContext ioContext(sConfig.get<uint32_t>(SERVER_THREAD_COUNT));
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
