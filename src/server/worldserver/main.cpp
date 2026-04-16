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

#include <Utils/Async.hpp>
#include <Utils/StringUtils.h>
#include <Utils/Log.h>
#include <Utils/ProgramOptions.h>
#include <Utils/IoContext.h>

#include <Network/TcpListener.h>

#include <Database/connection_pool_wrapper.h>

#include "WorldSession.h"

Fireland::Utils::Async::async<void> async_main(Fireland::Utils::IoContext& thread_pool)
{
    constexpr const char* BIND_ADDRESS = "0.0.0.0";
    constexpr uint16_t    BIND_PORT = 8085;

    Fireland::Database::Auth::AuthWrapper authdbPool(thread_pool.Get());
    authdbPool.start();
    if (!co_await authdbPool.ping())
    {
        FL_LOG_ERROR("WorldServer", "Failed to connect to the database. Shutting down.");
        authdbPool.stop();
        thread_pool.Stop();
        co_return;
    }

    Fireland::Network::TcpListener<Fireland::World::WorldSession> listener(
        thread_pool,
        [&authdbPool](boost::asio::ip::tcp::socket socket) {
            return std::make_shared<Fireland::World::WorldSession>(std::move(socket), authdbPool);
        }
    );

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
    co_await listener.Listen(BIND_ADDRESS, BIND_PORT);

    signals.cancel();
    authdbPool.stop();
    thread_pool.Stop();
}

int main(int argc, char* argv[])
{
    Fireland::Utils::ProgramOptions opts("worldserver", "0.1.0", "worldserver.conf");
    if (!opts.Parse(argc, argv))
        return opts.ExitCode();

    Fireland::Utils::Log::Init(opts.ConfigFile());
    if (opts.Quiet()) Fireland::Utils::Log::SetConsoleEnabled(false);

    std::cout << "========================================\n"
              << "  Fireland World Server\n"
              << "========================================\n";

    constexpr std::size_t THREAD_COUNT = 4;

    try
    {
        Fireland::Utils::IoContext ioContext(THREAD_COUNT);
        Fireland::Utils::Log::SetExecutor(ioContext.Get());
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
