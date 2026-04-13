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

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <Utils/Log.h>
#include <Utils/ProgramOptions.h>
#include <Utils/IoContext.h>

#include "AuthSession.h"

using namespace boost::asio;

static awaitable<void> AcceptLoop(ip::tcp::acceptor& acceptor)
{
    while (acceptor.is_open())
    {
        try
        {
            auto socket = co_await acceptor.async_accept(use_awaitable);
            socket.set_option(ip::tcp::no_delay(true));

            auto session = std::make_shared<Fireland::Auth::AuthSession>(std::move(socket));
            co_spawn(
                acceptor.get_executor(),
                [session]() -> awaitable<void> { co_await session->Run(); },
                detached);
        }
        catch (const boost::system::system_error& e)
        {
            if (e.code() == error::operation_aborted)
                break;
            FL_LOG_ERROR("AuthServer", "Accept error: {}", e.what());
        }
    }
}

int main(int argc, char* argv[])
{
    Fireland::Utils::ProgramOptions opts("authserver", "0.1.0", "authserver.conf");
    if (!opts.Parse(argc, argv))
        return opts.ExitCode();

    Fireland::Utils::Log::Init(opts.ConfigFile());
    if (opts.Quiet())
        Fireland::Utils::Log::SetConsoleEnabled(false);

    std::cout << "========================================\n"
              << "  Fireland Auth Server\n"
              << "  Account: TEST / TEST\n"
              << "========================================\n";

    constexpr const char* BIND_ADDRESS = "0.0.0.0";
    constexpr uint16_t    BIND_PORT    = 3724;
    constexpr std::size_t THREAD_COUNT = 2;

    try
    {
        Fireland::Utils::IoContext ioContext(THREAD_COUNT);

        ip::tcp::acceptor acceptor(ioContext.Get());
        ip::tcp::endpoint endpoint(ip::make_address(BIND_ADDRESS), BIND_PORT);

        acceptor.open(endpoint.protocol());
        acceptor.set_option(ip::tcp::acceptor::reuse_address(true));
        acceptor.bind(endpoint);
        acceptor.listen(socket_base::max_listen_connections);

        FL_LOG_INFO("AuthServer", "Listening on {}:{}", BIND_ADDRESS, BIND_PORT);

        co_spawn(ioContext.Get(), AcceptLoop(acceptor), detached);

        ioContext.InstallSignalHandlers();
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
