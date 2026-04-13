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

#include <Utils/Log.h>
#include <Utils/ProgramOptions.h>
#include <Utils/IoContext.h>

#include <Network/SessionKeyStore.h>
#include <Network/TcpListener.h>

#include "WorldSession.h"

int main(int argc, char* argv[])
{
    Fireland::Utils::ProgramOptions opts("worldserver", "0.1.0", "worldserver.conf");
    if (!opts.Parse(argc, argv))
        return opts.ExitCode();

    Fireland::Utils::Log::Init(opts.ConfigFile());
    if (opts.Quiet())
        Fireland::Utils::Log::SetConsoleEnabled(false);

    std::cout << "========================================\n"
              << "  Fireland World Server\n"
              << "========================================\n";

    constexpr const char* BIND_ADDRESS = "0.0.0.0";
    constexpr uint16_t    BIND_PORT    = 8085;
    constexpr std::size_t THREAD_COUNT = 4;

    try
    {
        Fireland::Utils::IoContext ioContext(THREAD_COUNT);

        Fireland::Network::SessionKeyStore sessionKeyStore(ioContext.Get());
        Fireland::Network::TcpListener<Fireland::World::WorldSession> listener(
            ioContext,
            [&sessionKeyStore](boost::asio::ip::tcp::socket socket) {
                return std::make_shared<Fireland::World::WorldSession>(
                    std::move(socket), sessionKeyStore);
            }
        );

        ioContext.InstallSignalHandlers();
        listener.Listen(BIND_ADDRESS, BIND_PORT);

        FL_LOG_INFO("WorldServer", "Running. Press Ctrl+C to stop.");

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
