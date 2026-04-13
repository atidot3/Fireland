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

#include <Utils/Log.h>
#include <Utils/ProgramOptions.h>
#include <Utils/IoContext.h>
#include <Network/SessionKeyStore.h>
#include <Network/TcpListener.h>

#include "AuthSession.h"

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

        Fireland::Network::SessionKeyStore sessionKeyStore(ioContext.Get());

        Fireland::Network::TcpListener<Fireland::Auth::AuthSession> listener(
            ioContext,
            [&sessionKeyStore](boost::asio::ip::tcp::socket socket) {
                return std::make_shared<Fireland::Auth::AuthSession>(std::move(socket), sessionKeyStore);
            }
        );

        ioContext.InstallSignalHandlers();
        listener.Listen(BIND_ADDRESS, BIND_PORT);

        FL_LOG_INFO("AuthServer", "Running. Press Ctrl+C to stop.");
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
