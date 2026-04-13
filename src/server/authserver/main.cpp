// ============================================================================
// Fireland Auth Server — Entry point
//
// Minimal TCP server using Boost.Asio C++20 coroutines.
// Listens on 0.0.0.0:3724 (default WoW auth port).
// ============================================================================

#include <cstdlib>
#include <iostream>

#include <Utils/Log.h>
#include <Utils/ProgramOptions.h>

#include <Network/IoContext.h>
#include <Network/TcpListener.h>
#include <Network/SessionManager.h>
#include <Network/PacketBuffer.h>

using namespace Fireland::Network;

static void OnPacketReceived(TcpSession::Ptr session, PacketBuffer packet)
{
    FL_LOG_INFO("AuthServer", "Session #{} received opcode 0x{:x} ({} bytes payload)",
        session->GetId(), packet.GetOpcode(), packet.GetPayloadSize());

    // Echo the packet back for now (placeholder for auth logic)
    session->Send(std::move(packet));
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
              << "========================================\n";

    constexpr const char* BIND_ADDRESS = "0.0.0.0";
    constexpr uint16_t    BIND_PORT    = 3724;
    constexpr std::size_t THREAD_COUNT = 2;

    try
    {
        IoContext       ioContext(THREAD_COUNT);
        SessionManager  sessionManager(ioContext.Get());
        TcpListener     listener(ioContext, sessionManager);

        ioContext.InstallSignalHandlers();
        listener.Listen(BIND_ADDRESS, BIND_PORT, OnPacketReceived);

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
