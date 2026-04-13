// ============================================================================
// Fireland World Server — Entry point (stub)
//
// Minimal TCP server using Boost.Asio C++20 coroutines.
// Listens on 0.0.0.0:8085 (default WoW world port).
// ============================================================================

#include <cstdlib>
#include <iostream>

#include <Utils/Log.h>
#include <Utils/ProgramOptions.h>
#include <Utils/IoContext.h>

#include <Network/TcpListener.h>
#include <Network/SessionManager.h>
#include <Network/PacketBuffer.h>

using namespace Fireland::Network;

static void OnPacketReceived(TcpSession::Ptr session, PacketBuffer packet)
{
    FL_LOG_INFO("WorldServer", "Session #{} received opcode 0x{:x} ({} bytes payload)",
        session->GetId(), packet.GetOpcode(), packet.GetPayloadSize());

    // Echo the packet back for now (placeholder for world logic)
    session->Send(std::move(packet));
}

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
        SessionManager  sessionManager(ioContext.Get());

        TcpListener<TcpSession> listener(
            ioContext,
            [&sessionManager](boost::asio::ip::tcp::socket socket) {
                auto session = std::make_shared<TcpSession>(std::move(socket), sessionManager, OnPacketReceived);
                sessionManager.Add(session);
                return session;
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
