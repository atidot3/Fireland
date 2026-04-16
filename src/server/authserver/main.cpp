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
#include <string>

#include <boost/asio/signal_set.hpp>

#include <Utils/Async.hpp>
#include <Utils/Log.h>
#include <Utils/ProgramOptions.h>
#include <Utils/IoContext.h>

#include <Network/TcpListener.h>

#include <Database/Auth/AuthWrapper.h>
#include <Crypto/SRP6.h>

#include "Network/AuthSession.h"
#include "Realm/Realm.h"

// ---------------------------------------------------------------------------
// CreateAccount — helper
// ---------------------------------------------------------------------------
Fireland::Utils::Async::async<void> create_account(
    Fireland::Utils::IoContext& thread_pool,
    std::string_view username,
    std::string_view password)
{
    Fireland::Database::Auth::AuthWrapper db(thread_pool.Get());
    db.start();

    if (!co_await db.ping())
    {
        FL_LOG_ERROR("AuthServer", "Cannot connect to database.");
        db.stop();
        thread_pool.Stop();
        co_return;
    }

    // Calcul SRP6 : génère sel aléatoire + vérificateur
    Fireland::Crypto::SRP6 srp;
    srp.ComputeVerifier(username, password);

    auto saltBytes     = srp.GetSalt().AsByteArray(32);
    auto verifierBytes = srp.GetVerifier().AsByteArray(32);

    account acc{};
    acc.username  = std::string(username);
    acc.salt      = std::vector<uint8_t>(saltBytes.begin(), saltBytes.end());
    acc.verifier  = std::vector<uint8_t>(verifierBytes.begin(), verifierBytes.end());
    acc.expansion = 3; // Cataclysm

    auto result = co_await db.Create(acc);
    if (result)
        FL_LOG_INFO("AuthServer", "Account '{}' created (id={}).", result->username, result->id);
    else
        FL_LOG_ERROR("AuthServer", "Failed to create account '{}' (already exists?).", username);

    db.stop();
    thread_pool.Stop();
}

Fireland::Utils::Async::async<void> async_main(Fireland::Utils::IoContext& thread_pool)
{
    constexpr const char* BIND_ADDRESS = "0.0.0.0";
    constexpr uint16_t    BIND_PORT = 3724;

    Fireland::Database::Auth::AuthWrapper dbPool(thread_pool.Get());
    dbPool.start();
    if (!co_await dbPool.ping())
    {
        FL_LOG_ERROR("AuthServer", "Failed to connect to the database. Shutting down.");
        dbPool.stop();
        thread_pool.Stop();
        co_return;
    }

    Realm::Init(thread_pool.Get(), dbPool);

    Fireland::Network::TcpListener<Fireland::Auth::AuthSession> listener(thread_pool, [&dbPool](boost::asio::ip::tcp::socket socket)
    {
        return std::make_shared<Fireland::Auth::AuthSession>(std::move(socket), dbPool);
    });

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
    co_await listener.Listen(BIND_ADDRESS, BIND_PORT);

    signals.cancel();
    Realm::Shutdown();
    dbPool.stop();
    thread_pool.Stop();
}

int main(int argc, char* argv[])
{
    constexpr std::size_t THREAD_COUNT = 2;

    Fireland::Utils::ProgramOptions opts("authserver", "0.1.0", "authserver.conf");
    if (!opts.Parse(argc, argv))
        return opts.ExitCode();

    std::string configFile = opts.ConfigFile();
    FL_LOG_INFO("AuthServer", "Using config file: {}", configFile);
    Fireland::Utils::Log::Init(configFile);
    if (opts.Quiet()) Fireland::Utils::Log::SetConsoleEnabled(false);

    std::cout << "========================================\n"
              << "  Fireland Auth Server\n"
              << "  Account: TEST / TEST\n"
              << "========================================\n";
    try
    {
        Fireland::Utils::IoContext ioContext(THREAD_COUNT);
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
