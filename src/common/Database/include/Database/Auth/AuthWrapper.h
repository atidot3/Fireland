#pragma once

#include <span>

#include <boost/asio/cancellation_signal.hpp>

#include <Database/connection_pool_wrapper.h>

#include <Utils/Async.hpp>

#include <Shared/Auth/Account.h>
#include <Shared/Realm/Realmlist.h>

namespace Fireland::Database::Auth
{
    class AuthWrapper
    {
        friend class Fireland::Database::connection_pool_wrapper;
    public:
        AuthWrapper(const AuthWrapper&) = delete;
        AuthWrapper& operator=(const AuthWrapper&) = delete;
        ~AuthWrapper();

        static void Init(boost::asio::any_io_executor exec, connection_pool_wrapper_options options);
        static AuthWrapper& Instance();
        static void Shutdown();

        // starting/stopping the wrapper
        void start();
        void stop();
        Utils::Async::async<bool> ping() noexcept;

        // -- Account operations
        Utils::Async::async<std::optional<account>> Create(account account) noexcept;
        Utils::Async::async<std::optional<account>> GetAccountByUsername(std::string_view username) noexcept;
        Utils::Async::async<void> StoreSessionKey(uint32_t accountId, std::span<const uint8_t, 40> sessionKey) noexcept;
        Utils::Async::async<std::optional<std::array<uint8_t, 40>>> LookupSessionKey(uint32_t accountId) noexcept;

        // -- Realmlist operations
        Utils::Async::async<bool> UpdateRealm(realmlist r) noexcept;
        Utils::Async::async<std::optional<realmlist>> CreateRealm(realmlist r) noexcept;
        Utils::Async::async<std::optional<std::vector<realmlist>>> GetRealmlist() noexcept;

    private:
        AuthWrapper(boost::asio::any_io_executor executor, connection_pool_wrapper_options options) noexcept;
       
    private:
        static std::unique_ptr<AuthWrapper> instance_;
        boost::asio::cancellation_signal _cancelSignal;
		const Fireland::Database::connection_pool_wrapper_options _options;
        connection_pool_wrapper _connection_pool;
    };
} // namespace Fireland::Database::Auth
#define sAuthDB Fireland::Database::Auth::AuthWrapper::Instance()