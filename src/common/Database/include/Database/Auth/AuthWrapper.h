#pragma once

#include <span>

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
        AuthWrapper(boost::asio::any_io_executor executor) noexcept;

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
        const std::string _database_host;
        const uint16_t _database_port;
        const std::string _database_name;
        const std::string _database_user;
        const std::string _database_password;
        connection_pool_wrapper _connection_pool;
    };
} // namespace Fireland::Database::Auth