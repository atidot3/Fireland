#pragma once

#pragma once

#include <Database/connection_pool_wrapper.h>

#include <Utils/Async.hpp>
#include <Utils/Describe.hpp>

struct account
{
    uint32_t id;
    std::string username;
    std::string email;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> verifier;
    uint8_t expansion;
};
BOOST_DESCRIBE_STRUCT(account, (), (id, username, email, salt, verifier, expansion))

struct account_session
{
    uint32_t id;
    std::vector<uint8_t> session_key;
};
BOOST_DESCRIBE_STRUCT(account_session, (), (id, session_key))

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

        // -- Implemented database operations
        Utils::Async::async<std::optional<account>> Create(account account) noexcept;
        Utils::Async::async<std::optional<account>> GetAccountByUsername(std::string_view username) noexcept;
        Utils::Async::async<void> StoreSessionKey(uint32_t accountId, std::span<const uint8_t, 40> sessionKey) noexcept;
        Utils::Async::async<std::optional<std::array<uint8_t, 40>>> LookupSessionKey(uint32_t accountId) noexcept;

    private:

    private:
        const std::string _database_host;
        const uint16_t _database_port;
        const std::string _database_name;
        const std::string _database_user;
        const std::string _database_password;
        connection_pool_wrapper _connection_pool;
    };
} // namespace Fireland::Database::Auth