#include <chrono>

#include <boost/mysql.hpp>
#include <boost/mysql/row_view.hpp>
#include <boost/asio/cancel_after.hpp>

#include <Database/Auth/AuthWrapper.h>

#include <Utils/Log.h>

using namespace Fireland::Database::Auth;
using namespace Fireland::Utils::Async;

// Helper: extract a readable error string from a Boost MySQL error.
// error_with_diagnostics::what() returns a null-terminated string that
// includes both the error code and the server/client diagnostic message.
void db_err(const boost::mysql::error_with_diagnostics& e)
{
    auto ec = e.code();
	auto diag = e.get_diagnostics();

    FL_LOG_FATAL("Database", "> {}: {}", e.code().to_string(), ec.message());
    std::string server_error(diag.server_message());
    std::string client_error(diag.client_message());
    FL_LOG_FATAL("Database", "> Diagnostics: server='{}', client='{}'", server_error, client_error);
}

AuthWrapper::AuthWrapper(boost::asio::any_io_executor exec) noexcept
    : _database_host{ "127.0.0.1" }
    , _database_port { 3306 }
    , _database_name { "firelands_auth" }
    , _database_user { "user" }
    , _database_password { "password" }
    , _connection_pool { exec}
{
}

void AuthWrapper::start()
{
    _connection_pool.start(connection_pool_wrapper_options{_database_user, _database_password, _database_name, _database_host, _database_port});
}

void AuthWrapper::stop()
{
	_connection_pool.stop();
}

async<bool> AuthWrapper::ping() noexcept
{
    auto result = co_await _connection_pool.async_get_connection();
    if (!result)
    {
        db_err(result.error());
        co_return false;
    }

    boost::mysql::pooled_connection& connection = result.value();
    auto [ec] = co_await connection->async_ping(boost::asio::cancel_after(std::chrono::seconds(5), boost::asio::as_tuple));
    if (ec && (ec == boost::asio::error::connection_reset || ec == boost::asio::error::eof || ec == boost::asio::error::broken_pipe))
    {
        FL_LOG_WARNING("Database", "ping failed with connection error: {}", ec.message());
        co_return false;
    }

    co_return true;
}

async<std::optional<account>> AuthWrapper::Create(account create_account) noexcept
{
    account saved = std::move(create_account);
    auto result = co_await _connection_pool.async_insert<account>(saved);
    if (!result)
    {
        db_err(result.error());
        co_return std::nullopt;
    }
    if (result.value().affected_rows() == 0) co_return std::nullopt;

    saved.id = static_cast<uint32_t>(result.value().last_insert_id());
    co_return saved;
}

async<std::optional<account>> AuthWrapper::GetAccountByUsername(std::string_view username) noexcept
{
    std::string username_str(username);
    auto result = co_await _connection_pool.async_execute<std::vector<account>>(
        "SELECT id, username, email, salt, verifier, expansion FROM account WHERE username = ?", username_str);
    if (!result)
    {
        db_err(result.error());
        co_return std::nullopt;
    }
    if (result.value().empty()) co_return std::nullopt;

    co_return result.value()[0];
}

async<void> AuthWrapper::StoreSessionKey(uint32_t accountId, std::span<const uint8_t, 40> sessionKey) noexcept
{
    std::vector<uint8_t> sessionKeyVec(sessionKey.begin(), sessionKey.end());
    // UPSERT: insert the row if it doesn't exist, update session_key otherwise.
    // ON DUPLICATE KEY UPDATE triggers when the primary key (id) conflicts.
    auto result = co_await _connection_pool.async_execute<boost::mysql::results>(
        "INSERT INTO account_session (id, session_key) VALUES (?, ?)"
        " ON DUPLICATE KEY UPDATE session_key = ?",
        accountId, sessionKeyVec, sessionKeyVec);
    if (!result)
        db_err(result.error());
}

async<std::optional<std::array<uint8_t, 40>>> AuthWrapper::LookupSessionKey(uint32_t accountId) noexcept
{
    auto result = co_await _connection_pool.async_execute<boost::mysql::results>(
        "SELECT session_key FROM account_session WHERE id = ?", accountId);
    if (!result)
    {
        db_err(result.error());
        co_return std::nullopt;
    }

    auto rows = result.value().rows();
    if (rows.empty()) co_return std::nullopt;

    auto blob = rows[0][0].as_blob();
    if (blob.size() != 40)
    {
        FL_LOG_ERROR("Database", "Invalid session key size for account ID '{}': expected 40 bytes, got {}", accountId, blob.size());
        co_return std::nullopt;
    }

    std::array<uint8_t, 40> sessionKey{};
    std::copy_n(blob.begin(), 40, sessionKey.begin());
    co_return sessionKey;
}
