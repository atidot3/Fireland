#include <chrono>

#include <boost/mysql.hpp>
#include <boost/mysql/row_view.hpp>
#include <boost/asio/cancel_after.hpp>

#include <Database/Auth/AuthWrapper.h>

#include <Utils/Log.h>

using namespace Fireland::Database::Auth;
using namespace Fireland::Utils::Async;
using namespace std::chrono_literals;

std::unique_ptr<AuthWrapper> AuthWrapper::instance_ = nullptr;

void AuthWrapper::Init(boost::asio::any_io_executor exec, connection_pool_wrapper_options options)
{
    if (!instance_)
        instance_ = std::unique_ptr<AuthWrapper>(new AuthWrapper(exec, options));
}

AuthWrapper& AuthWrapper::Instance()
{
    return *instance_;
}

void AuthWrapper::Shutdown()
{
    if (instance_)
    {
		instance_->stop();
        auto ptr = instance_.release();
        delete ptr;
        instance_.reset();
    }
}

AuthWrapper::AuthWrapper(boost::asio::any_io_executor exec, connection_pool_wrapper_options options) noexcept
    : _options{ std::move(options) }
    , _connection_pool { exec}
{
}

AuthWrapper::~AuthWrapper()
{
    stop();
}

void AuthWrapper::start()
{
    _connection_pool.start(_options);
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
        connection_pool_wrapper::db_err(result.error());
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
        connection_pool_wrapper::db_err(result.error());
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
        connection_pool_wrapper::db_err(result.error());
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
        connection_pool_wrapper::db_err(result.error());
}


async<std::optional<std::array<uint8_t, 40>>> AuthWrapper::LookupSessionKey(uint32_t accountId) noexcept
{
    auto result = co_await _connection_pool.async_execute<boost::mysql::results>(
        "SELECT session_key FROM account_session WHERE id = ?", accountId);
    if (!result)
    {
        connection_pool_wrapper::db_err(result.error());
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

// ------------------- REALMLIST MANAGEMENT -------------------

async<std::optional<std::vector<realmlist>>> AuthWrapper::GetRealmlist() noexcept
{
    auto result = co_await _connection_pool.async_execute<std::vector<realmlist>>("SELECT * FROM realmlist");
    if (!result)
    {
        connection_pool_wrapper::db_err(result.error());
        co_return std::nullopt;
    }
    if (result.value().empty()) co_return std::nullopt;

    co_return result.value();
}

async<std::optional<realmlist>> AuthWrapper::CreateRealm(realmlist realm) noexcept
{
    co_return std::nullopt;
}

async<bool> AuthWrapper::UpdateRealm(realmlist r) noexcept
{
    co_return false;
}
