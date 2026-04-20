#include <chrono>

#include <boost/mysql.hpp>
#include <boost/mysql/row_view.hpp>
#include <boost/asio/cancel_after.hpp>

#include <Database/Char/CharWrapper.h>

#include <Utils/Log.h>

using namespace Fireland::Database::Char;
using namespace Fireland::Utils::Async;
using namespace std::chrono_literals;

std::unique_ptr<CharWrapper> CharWrapper::instance_ = nullptr;

void CharWrapper::Init(boost::asio::any_io_executor exec, connection_pool_wrapper_options options)
{
    if (!instance_)
        instance_ = std::unique_ptr<CharWrapper>(new CharWrapper(exec, options));
}

CharWrapper& CharWrapper::Instance()
{
    return *instance_;
}

void CharWrapper::Shutdown()
{
    if (instance_)
    {
		instance_->stop();
        auto ptr = instance_.release();
        delete ptr;
        instance_.reset();
    }
}

CharWrapper::CharWrapper(boost::asio::any_io_executor exec, connection_pool_wrapper_options options) noexcept
    : _options{ std::move(options) }
    , _connection_pool { exec}
{
}

CharWrapper::~CharWrapper()
{
    stop();
}

void CharWrapper::start()
{
    _connection_pool.start(_options);
}

void CharWrapper::stop()
{
	_connection_pool.stop();
}

async<bool> CharWrapper::ping() noexcept
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

async<bool> CharWrapper::IsNameAvailable(std::string_view name) noexcept
{
    std::string name_str(name);
    auto result = co_await _connection_pool.async_execute<boost::mysql::results>(
        "SELECT guid FROM characters WHERE name = ?", name_str);
    if (!result)
    {
        connection_pool_wrapper::db_err(result.error());
        co_return true;
    }
    co_return result.value().rows().empty();
}

async<std::optional<characters>> CharWrapper::GetCharacterByGuid(uint64_t guid) noexcept
{
    auto result = co_await _connection_pool.async_execute<std::vector<characters>>(
        "SELECT * FROM characters WHERE guid = ?", guid);
    if (!result)
    {
        connection_pool_wrapper::db_err(result.error());
        co_return std::nullopt;
    }
    if (result.value().empty()) co_return std::nullopt;
    co_return result.value()[0];
}

Fireland::Utils::Async::async<std::vector<characters>> CharWrapper::GetCharactersForAccount(uint32_t accountid) noexcept
{
    auto result = co_await _connection_pool.async_execute<std::vector<characters>>("SELECT * FROM characters WHERE account = ?", accountid);
    if (!result)
    {
        connection_pool_wrapper::db_err(result.error());
        co_return std::vector<characters>{};
    }
	co_return result.value();
}

Fireland::Utils::Async::async<std::optional<characters>> CharWrapper::CreateCharacter(characters c) noexcept
{
    characters saved = std::move(c);
    auto result = co_await _connection_pool.async_insert<characters>(saved);
    if (!result)
    {
        connection_pool_wrapper::db_err(result.error());
        co_return std::nullopt;
    }
    if (result.value().affected_rows() == 0) co_return std::nullopt;
    saved.guid = static_cast<uint32_t>(result.value().last_insert_id());
	co_return saved;
}

Fireland::Utils::Async::async<bool> CharWrapper::DeleteCharacter(uint64_t guid, uint32_t accountid) noexcept
{
    auto result = co_await _connection_pool.async_execute<boost::mysql::results>(
        "DELETE FROM characters WHERE guid = ? AND account = ?", guid, accountid);
    if (!result)
    {
        connection_pool_wrapper::db_err(result.error());
        co_return false;
    }
    co_return result.value().affected_rows() != 0;
}