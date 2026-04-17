#include <Database/connection_pool_wrapper.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/cancel_after.hpp>

#include <Utils/NetUtils.h>
#include <Utils/Log.h>

using namespace Fireland::Database;

connection_pool_wrapper::connection_pool_wrapper(boost::asio::any_io_executor exec) noexcept
    : _exec{ boost::asio::make_strand(exec) }
    , _pool{ nullptr }
{
}

void connection_pool_wrapper::start(connection_pool_wrapper_options options) noexcept
{
    //already started
    if (_pool) return;

    auto ip_host = Fireland::Utils::Net::ip_for(options.hostname);
	FL_LOG_INFO("Database", "> Starting database connection pool... (database {}:{} / {} with user '{}')", options.hostname, options.port, options.database, options.username);

    auto max_co = 5;

    // -- pool options
    boost::mysql::pool_params param_opts;
    param_opts.server_address = boost::mysql::host_and_port{ ip_host, options.port };
    param_opts.username = options.username;
    param_opts.password = options.password;
    param_opts.database = options.database;
    param_opts.ssl = boost::mysql::ssl_mode::enable;
    param_opts.multi_queries = false;
    param_opts.initial_size = std::size_t(5);
    param_opts.max_size = std::size_t(max_co);
    param_opts.connect_timeout = std::chrono::steady_clock::duration{ std::chrono::seconds(20) };
    param_opts.retry_interval = std::chrono::steady_clock::duration{ std::chrono::seconds(30) };
    param_opts.ping_interval = std::chrono::steady_clock::duration{ std::chrono::seconds(10) };
    param_opts.ping_timeout = std::chrono::steady_clock::duration{ std::chrono::seconds(10) };

    //construct the pool from options
    _pool = std::make_unique<boost::mysql::connection_pool>(_exec, std::move(param_opts));

    //run the pool asynchronously
    _pool->async_run(boost::asio::detached);

    FL_LOG_INFO("Database", "> database connection pool is started.");
}

void connection_pool_wrapper::stop() noexcept
{
	if (!_pool) return;

    FL_LOG_INFO("Database", "> stopping database connection pool...");

    _pool->cancel();
    _pool.reset();

    FL_LOG_INFO("Database", "> database connection pool stopped.");
}

async_mysql_result<boost::mysql::pooled_connection> connection_pool_wrapper::async_get_connection() noexcept
{
    auto lambda = [this]() -> async_mysql_result<boost::mysql::pooled_connection>
    {
        //err managment
        boost::mysql::diagnostics diags;

        //get a fresh connection from the pool
        FL_LOG_DEBUG("Database", "Awaiting valid connection from MySQL connection pool object.");
        //auto [ec, connection] = co_await _pool->async_get_connection(diags, tuple_awaitable_token);
        auto [ec, connection] = co_await _pool->async_get_connection(diags, boost::asio::cancel_after(std::chrono::seconds(5), boost::asio::as_tuple));

        if (ec)
        {
            FL_LOG_ERROR("Database", "> MYSQL: get_async_connection failed");
            co_return std::unexpected{ boost::mysql::error_with_diagnostics(ec, diags) };
        }
        if (!connection.valid())
        {
            FL_LOG_ERROR("Database", "> MYSQL: connection is not valid");
            co_return std::unexpected{ boost::mysql::error_with_diagnostics(ec, diags) };
        }

        std::tie(ec) = co_await connection->async_ping(boost::asio::cancel_after(std::chrono::seconds(5), boost::asio::as_tuple));
        if (ec && (ec == boost::asio::error::connection_reset || ec == boost::asio::error::eof || ec == boost::asio::error::broken_pipe))
        {
            co_await Utils::Async::async_sleep(std::chrono::milliseconds(150));
            FL_LOG_WARNING("Database", "> MYSQL: connection to the database has been lost, retrying...");
            co_return co_await async_get_connection();
        }

        co_return std::move(connection);
    };

    return boost::asio::co_spawn(_exec, lambda, boost::asio::use_awaitable);
}
