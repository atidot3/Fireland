#pragma once
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <iostream>

#include <boost/mysql/connection_pool.hpp>
#include <boost/mysql/string_view.hpp>
#include <boost/mysql/error_with_diagnostics.hpp>

#include <Utils/Async.hpp>

namespace Fireland::Database
{
	//main return type from functions
	template<typename T>
	using async_mysql_result = Utils::Async::async<std::expected<T, boost::mysql::error_with_diagnostics>>;

	//wrapper connection infos
	struct connection_pool_wrapper_options {
		std::string username;
		std::string password;
		std::string database;
		std::string hostname;
		uint16_t port;
	};

	//our connection_pool_wrapper definition
	class connection_pool_wrapper {
	public:
		//create from executor
		connection_pool_wrapper(boost::asio::any_io_executor exec) noexcept;

		//start the mysql connection pooling
		void start(connection_pool_wrapper_options options) noexcept;

		//stop it
		void stop() noexcept;

		//get a connection from the pool for advanced use (transactions)
		async_mysql_result<boost::mysql::pooled_connection> async_get_connection() noexcept;

	private:
		boost::asio::strand<boost::asio::any_io_executor> _exec;
		std::unique_ptr<boost::mysql::connection_pool> _pool;
	};
} // Fireland::Database