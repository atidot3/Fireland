#pragma once
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <iostream>

#include <boost/describe.hpp>
#include <boost/core/demangle.hpp>
#include <boost/mp11.hpp>

#include <boost/mysql/connection_pool.hpp>
#include <boost/mysql/string_view.hpp>
#include <boost/mysql/error_with_diagnostics.hpp>
#include <boost/mysql/results.hpp>

#include <Utils/Asio/Async.hpp>

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

	namespace sql
	{
		//get typename (demangled), sans préfixe struct/class/union (MSVC)
		template<typename T>
		std::string name()
		{
			std::string n = boost::core::demangle(typeid(T).name());
			for (const char* prefix : {"struct ", "class ", "union "})
			{
				std::size_t len = std::strlen(prefix);
				if (n.size() >= len && n.compare(0, len, prefix) == 0)
				{
					n.erase(0, len);
					break;
				}
			}
			return n;
		}

		//get a tie (tuple of references) of all described members
		template<typename T, template<class...> typename L, typename... Descriptors>
		static auto as_tie(const T& object, L<Descriptors...>)
		{
			return std::tie(object.*Descriptors::pointer...);
		}

		//get a tuple (tuple of values) of all described members
		template<typename T, template<class...> typename L, typename... Descriptors>
		static auto as_tuple(const T& object, L<Descriptors...>)
		{
			return std::make_tuple(object.*Descriptors::pointer...);
		}
	}

	//our connection_pool_wrapper definition
	class connection_pool_wrapper {
	public:
		//create from executor
		connection_pool_wrapper(boost::asio::any_io_executor exec) noexcept;

		//start the mysql connection pooling
		void start(connection_pool_wrapper_options options) noexcept;

		//stop it
		void stop() noexcept;

		//log client/server err diagnostics
		static void db_err(const boost::mysql::error_with_diagnostics& e);

		//get a connection from the pool for advanced use (transactions)
		async_mysql_result<boost::mysql::pooled_connection> async_get_connection() noexcept;

		// Execute a query and return results.
		//
		// Result must be one of:
		//   - std::vector<RowType>        — SELECT: uses static_results<RowType>
		//   - boost::mysql::results       — INSERT/UPDATE/DELETE: uses dynamic results
		template<typename Result, typename... Args>
		async_mysql_result<Result>
		async_execute(std::string_view query, Args&&... args) noexcept
		{
			auto token = boost::asio::bind_executor(_pool->get_executor(), Utils::Async::tuple_awaitable_token);
			std::string statement{query};
			boost::mysql::error_code ec;
			boost::mysql::diagnostics diags;

			auto result_connection = co_await async_get_connection();
			if (!result_connection)
				co_return std::unexpected{result_connection.error()};

			boost::mysql::pooled_connection& connection = result_connection.value();

			if constexpr (std::is_same_v<Result, boost::mysql::results>)
			{
				// Write path: INSERT / UPDATE / DELETE
				boost::mysql::results result;

				if constexpr (sizeof...(Args) == 0)
				{
					std::tie(ec) = co_await connection->async_execute(statement, result, diags, token);
				}
				else
				{
					boost::mysql::statement stmt;
					std::tie(ec, stmt) = co_await connection->async_prepare_statement(statement, diags, token);
					if (ec) co_return std::unexpected{boost::mysql::error_with_diagnostics(ec, diags)};
					auto bound = stmt.bind(std::forward<Args>(args)...);
					std::tie(ec) = co_await connection->async_execute(bound, result, diags, token);
				}
				if (ec) co_return std::unexpected{boost::mysql::error_with_diagnostics(ec, diags)};
				connection.return_without_reset();
				co_return result;
			}
			else
			{
				// Read path: SELECT — Result = std::vector<RowType>
				using RowType = typename Result::value_type;
				boost::mysql::static_results<RowType> result;

				if constexpr (sizeof...(Args) == 0)
				{
					std::tie(ec) = co_await connection->async_execute(statement, result, diags, token);
				}
				else
				{
					boost::mysql::statement stmt;
					std::tie(ec, stmt) = co_await connection->async_prepare_statement(statement, diags, token);
					if (ec) co_return std::unexpected{boost::mysql::error_with_diagnostics(ec, diags)};
					auto bound = stmt.bind(std::forward<Args>(args)...);
					std::tie(ec) = co_await connection->async_execute(bound, result, diags, token);
				}
				if (ec) co_return std::unexpected{boost::mysql::error_with_diagnostics(ec, diags)};
				connection.return_without_reset();

				Result out;
				out.reserve(result.rows().size());
				for (auto& row : result.rows())
					out.push_back(row);
				co_return out;
			}
		}

		// async insert T for boost described objects
		template<class T,
				 class Members = boost::describe::describe_members<T, boost::describe::mod_any_access>,
				 class En = std::enable_if_t<!std::is_union<T>::value>>
		async_mysql_result<boost::mysql::results> async_insert(T& object) noexcept
		{
			std::stringstream query, names, values;

			bool first = true;
			boost::mp11::mp_for_each<Members>([&](auto column) {
				if (!first) { names << ","; values << ","; }
				first = false;
				names  << '`' << column.name << '`';
				values << '?';
			});

			query << "INSERT INTO `" << sql::name<T>() << "`"
			      << " (" << names.str() << ')'
			      << " VALUES (" << values.str() << ");";

			auto data = sql::as_tie(object, Members());
			co_return co_await async_execute<boost::mysql::results>(query.str(), data);
		}

		// async update T for boost described objects
		template<class T,
				 class Members = boost::describe::describe_members<T, boost::describe::mod_any_access>,
				 class En = std::enable_if_t<!std::is_union<T>::value>>
		async_mysql_result<boost::mysql::results> async_update(const T& object) noexcept
		{
			std::stringstream query, fields_part, where_part;

			bool first = true;
			using Others = boost::mp11::mp_pop_front<Members>;
			boost::mp11::mp_for_each<Others>([&](auto column) {
				if (!first) fields_part << ",";
				first = false;
				fields_part << '`' << column.name << "`=?";
			});

			using Id = boost::mp11::mp_list<boost::mp11::mp_first<Members>>;
			boost::mp11::mp_for_each<Id>([&](auto column) {
				where_part << '`' << column.name << "`=?";
			});

			query << "UPDATE `" << sql::name<T>() << '`'
			      << " SET " << fields_part.str()
			      << " WHERE " << where_part.str();

			// fields first, then id at the end for WHERE
			using ForUpdate = boost::mp11::mp_push_back<boost::mp11::mp_pop_front<Members>, boost::mp11::mp_first<Members>>;
			auto data = sql::as_tie(object, ForUpdate());
			co_return co_await async_execute<boost::mysql::results>(query.str(), data);
		}

		// async delete T for boost described objects
		template<class T,
				 class Members = boost::describe::describe_members<T, boost::describe::mod_any_access>,
				 class En = std::enable_if_t<!std::is_union<T>::value>>
		async_mysql_result<boost::mysql::results> async_delete(const T& object) noexcept
		{
			std::stringstream query, where_part;

			using Id = boost::mp11::mp_list<boost::mp11::mp_first<Members>>;
			boost::mp11::mp_for_each<Id>([&](auto column) {
				where_part << '`' << column.name << "`=?";
			});

			query << "DELETE FROM `" << sql::name<T>() << '`'
			      << " WHERE " << where_part.str();

			using ForDelete = boost::mp11::mp_list<boost::mp11::mp_first<Members>>;
			auto data = sql::as_tie(object, ForDelete());
			co_return co_await async_execute<boost::mysql::results>(query.str(), data);
		}

	private:
		boost::asio::strand<boost::asio::any_io_executor> _exec;
		std::unique_ptr<boost::mysql::connection_pool> _pool;
	};
} // Fireland::Database
