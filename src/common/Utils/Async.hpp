#pragma once

// ============================================================================
// Async — Utilities for asynchronous operations
// ============================================================================

#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/system_timer.hpp>

namespace utils
{
	template<typename T>
	using async = boost::asio::awaitable<T>;

	// This token transforms completion handlers:
	// void(error_code, T) -> tuple<error_code, T>
	// Useful to avoid exceptions and keep error_code explicitly
	constexpr auto tuple_awaitable_token = boost::asio::as_tuple(boost::asio::use_awaitable);

	// Awaitable sleep function that returns true on success, false on cancellation or error.
	[[nodiscard]] inline async<bool> async_sleep(std::chrono::milliseconds timeout) noexcept
	{
		auto executor = co_await boost::asio::this_coro::executor;
		auto [ec] = co_await boost::asio::system_timer(executor, std::chrono::milliseconds(timeout.count())).async_wait(tuple_awaitable_token);
		if (!ec) co_return true;
		co_return false;
	}
}