#pragma once

#include <optional>
#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/system/error_code.hpp>

#include <Utils/Log.h>

namespace Fireland::Utils::Async
{
    template <typename T>
    class AsyncQueue
    {
    private:
        using executor_type = boost::asio::any_io_executor;
        using channel_type  = boost::asio::experimental::channel<
                                  executor_type,
                                  void(boost::system::error_code, T)>;

    public:
        explicit AsyncQueue(executor_type ex, std::size_t capacity = 1024)
            : _channel(ex, capacity)
        {
        }

        executor_type get_executor() const noexcept
        {
            return _channel.get_executor();
        }

        // Non-blocking push; if full, spawns an async send on the executor.
        void push(T value)
        {
            if (!_channel.try_send(boost::system::error_code{}, value))
            {
                boost::asio::co_spawn(
                    _channel.get_executor(),
                    [this, v = std::move(value)]() mutable -> boost::asio::awaitable<void>
                    {
                        co_await _channel.async_send(
                            boost::system::error_code{}, std::move(v),
                            boost::asio::use_awaitable);
                    },
                    boost::asio::detached);
            }
        }

        // Awaitable pop; returns nullopt if the channel was closed or errored.
        boost::asio::awaitable<std::optional<T>> async_pop()
        {
            auto [ec, value] = co_await _channel.async_receive(
                boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                FL_LOG_ERROR("Network", "AsyncQueue receive error: {}", ec.message());
                co_return std::nullopt;
            }
            co_return std::move(value);
        }

        void close()
        {
            _channel.close();
        }

    private:
        channel_type _channel;
    };
} // namespace Fireland::Utils::Async
