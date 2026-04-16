#pragma once

// ============================================================================
// TcpListener — Accepts incoming TCP connections via C++23 coroutines
//
// Configurable generic TCP listener using Concepts.
// ============================================================================

#include <cstdint>
#include <concepts>
#include <functional>
#include <memory>
#include <string>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/system/system_error.hpp>

#include <Utils/Log.h>
#include <Utils/Async.hpp>
#include <Utils/IoContext.h>

namespace Fireland::Network
{
    template <typename T>
    concept IsSession = requires(std::shared_ptr<T> s) {
        { s->Start() } -> std::same_as<void>;
    };

    template <IsSession SessionType>
    class TcpListener final
    {
    public:
        using SessionFactory = std::move_only_function<std::shared_ptr<SessionType>(boost::asio::ip::tcp::socket)>;

        TcpListener(Utils::IoContext& ioContext, SessionFactory factory)
            : _factory(std::move(factory))
            , _acceptor(ioContext.Get())
        {
        }

        Utils::Async::async<void> Listen(const std::string& address, uint16_t port)
        {
            boost::asio::ip::tcp::endpoint endpoint(
                boost::asio::ip::make_address(address), port);

            boost::system::error_code ec;
            _acceptor.open(endpoint.protocol(), ec);
            _acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
            _acceptor.bind(endpoint, ec);
            if (ec)
            {
                FL_LOG_ERROR("TcpListener", "Failed to bind to {}:{} — {}", address, port, ec.message());
                co_return;
            }
            _acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
            if (ec)
            {
                FL_LOG_ERROR("TcpListener", "Failed to listen on {}:{} — {}", address, port, ec.message());
                co_return;
            }

            FL_LOG_INFO("TcpListener", "Listening on {}:{}", address, port);
            co_await AcceptLoop();
        }

        void Stop()
        {
            boost::system::error_code ec;
            _acceptor.close(ec);
            FL_LOG_INFO("TcpListener", "Stopped");
        }

    private:
        Utils::Async::async<void> AcceptLoop()
        {
            while (_acceptor.is_open())
            {
                try
                {
                    auto [ec, socket] = co_await _acceptor.async_accept(Utils::Async::tuple_awaitable_token);
                    if (ec) break;
                    socket.set_option(boost::asio::ip::tcp::no_delay(true));

                    if (auto session = _factory(std::move(socket)))
                    {
                        session->Start();
                    }
                }
                catch (const boost::system::system_error& e)
                {
                    if (e.code() == boost::asio::error::operation_aborted)
                        break;

                    FL_LOG_ERROR("TcpListener", "Accept error: {}", e.what());
                }
                catch (const std::exception& e)
                {
                    FL_LOG_ERROR("TcpListener", "Exception in accept loop: {}", e.what());
                    break;
                }
            }
            co_return;
        }

        SessionFactory                 _factory;
        boost::asio::ip::tcp::acceptor _acceptor;
    };
} // namespace Fireland::Network
