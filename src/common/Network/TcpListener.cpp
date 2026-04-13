// ============================================================================
// TcpListener implementation
// ============================================================================

#include "TcpListener.h"
#include "IoContext.h"

#include <boost/asio/co_spawn.hpp>

#include <Utils/Log.h>

namespace Fireland::Network {

TcpListener::TcpListener(IoContext& ioContext, SessionManager& sessionManager)
    : _ioContext(ioContext)
    , _sessionManager(sessionManager)
    , _acceptor(ioContext.Get())
{
}

void TcpListener::Listen(const std::string& address, uint16_t port,
                          TcpSession::PacketHandler handler)
{
    boost::asio::ip::tcp::endpoint endpoint(
        boost::asio::ip::make_address(address), port);

    _acceptor.open(endpoint.protocol());

    // Allow address reuse (important for quick restarts)
    _acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

    _acceptor.bind(endpoint);
    _acceptor.listen(boost::asio::socket_base::max_listen_connections);

    FL_LOG_INFO("TcpListener", "Listening on {}:{}", address, port);

    boost::asio::co_spawn(
        _acceptor.get_executor(),
        [this, h = std::move(handler)]() mutable -> boost::asio::awaitable<void>
        {
            co_await AcceptLoop(std::move(h));
        },
        boost::asio::detached);
}

void TcpListener::Stop()
{
    boost::system::error_code ec;
    _acceptor.close(ec);
    FL_LOG_INFO("TcpListener", "Stopped");
}

utils::async<void> TcpListener::AcceptLoop(TcpSession::PacketHandler handler)
{
    while (_acceptor.is_open())
    {
        try
        {
            auto socket = co_await _acceptor.async_accept(boost::asio::use_awaitable);

            // Disable Nagle for low-latency game packets
            socket.set_option(boost::asio::ip::tcp::no_delay(true));

            auto session = std::make_shared<TcpSession>(std::move(socket), _sessionManager);
            _sessionManager.Add(session);
            session->Start(handler);
        }
        catch (const boost::system::system_error& e)
        {
            if (e.code() == boost::asio::error::operation_aborted)
                break;   // acceptor was closed

            FL_LOG_ERROR("TcpListener", "Accept error: {}", e.what());
        }
    }
}

} // namespace Fireland::Network
