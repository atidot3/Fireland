#pragma once

// ============================================================================
// TcpListener — Accepts incoming TCP connections via C++20 coroutines
//
// Spawns a coroutine that loops on async_accept. Each accepted socket is
// wrapped in a TcpSession and registered with the SessionManager.
// ============================================================================

#include <cstdint>
#include <string>

#include <boost/asio/ip/tcp.hpp>

#include "TcpSession.h"
#include "SessionManager.h"

namespace Fireland::Network {

class IoContext;

class TcpListener final
{
public:
    TcpListener(IoContext& ioContext, SessionManager& sessionManager);

    /// Start listening on the given address and port.
    /// \param handler  Callback invoked for every received packet on every session.
    void Listen(const std::string& address, uint16_t port, TcpSession::PacketHandler handler);

    /// Stop accepting new connections.
    void Stop();

private:
    utils::async<void> AcceptLoop(TcpSession::PacketHandler handler);

    IoContext&                       _ioContext;
    SessionManager&                  _sessionManager;
    boost::asio::ip::tcp::acceptor   _acceptor;
};

} // namespace Fireland::Network
