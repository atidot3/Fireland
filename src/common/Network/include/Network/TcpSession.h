#pragma once

// ============================================================================
// TcpSession — One TCP connection managed by C++20 coroutines
//
// Uses boost::asio::awaitable for fully async read/write.
// Each session reads packets (header + payload), dispatches them via a
// user-supplied callback, and can queue outgoing packets.
//
// Lifecycle note: the optional OnClose callback is invoked once when the
// session closes (e.g. for removal from a session manager). The session
// does NOT hold a reference to any manager; callers wire that up via the
// callback at construction time.
// ============================================================================

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <Utils/Async.hpp>

#include "PacketBuffer.h"

namespace Fireland::Network
{
    class TcpSession : public std::enable_shared_from_this<TcpSession>
    {
    public:
        using Ptr = std::shared_ptr<TcpSession>;

        /// Callback invoked when a complete packet has been received.
        using PacketHandler = std::function<void(Ptr session, PacketBuffer packet)>;

        /// Callback invoked once when the session closes.
        using CloseCallback = std::function<void(Ptr session)>;

        TcpSession(boost::asio::ip::tcp::socket socket,
                   PacketHandler handler,
                   CloseCallback onClose = nullptr);
        ~TcpSession();

        TcpSession(const TcpSession&) = delete;
        TcpSession& operator=(const TcpSession&) = delete;

        /// Unique session id (monotonically increasing).
        uint64_t GetId() const noexcept { return _id; }

        /// Remote endpoint as string (e.g. "192.168.1.5:52301").
        const std::string& GetRemoteAddress() const noexcept { return _remoteAddress; }

        /// Start the read/write coroutine loops. Call once after accept.
        void Start();

        /// Queue a packet for asynchronous sending.
        void Send(PacketBuffer packet);

        /// Initiate a graceful close.
        void Close();

        bool IsOpen() const noexcept;

    private:
        Utils::Async::async<void> ReadLoop();
        Utils::Async::async<void> WriteLoop();

        static uint64_t NextId();

        uint64_t                          _id;
        boost::asio::ip::tcp::socket      _socket;
        std::string                       _remoteAddress;
        PacketHandler                     _packetHandler;
        CloseCallback                     _onClose;

        std::deque<std::vector<uint8_t>>  _sendQueue;
        boost::asio::steady_timer         _sendNotify;
        bool                              _closing = false;
    };
} // namespace Fireland::Network
