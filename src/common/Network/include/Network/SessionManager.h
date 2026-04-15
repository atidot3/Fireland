#pragma once

// ============================================================================
// SessionManager — Tracks active TCP sessions
// ============================================================================

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>

#include <boost/asio/strand.hpp>

#include <Utils/Async.hpp>

#include <Network/TcpSession.h>

namespace Fireland::Network
{
    class SessionManager final
    {
    public:
        SessionManager(boost::asio::any_io_executor exec) noexcept;

        /// Add a session (called by TcpListener after accept).
        void Add(TcpSession::Ptr session);

        /// Remove a session (called by TcpSession on close).
        void Remove(TcpSession::Ptr session);

        /// Number of active sessions.
        [[nodiscard]] Utils::Async::async<std::size_t> Count() const;

        /// Close all sessions.
        void CloseAll();

        /// Iterate all sessions (under lock — keep callback fast).
        void ForEach(const std::function<void(TcpSession::Ptr)>& fn) const;

        /// Iterate all sessions — callback is co_awaited for each session.
        using AsyncSessionHandler = std::function<Utils::Async::async<void>(TcpSession::Ptr)>;
        Utils::Async::async<void> ForEachAsync(const AsyncSessionHandler& fn) const;

    private:
	    boost::asio::strand<boost::asio::any_io_executor> _strand;
        std::unordered_map<uint64_t, TcpSession::Ptr> _sessions;
    };
} // namespace Fireland::Network
