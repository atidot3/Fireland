#pragma once

// ============================================================================
// SessionManager — Tracks active TCP sessions
// Full implementation in header (template class).
// ============================================================================

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>
#include <unordered_map>

#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <Utils/Log.h>
#include <Utils/Asio/Async.hpp>

#include <Network/NetDefines.h>

namespace Firelands::Network
{
    template <IsSession SessionType>
    class SessionManager final
    {
    public:
        using Ptr = std::shared_ptr<SessionType>;

        explicit SessionManager(boost::asio::any_io_executor exec) noexcept
            : _strand(exec)
        {
        }

        /// Add a session (called by TcpListener after accept).
        void Add(Ptr session)
        {
            boost::asio::post(_strand, [this, session = std::move(session)]() mutable
            {
                _sessions[session->GetId()] = std::move(session);
                FL_LOG_DEBUG("SessionManager", "Session added — active: {}", _sessions.size());
            });
        }

        /// Remove a session by id.
        void Remove(Ptr session)
        {
            boost::asio::post(_strand, [this, session = std::move(session)]() mutable
            {
                _sessions.erase(session->GetId());
                FL_LOG_DEBUG("SessionManager", "Session removed — active: {}", _sessions.size());
            });
        }

        /// Number of active sessions (awaitable).
        Utils::Async::async<std::size_t> Count() const
        {
            return boost::asio::co_spawn(_strand, [this]() -> Utils::Async::async<std::size_t>
            {
                co_return _sessions.size();
            }, boost::asio::use_awaitable);
        }

        /// Close and remove all sessions.
        void CloseAll()
        {
            boost::asio::post(_strand, [this]()
            {
                for (auto& [id, session] : _sessions)
                    session->Close();
                _sessions.clear();
                FL_LOG_DEBUG("SessionManager", "All sessions closed");
            });
        }

        /// Iterate all sessions synchronously (keep callback fast).
        void ForEach(const std::function<void(Ptr)>& fn) const
        {
            boost::asio::post(_strand, [this, fn]()
            {
                for (const auto& [id, session] : _sessions)
                    fn(session);
            });
        }

        /// Iterate all sessions, co_awaiting the callback for each.
        using AsyncSessionHandler = std::function<Utils::Async::async<void>(Ptr)>;
        Utils::Async::async<void> ForEachAsync(const AsyncSessionHandler& fn) const
        {
            auto sessions = co_await boost::asio::co_spawn(_strand,
                [this]() -> Utils::Async::async<std::vector<Ptr>>
                {
                    std::vector<Ptr> snapshot;
                    snapshot.reserve(_sessions.size());
                    for (const auto& [id, session] : _sessions)
                        snapshot.push_back(session);
                    co_return snapshot;
                },
                boost::asio::use_awaitable);

            for (const auto& session : sessions)
                co_await fn(session);
        }

    private:
        boost::asio::strand<boost::asio::any_io_executor> _strand;
        std::unordered_map<uint64_t, Ptr>                 _sessions;
    };

} // namespace Firelands::Network
