// ============================================================================
// SessionManager implementation
// ============================================================================

#include <boost/asio/co_spawn.hpp>

#include <Network/SessionManager.h>

#include <Utils/Log.h>

using namespace Fireland::Network;
using namespace Fireland::Utils::Async;

SessionManager::SessionManager(boost::asio::any_io_executor exec) noexcept
    : _strand(exec)
{
}

void SessionManager::Add(TcpSession::Ptr session)
{
    auto lambda = [this, session = std::move(session)]() mutable
    {
        _sessions[session->GetId()] = std::move(session);
        FL_LOG_DEBUG("SessionManager", "Active sessions: {}", _sessions.size());
    };
    boost::asio::post(_strand, lambda);
}

void SessionManager::Remove(TcpSession::Ptr session)
{
    auto lambda = [this, session = std::move(session)]() mutable
    {
        _sessions.erase(session->GetId());
        FL_LOG_DEBUG("SessionManager", "Active sessions: {}", _sessions.size());
    };
    boost::asio::post(_strand, lambda);
}

async<std::size_t> SessionManager::Count() const
{
    auto lambda = [this]() -> async<std::size_t>
    {
        co_return _sessions.size();
    };
    
    return boost::asio::co_spawn(_strand, lambda, boost::asio::use_awaitable);
}

void SessionManager::CloseAll()
{
    auto lambda = [this]()
    {
        for (auto& [id, session] : _sessions)
            session->Close();
        _sessions.clear();
    };
    boost::asio::post(_strand, lambda);
}

void SessionManager::ForEach(const std::function<void(TcpSession::Ptr)>& fn) const
{
    auto lambda = [this, fn]()
    {
        for (const auto& [id, session] : _sessions)
            fn(session);
    };
    boost::asio::post(_strand, lambda);
}

async<void> SessionManager::ForEachAsync(const AsyncSessionHandler& fn) const
{
    // Snapshot session list on the strand, then co_await each callback.
    auto snapshotLambda = [this]() -> async<std::vector<TcpSession::Ptr>>
    {
        std::vector<TcpSession::Ptr> snapshot;
        snapshot.reserve(_sessions.size());
        for (const auto& [id, session] : _sessions)
            snapshot.push_back(session);
        co_return snapshot;
    };

    auto sessions = co_await boost::asio::co_spawn(_strand, snapshotLambda, boost::asio::use_awaitable);

    for (const auto& session : sessions)
        co_await fn(session);
}
