// ============================================================================
// SessionKeyStore implementation
// ============================================================================

#include <boost/asio/co_spawn.hpp>

#include "SessionKeyStore.h"

using namespace Fireland::Network;
using namespace Fireland::Utils::Async;

SessionKeyStore::SessionKeyStore(boost::asio::any_io_executor exec) noexcept
    : _strand(exec)
{
}

void SessionKeyStore::Store(std::string const& username, SessionKey const& key)
{
    boost::asio::post(_strand, [this, username, key]()
    {
        _keys[username] = key;
    });
}

async<std::optional<SessionKeyStore::SessionKey>> SessionKeyStore::Lookup(std::string const& username) const
{
    auto lambda = [this, username]() -> async<std::optional<SessionKey>>
    {
        auto it = _keys.find(username);
        if (it != _keys.end())
            co_return it->second;
        co_return std::nullopt;
    };

    return boost::asio::co_spawn(_strand, lambda, boost::asio::use_awaitable);
}

void SessionKeyStore::Remove(std::string const& username)
{
    boost::asio::post(_strand, [this, username]()
    {
        _keys.erase(username);
    });
}
