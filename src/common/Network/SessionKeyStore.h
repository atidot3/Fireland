#pragma once

// ============================================================================
// SessionKeyStore — Stores SRP6 session keys for reconnect support
//
// When a client authenticates successfully, its 40-byte session key (K) is
// stored here keyed by uppercase username.  When the client reconnects
// (CMD_AUTH_RECONNECT_CHALLENGE), the stored key is retrieved to verify
// the reconnect proof without requiring a full logon.
//
// Thread-safety is provided by a boost::asio::strand (no mutex).
// Shared by both authserver and worldserver.
// ============================================================================

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include <boost/asio/strand.hpp>

#include <Utils/Async.hpp>

namespace Fireland::Network
{

class SessionKeyStore final
{
public:
    using SessionKey = std::array<uint8_t, 40>;

    explicit SessionKeyStore(boost::asio::any_io_executor exec) noexcept;

    /// Store a session key (fire-and-forget, strand-serialised).
    void Store(std::string const& username, SessionKey const& key);

    /// Look up a session key (co_await-able, strand-serialised).
    [[nodiscard]] Utils::Async::async<std::optional<SessionKey>> Lookup(std::string const& username) const;

    /// Remove a session key (fire-and-forget, strand-serialised).
    void Remove(std::string const& username);

private:
    boost::asio::strand<boost::asio::any_io_executor> _strand;
    std::unordered_map<std::string, SessionKey> _keys;
};

} // namespace Fireland::Network
