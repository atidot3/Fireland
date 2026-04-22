#pragma once

#include <functional>
#include <unordered_map>

#include <Network/Auth/AuthOpcode.hpp>
#include <Network/Auth/AuthPacket.hpp>
#include <Utils/Asio/Async.hpp>
#include <Utils/Asio/Describe.hpp>

namespace Firelands::Auth
{
    // AuthSessionStatus describes the current stage of the auth flow for a
    // single client connection.
    //
    // The auth session progresses through these states as the client sends
    // packets and the server responds. This enum is used to validate that
    // received opcodes are allowed in the current session phase.
    enum class AuthSessionStatus
    {
        LOGON_CHALLENGE,
        LOGON_PROOF,
        RECONNECT_PROOF,
        WAIT_FOR_REALM_LIST,
        CLOSED
    };
    BOOST_DESCRIBE_ENUM(AuthSessionStatus, LOGON_CHALLENGE, LOGON_PROOF, RECONNECT_PROOF, WAIT_FOR_REALM_LIST, CLOSED)

    using AuthHandler = std::function<Firelands::Utils::Async::async<void>(Firelands::Auth::AuthPacket)>;

    // AuthHandlerInfo binds a request handler to the session state in which it
    // is valid. The packet dispatcher uses this information to ensure that a
    // packet is only handled when the session is in the expected state.
    struct AuthHandlerInfo
    {
        AuthSessionStatus status;
        AuthHandler function_handler;
    };

    // AuthState maintains the current auth session state and the mapping
    // between auth opcodes and their handler metadata.
    //
    // It is responsible for registering opcode handlers, returning the
    // configured handler for an opcode, and tracking which session phase the
    // auth connection is currently in.
    class AuthState final
    {
    public:
        AuthState() noexcept;
        ~AuthState() = default;

        void AddHandler(AuthOpcode opcode, AuthHandlerInfo handler);
        std::optional<AuthHandlerInfo> GetHandler(AuthOpcode opcode) const;
        void SetStatus(AuthSessionStatus status);
        AuthSessionStatus GetStatus() const;

    private:
        AuthSessionStatus _cur_status;
        std::unordered_map<AuthOpcode, AuthHandlerInfo> _handlers;
    };
}