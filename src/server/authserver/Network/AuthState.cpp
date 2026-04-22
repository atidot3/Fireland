#include "AuthState.h"

#include <Utils/Log.h>

using namespace Firelands::Auth;

AuthState::AuthState() noexcept
    : _cur_status{AuthSessionStatus::LOGON_CHALLENGE}
{

}

void AuthState::AddHandler(AuthOpcode opcode, AuthHandlerInfo handler)
{
    auto it = _handlers.find(opcode);
    if (it != _handlers.end())
    {
        FL_LOG_WARNING("AuthSession", "Overriding existing handler for opcode {} (0x{:02X})", Utils::Describe::to_string(opcode), uint8_t(opcode));
    }
    _handlers[opcode] = std::move(handler);
}

std::optional<AuthHandlerInfo> AuthState::GetHandler(AuthOpcode opcode) const
{
    auto it = _handlers.find(opcode);
    if (it == _handlers.end())
        return std::nullopt;
    return it->second;
}

void AuthState::SetStatus(AuthSessionStatus status)
{
    _cur_status = status;
}

AuthSessionStatus AuthState::GetStatus() const
{
    return _cur_status;
}