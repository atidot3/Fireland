#pragma once

#include <Utils/ByteBuffer.h>
#include <Utils/Describe.hpp>

#include <Network/Auth/AuthOpcode.hpp>

namespace Fireland::Auth
{
    class AuthPacket : public Fireland::Utils::ByteBuffer
    {
    public:
        AuthPacket() = default;
        AuthPacket(AuthOpcode opcode, std::size_t payloadSize = 64)
            : ByteBuffer(payloadSize)
            , _opcode(opcode)
        {
        }

        auto opcode() const noexcept { return _opcode; }
        auto setOpcode(AuthOpcode opcode) noexcept { _opcode = opcode; }
        auto name() const { return Fireland::Utils::Describe::to_string(_opcode); }
        bool operator==(const AuthPacket& other) const noexcept
        {
            return _opcode == other._opcode;
        }
    private:
        AuthOpcode _opcode;
    };
} // namespace Fireland::Auth