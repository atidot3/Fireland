#pragma once

// ============================================================================
// WorldPacket — tagged byte buffer for WoW Cataclysm world packets
//
// Wraps ByteBuffer with an opcode and knows how to frame itself on the wire.
//
// Wire header formats (Cataclysm 4.3.4, build 15595):
//   SMSG (server → client): [uint16 size BE][uint16 opcode LE]  — 4 bytes
//   CMSG (client → server): [uint16 size BE][uint32 opcode LE]  — 6 bytes
//
// "size" counts the opcode field itself:
//   SMSG: size = 2 + payload_size
//   CMSG: size = 4 + payload_size
//
// The underlying ByteBuffer stores the *payload only* (no wire header).
// Use Serialize() to obtain a fully-framed SMSG buffer ready to send.
// Use FromCmsgHeader() to build an empty WorldPacket from a raw CMSG header.
// ============================================================================

#include <array>
#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <vector>

#include <Utils/Bytes/ByteBuffer.h>

namespace Fireland::World
{

class WorldPacket : public Utils::ByteBuffer
{
public:
    static constexpr std::size_t SMSG_HEADER_SIZE = 4; // [uint16 size][uint16 opcode]
    static constexpr std::size_t CMSG_HEADER_SIZE = 6; // [uint16 size][uint32 opcode]

    // ---- Construction -------------------------------------------------------

    WorldPacket() = default;

    explicit WorldPacket(uint32_t opcode, std::size_t capacity = 256)
        : ByteBuffer(capacity)
        , _opcode(opcode)
    {}

    // ---- Accessors ----------------------------------------------------------

    [[nodiscard]] uint32_t opcode()                     const noexcept { return _opcode; }
    void                   setOpcode(uint32_t opcode)         noexcept { _opcode = opcode; }

    [[nodiscard]] bool is(uint32_t op)                  const noexcept { return _opcode == op; }

    /// Human-readable opcode string, e.g. "0x5DB6".
    [[nodiscard]] std::string opcodeName() const
    {
        return std::format("0x{:04X}", _opcode);
    }

    // ---- SMSG serialisation -------------------------------------------------

    /// Build the 4-byte SMSG wire header [uint16 size BE][uint16 opcode LE].
    /// size = 2 (opcode width) + payload size.
    [[nodiscard]] std::array<uint8_t, SMSG_HEADER_SIZE> SmsgHeader() const noexcept
    {
        auto sz = static_cast<uint16_t>(Size() + 2);
        auto op = static_cast<uint16_t>(_opcode);
        return {
            static_cast<uint8_t>(sz >> 8),     // size  high byte (BE)
            static_cast<uint8_t>(sz & 0xFF),   // size  low  byte (BE)
            static_cast<uint8_t>(op & 0xFF),   // opcode low  byte (LE)
            static_cast<uint8_t>(op >> 8),     // opcode high byte (LE)
        };
    }

    /// Return a fully-framed SMSG buffer (header + payload) ready to send.
    /// Encrypt the first SMSG_HEADER_SIZE bytes before calling async_write.
    [[nodiscard]] std::vector<uint8_t> Serialize() const
    {
        auto hdr = SmsgHeader();
        std::vector<uint8_t> frame;
        frame.reserve(SMSG_HEADER_SIZE + Size());
        frame.insert(frame.end(), hdr.begin(), hdr.end());
        frame.insert(frame.end(), Storage().begin(), Storage().end());
        return frame;
    }

    // ---- CMSG deserialisation -----------------------------------------------

    /// Parse opcode and declared payload size from a raw 6-byte CMSG header.
    /// The caller is responsible for reading the payload into the returned packet.
    [[nodiscard]] static WorldPacket FromCmsgHeader(
        std::span<const uint8_t, CMSG_HEADER_SIZE> hdr) noexcept
    {
        uint16_t wireSize = static_cast<uint16_t>((uint16_t{hdr[0]} << 8) | hdr[1]);
        uint32_t opcode{};
        std::memcpy(&opcode, hdr.data() + 2, 4);
        // wireSize includes the 4-byte opcode field; reserve space for payload only
        std::size_t payloadCapacity = wireSize > 4 ? wireSize - 4 : 0;
        return WorldPacket(opcode, payloadCapacity);
    }

    // ---- Comparison ---------------------------------------------------------

    /// Packets are equal when their opcodes match (payload is not compared).
    [[nodiscard]] bool operator==(const WorldPacket& other) const noexcept
    {
        return _opcode == other._opcode;
    }

private:
    uint32_t _opcode = 0;
};

} // namespace Fireland::World
