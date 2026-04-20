#include <format>

#include <Network/World/WorldPacket.h>

#include <Utils/StringUtils.h>

using namespace Firelands::World;



std::ostream& Firelands::World::operator<<(std::ostream& os, const WorldPacket& pkt)
{
    std::string fmt = std::format("WorldPacket(opcode={}, data={}, size={})", pkt.opcodeName(), Firelands::Utils::StringUtils::HexStr(pkt.Serialize()), pkt.size());
    os << fmt;
    return os;
}

WorldPacket::WorldPacket()
    : ByteBuffer()
    , _opcode(0)
{}

WorldPacket::WorldPacket(uint32_t opcode, std::size_t capacity)
    : ByteBuffer(capacity)
    , _opcode(opcode)
{}

// ---- Accessors ----------------------------------------------------------

uint32_t WorldPacket::opcode() const noexcept
{
    return _opcode;
}
void WorldPacket::setOpcode(uint32_t opcode) noexcept
{
    _opcode = opcode;
}

bool WorldPacket::is(uint32_t op) const noexcept
{
    return _opcode == op;
}

/// Human-readable opcode string, e.g. "0x5DB6".
std::string WorldPacket::opcodeName() const
{
    return std::format("0x{:04X}", _opcode);
}

// ---- SMSG serialisation -------------------------------------------------

/// Build the 4-byte SMSG wire header [uint16 size BE][uint16 opcode LE].
/// size = 2 (opcode width) + payload size.
std::array<uint8_t, WorldPacket::SMSG_HEADER_SIZE> WorldPacket::SmsgHeader() const noexcept
{
    auto sz = static_cast<uint16_t>(wpos() + 2);
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
std::vector<uint8_t> WorldPacket::Serialize() const
{
    auto hdr = SmsgHeader();
    std::vector<uint8_t> frame;
    frame.reserve(SMSG_HEADER_SIZE + wpos());
    frame.insert(frame.end(), hdr.begin(), hdr.end());
    frame.insert(frame.end(), _storage.begin(), _storage.begin() + _wpos);
    return frame;
}

// ---- CMSG deserialisation -----------------------------------------------

/// Parse opcode and declared payload size from a raw 6-byte CMSG header.
/// The caller is responsible for reading the payload into the returned packet.
WorldPacket WorldPacket::FromCmsgHeader(std::span<const uint8_t, CMSG_HEADER_SIZE> hdr) noexcept
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
[[nodiscard]] bool WorldPacket::operator==(const WorldPacket& other) const noexcept
{
    return _opcode == other._opcode;
}
