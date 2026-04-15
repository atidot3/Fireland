// ============================================================================
// PacketBuffer implementation
// ============================================================================

#include <Network/PacketBuffer.h>

#include <cassert>
#include <cstring>

using namespace Fireland::Network;

PacketBuffer::PacketBuffer(uint16_t opcode)
{
    _header.opcode = opcode;
}

void PacketBuffer::Append(const void* data, std::size_t len)
{
    if (len == 0)
        return;
    const auto* bytes = static_cast<const uint8_t*>(data);
    _payload.insert(_payload.end(), bytes, bytes + len);
}

std::vector<uint8_t> PacketBuffer::Serialize() const
{
    PacketHeader hdr = _header;
    hdr.size = static_cast<uint16_t>(sizeof(uint16_t) + _payload.size()); // opcode + payload

    std::vector<uint8_t> buf;
    buf.resize(PacketHeader::WIRE_SIZE + _payload.size());

    // Write header (little-endian on most platforms; explicit memcpy is safe)
    std::memcpy(buf.data(),     &hdr.size,   sizeof(hdr.size));
    std::memcpy(buf.data() + 2, &hdr.opcode, sizeof(hdr.opcode));

    // Write payload
    if (!_payload.empty())
        std::memcpy(buf.data() + PacketHeader::WIRE_SIZE, _payload.data(), _payload.size());

    return buf;
}

PacketHeader PacketBuffer::DeserializeHeader(std::span<const uint8_t, PacketHeader::WIRE_SIZE> raw)
{
    PacketHeader hdr;
    std::memcpy(&hdr.size,   raw.data(),     sizeof(hdr.size));
    std::memcpy(&hdr.opcode, raw.data() + 2, sizeof(hdr.opcode));
    return hdr;
}
