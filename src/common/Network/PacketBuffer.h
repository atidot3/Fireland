#pragma once

// ============================================================================
// PacketBuffer — Simple header + payload framing for WoW-style packets
//
// Wire format (little-endian):
//   [uint16_t size][uint16_t opcode][payload ...]
//
// "size" covers opcode + payload (i.e. total packet size = 4 + payload_len).
// ============================================================================

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace Fireland::Network
{
    /// Header that prefixes every packet on the wire.
    struct PacketHeader
    {
        uint16_t size   = 0;   // opcode + payload length
        uint16_t opcode = 0;

        static constexpr std::size_t WIRE_SIZE = 4;
    };

    class PacketBuffer final
    {
    public:
        PacketBuffer() = default;
        explicit PacketBuffer(uint16_t opcode);

        /// Opcode
        uint16_t GetOpcode() const noexcept { return _header.opcode; }
        void     SetOpcode(uint16_t op) noexcept { _header.opcode = op; }

        /// Payload accessors
        std::span<const uint8_t> GetPayload() const noexcept { return _payload; }
        std::size_t              GetPayloadSize() const noexcept { return _payload.size(); }

        /// Append raw bytes to the payload.
        void Append(const void* data, std::size_t len);

        /// Convenience: append a trivially-copyable value.
        template <typename T>
            requires std::is_trivially_copyable_v<T>
        void Write(const T& value)
        {
            Append(&value, sizeof(T));
        }

        /// Read a trivially-copyable value at a given offset (no bounds check beyond assert).
        template <typename T>
            requires std::is_trivially_copyable_v<T>
        T Read(std::size_t offset) const
        {
            T value{};
            std::memcpy(&value, _payload.data() + offset, sizeof(T));
            return value;
        }

        /// Serialize header + payload into a contiguous buffer ready to send.
        [[nodiscard]] std::vector<uint8_t> Serialize() const;

        /// Deserialize a header from raw bytes.
        static PacketHeader DeserializeHeader(std::span<const uint8_t, PacketHeader::WIRE_SIZE> raw);

    private:
        PacketHeader          _header{};
        std::vector<uint8_t>  _payload;
    };
} // namespace Fireland::Network
