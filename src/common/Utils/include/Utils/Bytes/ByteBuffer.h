#pragma once

// ============================================================================
// ByteBuffer — Generic resizable byte buffer with read/write cursor
//
// Useful for serialization/deserialization of binary data.
// Network::PacketBuffer builds on top of this for WoW packet framing.
// ============================================================================

#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>
#include <format>

namespace Fireland::Utils
{
    class ByteBuffer
    {
    public:
        ByteBuffer() = default;
        explicit ByteBuffer(std::size_t reserveSize) { _storage.reserve(reserveSize); }
        explicit ByteBuffer(std::vector<uint8_t> data) : _storage(std::move(data)) {}
        uint8_t& operator[](std::size_t index) { return _storage[index]; }
        const uint8_t& operator[](std::size_t index) const { return _storage[index]; }

        // -- Write API --

        /// Append raw bytes.
        void Append(const void* data, std::size_t len)
        {
            if (len == 0) return;
            const auto* bytes = static_cast<const uint8_t*>(data);
            _storage.insert(_storage.end(), bytes, bytes + len);
        }

        /// Append a trivially-copyable value (little-endian on LE platforms).
        template <typename T>
            requires std::is_trivially_copyable_v<T>
        void Write(const T& value)
        {
            Append(&value, sizeof(T));
        }

        /// Append a length-prefixed string (uint16_t length + chars, no null).
        void WriteString(std::string_view str)
        {
            auto len = static_cast<uint16_t>(str.size());
            Write(len);
            Append(str.data(), str.size());
        }

        /// Append a null-terminated C string.
        ByteBuffer& WriteCString(std::string_view str)
        {
            Append(str.data(), str.size());
            _storage.push_back(0x00);
            return *this;
        }

        /// Append zero bytes as padding.
        ByteBuffer& Pad(std::size_t count)
        {
            _storage.insert(_storage.end(), count, 0x00);
            return *this;
        }

        // -- Stream operators --

        /// Append a trivially-copyable value via <<.
        template <typename T>
            requires (std::is_trivially_copyable_v<T> && !std::is_pointer_v<T>
                      && !std::is_convertible_v<T, std::string_view>)
        ByteBuffer& operator<<(const T& value)
        {
            Write(value);
            return *this;
        }

        /// Append a null-terminated C string via <<.
        ByteBuffer& operator<<(std::string_view str)
        {
            return WriteCString(str);
        }

        /// Append raw bytes from a span via <<.
        ByteBuffer& operator<<(std::span<const uint8_t> data)
        {
            Append(data.data(), data.size());
            return *this;
        }

        /// Append another ByteBuffer's contents via <<.
        ByteBuffer& operator<<(const ByteBuffer& other)
        {
            Append(other.RawData(), other.Size());
            return *this;
        }

        /// Read a trivially-copyable value via >>.
        template <typename T>
            requires std::is_trivially_copyable_v<T>
        ByteBuffer& operator>>(T& value)
        {
            value = Read<T>();
            return *this;
        }

        // -- Read API --

        /// Read a trivially-copyable value at the current read position.
        template <typename T>
            requires std::is_trivially_copyable_v<T>
        T Read()
        {
            EnsureReadable(sizeof(T));
            T value{};
            std::memcpy(&value, _storage.data() + _readPos, sizeof(T));
            _readPos += sizeof(T);
            return value;
        }

        /// Read a length-prefixed string.
        std::string ReadString()
        {
            auto len = Read<uint16_t>();
            EnsureReadable(len);
            std::string str(reinterpret_cast<const char*>(_storage.data() + _readPos), len);
            _readPos += len;
            return str;
        }

        /// Read a length-prefixed string with a specified length.
        std::string ReadString(std::size_t len)
        {
            EnsureReadable(len);
            std::string str(reinterpret_cast<const char*>(_storage.data() + _readPos), len);
            _readPos += len;
            return str;
        }

        /// Read raw bytes into a destination buffer.
        void ReadBytes(void* dest, std::size_t len)
        {
            EnsureReadable(len);
            std::memcpy(dest, _storage.data() + _readPos, len);
            _readPos += len;
        }

        // -- Bit read API (MSB-first within each byte, Cata 4.x wire format)
        /// Read one bit from the current byte, loading a new byte when needed.
        /// Bits are consumed from MSB (bit 7) down to LSB (bit 0).
        bool ReadBit() { if (_bitPos < 0) { _bitByte = Read<uint8_t>(); _bitPos = 7; } return (_bitByte >> _bitPos--) & 1; }
        
        /// Read n bits (MSB first) and return them packed in the low n bits of a uint32_t.
        uint32_t ReadBits(uint32_t n) { uint32_t result = 0; for (uint32_t i = n; i-- > 0;) result |= (ReadBit() ? 1u : 0u) << i; return result; }
        /// Discard the remaining bits of the current read byte (byte-align the reader).
        void ResetReadBits() noexcept { _bitPos = -1; }
        /// Commit any pending write bits to storage (zero-padding to a full byte) /// and reset the read bit state. Must be called before any byte-aligned
        /// write after WriteBit/WriteBits.
        void FlushBits() noexcept { _bitPos = 8; }

        // -- Accessors --
        std::span<const uint8_t> Data() const noexcept { return _storage; }
        const uint8_t*           RawData() const noexcept { return _storage.data(); }
        std::size_t              Size() const noexcept { return _storage.size(); }
        std::size_t              ReadPos() const noexcept { return _readPos; }
        std::size_t              Remaining() const noexcept { return _storage.size() - _readPos; }
        bool                     Empty() const noexcept { return _storage.empty(); }

        void ResetReadPos() noexcept { _readPos = 0; }
        void Clear() noexcept { _storage.clear(); _readPos = 0; }

        /// Advance read position by len bytes without copying data.
        void Skip(std::size_t len)
        {
            EnsureReadable(len);
            _readPos += len;
        }

        /// Access the underlying vector (for direct manipulation / move).
        std::vector<uint8_t>&       Storage() noexcept { return _storage; }
        const std::vector<uint8_t>& Storage() const noexcept { return _storage; }

    private:
        void EnsureReadable(std::size_t len) const
        {
            if (_readPos + len > _storage.size())
            {
                auto err = std::format("ByteBuffer: attempt to read {} bytes with only {} bytes remaining", len, Remaining());
                throw std::out_of_range(err);
            }
        }

        std::vector<uint8_t> _storage;
        std::size_t          _readPos = 0;
        // Bit-read state
        uint8_t _bitByte = 0;
        int32_t _bitPos = -1; // -1 = need new byte
    };
} // namespace Fireland::Utils
