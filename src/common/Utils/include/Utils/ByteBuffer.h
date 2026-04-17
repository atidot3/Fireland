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
        ByteBuffer()
            : _storage(), _readPos(0), _bitpos(8), _curbitval(0)
        {
        }

        explicit ByteBuffer(std::size_t reserveSize)
            : _storage(), _readPos(0), _bitpos(8), _curbitval(0)
        {
            _storage.reserve(reserveSize);
        }

        explicit ByteBuffer(std::vector<uint8_t> data)
            : _storage(std::move(data)), _readPos(0), _bitpos(8), _curbitval(0)
        {
        }

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

        /// Append raw bytes from a vector via <<.
        ByteBuffer& operator<<(const std::vector<uint8_t>& data)
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
            auto begin = _storage.data() + _readPos;
            auto end = _storage.data() + _storage.size();

            auto it = std::find(begin, end, '\0');

            std::string result(begin, it);

            _readPos += std::distance(begin, it);
            if (it != end) {
                ++_readPos; // skip null terminator
            }

            return result;
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
            if (len == 0) return;
            EnsureReadable(len);
            std::memcpy(dest, _storage.data() + _readPos, len);
            _readPos += len;
        }

        // -- Bit read API (MSB-first within each byte, Cata 4.x wire format)

        /// Read one bit from the current byte, loading a new byte when needed.
        /// Bits are consumed from MSB (bit 7) down to LSB (bit 0).
        bool ReadBit()
        {
            if (_bitpos >= 8)
            {
                _curbitval = Read<uint8_t>();
                _bitpos = 0;
            }

            return ((_curbitval >> (8 - ++_bitpos)) & 1) != 0;
        }

        /// Read n bits (MSB first) and return them packed in the low n bits of a uint32_t.
        uint32_t ReadBits(uint32_t n)
        {
            uint32_t result = 0;
            for (uint32_t i = n; i-- > 0;)
                result |= (ReadBit() ? 1u : 0u) << i;
            return result;
        }

        /// Commit any pending write bits to storage (zero-padding to a full byte) 
        /// and reset the read bit state. Must be called before any byte-aligned
        /// write after WriteBit/WriteBits.
        void FlushBits()
        {
            if (_bitpos == 8)
                return;

            _bitpos = 8;
            Append(&_curbitval, sizeof(uint8_t));
            _curbitval = 0;
        }

        bool WriteBit(uint32_t bit)
        {
            --_bitpos;
            if (bit)
                _curbitval |= (1 << _bitpos);

            if (_bitpos == 0)
            {
                _bitpos = 8;
                Append(&_curbitval, sizeof(_curbitval));
                _curbitval = 0;
            }

            return (bit != 0);
        }

        void WriteBits(uint32_t value, uint32_t bits)
        {
            if (bits == 0)
                return;

            // Remove bits that don't fit (secured against undefined behavior if bits == 32)
            if (bits < 32)
                value &= (1U << bits) - 1;

            if (bits > _bitpos)
            {
                // First write to fill bit buffer
                _curbitval |= value >> (bits - _bitpos);
                bits -= _bitpos;
                _bitpos = 8; // required "unnecessary" write to avoid double flushing
                Append(&_curbitval, sizeof(_curbitval));

                // Then append as many full bytes as possible
                while (bits >= 8)
                {
                    bits -= 8;
                    uint8_t byteVal = static_cast<uint8_t>(value >> bits);
                    Append(&byteVal, sizeof(byteVal));
                }

                // Store remaining bits in the bit buffer
                _bitpos = 8 - bits;
                if (bits > 0)
                    _curbitval = (value & ((1U << bits) - 1)) << _bitpos;
                else
                    _curbitval = 0;
            }
            else
            {
                // Entire value fits in the bit buffer
                _bitpos -= bits;
                _curbitval |= value << _bitpos;

                if (_bitpos == 0)
                {
                    _bitpos = 8;
                    Append(&_curbitval, sizeof(_curbitval));
                    _curbitval = 0;
                }
            }
        }

		// Write a byte as a single bit (1 if nonzero, 0 if zero) for the bit buffer.
        void WriteByteSeq(uint8_t b)
        {
            if (b != 0)
                *this << uint8_t(b ^ 1);
        }

        // -- Accessors --
        std::span<const uint8_t> Data() const noexcept { return _storage; }
        const uint8_t* RawData() const noexcept { return _storage.data(); }
        std::size_t              Size() const noexcept { return _storage.size(); }
        std::size_t              ReadPos() const noexcept { return _readPos; }
        std::size_t              Remaining() const noexcept { return _storage.size() - _readPos; }
        bool                     Empty() const noexcept { return _storage.empty(); }

        void ResetReadPos() noexcept
        {
            _readPos = 0;
            _bitpos = 8;
            _curbitval = 0;
        }

        void Clear() noexcept
        {
            _storage.clear();
            _readPos = 0;
            _bitpos = 8;
            _curbitval = 0;
        }

        /// Advance read position by len bytes without copying data.
        void Skip(std::size_t len)
        {
            EnsureReadable(len);
            _readPos += len;
        }

        /// Access the underlying vector (for direct manipulation / move).
        std::vector<uint8_t>& Storage() noexcept { return _storage; }
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
        std::size_t          _readPos;

        uint32_t _bitpos;
        uint8_t  _curbitval;
    };
} // namespace Fireland::Utils