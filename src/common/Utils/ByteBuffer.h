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

namespace Fireland::Utils {

class ByteBuffer final
{
public:
    ByteBuffer() = default;
    explicit ByteBuffer(std::size_t reserveSize) { _storage.reserve(reserveSize); }
    explicit ByteBuffer(std::vector<uint8_t> data) : _storage(std::move(data)) {}

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

    /// Read raw bytes into a destination buffer.
    void ReadBytes(void* dest, std::size_t len)
    {
        EnsureReadable(len);
        std::memcpy(dest, _storage.data() + _readPos, len);
        _readPos += len;
    }

    // -- Accessors --

    std::span<const uint8_t> Data() const noexcept { return _storage; }
    const uint8_t*           RawData() const noexcept { return _storage.data(); }
    std::size_t              Size() const noexcept { return _storage.size(); }
    std::size_t              ReadPos() const noexcept { return _readPos; }
    std::size_t              Remaining() const noexcept { return _storage.size() - _readPos; }
    bool                     Empty() const noexcept { return _storage.empty(); }

    void ResetReadPos() noexcept { _readPos = 0; }
    void Clear() noexcept { _storage.clear(); _readPos = 0; }

    /// Access the underlying vector (for direct manipulation / move).
    std::vector<uint8_t>&       Storage() noexcept { return _storage; }
    const std::vector<uint8_t>& Storage() const noexcept { return _storage; }

private:
    void EnsureReadable(std::size_t len) const
    {
        if (_readPos + len > _storage.size())
            throw std::out_of_range("ByteBuffer: read past end");
    }

    std::vector<uint8_t> _storage;
    std::size_t          _readPos = 0;
};

} // namespace Fireland::Utils
