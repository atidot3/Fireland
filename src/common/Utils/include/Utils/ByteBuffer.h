#pragma once

#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace Fireland::Utils
{
    class ByteBuffer
    {
    public:
        static constexpr size_t  DEFAULT_SIZE   = 0x1000;
        static constexpr uint8_t InitialBitPos  = 8;

        // ---- Construction -------------------------------------------------------

        ByteBuffer() : _rpos(0), _wpos(0), _bitpos(InitialBitPos), _curbitval(0)
        {
            _storage.reserve(DEFAULT_SIZE);
        }

        explicit ByteBuffer(size_t reserve) : _rpos(0), _wpos(0), _bitpos(InitialBitPos), _curbitval(0)
        {
            _storage.reserve(reserve);
        }

        explicit ByteBuffer(std::vector<uint8_t> data)
            : _rpos(0), _wpos(data.size()), _bitpos(InitialBitPos), _curbitval(0),
              _storage(std::move(data))
        {}

        // ---- Raw write ----------------------------------------------------------

        // Writes cnt bytes at _wpos, growing storage as needed. (TC: append)
        void append(const void* src, size_t cnt)
        {
            if (!cnt) return;
            if (_storage.size() < _wpos + cnt)
                _storage.resize(_wpos + cnt);
            std::memcpy(_storage.data() + _wpos, src, cnt);
            _wpos += cnt;
        }

        // Typed append — fundamental types only.
        template <typename T>
            requires std::is_trivially_copyable_v<T>
        void append(const T& value) { append(&value, sizeof(T)); }

        // Appends the written portion of another buffer.
        void append(const ByteBuffer& buf)
        {
            if (buf._wpos)
                append(buf._storage.data(), buf._wpos);
        }

        // Overwrite bytes at an arbitrary position (does not move _wpos).
        void put(size_t pos, const void* src, size_t cnt)
        {
            if (pos + cnt > _storage.size())
                throw std::out_of_range("ByteBuffer::put: position out of range");
            std::memcpy(_storage.data() + pos, src, cnt);
        }

        template <typename T>
            requires std::is_trivially_copyable_v<T>
        void put(size_t pos, const T& value) { put(pos, &value, sizeof(value)); }

        // ---- PascalCase aliases (backward compat) --------------------------------

        void Append(const void* data, size_t len)           { append(data, len); }
        template <typename T> requires std::is_trivially_copyable_v<T>
        void Append(const T& value)                         { append(value); }

        // ---- Bit write ----------------------------------------------------------

        bool WriteBit(uint32_t bit)
        {
            --_bitpos;
            if (bit)
                _curbitval |= (1u << _bitpos);
            if (_bitpos == 0)
            {
                _bitpos = 8;
                append(&_curbitval, 1u);
                _curbitval = 0;
            }
            return bit != 0;
        }

        void WriteBits(uint64_t value, int32_t bits)
        {
            value &= (uint64_t(1) << bits) - 1;

            if (bits > int32_t(_bitpos))
            {
                _curbitval |= uint8_t(value >> (bits - int32_t(_bitpos)));
                bits -= int32_t(_bitpos);
                _bitpos = 8;
                append(&_curbitval, 1u);

                while (bits >= 8)
                {
                    bits -= 8;
                    uint8_t b = uint8_t(value >> bits);
                    append(&b, 1u);
                }

                _bitpos  = uint32_t(8 - bits);
                _curbitval = bits > 0 ? uint8_t((value & ((uint64_t(1) << bits) - 1)) << _bitpos) : 0;
            }
            else
            {
                _bitpos -= uint32_t(bits);
                _curbitval |= uint8_t(value << _bitpos);
                if (_bitpos == 0)
                {
                    _bitpos = 8;
                    append(&_curbitval, 1u);
                    _curbitval = 0;
                }
            }
        }

        void FlushBits()
        {
            if (_bitpos == 8) return;
            _bitpos = 8;
            append(&_curbitval, 1u);
            _curbitval = 0;
        }

        void WriteByteSeq(uint8_t b)
        {
            if (b != 0)
                append<uint8_t>(b ^ 1);
        }

        // Returns the current write position in bits (for use with PutBits).
        size_t bitwpos() const { return _wpos * 8 + 8 - _bitpos; }

        // Overwrite bitCount bits at bit position pos (call after FlushBits).
        void PutBits(size_t pos, size_t value, uint32_t bitCount)
        {
            for (uint32_t i = bitCount; i > 0; )
            {
                --i;
                size_t byteIdx = pos / 8;
                uint8_t bitMask = uint8_t(1u << (7u - (pos % 8)));
                if ((value >> i) & 1)
                    _storage[byteIdx] |= bitMask;
                else
                    _storage[byteIdx] &= ~bitMask;
                ++pos;
            }
        }

        // ---- Stream write operators --------------------------------------------

        template <typename T>
            requires (std::is_trivially_copyable_v<T>
                   && !std::is_pointer_v<T>
                   && !std::is_same_v<std::remove_cvref_t<T>, std::string>
                   && !std::is_same_v<std::remove_cvref_t<T>, std::string_view>)
        ByteBuffer& operator<<(const T& value) { append(value); return *this; }

        // operator<<(string) appends bytes + null terminator
        ByteBuffer& operator<<(const std::string& str)
        {
            if (size_t len = str.size()) append(str.data(), len);
            append<uint8_t>(0);
            return *this;
        }
        ByteBuffer& operator<<(std::string_view str)
        {
            if (size_t len = str.size()) append(str.data(), len);
            append<uint8_t>(0);
            return *this;
        }
        ByteBuffer& operator<<(const char* str)
        {
            if (size_t len = str ? std::strlen(str) : 0) append(str, len);
            // '\0' is included by append(str, len)
            //append<uint8_t>(0);
            return *this;
        }
        ByteBuffer& operator<<(std::span<const uint8_t> data)
        {
            append(data.data(), data.size());
            return *this;
        }
        ByteBuffer& operator<<(const std::vector<uint8_t>& data)
        {
            append(data.data(), data.size());
            return *this;
        }
        ByteBuffer& operator<<(const ByteBuffer& other)
        {
            append(other._storage.data(), other._wpos);
            return *this;
        }

        // ---- Raw read -----------------------------------------------------------

        void read(uint8_t* dest, size_t len)
        {
            if (_rpos + len > _storage.size())
                throw std::out_of_range(
                    std::format("ByteBuffer: read {} bytes but only {} remaining",
                                len, _storage.size() - _rpos));
            std::memcpy(dest, _storage.data() + _rpos, len);
            _rpos += len;
        }

        // Read at current position, advance _rpos. (TC: read<T>())
        template <typename T>
            requires std::is_trivially_copyable_v<T>
        T read()
        {
            T value{};
            read(reinterpret_cast<uint8_t*>(&value), sizeof(T));
            return value;
        }

        // Read at an arbitrary position without moving _rpos. (TC: read<T>(pos))
        template <typename T>
            requires std::is_trivially_copyable_v<T>
        T read(size_t pos) const
        {
            if (pos + sizeof(T) > _storage.size())
                throw std::out_of_range("ByteBuffer::read(pos): out of range");
            T value{};
            std::memcpy(&value, _storage.data() + pos, sizeof(T));
            return value;
        }

        // PascalCase alias
        template <typename T> requires std::is_trivially_copyable_v<T>
        T Read() { return read<T>(); }

        void ReadBytes(void* dest, size_t len)
        {
            read(static_cast<uint8_t*>(dest), len);
        }

        // ---- Bit read -----------------------------------------------------------

        bool ReadBit()
        {
            if (_bitpos >= 8)
            {
                read(&_curbitval, 1);
                _bitpos = 0;
            }
            return ((_curbitval >> (8 - ++_bitpos)) & 1) != 0;
        }

        uint32_t ReadBits(int32_t bits)
        {
            uint32_t value = 0;
            for (int32_t i = bits - 1; i >= 0; --i)
                value |= uint32_t(ReadBit()) << i;
            return value;
        }

        void ReadByteSeq(uint8_t& b)
        {
            if (b != 0)
                b ^= read<uint8_t>();
        }

        // ---- String read --------------------------------------------------------

        // reads until null terminator.
        std::string ReadString()
        {
            std::string str;
            while (_rpos < _storage.size())
            {
                char c = read<char>();
                if (c == '\0') break;
                str += c;
            }
            return str;
        }

        // reads exactly len bytes, no null terminator.
        std::string ReadString(size_t len)
        {
            if (!len) return {};
            if (_rpos + len > _storage.size())
                throw std::out_of_range("ByteBuffer::ReadString: out of range");
            std::string str(reinterpret_cast<const char*>(_storage.data() + _rpos), len);
            _rpos += len;
            return str;
        }

        // ---- Stream read operators ----------------------------------------------

        template <typename T>
            requires std::is_trivially_copyable_v<T>
        ByteBuffer& operator>>(T& value) { value = read<T>(); return *this; }

        ByteBuffer& operator>>(std::string& str)
        {
            str.clear();
            while (_rpos < _storage.size())
            {
                char c = read<char>();
                if (c == '\0') break;
                str += c;
            }
            return *this;
        }

        // ---- Skip ---------------------------------------------------------------

        void Skip(size_t len)
        {
            if (_rpos + len > _storage.size())
                throw std::out_of_range("ByteBuffer::Skip: out of range");
            _rpos += len;
        }
        void read_skip(size_t len) { Skip(len); }
        template <typename T> void read_skip() { Skip(sizeof(T)); }

        // ---- Position -----------------------------------------------------------

        size_t rpos() const              { return _rpos; }
        size_t rpos(size_t p)            { _rpos = p; return _rpos; }
        void   rfinish()                 { _rpos = _wpos; }
        size_t ReadPos() const           { return _rpos; }

        size_t wpos() const              { return _wpos; }
        size_t wpos(size_t p)            { _wpos = p; return _wpos; }

        // ---- Capacity / state ---------------------------------------------------

        size_t size()  const { return _storage.size(); }
        size_t Size()  const { return _storage.size(); }
        bool   empty() const { return _storage.empty(); }
        bool   Empty() const { return _storage.empty(); }

        size_t Remaining() const { return _storage.size() - _rpos; }

        void clear()
        {
            _storage.clear();
            _rpos = _wpos = 0;
            _bitpos    = InitialBitPos;
            _curbitval = 0;
        }
        void Clear() { clear(); }

        void ResetReadPos()
        {
            _rpos      = 0;
            _bitpos    = InitialBitPos;
            _curbitval = 0;
        }

        void resize(size_t n)
        {
            _storage.resize(n, 0);
            _rpos = 0;
            _wpos = _storage.size();
        }

        void reserve(size_t n)
        {
            if (n > _storage.size())
                _storage.reserve(n);
        }

        // ---- Packed GUID --------------------------------------------------------

        void WritePackedGuid(uint64_t guid)
        {
            uint8_t pack[9] = {};
            size_t  sz = 1;
            for (uint8_t i = 0; guid != 0; ++i)
            {
                if (guid & 0xFF)
                {
                    pack[0] |= uint8_t(1u << i);
                    pack[sz++] = uint8_t(guid & 0xFF);
                }
                guid >>= 8;
            }
            append(pack, sz);
        }

        void readPackGUID(uint64_t& guid)
        {
            guid = 0;
            uint8_t mask = read<uint8_t>();
            for (int i = 0; i < 8; ++i)
                if (mask & (1u << i))
                    guid |= uint64_t(read<uint8_t>()) << (i * 8);
        }

        // ---- Raw access ---------------------------------------------------------

        uint8_t*       contents()
        {
            if (_storage.empty()) throw std::runtime_error("ByteBuffer::contents: empty buffer");
            return _storage.data();
        }
        const uint8_t* contents() const
        {
            if (_storage.empty()) throw std::runtime_error("ByteBuffer::contents: empty buffer");
            return _storage.data();
        }

        std::span<const uint8_t>     Data()    const { return _storage; }
        const uint8_t*               RawData() const { return _storage.data(); }
        std::vector<uint8_t>&        Storage()       { return _storage; }
        const std::vector<uint8_t>&  Storage() const { return _storage; }

        uint8_t&       operator[](size_t i)       { return _storage[i]; }
        const uint8_t& operator[](size_t i) const { return _storage[i]; }

        // ---- String helpers -----------------------------------------------------

        // WriteCString: appends bytes + null terminator (same as operator<<(string)).
        ByteBuffer& WriteCString(std::string_view str)
        {
            if (size_t len = str.size()) append(str.data(), len);
            append<uint8_t>(0);
            return *this;
        }

        // WriteString (TC style): appends bytes WITHOUT null terminator.
        void WriteString(const std::string& str)
        {
            if (size_t len = str.size()) append(str.data(), len);
        }

        ByteBuffer& Pad(size_t count)
        {
            for (size_t i = 0; i < count; ++i) append<uint8_t>(0);
            return *this;
        }

    protected:
        size_t   _rpos, _wpos, _bitpos;
        uint8_t  _curbitval;
        std::vector<uint8_t> _storage;
    };

} // namespace Fireland::Utils
