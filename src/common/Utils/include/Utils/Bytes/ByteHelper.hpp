#pragma once

#include <Utils/Bytes/ByteBuffer.h>

namespace Fireland::Utils
{
    class ByteHelper
    {
    public:
        explicit ByteHelper(ByteBuffer& buffer)
            : _buffer(buffer) {}

        void WriteBit(bool bit)
        {
            if (bit)
                _bitbuf |= (1 << (7 - _bitpos));

            if (++_bitpos == 8)
                FlushByte();
        }

        void WriteBits(uint32_t value, uint8_t count)
        {
            for (int i = count - 1; i >= 0; --i)
                WriteBit((value >> i) & 1);
        }

        void FlushBits()
        {
            if (_bitpos != 0)
                FlushByte();
        }

    private:
        void FlushByte()
        {
            _buffer << _bitbuf;
            _bitbuf = 0;
            _bitpos = 0;
        }

        ByteBuffer& _buffer;
        uint8_t _bitbuf = 0;
        uint8_t _bitpos = 0;
    };
} // namespace Fireland::Utils