#include <Crypto/BigNumber.h>

#include <algorithm>
#include <random>

namespace Firelands::Crypto {

void BigNumber::SetBinary(std::span<const uint8_t> littleEndian)
{
    _val = 0;
    for (auto it = littleEndian.rbegin(); it != littleEndian.rend(); ++it)
        _val = (_val << 8) | *it;
}

std::vector<uint8_t> BigNumber::AsByteArray(std::size_t minSize) const
{
    std::vector<uint8_t> result;
    auto temp = _val;

    while (temp > 0)
    {
        result.push_back(static_cast<uint8_t>(temp & 0xFF));
        temp >>= 8;
    }

    if (result.empty())
        result.push_back(0);

    if (minSize > result.size())
        result.resize(minSize, 0);

    return result;
}

void BigNumber::SetRandom(std::size_t numBytes)
{
    std::vector<uint8_t> buf(numBytes);
    std::random_device rd;
    for (auto& b : buf)
        b = static_cast<uint8_t>(rd());
    SetBinary(buf);
}

BigNumber BigNumber::ModExp(const BigNumber& exp, const BigNumber& mod) const
{
    return BigNumber(boost::multiprecision::powm(_val, exp._val, mod._val));
}

} // namespace Firelands::Crypto
