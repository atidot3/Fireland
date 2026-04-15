#pragma once

// ============================================================================
// BigNumber — Arbitrary-precision integer for SRP6 crypto
//
// Wraps boost::multiprecision::cpp_int.
// All byte arrays are in LITTLE-ENDIAN order (WoW wire format).
// ============================================================================

#include <cstdint>
#include <span>
#include <vector>

#include <boost/multiprecision/cpp_int.hpp>

namespace Fireland::Crypto {

class BigNumber
{
public:
    BigNumber() = default;
    explicit BigNumber(uint32_t val) : _val(val) {}

    void SetBinary(std::span<const uint8_t> littleEndian);
    std::vector<uint8_t> AsByteArray(std::size_t minSize = 0) const;

    void SetRandom(std::size_t numBytes);

    BigNumber ModExp(const BigNumber& exp, const BigNumber& mod) const;

    BigNumber operator+(const BigNumber& o) const { return BigNumber(_val + o._val); }
    BigNumber operator-(const BigNumber& o) const { return BigNumber(_val - o._val); }
    BigNumber operator*(const BigNumber& o) const { return BigNumber(_val * o._val); }
    BigNumber operator%(const BigNumber& o) const { return BigNumber(_val % o._val); }
    bool operator==(const BigNumber& o) const     { return _val == o._val; }
    bool IsZero() const { return _val == 0; }

private:
    explicit BigNumber(boost::multiprecision::cpp_int val) : _val(std::move(val)) {}
    boost::multiprecision::cpp_int _val;
};

} // namespace Fireland::Crypto
