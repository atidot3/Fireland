// ============================================================================
// Tests unitaires Utils::ByteBuffer
// ============================================================================
#include <boost/test/unit_test.hpp>
#include <Utils/ByteBuffer.h>

using namespace Firelands::Utils;

BOOST_AUTO_TEST_CASE(bytebuffer_constructor_test)
{
    ByteBuffer bb1;
    BOOST_TEST(bb1.Size() == 0U);

    ByteBuffer bb2(100);
    BOOST_TEST(bb2.Size() == 0U); // reserve doesn't count as size

    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    ByteBuffer bb3(data);
    BOOST_TEST(bb3.Size() == 3U);
}

BOOST_AUTO_TEST_CASE(bytebuffer_write_read_integer_test)
{
    ByteBuffer bb;
    
    // Write uint32_t
    bb << uint32_t(0x12345678);
    BOOST_TEST(bb.Size() == 4U);

    // Read it back
    uint32_t value = bb.Read<uint32_t>();
    BOOST_TEST(value == 0x12345678U);

    // Write multiple values
    bb << uint8_t(0xAA);
    bb << uint16_t(0xBBCC);
    BOOST_TEST(bb.Size() == 4U + 1U + 2U);  // Total buffer size is 7

    uint8_t b = bb.Read<uint8_t>();
    BOOST_TEST(b == 0xAAU);

    uint16_t w = bb.Read<uint16_t>();
    BOOST_TEST(w == 0xBBCCU);
}

BOOST_AUTO_TEST_CASE(bytebuffer_append_test)
{
    ByteBuffer bb;
    
    const uint8_t data[] = {0x11, 0x22, 0x33};
    bb.Append(data, 3);
    BOOST_TEST(bb.Size() == 3U);

    auto raw = bb.RawData();
    BOOST_TEST(raw[0] == 0x11);
    BOOST_TEST(raw[1] == 0x22);
    BOOST_TEST(raw[2] == 0x33);
}

BOOST_AUTO_TEST_CASE(bytebuffer_pad_test)
{
    ByteBuffer bb;
    bb << uint16_t(0x1234);
    bb.Pad(4);
    
    BOOST_TEST(bb.Size() == 2U + 4U);
    
    uint16_t val = bb.Read<uint16_t>();
    BOOST_TEST(val == 0x1234U);

    for (int i = 0; i < 4; ++i)
        BOOST_TEST(bb.Read<uint8_t>() == 0x00);
}

BOOST_AUTO_TEST_CASE(bytebuffer_write_string_test)
{
    ByteBuffer bb;
	bb << "hello";
	BOOST_TEST(bb.Size() == (5U)); // "hello" + '\0' is included in operator<<

    auto str = bb.ReadString();
    BOOST_TEST(str == "hello");
}

BOOST_AUTO_TEST_CASE(bytebuffer_write_cstring_test)
{
    ByteBuffer bb;
    bb.WriteCString("world");
    
    BOOST_TEST(bb.Size() == 6U); // "world" + \0

    // Read raw bytes manually
    const auto* data = bb.RawData();
    BOOST_TEST(data[0] == 'w');
    BOOST_TEST(data[1] == 'o');
    BOOST_TEST(data[4] == 'd');
    BOOST_TEST(data[5] == 0x00);
}

BOOST_AUTO_TEST_CASE(bytebuffer_stream_operators_test)
{
    ByteBuffer bb;
    bb << uint32_t(0xAABBCCDD) << uint16_t(0x1122) << "test";
    
    BOOST_TEST(bb.Size() > 0U);

    uint32_t val1 = bb.Read<uint32_t>();
    BOOST_TEST(val1 == 0xAABBCCDDU);

    uint16_t val2 = bb.Read<uint16_t>();
    BOOST_TEST(val2 == 0x1122U);
}

BOOST_AUTO_TEST_CASE(bytebuffer_operator_bracket_test)
{
    ByteBuffer bb;
    bb << uint8_t(0xAA);
    bb << uint8_t(0xBB);

    BOOST_TEST(bb[0] == 0xAAU);
    BOOST_TEST(bb[1] == 0xBBU);

    bb[0] = 0xCC;
    BOOST_TEST(bb[0] == 0xCCU);
}

BOOST_AUTO_TEST_CASE(bytebuffer_read_position_test)
{
    ByteBuffer bb;
    bb << uint32_t(1);
    bb << uint32_t(2);
    bb << uint32_t(3);

    BOOST_TEST(bb.Read<uint32_t>() == 1U);
    BOOST_TEST(bb.ReadPos() == 4U);

    BOOST_TEST(bb.Read<uint32_t>() == 2U);
    BOOST_TEST(bb.ReadPos() == 8U);

    BOOST_TEST(bb.Read<uint32_t>() == 3U);
    BOOST_TEST(bb.ReadPos() == 12U);
}

BOOST_AUTO_TEST_CASE(bytebuffer_underflow_test)
{
    ByteBuffer bb;
    bb << uint16_t(0x1234);

    uint16_t val = bb.Read<uint16_t>();
    BOOST_TEST(val == 0x1234U);

    // Reading beyond available data should throw
    BOOST_CHECK_THROW(bb.Read<uint32_t>(), std::out_of_range);
}
