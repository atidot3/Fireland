// ============================================================================
// Tests unitaires Network::PacketBuffer
// ============================================================================
#include <boost/test/unit_test.hpp>
#include <Network/PacketBuffer.h>

using namespace Fireland::Network;

BOOST_AUTO_TEST_CASE(packet_buffer_constructor_test)
{
    PacketBuffer pb1;
    BOOST_TEST(pb1.GetOpcode() == 0U);
    BOOST_TEST(pb1.GetPayloadSize() == 0U);

    PacketBuffer pb2(0x1234);
    BOOST_TEST(pb2.GetOpcode() == 0x1234U);
    BOOST_TEST(pb2.GetPayloadSize() == 0U);
}

BOOST_AUTO_TEST_CASE(packet_buffer_opcode_test)
{
    PacketBuffer pb;
    
    pb.SetOpcode(0x0001);
    BOOST_TEST(pb.GetOpcode() == 0x0001U);

    pb.SetOpcode(0xFFFF);
    BOOST_TEST(pb.GetOpcode() == 0xFFFFU);
}

BOOST_AUTO_TEST_CASE(packet_buffer_append_test)
{
    PacketBuffer pb(0x0100);

    const uint8_t data[] = {0x11, 0x22, 0x33, 0x44};
    pb.Append(data, 4);

    BOOST_TEST(pb.GetPayloadSize() == 4U);

    auto payload = pb.GetPayload();
    BOOST_TEST(payload[0] == 0x11);
    BOOST_TEST(payload[1] == 0x22);
    BOOST_TEST(payload[2] == 0x33);
    BOOST_TEST(payload[3] == 0x44);
}

BOOST_AUTO_TEST_CASE(packet_buffer_write_test)
{
    PacketBuffer pb(0x0200);

    pb.Write(uint32_t(0x11223344));
    pb.Write(uint16_t(0x5566));

    BOOST_TEST(pb.GetPayloadSize() > 0U);

    auto payload = pb.GetPayload();
    // First 4 bytes should be 0x11223344 (little-endian)
    BOOST_TEST(payload[0] == 0x44);
    BOOST_TEST(payload[1] == 0x33);
    BOOST_TEST(payload[2] == 0x22);
    BOOST_TEST(payload[3] == 0x11);
}

BOOST_AUTO_TEST_CASE(packet_buffer_multiple_writes_test)
{
    PacketBuffer pb(0x0001);

    pb.Write(uint8_t(0xAA));
    pb.Write(uint16_t(0xBBCC));
    pb.Write(uint8_t(0xDD));

    BOOST_TEST(pb.GetPayloadSize() == 4U);
}

BOOST_AUTO_TEST_CASE(packet_buffer_header_size_test)
{
    // Verify PacketHeader is properly sized
    BOOST_TEST(PacketHeader::WIRE_SIZE == 4U);
    
    PacketHeader hdr;
    BOOST_TEST(sizeof(hdr) >= 4U);
}

BOOST_AUTO_TEST_CASE(packet_buffer_empty_payload_test)
{
    PacketBuffer pb(0x9999);

    auto payload = pb.GetPayload();
    BOOST_TEST(payload.size() == 0U);
    BOOST_TEST(pb.GetPayloadSize() == 0U);
}
