// ============================================================================
// Tests unitaires WorldPacket / ByteBuffer
// ============================================================================
#include <boost/test/unit_test.hpp>

#include <Network/World/WorldPacket.h>
#include <Utils/ByteBuffer.h>

using namespace Firelands::World;
using namespace Firelands::Utils;

// ---- WorldPacket construction -----------------------------------------------

BOOST_AUTO_TEST_CASE(worldpacket_default_constructor)
{
    WorldPacket pkt;
    BOOST_TEST(pkt.opcode() == 0U);
    BOOST_TEST(pkt.wpos()   == 0U);
}

BOOST_AUTO_TEST_CASE(worldpacket_opcode_constructor)
{
    WorldPacket pkt(0x1234);
    BOOST_TEST(pkt.opcode() == 0x1234U);
    BOOST_TEST(pkt.wpos()   == 0U);
}

// ---- Opcode accessors -------------------------------------------------------

BOOST_AUTO_TEST_CASE(worldpacket_set_opcode)
{
    WorldPacket pkt;
    pkt.setOpcode(0x5DB6);
    BOOST_TEST(pkt.opcode() == 0x5DB6U);
    BOOST_TEST(pkt.is(0x5DB6U));
    BOOST_TEST(!pkt.is(0x0000U));
}

// ---- ByteBuffer write / append ----------------------------------------------

BOOST_AUTO_TEST_CASE(bytebuffer_append_raw)
{
    WorldPacket pkt(0x0100);
    const uint8_t data[] = {0x11, 0x22, 0x33, 0x44};
    pkt.append(data, 4);

    BOOST_TEST(pkt.wpos() == 4U);
    BOOST_TEST(pkt[0] == 0x11);
    BOOST_TEST(pkt[1] == 0x22);
    BOOST_TEST(pkt[2] == 0x33);
    BOOST_TEST(pkt[3] == 0x44);
}

BOOST_AUTO_TEST_CASE(bytebuffer_write_uint32_little_endian)
{
    WorldPacket pkt(0x0200);
    pkt << uint32_t(0x11223344);

    BOOST_TEST(pkt.wpos() == 4U);
    BOOST_TEST(pkt[0] == 0x44); // little-endian
    BOOST_TEST(pkt[1] == 0x33);
    BOOST_TEST(pkt[2] == 0x22);
    BOOST_TEST(pkt[3] == 0x11);
}

BOOST_AUTO_TEST_CASE(bytebuffer_write_multiple_types)
{
    WorldPacket pkt(0x0001);
    pkt << uint8_t(0xAA);
    pkt << uint16_t(0xBBCC);
    pkt << uint8_t(0xDD);

    BOOST_TEST(pkt.wpos() == 4U);
}

BOOST_AUTO_TEST_CASE(bytebuffer_read_back)
{
    WorldPacket pkt(0x0300);
    pkt << uint32_t(0xDEADBEEF);
    pkt << uint16_t(0x1234);

    BOOST_TEST(pkt.Read<uint32_t>() == 0xDEADBEEFU);
    BOOST_TEST(pkt.Read<uint16_t>() == 0x1234U);
}

// ---- SMSG wire serialisation ------------------------------------------------

BOOST_AUTO_TEST_CASE(worldpacket_smsg_header_empty_payload)
{
    // size = 2 (opcode width) + 0 (payload) = 2
    WorldPacket pkt(0x4542); // SMSG_AUTH_CHALLENGE opcode
    auto hdr = pkt.SmsgHeader();

    uint16_t wireSize = (uint16_t{hdr[0]} << 8) | hdr[1];
    uint16_t opcode   = uint16_t{hdr[2]} | (uint16_t{hdr[3]} << 8);

    BOOST_TEST(wireSize == 2U);
    BOOST_TEST(opcode   == 0x4542U);
}

BOOST_AUTO_TEST_CASE(worldpacket_smsg_serialize)
{
    WorldPacket pkt(0x0001);
    pkt << uint32_t(0xAABBCCDD);

    auto frame = pkt.Serialize();

    // Header (4) + payload (4)
    BOOST_TEST(frame.size() == 8U);

    // size field (BE) = 2 + 4 = 6
    uint16_t wireSize = (uint16_t{frame[0]} << 8) | frame[1];
    BOOST_TEST(wireSize == 6U);

    // Payload starts at byte 4
    BOOST_TEST(frame[4] == 0xDD);
    BOOST_TEST(frame[5] == 0xCC);
    BOOST_TEST(frame[6] == 0xBB);
    BOOST_TEST(frame[7] == 0xAA);
}

// ---- CMSG deserialisation ---------------------------------------------------

BOOST_AUTO_TEST_CASE(worldpacket_from_cmsg_header)
{
    // wireSize=8 → payloadCapacity=4, opcode=0x0449
    std::array<uint8_t, 6> raw = {0x00, 0x08, 0x49, 0x04, 0x00, 0x00};
    auto pkt = WorldPacket::FromCmsgHeader(raw);

    BOOST_TEST(pkt.opcode() == 0x0449U);
    BOOST_TEST(pkt.wpos()   == 0U);
}

// ---- Equality ---------------------------------------------------------------

BOOST_AUTO_TEST_CASE(worldpacket_equality_by_opcode)
{
    WorldPacket a(0xABCD);
    WorldPacket b(0xABCD);
    WorldPacket c(0x1234);

    BOOST_TEST(a == b);
    BOOST_TEST(!(a == c));
}
