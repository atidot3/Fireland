#include <Network/World/WorldOpcode.hpp>
#include <Game/Objects/UpdateData.h>

#include <Utils/Log.h>
#include <Utils/Time.h>

using namespace Fireland;
using namespace Fireland::World;
using namespace Fireland::Utils;

// Movement speeds matching TrinityCore 4.3.4 defaults
static constexpr float SPEED_WALK        = 2.5f;
static constexpr float SPEED_RUN         = 7.0f;
static constexpr float SPEED_RUN_BACK    = 4.5f;
static constexpr float SPEED_SWIM        = 4.722222f;
static constexpr float SPEED_SWIM_BACK   = 2.5f;
static constexpr float SPEED_FLIGHT      = 7.0f;
static constexpr float SPEED_FLIGHT_BACK = 4.5f;
static constexpr float SPEED_TURN_RATE   = 3.141593f;
static constexpr float SPEED_PITCH_RATE  = 3.141593f;

enum OBJECT_UPDATE_FLAGS
{
    UPDATEFLAG_NONE = 0x0000,
    UPDATEFLAG_SELF = 0x0001,
    UPDATEFLAG_TRANSPORT = 0x0002,
    UPDATEFLAG_HAS_TARGET = 0x0004,
    UPDATEFLAG_UNKNOWN = 0x0008,
    UPDATEFLAG_LOWGUID = 0x0010,
    UPDATEFLAG_LIVING = 0x0020,
    UPDATEFLAG_STATIONARY_POSITION = 0x0040,
    UPDATEFLAG_VEHICLE = 0x0080,
    UPDATEFLAG_GO_TRANSPORT_POSITION = 0x0100,
    UPDATEFLAG_ROTATION = 0x0200,
    UPDATEFLAG_UNK3 = 0x0400,
    UPDATEFLAG_ANIMKITS = 0x0800,
    UPDATEFLAG_UNK5 = 0x1000,
    UPDATEFLAG_UNK6 = 0x2000,
};

UpdateData::UpdateData(uint16_t mapId) noexcept : _mapId(mapId), _count(0) {}

// Adds a UPDATETYPE_CREATE_OBJECT / CREATE_OBJECT2 block.
// isSelf must be true when the player is the object's owner (self-create).
// The movement block follows TrinityCore's Cata 4.3.4 Object::BuildMovementUpdate()
// for the simple case: no transport, no spline, no fall, movementFlags=0.
void UpdateData::AddCreateObject(uint64_t guid, TypeID typeId, MovementInfo const& move,
                                 std::map<uint16_t, uint32_t> const& fields, bool isSelf)
{
    _count++;

    uint16_t flags = 0x00;
    flags |= UPDATEFLAG_SELF;
    flags |= UPDATEFLAG_STATIONARY_POSITION;
    flags |= UPDATEFLAG_LIVING;

    _data << std::to_underlying(UPDATETYPE_CREATE_OBJECT2);
    _data.WritePackedGuid(guid);
    _data << std::to_underlying(typeId);
    //_data << flags;

    // Extract guid bytes for bit-packed sequences (little-endian order)
    uint8_t g[8];
    for (int i = 0; i < 8; ++i)
        g[i] = static_cast<uint8_t>((guid >> (i * 8)) & 0xFF);

    bool orientationIsZero = (move.orientation == 0.0f);

    // -----------------------------------------------------------------------
    // Bit section — CreateObjectBits header (TC: Object::BuildMovementUpdate)
    // -----------------------------------------------------------------------
    _data.WriteBit(false); // PlayerHoverAnim
    _data.WriteBit(false); // SupressedGreetings
    _data.WriteBit(false); // Rotation
    _data.WriteBit(false); // AnimKit
    _data.WriteBit(false); // CombatVictim
    _data.WriteBit(isSelf); // ThisIsYou
    _data.WriteBit(false); // Vehicle
    _data.WriteBit(true);  // MovementUpdate (player always has movement)
    _data.WriteBits(0, 24);// PauseTimes count = 0
    _data.WriteBit(false); // NoBirthAnim
    _data.WriteBit(false); // MovementTransport
    _data.WriteBit(false); // Stationary
    _data.WriteBit(false); // AreaTrigger
    _data.WriteBit(false); // EnablePortals
    _data.WriteBit(false); // ServerTime

    // MovementUpdate bit sub-section (TC: if (flags.MovementUpdate))
    _data.WriteBit(true);           // !movementFlags (no flags → bit=1)
    _data.WriteBit(orientationIsZero); // orientation==0 → bit=1, skip writing orientation
    _data.WriteBit(g[7]);
    _data.WriteBit(g[3]);
    _data.WriteBit(g[2]);
    // (no 30-bit movementFlags since bit above = 1)
    _data.WriteBit(false);          // hasSplineData (direct: 0 = no spline data)
    _data.WriteBit(true);           // !hasPitch    (inverted: 1 = no pitch)
    _data.WriteBit(false);          // hasSpline    (direct: 0 = no spline)
    _data.WriteBit(false);          // hasFall      (direct: 0 = no fall data)
    _data.WriteBit(true);           // !hasSplineElevation (inverted: 1 = no elevation)
    _data.WriteBit(g[5]);
    _data.WriteBit(false);          // hasTransport (direct: 0 = no transport)
    _data.WriteBit(0);              // !hasTimestamp (inverted: 0 = timestamp present)
    // (no transport bits)
    _data.WriteBit(g[4]);
    // (no spline bits)
    _data.WriteBit(g[6]);
    // (no fall direction — hasFallData=false)
    _data.WriteBit(g[0]);
    _data.WriteBit(g[1]);
    _data.WriteBit(false);          // HeightChangeFailed = false
    _data.WriteBit(true);           // !movementFlagsExtra (no extra flags)

    _data.FlushBits();

    // -----------------------------------------------------------------------
    // Data section — bytes follow FlushBits (TC: if (flags.MovementUpdate))
    // -----------------------------------------------------------------------
    _data.WriteByteSeq(g[4]);
    _data << SPEED_RUN_BACK;
    // (no fall data)
    _data << SPEED_SWIM_BACK;
    // (no spline elevation, no spline data)
    _data << move.z;
    _data.WriteByteSeq(g[5]);
    // (no transport data)
    _data << move.x;
    _data << SPEED_PITCH_RATE;
    _data.WriteByteSeq(g[3]);
    _data.WriteByteSeq(g[0]);
    _data << SPEED_SWIM;
    _data << move.y;
    _data.WriteByteSeq(g[7]);
    _data.WriteByteSeq(g[1]);
    _data.WriteByteSeq(g[2]);
    _data << SPEED_WALK;
    _data << Time::CurrentGameTimeMs(); // HasTime=true → always write game time (ms)
    _data << SPEED_TURN_RATE;
    _data.WriteByteSeq(g[6]);
    _data << SPEED_FLIGHT;
    if (!orientationIsZero)
        _data << move.orientation;
    _data << SPEED_RUN;
    // (no pitch)
    _data << SPEED_FLIGHT_BACK;

    // -----------------------------------------------------------------------
    // Update fields (values block)
    // -----------------------------------------------------------------------
    uint32_t maxField = 0;
    if (!fields.empty()) {
        maxField = fields.rbegin()->first + 1;
    }

	FL_LOG_DEBUG("Network", "maxField={}", maxField);

    uint32_t maskSize = (maxField + 31) / 32;
    _data << static_cast<uint8_t>(maskSize);

    if (maskSize > 0)
    {
        std::vector<uint32_t> mask(maskSize, 0);
        for (auto const& [index, value] : fields)
            mask[index / 32] |= (1u << (index % 32));

        for (uint32_t m : mask)
            _data << m;

        for (uint32_t i = 0; i < maxField; ++i)
        {
            if (mask[i / 32] & (1u << (i % 32)))
                _data << fields.at(static_cast<uint16_t>(i));
        }
    }
}

void UpdateData::Build(World::WorldPacket& packet)
{
    packet.setOpcode(SMSG_UPDATE_OBJECT);
    packet << uint16_t(_mapId);
    packet << _count;
    packet << _data;
}

size_t UpdateData::GetBlockCount() const { return _count; }
