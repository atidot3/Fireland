#pragma once


#include <vector>
#include <map>

#include <Shared/Char/UpdateFields.h>
#include <Shared/Char/MovementInfo.h>

#include <Utils/ByteBuffer.h>
#include <Network/World/WorldPacket.hpp>

namespace Fireland
{
    class UpdateData
    {
    public:
        UpdateData() noexcept;

		// Create Object update with movement and fields.
        // isSelf=true when the receiving player is the object (uses UPDATETYPE_CREATE_OBJECT2).
        void AddCreateObject(uint64_t guid, TypeID typeId, MovementInfo const& move,
                             std::map<uint16_t, uint32_t> const& fields, bool isSelf = false);

		// Build the SMSG_UPDATE_OBJECT packet payload with the accumulated updates. The caller is responsible for setting the opcode and framing the packet.
        void Build(World::WorldPacket& packet);

		// Get the number of updates added.
        size_t GetBlockCount() const;

    private:
        uint32_t _count;
        Utils::ByteBuffer _data;
    };

} // namespace Fireland