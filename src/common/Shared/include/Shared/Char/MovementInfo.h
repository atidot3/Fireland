#pragma once

#include <cinttypes>

namespace Fireland {

    struct MovementInfo
    {
        uint32_t flags = 0;
        uint16_t flags2 = 0;
        uint32_t time = 0;
        float x = 0.0f, y = 0.0f, z = 0.0f, orientation = 0.0f;
        uint32_t fallTime = 0;
    };

} // namespace Fireland