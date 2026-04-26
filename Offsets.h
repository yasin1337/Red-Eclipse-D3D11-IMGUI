#pragma once
#include <cstdint>

namespace Offsets {
    // Global / Module Base Offsets
    namespace Global {
        constexpr uintptr_t EntityList = 0x8206A0;
        constexpr uintptr_t ViewMatrix = 0x7CAF60;
    }

    // Offsets relative to an Entity pointer
    namespace Entity {
        constexpr uintptr_t Health   = 0x48; // int
        constexpr uintptr_t Position = 0x24; // Vec3 (XYZ)
    }
}
