#pragma once

#include <memory>
#include <concepts>
#include <cstdint>

namespace Firelands::Network
{
    template <typename T>
    concept IsSession = requires(std::shared_ptr<T> s) {
        { s->Start()   } -> std::same_as<void>;
        { s->Close()   } -> std::same_as<void>;
        { s->GetId()   } -> std::convertible_to<uint64_t>;
    };
}
