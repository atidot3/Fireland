#include <chrono>

namespace Firelands::Utils::Time
{
    static inline uint32_t CurrentGameTimeMs()
    {
        using namespace std::chrono;
        static const system_clock::time_point ApplicationStartTime = system_clock::now();
        auto sinceStart = duration_cast<milliseconds>(system_clock::now() - ApplicationStartTime).count();
        return static_cast<uint32_t>(sinceStart);
    }
}