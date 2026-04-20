// ============================================================================
// IoContext implementation
// ============================================================================

#include <Utils/Asio/IoContext.h>
#include <Utils/Log.h>

using namespace Firelands::Utils;

IoContext::IoContext(std::size_t threadCount)
    : _pool(threadCount > 0 ? threadCount : std::thread::hardware_concurrency())
{
}

IoContext::~IoContext()
{
    Stop();
    Join();
}

void IoContext::Stop()
{
    _pool.stop();
}

void IoContext::Join()
{
    _pool.join();
}
