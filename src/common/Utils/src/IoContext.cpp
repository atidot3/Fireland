// ============================================================================
// IoContext implementation
// ============================================================================

#include <Utils/IoContext.h>
#include <Utils/Log.h>

using namespace Fireland::Utils;

IoContext::IoContext(std::size_t threadCount)
    : _pool(threadCount > 0 ? threadCount : 1)
{
    FL_LOG_INFO("IoContext", "Running with {} thread(s)", threadCount > 0 ? threadCount : 1);
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
