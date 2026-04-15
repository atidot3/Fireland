// ============================================================================
// IoContext implementation
// ============================================================================

#include <Utils/IoContext.h>

#include <boost/asio/signal_set.hpp>
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

void IoContext::InstallSignalHandlers()
{
    auto signals = std::make_shared<boost::asio::signal_set>(Get(), SIGINT, SIGTERM);

    signals->async_wait([this, signals](const boost::system::error_code& ec, int signo)
    {
        if (!ec)
        {
            FL_LOG_INFO("IoContext", "Received signal {}, shutting down", signo);
            Stop();
        }
    });
}
