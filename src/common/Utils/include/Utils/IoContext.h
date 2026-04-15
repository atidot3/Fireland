#pragma once

// ============================================================================
// IoContext — Boost.Asio io_context wrapper with a managed thread pool
// ============================================================================

#include <cstddef>
#include <memory>
#include <vector>
#include <thread>

#include <boost/asio/thread_pool.hpp>
#include <boost/asio/signal_set.hpp>

namespace Fireland::Utils
{
    class IoContext final
    {
    public:
        explicit IoContext(std::size_t threadCount = std::thread::hardware_concurrency());
        ~IoContext();

        IoContext(const IoContext&) = delete;
        IoContext& operator=(const IoContext&) = delete;

        /// Request a graceful stop. All pending coroutines will complete.
        void Stop();

        /// Block until all threads have joined.
        void Join();

        /// Access the underlying io_context.
        [[nodiscard]] boost::asio::any_io_executor Get() noexcept { return _pool.get_executor(); }

        /// Install SIGINT / SIGTERM handlers for graceful shutdown.
        void InstallSignalHandlers();

    private:
        boost::asio::thread_pool _pool;
    };
} // namespace Fireland::Utils
