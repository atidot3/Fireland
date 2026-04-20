#pragma once

// ============================================================================
// IoContext — Boost.Asio io_context wrapper with a managed thread pool
// ============================================================================

#include <cstddef>
#include <thread>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/thread_pool.hpp>

namespace Firelands::Utils
{
    class IoContext final
    {
    public:
        explicit IoContext(std::size_t threadCount = std::thread::hardware_concurrency());
        ~IoContext();

        IoContext(const IoContext&) = delete;
        IoContext& operator=(const IoContext&) = delete;

        /// Request a graceful stop.
        void Stop();

        /// Block until all threads have joined.
        void Join();

        /// Access the underlying executor.
        [[nodiscard]] boost::asio::any_io_executor Get() noexcept { return _pool.get_executor(); }

    private:
        boost::asio::thread_pool _pool;
    };
} // namespace Firelands::Utils
