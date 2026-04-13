// ============================================================================
// TcpSession implementation — C++20 coroutine-based TCP session
// ============================================================================

#include "TcpSession.h"
#include "SessionManager.h"

#include <atomic>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/redirect_error.hpp>
#include <Utils/Log.h>

using namespace Fireland::Network;
using namespace Fireland::Utils::Async;

// --------------------------------------------------------------------------
// Static id generator
// --------------------------------------------------------------------------
static std::atomic<uint64_t> sSessionIdCounter{0};

uint64_t TcpSession::NextId()
{
    return ++sSessionIdCounter;
}

// --------------------------------------------------------------------------
// Construction / Destruction
// --------------------------------------------------------------------------
TcpSession::TcpSession(boost::asio::ip::tcp::socket socket, SessionManager& manager, PacketHandler handler)
    : _id(NextId())
    , _socket(std::move(socket))
    , _manager(manager)
    , _packetHandler(std::move(handler))
    , _sendNotify(_socket.get_executor(), boost::asio::steady_timer::time_point::max())
{
    boost::system::error_code ec;
    auto ep = _socket.remote_endpoint(ec);
    if (!ec)
        _remoteAddress = ep.address().to_string() + ":" + std::to_string(ep.port());
    else
        _remoteAddress = "<unknown>";
}

TcpSession::~TcpSession()
{
    FL_LOG_DEBUG("TcpSession", "Session #{} destroyed", _id);
}

// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------
void TcpSession::Start()
{
    FL_LOG_INFO("TcpSession", "Session #{} connected from {}", _id, _remoteAddress);

    auto self = shared_from_this();

    boost::asio::co_spawn(_socket.get_executor(),
        [self]() -> boost::asio::awaitable<void> { co_await self->ReadLoop(); },
        boost::asio::detached);

    boost::asio::co_spawn(_socket.get_executor(),
        [self]() -> boost::asio::awaitable<void> { co_await self->WriteLoop(); },
        boost::asio::detached);
}

void TcpSession::Send(PacketBuffer packet)
{
    if (_closing)
        return;

    auto data = packet.Serialize();
    _sendQueue.push_back(std::move(data));

    // Wake the write loop
    _sendNotify.cancel_one();
}

void TcpSession::Close()
{
    if (_closing)
        return;

    _closing = true;

    boost::system::error_code ec;
    _socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    _socket.close(ec);

    // Wake write loop so it can exit
    _sendNotify.cancel_one();

    _manager.Remove(shared_from_this());

    FL_LOG_INFO("TcpSession", "Session #{} closed ({})", _id, _remoteAddress);
}

bool TcpSession::IsOpen() const noexcept
{
    return _socket.is_open() && !_closing;
}

// --------------------------------------------------------------------------
// ReadLoop coroutine
// --------------------------------------------------------------------------
async<void> TcpSession::ReadLoop()
{
    try
    {
        std::array<uint8_t, PacketHeader::WIRE_SIZE> headerBuf{};

        while (IsOpen())
        {
            // 1. Read the 4-byte packet header
            co_await boost::asio::async_read(
                _socket,
                boost::asio::buffer(headerBuf),
                boost::asio::use_awaitable);

            auto header = PacketBuffer::DeserializeHeader(
                std::span<const uint8_t, PacketHeader::WIRE_SIZE>(headerBuf));

            // Sanity check: size includes opcode (2 bytes), so payload = size - 2
            if (header.size < sizeof(uint16_t))
            {
                FL_LOG_WARNING("TcpSession", "Session #{} invalid packet size {}", _id, header.size);
                break;
            }

            std::size_t payloadSize = header.size - sizeof(uint16_t);

            // 2. Read the payload
            PacketBuffer packet(header.opcode);

            if (payloadSize > 0)
            {
                // Cap at 64 KB to prevent abuse
                constexpr std::size_t MAX_PAYLOAD = 64 * 1024;
                if (payloadSize > MAX_PAYLOAD)
                {
                    FL_LOG_WARNING("TcpSession", "Session #{} payload too large ({} bytes), disconnecting", _id, payloadSize);
                    break;
                }

                std::vector<uint8_t> payloadBuf(payloadSize);
                co_await boost::asio::async_read(
                    _socket,
                    boost::asio::buffer(payloadBuf),
                    boost::asio::use_awaitable);

                packet.Append(payloadBuf.data(), payloadBuf.size());
            }

            // 3. Dispatch
            if (_packetHandler)
                _packetHandler(shared_from_this(), std::move(packet));
        }
    }
    catch (const boost::system::system_error& e)
    {
        if (e.code() != boost::asio::error::eof &&
            e.code() != boost::asio::error::operation_aborted)
        {
            FL_LOG_ERROR("TcpSession", "Session #{} read error: {}", _id, e.what());
        }
    }

    Close();
}

// --------------------------------------------------------------------------
// WriteLoop coroutine
// --------------------------------------------------------------------------
async<void> TcpSession::WriteLoop()
{
    try
    {
        while (IsOpen())
        {
            if (_sendQueue.empty())
            {
                // Wait until Send() wakes us via cancel
                boost::system::error_code ec;
                co_await _sendNotify.async_wait(
                    boost::asio::redirect_error(boost::asio::use_awaitable, ec));

                // Timer cancelled = we have data (or closing)
                if (_closing)
                    break;
                continue;
            }

            // Drain the queue
            while (!_sendQueue.empty() && IsOpen())
            {
                auto& front = _sendQueue.front();
                co_await boost::asio::async_write(
                    _socket,
                    boost::asio::buffer(front),
                    boost::asio::use_awaitable);
                _sendQueue.pop_front();
            }
        }
    }
    catch (const boost::system::system_error& e)
    {
        if (e.code() != boost::asio::error::operation_aborted)
        {
            FL_LOG_ERROR("TcpSession", "Session #{} write error: {}", _id, e.what());
        }
    }
}