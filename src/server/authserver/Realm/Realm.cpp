#include "Realm.h"

#include <Shared/Realm/Realmlist.h>

#include <Utils/Log.h>
#include <Database/Auth/AuthWrapper.h>

#include <boost/asio/bind_cancellation_slot.hpp>

using namespace Fireland::Utils::Async;
using namespace std::chrono_literals;

std::unique_ptr<Realm> Realm::instance_ = nullptr;

void Realm::Init(boost::asio::any_io_executor exec)
{
    if (!instance_)
        instance_ = std::unique_ptr<Realm>(new Realm(exec));
}

Realm& Realm::Instance()
{
    return *instance_;
}

void Realm::Shutdown()
{
    if (instance_)
    {
        auto ptr = instance_.release();
        delete ptr;
        instance_.reset();
    }
}

Realm::Realm(boost::asio::any_io_executor exec)
    : _strand(boost::asio::make_strand(exec))
    , _realms(std::make_shared<std::vector<realmlist>>())
{
    _updateFuture = boost::asio::co_spawn(
        _strand,
        realm_update(),
        boost::asio::bind_cancellation_slot(_cancelSignal.slot(), boost::asio::use_future)
    );
}

Realm::~Realm()
{
    _cancelSignal.emit(boost::asio::cancellation_type::all);
    try { _updateFuture.get(); } catch (...) {}
}

std::shared_ptr<const std::vector<realmlist>> Realm::GetRealms() const noexcept
{
    return _realms;
}

Fireland::Utils::Async::async<void> Realm::realm_update()
{
    auto safe_lambda = [this]() -> Fireland::Utils::Async::async<void>
    {
        auto opt_db_realms = co_await sAuthDB.GetRealmlist();
        if (opt_db_realms && opt_db_realms->size() > 0)
        {
            _realms = std::make_shared<std::vector<realmlist>>(std::move(opt_db_realms.value()));
            FL_LOG_INFO("Realmlist", "Updated realm list cache with {} realms", _realms->size());
        }
        else
        {
            FL_LOG_WARNING("Realmlist", "Failed to update realm list cache: no realms retrieved from database");
        }
        co_return;
    };

    for (;;)
    {
        co_await boost::asio::co_spawn(_strand, safe_lambda, boost::asio::use_awaitable);
        if (!co_await async_sleep(10s)) co_return;
    }
}
