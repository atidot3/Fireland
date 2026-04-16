#pragma once

#include <Shared/Realm/Realmlist.h>
#include <Database/Auth/AuthWrapper.h>
#include <Utils/Async.hpp>

#include <boost/asio/cancellation_signal.hpp>

#include <future>
#include <memory>
#include <vector>

class Realm
{
public:
    Realm(const Realm&) = delete;
    Realm& operator=(const Realm&) = delete;
    ~Realm();

    static void Init(boost::asio::any_io_executor exec, Fireland::Database::Auth::AuthWrapper& authWrapper);
    static Realm& Instance();
    static void Shutdown();

    std::shared_ptr<const std::vector<realmlist>> GetRealms() const noexcept;

private:
    explicit Realm(boost::asio::any_io_executor exec, Fireland::Database::Auth::AuthWrapper& authWrapper);
    Fireland::Utils::Async::async<void> realm_update();

private:
    static std::unique_ptr<Realm> instance_;

    boost::asio::strand<boost::asio::any_io_executor> _strand;
    Fireland::Database::Auth::AuthWrapper& _authWrapper;
    std::shared_ptr<std::vector<realmlist>> _realms;

    boost::asio::cancellation_signal _cancelSignal;
    std::future<void> _updateFuture;
};
#define sRealm Realm::Instance()