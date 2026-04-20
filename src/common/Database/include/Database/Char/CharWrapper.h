#pragma once

#include <span>

#include <boost/asio/cancellation_signal.hpp>

#include <Database/connection_pool_wrapper.h>

#include <Utils/Asio/Async.hpp>

#include <Shared/Auth/Account.h>
#include <Shared/Char/Characters.h>
#include <Shared/Realm/Realmlist.h>

namespace Firelands::Database::Char
{
    class CharWrapper
    {
        friend class Firelands::Database::connection_pool_wrapper;
    public:
        CharWrapper(const CharWrapper&) = delete;
        CharWrapper& operator=(const CharWrapper&) = delete;
        ~CharWrapper();

        static void Init(boost::asio::any_io_executor exec, connection_pool_wrapper_options options);
        static CharWrapper& Instance();
        static void Shutdown();

        // starting/stopping the wrapper
        void start();
        void stop();
        Utils::Async::async<bool> ping() noexcept;

        // -- Characters operations
        Firelands::Utils::Async::async<bool> IsNameAvailable(std::string_view name) noexcept;
        Firelands::Utils::Async::async<std::optional<characters>> GetCharacterByGuid(uint64_t guid) noexcept;
        Firelands::Utils::Async::async<std::vector<characters>> GetCharactersForAccount(uint32_t accountid) noexcept;
        Firelands::Utils::Async::async<std::optional<characters>> CreateCharacter(characters c) noexcept;
        Firelands::Utils::Async::async<bool> DeleteCharacter(uint64_t guid, uint32_t accountid) noexcept;
    private:
        CharWrapper(boost::asio::any_io_executor executor, connection_pool_wrapper_options options) noexcept;
       
    private:
        static std::unique_ptr<CharWrapper> instance_;
        boost::asio::cancellation_signal _cancelSignal;
		const Firelands::Database::connection_pool_wrapper_options _options;
        connection_pool_wrapper _connection_pool;
    };
} // namespace Firelands::Database::Char
#define sCharDB Firelands::Database::Char::CharWrapper::Instance()