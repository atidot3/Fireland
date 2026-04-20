#pragma once

#include <span>

#include <boost/asio/cancellation_signal.hpp>

#include <Database/connection_pool_wrapper.h>

#include <Utils/Asio/Async.hpp>

#include <Shared/Auth/Account.h>
#include <Shared/Char/Characters.h>
#include <Shared/Realm/Realmlist.h>

namespace Fireland::Database::Char
{
    class CharWrapper
    {
        friend class Fireland::Database::connection_pool_wrapper;
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
        Fireland::Utils::Async::async<bool> IsNameAvailable(std::string_view name) noexcept;
        Fireland::Utils::Async::async<std::optional<characters>> GetCharacterByGuid(uint64_t guid) noexcept;
        Fireland::Utils::Async::async<std::vector<characters>> GetCharactersForAccount(uint32_t accountid) noexcept;
        Fireland::Utils::Async::async<std::optional<characters>> CreateCharacter(characters c) noexcept;
        Fireland::Utils::Async::async<bool> DeleteCharacter(uint64_t guid, uint32_t accountid) noexcept;
    private:
        CharWrapper(boost::asio::any_io_executor executor, connection_pool_wrapper_options options) noexcept;
       
    private:
        static std::unique_ptr<CharWrapper> instance_;
        boost::asio::cancellation_signal _cancelSignal;
		const Fireland::Database::connection_pool_wrapper_options _options;
        connection_pool_wrapper _connection_pool;
    };
} // namespace Fireland::Database::Char
#define sCharDB Fireland::Database::Char::CharWrapper::Instance()