#pragma once

#include <Utils/Asio/Describe.hpp>

struct account
{
    uint32_t id;
    std::string username;
    std::string email;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> verifier;
    uint8_t expansion;
};
BOOST_DESCRIBE_STRUCT(account, (), (id, username, email, salt, verifier, expansion))


struct account_session
{
    uint32_t id;
    std::vector<uint8_t> session_key;
};
BOOST_DESCRIBE_STRUCT(account_session, (), (id, session_key))