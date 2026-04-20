#include <Utils/NetUtils.h>
#include <boost/regex.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/system_executor.hpp>

std::string Firelands::Utils::Net::ip_for(const std::string ip_or_name)
{
    if (!boost::regex_match(ip_or_name, boost::regex("(?:\\d+\\.)+")))
    {
        using tcp = boost::asio::ip::tcp;
        auto resolver = tcp::resolver(boost::asio::system_executor{});
        auto endpoints = resolver.resolve(ip_or_name, "");
        for (auto& endpoint : endpoints)
        {
            return endpoint.endpoint().address().to_string();
        }
    }

    return ip_or_name;
}