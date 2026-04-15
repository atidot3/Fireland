#pragma once

// ============================================================================
// Realm – Realm descriptor with smart address selection for clients
// ============================================================================

#include <cstdint>
#include <optional>
#include <string>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/address_v4.hpp>

namespace Fireland::Auth {

struct Realm
{
    std::string  Name;
    uint8_t      Type       = 0;   // 0 = Normal, 1 = PvP, ...
    uint8_t      Flags      = 0;
    uint8_t      Locked     = 0;
    uint8_t      Timezone   = 1;
    uint8_t      Id         = 1;
    uint8_t      Characters = 0;
    float        Population = 0.5f;
    uint16_t     Port       = 8085;

    boost::asio::ip::address LocalAddress;
    boost::asio::ip::address ExternalAddress;
    boost::asio::ip::address_v4 LocalSubnetMask = boost::asio::ip::make_address_v4("255.255.255.0");

    /// Pick the best realm IP for the given client address.
    boost::asio::ip::tcp::endpoint GetAddressForClient(
        boost::asio::ip::address const& clientAddr) const
    {
        boost::asio::ip::address realmIp;

        if (clientAddr.is_loopback())
        {
            // Client is local – try to match a loopback realm address
            if (LocalAddress.is_loopback() || ExternalAddress.is_loopback())
                realmIp = clientAddr;
            else
                realmIp = LocalAddress;
        }
        else
        {
            if (clientAddr.is_v4() && IsInNetwork(
                    LocalAddress.to_v4(), LocalSubnetMask, clientAddr.to_v4()))
                realmIp = LocalAddress;
            else
                realmIp = ExternalAddress;
        }

        return boost::asio::ip::tcp::endpoint(realmIp, Port);
    }

    /// Format the endpoint as "ip:port" for the wire protocol.
    std::string GetAddressStringForClient(
        boost::asio::ip::address const& clientAddr) const
    {
        auto ep = GetAddressForClient(clientAddr);
        return std::format("{}:{}", ep.address().to_string(), ep.port());
    }

private:
    /// Check whether `client` is in the same subnet as `network`/`mask`.
    static bool IsInNetwork(
        boost::asio::ip::address_v4 const& network,
        boost::asio::ip::address_v4 const& mask,
        boost::asio::ip::address_v4 const& client)
    {
        return (network.to_uint() & mask.to_uint()) ==
               (client.to_uint()  & mask.to_uint());
    }
};

} // namespace Fireland::Auth
