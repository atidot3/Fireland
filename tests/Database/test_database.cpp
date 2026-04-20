// ============================================================================
// Tests unitaires Database
// ============================================================================
#include <boost/test/unit_test.hpp>
#include <Database/connection_pool_wrapper.h>

using namespace Firelands::Database;

BOOST_AUTO_TEST_CASE(connection_pool_wrapper_options_test)
{
    connection_pool_wrapper_options opts;
    opts.username = "root";
    opts.password = "password";
    opts.database = "firelands";
    opts.hostname = "localhost";
    opts.port = 3306;

    BOOST_TEST(opts.username == "root");
    BOOST_TEST(opts.password == "password");
    BOOST_TEST(opts.database == "firelands");
    BOOST_TEST(opts.hostname == "localhost");
    BOOST_TEST(opts.port == 3306);
}

BOOST_AUTO_TEST_CASE(connection_pool_wrapper_options_default_test)
{
    connection_pool_wrapper_options opts;
    
    // Default values should be empty strings (port is uninitialized)
    BOOST_TEST(opts.username == "");
    BOOST_TEST(opts.password == "");
    BOOST_TEST(opts.database == "");
    BOOST_TEST(opts.hostname == "");
}

BOOST_AUTO_TEST_CASE(sql_name_demangle_test)
{
    // Test struct name demangling
    auto name = sql::name<int>();
    BOOST_TEST(!name.empty());

    auto int_name = sql::name<int>();
    auto string_name = sql::name<std::string>();
    BOOST_TEST(int_name != string_name);
}
