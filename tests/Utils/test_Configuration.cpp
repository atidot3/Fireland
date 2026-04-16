// ============================================================================
// Unit tests for Utils::Configuration
// ============================================================================
#include <boost/test/unit_test.hpp>

#include <Utils/Configuration/Configuration.h>
#include <fstream>
#include <cstdio>

using namespace Fireland::Utils;

struct ConfigurationFixture {
    std::string testFile = "test_config.conf";
    ConfigurationFixture() {
        std::ofstream file(testFile);
        file << R"(
            # Comment line
            key1=value1
            key2 = 42
            key3 = true
            key4 = "quoted value"
            key5 = 3.14
        )";
        file.close();
    }
    ~ConfigurationFixture() {
        std::remove(testFile.c_str());
    }
};

BOOST_FIXTURE_TEST_CASE(LoadAndGetValues, ConfigurationFixture)
{
    Configuration config;
    BOOST_TEST(config.load(testFile));
    BOOST_TEST(config.get<std::string>("key1") == "value1");
    BOOST_TEST(config.get<int>("key2") == 42);
    BOOST_TEST(config.get<bool>("key3") == true);
    BOOST_TEST(config.get<std::string>("key4") == "quoted value");
    BOOST_TEST(config.get<float>("key5") == 3.14f, boost::test_tools::tolerance(0.0001f));
}

BOOST_FIXTURE_TEST_CASE(DefaultValues, ConfigurationFixture)
{
    Configuration config;
    BOOST_TEST(config.load(testFile));
    BOOST_TEST(config.get<std::string>("notfound", "default") == "default");
    BOOST_TEST(config.get<int>("notfound", 123) == 123);
    BOOST_TEST(config.get<bool>("notfound", false) == false);
}

BOOST_FIXTURE_TEST_CASE(SetOverrides, ConfigurationFixture)
{
    Configuration config;
    BOOST_TEST(config.load(testFile));
    config.set("key1", "newvalue");
    BOOST_TEST(config.get<std::string>("key1") == "newvalue");
}
