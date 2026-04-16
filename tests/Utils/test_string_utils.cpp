// ============================================================================
// Tests unitaires Utils::StringUtils
// ============================================================================
#include <boost/test/unit_test.hpp>
#include <Utils/StringUtils.h>

using namespace Fireland::Utils::StringUtils;
using namespace std::string_literals;

BOOST_AUTO_TEST_CASE(trim_test)
{
    BOOST_TEST(Trim("  hello  ") == "hello");
    BOOST_TEST(Trim("\t\nworld\r\n") == "world");
    BOOST_TEST(Trim("   ") == "");
    BOOST_TEST(Trim("no spaces") == "no spaces");
}

BOOST_AUTO_TEST_CASE(trim_left_test)
{
    BOOST_TEST(TrimLeft("  hello  ") == "hello  ");
    BOOST_TEST(TrimLeft("\t\nworld") == "world");
    BOOST_TEST(TrimLeft("no spaces") == "no spaces");
}

BOOST_AUTO_TEST_CASE(trim_right_test)
{
    BOOST_TEST(TrimRight("  hello  ") == "  hello");
    BOOST_TEST(TrimRight("world\r\n") == "world");
    BOOST_TEST(TrimRight("no spaces") == "no spaces");
}

BOOST_AUTO_TEST_CASE(to_lower_test)
{
    BOOST_TEST(ToLower("HELLO") == "hello");
    BOOST_TEST(ToLower("WoRlD") == "world");
    BOOST_TEST(ToLower("123ABC") == "123abc");
}

BOOST_AUTO_TEST_CASE(to_upper_test)
{
    BOOST_TEST(ToUpper("hello"s) == "HELLO");
    BOOST_TEST(ToUpper("WoRlD"s) == "WORLD");
    BOOST_TEST(ToUpper("123abc"s) == "123ABC");
}

BOOST_AUTO_TEST_CASE(starts_with_test)
{
    BOOST_TEST(StartsWith("hello world", "hello"));
    BOOST_TEST(StartsWith("hello", "hello"));
    BOOST_TEST(!StartsWith("hello", "world"));
    BOOST_TEST(!StartsWith("hi", "hello"));
}

BOOST_AUTO_TEST_CASE(ends_with_test)
{
    BOOST_TEST(EndsWith("hello world", "world"));
    BOOST_TEST(EndsWith("world", "world"));
    BOOST_TEST(!EndsWith("world", "hello"));
    BOOST_TEST(!EndsWith("hi", "hello"));
}

BOOST_AUTO_TEST_CASE(split_test)
{
    auto parts = Split("a,b,c", ',');
    BOOST_TEST(parts.size() == 3U);
    BOOST_TEST(parts[0] == "a");
    BOOST_TEST(parts[1] == "b");
    BOOST_TEST(parts[2] == "c");

    auto single = Split("hello", ',');
    BOOST_TEST(single.size() == 1U);
    BOOST_TEST(single[0] == "hello");
}

BOOST_AUTO_TEST_CASE(join_test)
{
    BOOST_TEST(Join({"a", "b", "c"}, ",") == "a,b,c");
    BOOST_TEST(Join({"hello"}, ",") == "hello");
    BOOST_TEST(Join({}, ",") == "");
    BOOST_TEST(Join({"x", "y", "z"}, " - ") == "x - y - z");
}

BOOST_AUTO_TEST_CASE(replace_all_test)
{
    BOOST_TEST(ReplaceAll("hello hello", "hello", "hi") == "hi hi");
    BOOST_TEST(ReplaceAll("aaa", "a", "b") == "bbb");
    BOOST_TEST(ReplaceAll("test", "x", "y") == "test");
    BOOST_TEST(ReplaceAll("test", "", "x") == "test"); // empty 'from' returns original
}

BOOST_AUTO_TEST_CASE(hex_str_compact_test)
{
    std::vector<uint8_t> data = {0x12, 0x34, 0xAB};
    BOOST_TEST(HexStrCompact(data) == "1234ab");

    std::vector<uint8_t> empty = {};
    BOOST_TEST(HexStrCompact(empty) == "");
}
