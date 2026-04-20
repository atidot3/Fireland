// ============================================================================
// Tests unitaires Utils::Describe
// ============================================================================
#include <boost/test/unit_test.hpp>
#include <Utils/Asio/Describe.hpp>
#include <string_view>

// Example enum for testing
enum class Color { Red, Green, Blue };
BOOST_DESCRIBE_ENUM(Color, Red, Green, Blue)

// Pour permettre l'affichage de Color dans les tests
std::ostream& operator<<(std::ostream& os, Color c) {
    using Fireland::Utils::Describe::to_string;
    return os << to_string(c);
}

BOOST_AUTO_TEST_CASE(to_string_test)
{
    using Fireland::Utils::Describe::to_string;
    BOOST_TEST(to_string(Color::Red) == "Red");
    BOOST_TEST(to_string(Color::Green) == "Green");
    BOOST_TEST(to_string(Color::Blue) == "Blue");
}

BOOST_AUTO_TEST_CASE(from_string_test)
{
    using Fireland::Utils::Describe::from_string;
    BOOST_TEST(from_string("Red", Color::Green) == Color::Red);
    BOOST_TEST(from_string("Blue", Color::Green) == Color::Blue);
    BOOST_TEST(from_string("Invalid", Color::Green) == Color::Green); // fallback
}
