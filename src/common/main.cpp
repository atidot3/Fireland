// ============================================================================
// Fireland — Boost smoke test
// Validates that all required Boost components compile and link correctly.
// ============================================================================

#include <cstdlib>
#include <iostream>

#include <boost/system/error_code.hpp>
#include <boost/regex.hpp>
#include <boost/log/trivial.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/program_options.hpp>
#include <boost/url.hpp>
#include <boost/charconv.hpp>
#include <boost/version.hpp>

int main(int argc, char* argv[])
{
    std::cout << "Fireland — Boost smoke test\n";
    std::cout << "Boost version: " << BOOST_LIB_VERSION << "\n";

    // Boost.System
    boost::system::error_code ec;
    std::cout << "[system]          default error_code: " << ec.message() << "\n";

    // Boost.Regex
    boost::regex pattern(R"(\d+)");
    std::cout << "[regex]           pattern compiled OK\n";

    // Boost.Log
    BOOST_LOG_TRIVIAL(info) << "[log]             trivial log works";

    // Boost.DateTime
    auto now = boost::posix_time::second_clock::local_time();
    std::cout << "[date_time]       " << now << "\n";

    // Boost.ProgramOptions
    boost::program_options::options_description desc("Test");
    desc.add_options()("help", "show help");
    std::cout << "[program_options] options_description created\n";

    // Boost.URL
    auto url = boost::urls::parse_uri("https://fireland.example.com/api");
    std::cout << "[url]             parsed host: " << url->host() << "\n";

    // Boost.Charconv
    char buf[32];
    auto res = boost::charconv::to_chars(buf, buf + sizeof(buf), 3.14159);
    std::cout << "[charconv]        3.14159 -> " << std::string(buf, res.ptr) << "\n";

    std::cout << "\nAll Boost components OK!\n";
    return EXIT_SUCCESS;
}
