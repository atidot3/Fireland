#pragma once

// ============================================================================
// ProgramOptions — Command-line argument parsing for Fireland servers
//
// Usage:
//   int main(int argc, char* argv[])
//   {
//       Fireland::Utils::ProgramOptions opts("authserver", "0.1.0", "authserver.conf");
//       if (!opts.Parse(argc, argv))
//           return opts.ExitCode();
//
//       Fireland::Utils::Log::Init(opts.ConfigFile());
//       if (opts.Quiet())
//           Fireland::Utils::Log::SetConsoleEnabled(false);
//   }
// ============================================================================

#include <cstdlib>
#include <iostream>
#include <string>

#include <boost/program_options.hpp>

namespace Fireland::Utils {

class ProgramOptions final
{
public:
    ProgramOptions(std::string_view appName,
                   std::string_view version,
                   std::string_view defaultConfig)
        : _appName(appName)
        , _version(version)
        , _configFile(defaultConfig)
    {
    }

    /// Parse argc/argv.  Returns true if the program should continue,
    /// false if it should exit (--help / --version).
    bool Parse(int argc, char* argv[])
    {
        namespace po = boost::program_options;

        po::options_description options("Options");
        options.add_options()
            ("help,h",    "Show this help message")
            ("version,v", "Show version number")
            ("config,c",  po::value<std::string>(&_configFile)
                              ->default_value(std::string(_configFile)),
                          "Set the configuration file path")
            ("quiet,q",   "Disable console logging");

        po::variables_map vm;

        try
        {
            po::store(po::parse_command_line(argc, argv, options), vm);

            if (vm.count("help"))
            {
                std::cout << _appName << " v" << _version << "\n\n"
                          << options << std::endl;
                _exitCode = EXIT_SUCCESS;
                return false;
            }

            if (vm.count("version"))
            {
                std::cout << _appName << " v" << _version << std::endl;
                _exitCode = EXIT_SUCCESS;
                return false;
            }

            po::notify(vm);

            _quiet = vm.count("quiet") > 0;
        }
        catch (const po::error& e)
        {
            std::cerr << _appName << ": " << e.what() << "\n\n"
                      << options << std::endl;
            _exitCode = EXIT_FAILURE;
            return false;
        }

        return true;
    }

    [[nodiscard]] const std::string& ConfigFile() const noexcept { return _configFile; }
    [[nodiscard]] bool               Quiet()      const noexcept { return _quiet; }
    [[nodiscard]] int                ExitCode()   const noexcept { return _exitCode; }

private:
    std::string _appName;
    std::string _version;
    std::string _configFile;
    bool        _quiet    = false;
    int         _exitCode = EXIT_SUCCESS;
};

} // namespace Fireland::Utils
