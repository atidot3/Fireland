#include <Utils/Configuration/Configuration.h>
#include <fstream>

using namespace Fireland::Utils;

Configuration& Configuration::Instance()
{
    static Configuration instance;
	return instance;
}

bool Configuration::load(const std::string& filename)
{
    try
    {
        std::ifstream file(filename);
        if (!file.is_open()) return false;

        std::string line;
        while (std::getline(file, line)) {
            trim(line);
            if (line.empty() || line[0] == '#') continue;

            auto pos = line.find('=');
            if (pos == std::string::npos) continue;

            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);

            trim(key);
            trim(value);
            removeQuotes(value);

            _values[key] = value;
        }

        return true;
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(std::format("Configuration has failed to load: {}", e.what()));
    }
    return false;
}
