#pragma once

#include <string>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include <iostream>

#include <Utils/Configuration/Configuration_defs.hpp>

namespace Fireland::Utils
{
    class Configuration final
    {
    public:
        Configuration() = default;
        Configuration(const Configuration&) = delete;
        Configuration& operator=(const Configuration&) = delete;

        static Configuration& Instance();

        bool load(const std::string& filename);

        template<typename T>
        T get(const std::string& key, const T& defaultValue = T()) const {
            auto it = _values.find(key);
            if (it == _values.end())
                return defaultValue;

            std::istringstream iss(it->second);
            T result;
            if (!(iss >> std::boolalpha >> result)) return defaultValue;
            return result;
        }
        // allow overriding
        void set(const std::string& key, const std::string& value)
        {
            _values[key] = value;
        }

    private:
        static void trim(std::string& s) {
            size_t start = s.find_first_not_of(" \t\r\n");
            size_t end = s.find_last_not_of(" \t\r\n");
            if (start == std::string::npos) s.clear();
            else s = s.substr(start, end - start + 1);
        }

        static void removeQuotes(std::string& s) {
            if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
                s = s.substr(1, s.size() - 2);
            }
        }

    private:
        std::unordered_map<std::string, std::string> _values;
    };

    // std::string
    template<>
    inline std::string Configuration::get<std::string>(const std::string& key, const std::string& defaultValue) const {
        auto it = _values.find(key);
        return it != _values.end() ? it->second : defaultValue;
    }

    // bool "true"/"false" or "1"/"0"
    template<>
    inline bool Configuration::get<bool>(const std::string& key, const bool& defaultValue) const {
        auto it = _values.find(key);
        if (it == _values.end())
            return defaultValue;

        std::string val = it->second;
        std::transform(val.begin(), val.end(), val.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (val == "true" || val == "1") return true;
        if (val == "false" || val == "0") return false;
        return defaultValue;
    }

    template<>
    inline std::string_view Configuration::get<std::string_view>(const std::string& key, const std::string_view& defaultValue) const {
        auto it = _values.find(key);
        return it != _values.end() ? std::string_view(it->second) : defaultValue;
    }
}; // namespace FireLand::Utils
#define sConfig Fireland::Utils::Configuration::Instance()