#pragma once

// ============================================================================
// StringUtils — Common string operations
// ============================================================================

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <ranges>
#include <span>
#include <format>

namespace Fireland::Utils::StringUtils
{
    /// Trim whitespace from both ends.
    inline std::string Trim(std::string_view sv)
    {
        auto start = sv.find_first_not_of(" \t\r\n");
        if (start == std::string_view::npos)
            return {};
        auto end = sv.find_last_not_of(" \t\r\n");
        return std::string(sv.substr(start, end - start + 1));
    }

    /// Trim whitespace from the left.
    inline std::string TrimLeft(std::string_view sv)
    {
        auto start = sv.find_first_not_of(" \t\r\n");
        if (start == std::string_view::npos)
            return {};
        return std::string(sv.substr(start));
    }

    /// Trim whitespace from the right.
    inline std::string TrimRight(std::string_view sv)
    {
        auto end = sv.find_last_not_of(" \t\r\n");
        if (end == std::string_view::npos)
            return {};
        return std::string(sv.substr(0, end + 1));
    }

    /// Convert to lowercase.
    inline std::string ToLower(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }

    /// Convert to uppercase.
    inline std::string ToUpper(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        return s;
    }

    /// Check if string starts with prefix.
    inline bool StartsWith(std::string_view str, std::string_view prefix) noexcept
    {
        return str.size() >= prefix.size() && str.substr(0, prefix.size()) == prefix;
    }

    /// Check if string ends with suffix.
    inline bool EndsWith(std::string_view str, std::string_view suffix) noexcept
    {
        return str.size() >= suffix.size() && str.substr(str.size() - suffix.size()) == suffix;
    }

    /// Split a string by a delimiter character.
    inline std::vector<std::string> Split(std::string_view str, char delimiter)
    {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream stream{std::string(str)};
        while (std::getline(stream, token, delimiter))
            tokens.push_back(token);
        return tokens;
    }

    /// Join strings with a separator.
    inline std::string Join(const std::vector<std::string>& parts, std::string_view separator)
    {
        std::string result;
        for (std::size_t i = 0; i < parts.size(); ++i)
        {
            if (i > 0)
                result.append(separator);
            result.append(parts[i]);
        }
        return result;
    }

    /// Replace all occurrences of `from` with `to` in `str`.
    inline std::string ReplaceAll(std::string str, std::string_view from, std::string_view to)
    {
        if (from.empty())
            return str;
        std::size_t pos = 0;
        while ((pos = str.find(from, pos)) != std::string::npos)
        {
            str.replace(pos, from.size(), to);
            pos += to.size();
        }
        return str;
    }

	/// Convert to lowercase using views (C++20).
    inline static std::string ToUpper(std::string_view sv)
    {
        return sv
            | std::views::transform([](unsigned char c) -> char {
            return static_cast<char>(std::toupper(c));
                })
            | std::ranges::to<std::string>();
    }

    inline std::string HexStrCompact(std::span<const uint8_t> data)
    {
        std::string out;
        out.reserve(data.size() * 2);

        for (uint8_t b : data)
        {
            std::format_to(std::back_inserter(out), "{:02x}", b);
        }

        return out;
    }

    /// Convert binary data to a hexadecimal string (C++20).
    inline std::string HexStr(std::span<const uint8_t> data)
    {
        return data
            | std::views::transform([](uint8_t b) { return std::format("{:02X}", b); })
            | std::views::join_with(' ')
            | std::ranges::to<std::string>();
    }

    template<typename... Args>
    inline std::string concat_as_string_with_separator(std::string separator, Args&&... args) noexcept
    {
        std::ostringstream oss;
        ((oss << args << separator), ...);
        auto s = oss.str();
        return s.substr(0, s.length() - separator.length()); //remove last separator
    }
} // namespace Fireland::Utils::StringUtils
