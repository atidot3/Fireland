#include <Utils/Filesystem.h>
#include <fstream>

using namespace Firelands::Utils::Filesystem;

inline filesystem_error_code to_fs_error(const std::error_code& ec)
{
    if (!ec) return filesystem_error_code::none;

    switch (static_cast<std::errc>(ec.value()))
    {
        case std::errc::file_exists:
            return filesystem_error_code::file_exists;
        case std::errc::file_too_large:
            return filesystem_error_code::file_too_large;
        case std::errc::filename_too_long:
            return filesystem_error_code::filename_too_long;
        case std::errc::directory_not_empty:
            return filesystem_error_code::directory_not_empty;
        case std::errc::cross_device_link:
            return filesystem_error_code::cross_device_link;
        case std::errc::invalid_argument:
            return filesystem_error_code::invalid_argument;
        case std::errc::is_a_directory:
            return filesystem_error_code::is_a_directory;
        case std::errc::not_a_directory:
            return filesystem_error_code::not_a_directory;
        case std::errc::no_such_file_or_directory:
            return filesystem_error_code::no_such_file_or_directory;
        case std::errc::permission_denied:
            return filesystem_error_code::permission_denied;
        case std::errc::read_only_file_system:
            return filesystem_error_code::read_only_file_system;
        case std::errc::too_many_files_open:
            return filesystem_error_code::too_many_files_open;
        case std::errc::too_many_files_open_in_system:
            return filesystem_error_code::too_many_files_open_in_system;
        case std::errc::too_many_links:
            return filesystem_error_code::too_many_links;
        case std::errc::too_many_symbolic_link_levels:
            return filesystem_error_code::too_many_symbolic_link_levels;
        case std::errc::text_file_busy:
            return filesystem_error_code::text_file_busy;
        case std::errc::io_error:
            return filesystem_error_code::io_error;
        case std::errc::no_space_on_device:
            return filesystem_error_code::no_space_on_device;
        case std::errc::value_too_large:
            return filesystem_error_code::value_too_large;
        default:
            return filesystem_error_code::unknown;
    }
}

filesystem_error::filesystem_error(std::error_code& errc, std::string_view errm)
    : _error_message{ errm }
    , _error_code{ to_fs_error(errc) }
{

}

bool filesystem_error::error()
{
    return _error_code != filesystem_error_code::none;
}

std::string_view filesystem_error::error_message()
{
    return _error_message;
}

filesystem_error_code filesystem_error::error_code()
{
    return _error_code;
}

/*static*/ std::expected<bool, filesystem_error> filesystem_helpers::exists(const std::filesystem::path where)
{
    std::error_code ec;
    if (!std::filesystem::exists(where, ec))
    {
        auto errc = std::make_error_code(std::errc::no_such_file_or_directory);
        return std::unexpected(filesystem_error(errc, "[" + where.string() + "] not found"));
    }

    return true;
}

/*static*/ std::expected<bool, filesystem_error> filesystem_helpers::create_directory(const std::filesystem::path where)
{
    std::stringstream error;
    std::error_code ec;

    auto res = std::filesystem::create_directories(where, ec);
    if (!res || ec)
    {
        if (ec)
            error << "Create ["<< where.string() <<"] has failed: " << ec.message();
        else
        {
            auto exist_already = exists(where);
            if (exist_already.has_value() && exist_already.value())
            {
                auto errc = std::make_error_code(std::errc::file_exists);
                return std::unexpected(filesystem_error(errc, "[" + where.string() + "] already exists"));
            }

            error << "Unable to create [" << where.string() << "] : unknown reason.";
        }

        return std::unexpected(filesystem_error(ec, error.str()));
    }

    return true;
}

/*static*/ std::expected<bool, filesystem_error> filesystem_helpers::check_or_create_directory(const std::filesystem::path where)
{
    std::stringstream error;
    std::error_code ec;

    auto exist_already = exists(where);
    if (exist_already.has_value() && exist_already.value())
        return true;

    if (!std::filesystem::create_directories(where, ec))
    {
        if (ec)
            error << "Create ["<< where.string() <<"] has failed: " << ec.message();
        else
            error << "Unable to create [" << where.string() << "] : unknown reason.";
        return std::unexpected(filesystem_error(ec, error.str()));
    }

    return true;
}

/*static*/ std::expected<std::vector<char>, filesystem_error> filesystem_helpers::read_file(const std::filesystem::path file_path)
{
    std::error_code errc;
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    std::stringstream error;

    if (!file)
    {
        std::error_code ec(errno, std::generic_category());
        error << "Unable to open file at: " << file_path.string();
        return std::unexpected(filesystem_error(ec, error.str()));
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size))
    {
        std::error_code ec(errno, std::generic_category());
        error << "Unable to read file at: " << file_path.string();
        return std::unexpected(filesystem_error(ec, error.str()));
    }
    return buffer;
}

/*static*/ std::expected<bool, filesystem_error> filesystem_helpers::write_file(const std::filesystem::path file_path, const std::vector<char>& data, std::ios::openmode mode)
{
    std::ofstream file(file_path, mode);
    if (!file.is_open())
    {
        auto errc = std::error_code(errno, std::generic_category());
        std::stringstream error;
        error << "["<< file_path.string() <<"] " << errc.message();
        return std::unexpected(filesystem_error(errc, error.str()));
    }

    file.write(data.data(), data.size());
    file.close();

    return true;
}

/*static*/ std::expected<std::vector<std::filesystem::path>, filesystem_error> filesystem_helpers::get_files(const std::filesystem::path where)
{
    std::stringstream error;
    std::error_code ec;

    if (!std::filesystem::exists(where, ec))
    {
        error << "["<< where.string() <<"] " << ec.message();
        return std::unexpected(filesystem_error(ec, error.str()));
    }

    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(where))
    {
        if (entry.is_regular_file())
        {
            files.push_back(entry);
        }
    }

    return files;
}

/*static*/ std::expected<bool, filesystem_error> filesystem_helpers::remove_file(const std::filesystem::path file_path, bool ignore_non_empty)
{
    std::error_code ec;

    if (!std::filesystem::exists(file_path, ec))
    {
        auto errc = std::make_error_code(std::errc::no_such_file_or_directory);
        return std::unexpected(filesystem_error(errc, "[" + file_path.string() + "] " + errc.message()));
    }

    bool res = false;
    if (!ignore_non_empty)
    {
        res = std::filesystem::remove(file_path, ec);
        if (ec)
            return std::unexpected(filesystem_error(ec, "[" + file_path.string() + "] " + ec.message()));
    }
    else
    {
        res = std::filesystem::remove_all(file_path, ec);
        if (ec)
            return std::unexpected(filesystem_error(ec, "[" + file_path.string() + "] " + ec.message()));
    }

    return res;
}

/*static*/ std::expected<bool, filesystem_error> filesystem_helpers::rename_file(const std::filesystem::path from_file, const std::filesystem::path to_file)
{
    std::stringstream error;
    std::error_code errc;

    std::filesystem::rename(from_file, to_file, errc);
    if (errc)
    {
        std::stringstream ss;
        ss << "["<< from_file.string() <<"] " << errc.message();
        return std::unexpected(filesystem_error(errc, ss.str()));
    }

    return true;
}

/*static*/ std::expected<bool, filesystem_error> filesystem_helpers::test_folder(const std::filesystem::path where)
{
    auto result = filesystem_helpers::check_or_create_directory(where);
    if (!result || !result.has_value())
        return result;
    std::filesystem::path file(where / "toto.txt");
    auto result2 = filesystem_helpers::write_file(file, {'t', 'e', 's', 't'});
    if (!result2 || !result2.has_value())
        return result;
    auto result3 = filesystem_helpers::remove_file(file);
    if (!result3 || !result3.has_value())
        return result;

    return true;
}