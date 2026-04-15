#include <filesystem>
#include <string>
#include <string_view>
#include <vector>
#include <expected>

#include <Utils/Describe.hpp>

namespace Fireland::Utils
{
    namespace Filesystem
    {
        enum class filesystem_error_code
        {
            none,
            file_exists,                    // EEXIST
            file_too_large,                 // EFBIG
            filename_too_long,              // ENAMETOOLONG
            directory_not_empty,            // ENOTEMPTY
            cross_device_link,              // EXDEV
            invalid_argument,               // EINVAL
            is_a_directory,                 // EISDIR
            not_a_directory,                // ENOTDIR
            no_such_file_or_directory,      // ENOENT
            permission_denied,              // EACCES / EPERM
            read_only_file_system,          // EROFS
            too_many_files_open,            // EMFILE
            too_many_files_open_in_system,  // ENFILE
            too_many_links,                 // EMLINK
            too_many_symbolic_link_levels,  // ELOOP
            text_file_busy,                 // ETXTBSY
            io_error,                       // EIO
            no_space_on_device,             // ENOSPC
            value_too_large,                // EOVERFLOW
            unknown
        };
        BOOST_DESCRIBE_ENUM(filesystem_error_code, none, file_exists, file_too_large, filename_too_long,
                            directory_not_empty, cross_device_link, invalid_argument, is_a_directory,
                            not_a_directory, no_such_file_or_directory, permission_denied,
                            read_only_file_system, too_many_files_open, too_many_files_open_in_system,
                            too_many_links, too_many_symbolic_link_levels, text_file_busy, io_error,
                            no_space_on_device, value_too_large, unknown)

        class filesystem_error
        {
        public:
            filesystem_error(std::error_code& errc, std::string_view errm);
            bool error();
            std::string_view error_message();
            filesystem_error_code error_code();

        private:
            const std::string _error_message;
            const filesystem_error_code _error_code;
        };

        class filesystem_helpers
        {
        public:
            static std::expected<bool, filesystem_error> exists(const std::filesystem::path where);
            static std::expected<bool, filesystem_error> create_directory(const std::filesystem::path where);
            static std::expected<bool, filesystem_error> check_or_create_directory(const std::filesystem::path where);
            static std::expected<std::vector<char>, filesystem_error> read_file(const std::filesystem::path file_path);
            static std::expected<bool, filesystem_error> write_file(const std::filesystem::path file_path, const std::vector<char>& data, std::ios::openmode mode = std::ios::out | std::ios::trunc | std::ios::binary);
            static std::expected<std::vector<std::filesystem::path>, filesystem_error> get_files(const std::filesystem::path where);
            static std::expected<bool, filesystem_error> remove_file(const std::filesystem::path file_path, bool ignore_non_empty = false);
            static std::expected<bool, filesystem_error> rename_file(const std::filesystem::path from_file, const std::filesystem::path to_file);
            static std::expected<bool, filesystem_error> test_folder(const std::filesystem::path where);
        };
    }
}