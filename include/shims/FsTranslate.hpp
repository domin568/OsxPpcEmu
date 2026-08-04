/**
 * Author:    domin568
 * Created:   03.08.2026
 * Brief:     Guest (Darwin/Mac OS X 10.4) case insensitive FS <-> host FS translation layer
 **/

#pragma once
#include <filesystem>

namespace fs = std::filesystem;
namespace fs_translate
{
fs::path translate_path( fs::path path );

inline static const bool is_filesystem_case_sensitive{ []() -> bool {
    const fs::path temp_file{ fs::temp_directory_path() / "case_test" };
    const fs::path temp_file_upper{ fs::temp_directory_path() / "CASE_TEST" };
    fs::remove( temp_file );
    fs::remove( temp_file_upper );
    fs::create_directory( temp_file );
    const bool case_sensitive = !fs::exists( temp_file_upper );
    fs::remove( temp_file );
    return case_sensitive;
}() };
} // namespace fs_translate