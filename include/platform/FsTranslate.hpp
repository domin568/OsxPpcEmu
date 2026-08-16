/**
 * Author:    domin568
 * Created:   03.08.2026
 * Brief:     Guest (Darwin/Mac OS X 10.4) case insensitive FS <-> host FS translation layer
 **/

#pragma once
#include <filesystem>
#include <optional>
#include <string>

namespace fs = std::filesystem;
namespace fs_translate
{
fs::path translate_path( fs::path path );
std::optional<std::string> msys_to_host_path( const std::string &p );
std::optional<std::string> host_to_msys_path( const std::string &p );

// regex convert windows paths inside string to msys
std::string host_path_list_to_msys( const std::string &value );

bool is_filesystem_case_sensitive();
} // namespace fs_translate