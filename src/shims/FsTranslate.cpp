/**
 * Author:    domin568
 * Created:   03.08.2026
 * Brief:     Guest (Darwin/Mac OS X 10.4) case insensitive FS <-> host FS translation layer
 **/

#include "shims/FsTranslate.hpp"
#include <algorithm>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;
namespace fs_translate
{

fs::path translate_path( fs::path path )
{
    if (fs::exists( path ) || !is_filesystem_case_sensitive)
        return path;

    if (path.is_relative())
    {
        path = fs::path( "." ) / path;
    }
    // scan for case-insensitive file on case-sensitive FS
    auto lower_pred{ []( char a, char b ) { return std::tolower( a ) == std::tolower( b ); } };
    fs::path result{};
    for (const auto &part : path)
    {
        fs::path check{ result / part };
        if (fs::exists( check ))
        {
            result = check;
            continue;
        }

        bool found{ false };
        for (const auto &entry : fs::directory_iterator( result ))
        {
            const bool case_insensitive_match{
                std::ranges::equal( entry.path().filename().string(), part.string(), lower_pred ) };
            if (case_insensitive_match)
            {
                result /= entry;
                found = true;
                break;
            }
        }
        if (!found)
            return path; // if not found then return original path
    }
    return result;
}
} // namespace fs_translate