/**
 * Author:    domin568
 * Created:   03.08.2026
 * Brief:     Guest (Darwin/Mac OS X 10.4) case insensitive FS <-> host FS translation layer
 **/

#include "platform/FsTranslate.hpp"
#include <algorithm>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;
namespace fs_translate
{

#ifdef _WIN32
namespace
{
// "/c/a/b" (or "/c") -> "C:\a\b". Returns nullopt when the path is not in MSYS drive form.
std::optional<fs::path> from_guest_drive_form( const std::string &p )
{
    if (p.size() < 2 || p[0] != '/' || !std::isalpha( static_cast<unsigned char>( p[1] ) ))
        return std::nullopt;
    if (p.size() > 2 && p[2] != '/')
        return std::nullopt;

    std::string host{ std::string{ p[1] } + ":\\" };
    if (p.size() > 3)
        host += p.substr( 3 );
    std::ranges::replace( host, '/', '\\' );
    return fs::path{ host };
}
} // namespace
#endif

fs::path translate_path( fs::path path )
{
    /*
#ifdef _WIN32
    // Undo to_guest_path(): the guest hands back the POSIX spelling we gave it.
    if (const auto host{ from_guest_drive_form( path.generic_string() ) })
        path = *host;
#endif
    */
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