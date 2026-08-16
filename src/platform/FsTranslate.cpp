/**
 * Author:    domin568
 * Created:   03.08.2026
 * Brief:     Guest (Darwin/Mac OS X 10.4) case insensitive FS <-> host FS translation layer
 **/

#include "platform/FsTranslate.hpp"
#include <algorithm>
#include <atomic>
#include <filesystem>
#include <iostream>
#include <regex>
#include <string>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace fs_translate
{

namespace
{

long current_pid()
{
#ifdef _WIN32
    return static_cast<long>( ::_getpid() );
#else
    return static_cast<long>( ::getpid() );
#endif
}

bool probe_filesystem_case_sensitivity()
{
    std::error_code ec{};
    const fs::path tempDir{ fs::temp_directory_path( ec ) };
    if (ec || tempDir.empty())
        return false; // no usable temp dir (e.g. no TMP/TEMP on Windows) - assume insensitive

    static std::atomic<unsigned long> counter{ 0 };
    const std::string unique{ std::to_string( current_pid() ) + "_" + std::to_string( ++counter ) };

    const fs::path lower{ tempDir / ( "osxppcemu_case_probe_" + unique ) };
    const fs::path upper{ tempDir / ( "OSXPPCEMU_CASE_PROBE_" + unique ) };

    fs::remove_all( lower, ec );
    fs::remove_all( upper, ec );

    if (!fs::create_directory( lower, ec ) || ec)
        return false; // could not probe - assume insensitive

    const bool caseSensitive{ !fs::exists( upper, ec ) };

    fs::remove_all( lower, ec );
    return caseSensitive;
}

} // namespace

bool is_filesystem_case_sensitive()
{
    // Function-local static: initialised on first use and thread-safe per [stmt.dcl]/4.
    static const bool caseSensitive{ probe_filesystem_case_sensitivity() };
    return caseSensitive;
}

#ifdef _WIN32

// "/c/a/b" (or "/c") -> "C:\a\b". Returns nullopt when the path is not in MSYS drive form.
std::optional<std::string> msys_to_host_path( const std::string &p )
{
    if (p.size() < 2 || p[0] != '/' || !std::isalpha( static_cast<unsigned char>( p[1] ) ))
        return std::nullopt;
    if (p.size() > 2 && p[2] != '/')
        return std::nullopt;

    std::string host{ std::string{ p[1] } + ":\\" };
    if (p.size() > 3)
        host += p.substr( 3 );
    std::ranges::replace( host, '/', '\\' );
    return host;
}

std::optional<std::string> host_to_msys_path( const std::string &p )
{
    if (p.size() < 3 || !std::isalpha( static_cast<unsigned char>( p[0] ) ) || p[1] != ':' || p[2] != '\\')
        return std::nullopt;

    std::string msys{ "/" + std::string{ static_cast<char>( std::tolower( static_cast<unsigned char>( p[0] ) ) ) } };
    if (p.size() > 3)
        msys += p.substr( 2 );
    std::ranges::replace( msys, '\\', '/' );
    return msys;
}

std::string host_path_list_to_msys( const std::string &value )
{
    static const std::regex driveRe{ R"([A-Za-z]:(?:\\[^:;]*)?)" };
    std::string result{};
    result.reserve( value.size() );
    std::size_t last{ 0 };
    for (auto it{ std::sregex_iterator( value.begin(), value.end(), driveRe ) }; it != std::sregex_iterator(); ++it)
    {
        const auto &m{ *it };
        result.append( value, last, static_cast<std::size_t>( m.position() ) - last );
        if (const auto msys{ host_to_msys_path( m.str() ) })
            result += *msys;
        else
            result += m.str();
        last = static_cast<std::size_t>( m.position() ) + static_cast<std::size_t>( m.length() );
    }
    result.append( value, last, std::string::npos );
    return result;
}
#endif

fs::path translate_path( fs::path path )
{
#ifdef _WIN32
    if (const auto host{ msys_to_host_path( path.generic_string() ) })
        path = *host;
#endif
    std::error_code ec{};
    if (fs::exists( path, ec ) || !is_filesystem_case_sensitive())
        return path;

    const fs::path original{ path };
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
        if (fs::exists( check, ec ))
        {
            result = check;
            continue;
        }

        bool found{ false };
        for (fs::directory_iterator it{ result, ec }, end{}; !ec && it != end; it.increment( ec ))
        {
            const bool case_insensitive_match{
                std::ranges::equal( it->path().filename().string(), part.string(), lower_pred ) };
            if (case_insensitive_match)
            {
                result /= it->path().filename();
                found = true;
                break;
            }
        }
        if (!found)
            return original; // if not found then return original path
    }
    return result;
}
} // namespace fs_translate