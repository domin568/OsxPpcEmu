/**
 * Author:    domin568
 * Created:   22.09.2025
 * Brief:     Common types
 **/

#include "../include/Common.hpp"
#include "../include/hook/ImportDispatch.hpp"
#include "../include/loader/CMachoLoader.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <format>
#include <numeric>

namespace common
{
uint64_t page_align_down( uint64_t a )
{
    uint64_t ps = 0x1000;
    return a & ~( ps - 1 );
}

uint64_t page_align_up( uint64_t a )
{
    uint64_t ps = 0x1000;
    return ( a + ps - 1 ) & ~( ps - 1 );
}

std::string_view heap_mode_name( HeapMode mode )
{
    switch (mode)
    {
    case HeapMode::Bump:
        return "bump";
    case HeapMode::Quarantine:
        return "quarantine";
    case HeapMode::Real:
        return "real";
    }
    return "?";
}

std::optional<HeapMode> heap_mode_from_string( std::string_view name )
{
    std::string lower{ name };
    std::ranges::transform( lower, lower.begin(),
                            []( unsigned char c ) { return static_cast<char>( std::tolower( c ) ); } );
    if (lower == "bump")
        return HeapMode::Bump;
    if (lower == "quarantine")
        return HeapMode::Quarantine;
    if (lower == "real")
        return HeapMode::Real;
    return std::nullopt;
}

std::string human_readable_bytes( std::uint64_t bytes )
{
    static constexpr std::array<const char *, 5> Units{ "B", "KB", "MB", "GB", "TB" };
    std::size_t unit{ 0 };
    std::uint64_t divisor{ 1 };
    while (bytes / divisor >= 1024 && unit + 1 < Units.size())
    {
        divisor *= 1024;
        ++unit;
    }
    if (unit == 0)
        return std::format( "{} {}", bytes, Units[unit] );

    const std::uint64_t whole{ bytes / divisor };
    const std::uint64_t remainder{ bytes % divisor };
    const std::uint64_t hundredths{ ( remainder * 100 ) / divisor };
    return std::format( "{}.{:02} {}", whole, hundredths, Units[unit] );
}

std::optional<std::string> read_string_at_va( uc_engine *uc, uint32_t va )
{
    static constexpr size_t Max_String_Size{ 0x1000 };

    uc_mem_region *regions;
    uint32_t count{};
    if (uc_mem_regions( uc, &regions, &count ) != UC_ERR_OK)
        return {};
    std::optional<uint32_t> endVa{ std::nullopt };
    for (uint32_t i = 0; i < count; i++)
    {
        if (va >= regions[i].begin && va <= regions[i].end)
        {
            endVa = regions[i].end;
            break;
        }
    }
    if (!endVa)
        return {};

    const size_t leftBytesInRegion{ *endVa - va };
    const size_t toRead{ std::min<size_t>( Max_String_Size, leftBytesInRegion ) };
    std::string name{};
    name.resize( toRead );
    if (uc_mem_read( uc, va, name.data(), name.size() ) != UC_ERR_OK)
        return {};
    name.resize( strnlen( name.c_str(), name.size() ) );
    return name;
}

std::optional<uint32_t> get_import_entry_va_by_name( const std::string &name )
{
    const std::optional<std::size_t> idx{ import::find_known_import( name ) };
    if (!idx)
        return std::nullopt;
    return import::import_entry_address( *idx );
}

std::size_t count_format_specifiers( std::string_view format )
{
    std::size_t count{ 0 };
    for (std::size_t p{ format.find( '%' ) }; p != std::string_view::npos; p = format.find( '%', p + 1 ))
    {
        if (p + 1 < format.size())
        {
            if (format[p + 1] == '%')
            {
                ++p;
                continue;
            }
            count++;

            // Check for * (dynamic width/precision) which consume additional arguments
            std::size_t i = p + 1;
            while (i < format.size())
            {
                char c = format[i];

                if (c == '*')
                {
                    count++;
                    i++;
                    continue;
                }

                if (c == '-' || c == '+' || c == ' ' || c == '#' || c == '0' || ( c >= '1' && c <= '9' ) || c == '.')
                {
                    i++;
                    continue;
                }

                // Skip length modifiers
                if (c == 'h' || c == 'l' || c == 'L' || c == 'j' || c == 'z' || c == 't')
                {
                    i++;
                    continue;
                }
                break;
            }
        }
    }
    return count;
};

static inline bool is_pointer_specifier( char spec )
{
    return spec == 's' || spec == 'p' || spec == 'n';
}

template <typename Func> static void process_format_arguments( std::string_view format, Func &&c )
{
    std::size_t argIdx = 0;

    for (std::size_t i = 0; i < format.size(); i++)
    {
        if (format[i] == '%')
        {
            if (i + 1 < format.size() && format[i + 1] == '%')
            {
                i++; // Skip %%
                continue;
            }

            // Find the conversion specifier
            i++;
            while (i < format.size())
            {
                char ch = format[i];

                // Handle dynamic width/precision (*)
                if (ch == '*')
                {
                    c( argIdx, 'd' ); // * consumes an integer argument
                    argIdx++;
                    i++;
                    continue;
                }

                // Skip flags, width digits, and other modifiers
                if (::strchr( "-+ #0123456789.hlLjzt", ch ))
                {
                    i++;
                    continue;
                }

                break;
            }

            if (i >= format.size())
                break;

            char spec = format[i];
            c( argIdx, spec );
            argIdx++;
        }
    }
}

// TODO: This function misses getting arguments from stack
std::vector<std::uint64_t> get_va_arguments( memory::CMemory *mem, void *argsPtr, std::string_view format )
{
    std::vector<std::uint64_t> args{};
    const std::span<const uint32_t> argsGuest{ reinterpret_cast<uint32_t *>( argsPtr ), 256 }; // Large enough buffer

    process_format_arguments( format, [&]( std::size_t argIdx, char spec ) {
        const uint32_t guestVa{ ensure_endianness( argsGuest[argIdx], std::endian::big ) };

        if (is_pointer_specifier( spec ))
        {
            args.push_back( reinterpret_cast<std::uint64_t>( mem->get( guestVa ) ) );
        }
        else
        {
            args.push_back( guestVa );
        }
    } );
    return args;
}

// TODO: This function misses getting arguments from stack
std::vector<std::uint64_t> get_ellipsis_arguments( uc_engine *uc, memory::CMemory *mem, std::string_view format,
                                                   const int regIdx, bool scan )
{
    std::vector<uint64_t> formatArgs;
    process_format_arguments( format, [&]( std::size_t argIdx, char spec ) {
        if (regIdx + static_cast<int>( argIdx ) > UC_PPC_REG_10)
            return;

        uint32_t guestArg{ 0 };
        if (uc_reg_read( uc, regIdx + static_cast<int>( argIdx ), &guestArg ) != UC_ERR_OK)
        {
            std::cerr << "Error while reading reg in get_ellipsis_arguments" << std::endl;
            return;
        }

        if (is_pointer_specifier( spec ) || scan)
        {
            void *hostPtr{ mem->get( guestArg ) };
            formatArgs.push_back( reinterpret_cast<uint64_t>( hostPtr ) );
        }
        else
        {
            formatArgs.push_back( static_cast<uint64_t>( guestArg ) );
        }
    } );
    return formatArgs;
}

FILE *resolve_file_stream( std::uint32_t guestStream )
{
    const std::optional<std::size_t> sfIdx{ import::find_known_import( "___sF" ) };
    if (!sfIdx)
        return nullptr;
    const std::uint32_t sfAddr{ import::import_entry_address( *sfIdx ) };

    const std::ptrdiff_t inSfOffset{ guestStream - static_cast<std::ptrdiff_t>( sfAddr ) };
    static const std::ptrdiff_t fileObjSize{ 0x58 };

    if (inSfOffset == 0)
        return stdin;
    else if (inSfOffset == fileObjSize)
        return stdout;
    else if (inSfOffset == fileObjSize * 2)
        return stderr;

    return nullptr;
}

} // namespace common
