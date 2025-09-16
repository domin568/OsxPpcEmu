/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Common types
 **/
#pragma once
#include <bit>
#include <expected>
#include <string>

namespace common
{

struct Error
{
    enum Type
    {
        Argument_Parsing_Error,
        NotFound,
        Unsupported,
        Unicorn_Open_Error,
        Memory_Map_Error,
        No_Unix_Thread_Command_Error,
        Stack_Map_Error,
        Redirect_Api_Error,
        Missing_Dynamic_Bind_Command_Error,
        Indirect_Symbols_Error,
        Bad_Dyld_Section_Error
    };
    Type type;
    std::string message{};
};

template <std::integral T> constexpr T ensure_endianness( T v, std::endian data_order )
{
    if (data_order == std::endian::native)
        return v;
    else
        return std::byteswap( v );
}

template <std::integral T> constexpr T align_up( T v, size_t alignment )
{
    return ( v + alignment - 1 ) & ~( alignment - 1 );
}

static inline uint64_t page_align_down( uint64_t a )
{
    uint64_t ps = 0x1000;
    return a & ~( ps - 1 );
}

static inline uint64_t page_align_up( uint64_t a )
{
    uint64_t ps = 0x1000;
    return ( a + ps - 1 ) & ~( ps - 1 );
}

} // namespace common
