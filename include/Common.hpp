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
        NotFound,
        Unsupported,
        Unicorn_Open_Error,
        Memory_Map_Error,
        No_Unix_Thread_Command_Error,
    };
    Type type;
    std::string message{};
};

template <typename T> constexpr T to_host( T v, std::endian data_order )
{
    if constexpr (std::is_integral_v<T>)
    {
        if (data_order == std::endian::native)
        {
            return v;
        }
        else
        {
            return std::byteswap( v );
        }
    }
    else
    {
        return v; // non-integral types: do nothing
    }
}

} // namespace common
