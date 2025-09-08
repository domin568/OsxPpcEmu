/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Common types
 **/
#pragma once
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
    };
    Type type;
    std::string message{};
};

} // namespace common
