/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Common types
 **/
#include <exception> // LIEF fix
#pragma once
#include "CMemory.hpp"
#include <LIEF/MachO.hpp>
#include <bit>
#include <optional>
#include <span>
#include <string>
#include <unicorn/unicorn.h>

class CMachoLoader;

namespace common
{

inline constexpr uint32_t Import_Dispatch_Table_Address{ 0xF0'00'00'00 };

enum class ImportType
{
    Direct,
    Indirect,
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

uint64_t page_align_down( uint64_t a );
uint64_t page_align_up( uint64_t a );

std::optional<std::string> read_string_at_va( uc_engine *uc, uint32_t va );
std::optional<uint32_t> get_import_entry_va_by_name( const std::string &name );
std::size_t count_format_specifiers( std::string_view format_spec );
std::vector<void *> get_format_arguments( memory::CMemory *mem, void *argsPtr, std::string_view format );
std::vector<uint64_t> get_sprintf_arguments( uc_engine *uc, memory::CMemory *mem, const char *format );
FILE *resolve_file_stream( std::uint32_t guestStream );

} // namespace common
