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
static constexpr uint64_t Guest_Virtual_Memory_Size{ 0x1'00'00'00'00 }; // 32 bit virtual address space size
static constexpr uint32_t Stack_Max_Address{ 0xC0'00'00'00 };
static constexpr uint32_t Stack_Size{ 2u * 0x1000 * 0x1000 }; // 2MB
static constexpr uint32_t Stack_Region_Start_Address{ Stack_Max_Address - Stack_Size };
static constexpr uint32_t Stack_Dyld_Region_Size{ 0x1000'0 };
static constexpr uint32_t Stack_Dyld_Region_Start_Address{ Stack_Max_Address -
                                                           Stack_Dyld_Region_Size }; // it is also initial stack address
static constexpr std::size_t Default_Page_Size{ 0x1000 };
static constexpr std::size_t Heap_Start{ 0x10'00'00'00 };
static constexpr std::size_t Heap_Size{ 0x10'00'00'00 };

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
