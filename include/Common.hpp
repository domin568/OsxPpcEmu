/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Common types
 **/
#include <exception> // LIEF fix
#pragma once
#include <LIEF/MachO.hpp>
#include <bit>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unicorn/unicorn.h>

class CMachoLoader;

// Forward declarations to avoid circular dependencies
namespace memory
{
class CMemory;
}

namespace common
{

inline constexpr uint32_t Import_Dispatch_Table_Address{ 0xF0'00'00'00 };
inline constexpr uint32_t Inner_Emulation_Sentinel{ Import_Dispatch_Table_Address };
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

static constexpr std::size_t Heap_Alignment{ 16 };
static constexpr std::size_t Heap_Header_Size{ 16 };
static constexpr std::size_t Heap_Min_Chunk_Size{ 32 };
static constexpr std::size_t Heap_Small_Bin_Count{ 31 }; // exact chunk sizes 32..512, step 16
static constexpr std::size_t Heap_Small_Bin_Max_Size{ 512 };
static constexpr std::size_t Heap_Large_Bin_Scan_Cap{ 64 };
static constexpr std::size_t Heap_Initial_Commit{ 1u << 20 };     // 1 MiB
static constexpr std::size_t Heap_Commit_Granularity{ 1u << 20 }; // 1 MiB
static constexpr std::size_t Heap_Quarantine_Bytes{ 4u << 20 };   // 4 MiB
static_assert( Heap_Start % Heap_Alignment == 0 );
static_assert( Heap_Small_Bin_Count == ( Heap_Small_Bin_Max_Size / Heap_Alignment ) - 1 );

// Selectable free() policy for CHeap:
//  - Bump:       free() retires the chunk permanently (poisoned, never coalesced, never
//                reused). Address space is only ever consumed. This is the pre-real-heap
//                behaviour and exists as a bisection tool: if a sample regresses under a real
//                allocator, run it in Bump to prove whether reuse is the cause.
//  - Quarantine: free() poisons and holds the chunk in a FIFO for Heap_Quarantine_Bytes before
//                allowing reuse. Maximises the chance of catching a use-after-free. Default.
//  - Real:       free() coalesces and returns the chunk to the free bins immediately, like a
//                normal allocator. Highest fidelity to real malloc, no quarantine overhead, no
//                UAF poison.
enum class HeapMode
{
    Bump,
    Quarantine,
    Real,
};

inline constexpr HeapMode Heap_Default_Mode{ HeapMode::Quarantine };

std::string_view heap_mode_name( HeapMode mode );
std::optional<HeapMode> heap_mode_from_string( std::string_view name );

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

// Formats a byte count as a human-readable string, e.g. 3871136 -> "3.69 MB".
// Uses binary (1024-based) units: B, KB, MB, GB, TB.
std::string human_readable_bytes( std::uint64_t bytes );

std::optional<std::string> read_string_at_va( uc_engine *uc, uint32_t va );
std::optional<uint32_t> get_import_entry_va_by_name( const std::string &name );
std::size_t count_format_specifiers( std::string_view format_spec );
std::vector<std::uint64_t> get_va_arguments( memory::CMemory *mem, void *argsPtr, std::string_view format );
std::vector<std::uint64_t> get_ellipsis_arguments( uc_engine *uc, memory::CMemory *mem, std::string_view format,
                                                   const int regIdx, bool scan );
FILE *resolve_file_stream( std::uint32_t guestStream );

} // namespace common
