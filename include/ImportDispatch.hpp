/**
 * Author:    domin568
 * Created:   15.09.2025
 * Brief:     redirected API implementations
 **/
#pragma once

#include "CMachoLoader.hpp"
#include "Common.hpp"
#include <algorithm>
#include <iostream>
#include <unicorn/unicorn.h>

namespace import
{

namespace callback
{
using CallbackPtr = bool ( * )( uc_engine *, memory::CMemory *mem, loader::CMachoLoader * );
#define callback( name ) bool name( uc_engine *, memory::CMemory *, loader::CMachoLoader * )
callback( clock );
callback( setlocale );
callback( snprintf );
callback( strncat );
callback( keymgr_dwarf2_register_sections );
callback( cthread_init_routine );
callback( dyld_make_delayed_module_initializer_calls );
callback( dyld_func_lookup );
callback( atexit );
callback( bsearch );
callback( chmod );
callback( exit );
callback( fclose );
callback( fwrite );
callback( fflush );
callback( fgetc );
callback( fopen );
callback( fstat );
callback( ioctl );
callback( mach_init_routine );
callback( malloc );
callback( calloc );
callback( memcpy );
callback( memmove );
callback( memset );
callback( printf );
callback( puts );
callback( qsort );
callback( setvbuf );
callback( signal );
callback( sprintf );
callback( vsprintf );
callback( stat );
callback( strcat );
callback( strchr );
callback( strcpy );
callback( strlen );
callback( strpbrk );
callback( strrchr );
callback( strncpy );
callback( dyld_stub_binding_helper );
callback( vsnprintf );
callback( getcwd );
callback( free );
callback( strcmp );
callback( strncmp );
callback( fprintf );
callback( getenv );
callback( ___error );
callback( ___tolower );
callback( ___toupper );
callback( _setjmp );
callback( _longjmp );
callback( realloc );
callback( readlink );
callback( lseek );
callback( open );
callback( close );
callback( read );
callback( write );
callback( memcmp );
callback( time );
callback( times );
callback( getdtablesize );
callback( localtime );
callback( umask );
callback( gethostbyname );
callback( gethostname );
callback( sscanf );
callback( ungetc );
callback( mktime );

template <std::size_t I, template <typename> class Pred, typename... Ts> struct count_before;
template <std::size_t I, template <typename> class Pred> struct count_before<I, Pred>
{
    static constexpr std::size_t value = 0;
};
template <std::size_t I, template <typename> class Pred, typename First, typename... Rest>
struct count_before<I, Pred, First, Rest...>
{
    static constexpr std::size_t value =
        I == 0 ? 0 : ( ( Pred<First>::value ? 1u : 0u ) + count_before<I - 1, Pred, Rest...>::value );
};

template <typename T> using IsGprArg = std::bool_constant<std::is_integral_v<T> || std::is_pointer_v<T>>;
template <typename T> using IsFprArg = std::bool_constant<std::is_floating_point_v<T>>;

template <typename T> std::optional<T> read_argument( uc_engine *uc, memory::CMemory *mem, const uc_ppc_reg regId )
{
    uint64_t reg{};
    if (uc_reg_read( uc, regId, &reg ) != UC_ERR_OK)
    {
        std::cerr << "Could not read argument" << std::endl;
        return {};
    }
    if constexpr (std::is_integral_v<T>)
        return static_cast<T>( reg );
    else if constexpr (std::is_pointer_v<T>)
        return reinterpret_cast<T>( mem->get( reg ) );
    else if constexpr (std::is_same_v<T, double>)
        return std::bit_cast<double>( reg );
    else if constexpr (std::is_same_v<T, float>)
        return std::bit_cast<float>( static_cast<uint32_t>( reg ) );
    return {};
}

template <typename... Args, std::size_t... I>
std::optional<std::tuple<Args...>> read_arguments_idx( uc_engine *uc, memory::CMemory *mem, std::index_sequence<I...> )
{
    auto opts{ std::make_tuple( ( [uc, mem]<std::size_t idx, typename T>() -> std::optional<T> {
        if constexpr (IsGprArg<T>::value)
        {
            constexpr std::size_t offset{ count_before<idx, IsGprArg, Args...>::value };
            constexpr uc_ppc_reg base{ UC_PPC_REG_3 };
            return read_argument<T>( uc, mem, static_cast<uc_ppc_reg>( base + offset ) );
        }
        else if constexpr (IsFprArg<T>::value)
        {
            constexpr std::size_t offset{ count_before<idx, IsFprArg, Args...>::value };
            constexpr uc_ppc_reg base{ UC_PPC_REG_FPR1 };
            return read_argument<T>( uc, mem, static_cast<uc_ppc_reg>( base + offset ) );
        }
        return std::optional<T>{};
    }.template operator()<I, std::tuple_element_t<I, std::tuple<Args...>>>() )... ) };

    const bool ok{ ( ... && static_cast<bool>( std::get<I>( opts ) ) ) };
    if (!ok)
        return {};
    return std::make_optional( std::make_tuple( ( *std::get<I>( opts ) )... ) );
}

template <typename... Args> std::optional<std::tuple<Args...>> get_arguments( uc_engine *uc, memory::CMemory *mem )
{
    return read_arguments_idx<Args...>( uc, mem, std::index_sequence_for<Args...>{} );
}

// Helper function to set errno in guest memory
inline void set_guest_errno( memory::CMemory *mem, int errnoValue )
{
    std::optional<uint32_t> errnoVa{ common::get_import_entry_va_by_name( "_errno" ) };
    if (errnoVa.has_value())
    {
        uint32_t guestErrno = common::ensure_endianness( static_cast<uint32_t>( errnoValue ), std::endian::big );
        void *errnoPtr = mem->get( *errnoVa );
        if (errnoPtr)
        {
            ::memcpy( errnoPtr, &guestErrno, sizeof( guestErrno ) );
        }
    }
}

} // namespace callback

namespace data
{
inline constexpr std::array<uint8_t, 4> Blr_Opcode{ 0x4E, 0x80, 0x00, 0x20 };
inline constexpr std::array<uint8_t, 4> Dword_Mem{ 0x00, 0x00, 0x00, 0x00 };
inline constexpr std::array<uint8_t, 4> Trap_Opcode{ 0x7F, 0xE0, 0x00, 0x08 };
// inline constexpr std::array<uint8_t, 3 * sizeof( FILE )> Stdio_File_Std_Descriptors{};
} // namespace data

struct Known_Import_Entry
{
    std::span<const uint8_t> data{}; // code for functions, memory for variables
    callback::CallbackPtr hook{};
};

struct Runtime_Import_Table_Entry // import redirection entry starting at 0xF0 00 00 00
{
    uint32_t ptrToData{};            // points to
    std::span<const uint8_t> data{}; // <- here, in runtime
};

struct Import_Info
{
    std::string name{};
    uint32_t importVa{};
    common::ImportType type{};
};

// BEWARE! items must be sorted in Known_Import_Names and Import_Items
// static imports
inline constexpr size_t Unknown_Import_Index{ 0 };
inline constexpr size_t Unknown_Import_Shift{ 1 };
inline constexpr auto Known_Import_Names{ std::to_array<std::string_view>( {
    "__DefaultRuneLocale",
    "___error",
    "___keymgr_dwarf2_register_sections",
    "___sF",
    "___tolower",
    "___toupper",
    "__cthread_init_routine",
    "__dyld_make_delayed_module_initializer_calls",
    "_atexit",
    "_bsearch",
    "_calloc",
    "_chmod",
    "_clock",
    "_close",
    "_dyld_func_lookup_ptr_in_dyld",
    "_errno",
    "_exit",
    "_fclose",
    "_fflush",
    "_fgetc",
    "_fopen",
    "_fprintf",
    "_free",
    "_fstat",
    "_fwrite",
    "_getcwd",
    "_getdtablesize",
    "_getenv",
    "_gethostbyname",
    "_gethostname",
    "_ioctl",
    "_localtime",
    "_longjmp",
    "_lseek",
    "_mach_init_routine",
    "_malloc",
    "_memcmp",
    "_memcpy",
    "_memmove",
    "_memset",
    "_mktime",
    "_open",
    "_printf",
    "_puts",
    "_qsort",
    "_read",
    "_readlink",
    "_realloc",
    "_setjmp",
    "_setlocale",
    "_setvbuf",
    "_signal",
    "_snprintf",
    "_sprintf",
    "_sscanf",
    "_stat",
    "_strcat",
    "_strchr",
    "_strcmp",
    "_strcpy",
    "_strlen",
    "_strncat",
    "_strncmp",
    "_strncpy",
    "_strpbrk",
    "_strrchr",
    "_stub_binding_helper_ptr_in_dyld",
    "_time",
    "_times",
    "_umask",
    "_ungetc",
    "_vsnprintf",
    "_vsprintf",
    "_write",
} ) };
static_assert( std::ranges::is_sorted( ( Known_Import_Names ) ) );

inline constexpr std::array<Known_Import_Entry, Known_Import_Names.size()> Import_Items{ {
    { data::Dword_Mem, nullptr },                                    // __DefaultRuneLocale
    { data::Blr_Opcode, callback::___error },                        // ___error
    { data::Blr_Opcode, callback::keymgr_dwarf2_register_sections }, // ___keymgr_dwarf2_register_sections
    { data::Blr_Opcode, callback::___tolower },                      // ___tolower
    { data::Blr_Opcode, callback::___toupper },                      // ___toupper
    { data::Dword_Mem, nullptr },                                    // ___sF
    { data::Blr_Opcode, callback::cthread_init_routine },            // __cthread_init_routine
    { data::Blr_Opcode,
      callback::dyld_make_delayed_module_initializer_calls }, // __dyld_make_delayed_module_initializer_calls
    { data::Blr_Opcode, callback::atexit },                   // _atexit
    { data::Blr_Opcode, callback::bsearch },                  // _bsearch
    { data::Blr_Opcode, callback::calloc },                   // _calloc
    { data::Blr_Opcode, callback::chmod },                    // _chmod
    { data::Blr_Opcode, callback::clock },                    // _clock
    { data::Blr_Opcode, callback::close },                    // _close
    { data::Blr_Opcode, callback::dyld_func_lookup },         // _dyld_func_lookup_ptr_in_dyld
    { data::Dword_Mem, nullptr },                             // _errno
    { data::Trap_Opcode, callback::exit },                    // _exit
    { data::Blr_Opcode, callback::fclose },                   // _fclose
    { data::Blr_Opcode, callback::fflush },                   // _fflush
    { data::Blr_Opcode, callback::fgetc },                    // _fgetc
    { data::Blr_Opcode, callback::fopen },                    // _fopen
    { data::Blr_Opcode, callback::fprintf },                  // _fprintf
    { data::Blr_Opcode, callback::free },                     // _free
    { data::Blr_Opcode, callback::fstat },                    // _fstat
    { data::Blr_Opcode, callback::fwrite },                   // _fwrite
    { data::Blr_Opcode, callback::getcwd },                   // _getcwd
    { data::Blr_Opcode, callback::getdtablesize },            // _getdtablesize
    { data::Blr_Opcode, callback::getenv },                   // _getenv
    { data::Blr_Opcode, callback::gethostbyname },            // _gethostbyname
    { data::Blr_Opcode, callback::gethostname },              // _gethostname
    { data::Blr_Opcode, callback::ioctl },                    // _ioctl
    { data::Blr_Opcode, callback::localtime },                // _localtime
    { data::Blr_Opcode, callback::_longjmp },                 // _longjmp
    { data::Blr_Opcode, callback::lseek },                    // _lseek
    { data::Blr_Opcode, callback::mach_init_routine },        // _mach_init_routine
    { data::Blr_Opcode, callback::malloc },                   // _malloc
    { data::Blr_Opcode, callback::memcmp },                   // _memcmp
    { data::Blr_Opcode, callback::memcpy },                   // _memcpy
    { data::Blr_Opcode, callback::memmove },                  // _memmove
    { data::Blr_Opcode, callback::memset },                   // _memset
    { data::Blr_Opcode, callback::mktime },                   // _mktime
    { data::Blr_Opcode, callback::open },                     // _open
    { data::Blr_Opcode, callback::printf },                   // _printf
    { data::Blr_Opcode, callback::puts },                     // _puts
    { data::Blr_Opcode, callback::qsort },                    // _qsort
    { data::Blr_Opcode, callback::read },                     // _read
    { data::Blr_Opcode, callback::readlink },                 // _readlink
    { data::Blr_Opcode, callback::realloc },                  // _realloc
    { data::Blr_Opcode, callback::_setjmp },                  // _setjmp
    { data::Blr_Opcode, callback::setlocale },                // _setlocale
    { data::Blr_Opcode, callback::setvbuf },                  // _setvbuf
    { data::Blr_Opcode, callback::signal },                   // _signal
    { data::Blr_Opcode, callback::snprintf },                 // _snprintf
    { data::Blr_Opcode, callback::sprintf },                  // _sprintf
    { data::Blr_Opcode, callback::sscanf },                   // _sscanf
    { data::Blr_Opcode, callback::stat },                     // _stat
    { data::Blr_Opcode, callback::strcat },                   // _strcat
    { data::Blr_Opcode, callback::strchr },                   // _strchr
    { data::Blr_Opcode, callback::strcmp },                   // _strcmp
    { data::Blr_Opcode, callback::strcpy },                   // _strcpy
    { data::Blr_Opcode, callback::strlen },                   // _strlen
    { data::Blr_Opcode, callback::strncat },                  // _strncat
    { data::Blr_Opcode, callback::strncmp },                  // _strncmp
    { data::Blr_Opcode, callback::strncpy },                  // _strncpy
    { data::Blr_Opcode, callback::strpbrk },                  // _strpbrk
    { data::Blr_Opcode, callback::strrchr },                  // _strrchr
    { data::Blr_Opcode, callback::dyld_stub_binding_helper }, // _stub_binding_helper_ptr_in_dyld
    { data::Blr_Opcode, callback::time },                     // _time
    { data::Blr_Opcode, callback::times },                    // _times
    { data::Blr_Opcode, callback::umask },                    // _umask
    { data::Blr_Opcode, callback::ungetc },                   // _ungetc
    { data::Blr_Opcode, callback::vsnprintf },                // _vsnprintf
    { data::Blr_Opcode, callback::vsprintf },                 // _vsprintf
    { data::Blr_Opcode, callback::write },                    // _write
} };

// Argument counts for each API (-1 for variadic functions)
inline constexpr std::array<int, Known_Import_Names.size()> Import_Arg_Counts{ {
    0,  // __DefaultRuneLocale
    0,  // ___error
    0,  // ___keymgr_dwarf2_register_sections
    0,  // ___sF
    1,  // ___tolower
    1,  // ___toupper
    0,  // __cthread_init_routine
    0,  // __dyld_make_delayed_module_initializer_calls
    1,  // _atexit
    5,  // _bsearch
    2,  // _calloc
    2,  // _chmod
    0,  // _clock
    1,  // _close
    2,  // _dyld_func_lookup_ptr_in_dyld
    0,  // _errno
    1,  // _exit
    1,  // _fclose
    1,  // _fflush
    1,  // _fgetc
    2,  // _fopen
    -1, // _fprintf (variadic)
    1,  // _free
    2,  // _fstat
    4,  // _fwrite
    2,  // _getcwd
    0,  // _getdtablesize
    1,  // _getenv
    1,  // _gethostbyname
    2,  // _gethostname
    -1, // _ioctl (variadic)
    1,  // _localtime
    2,  // _longjmp
    3,  // _lseek
    0,  // _mach_init_routine
    1,  // _malloc
    3,  // _memcmp
    3,  // _memcpy
    3,  // _memmove
    3,  // _memset
    1,  // _mktime
    3,  // _open
    -1, // _printf
    1,  // _puts
    4,  // _qsort
    3,  // _read
    3,  // _readlink
    2,  // _realloc
    1,  // _setjmp
    2,  // _setlocale
    4,  // _setvbuf
    2,  // _signal
    -1, // _snprintf (variadic)
    -1, // _sprintf (variadic)
    -1, // _sscanf (variadic)
    2,  // _stat
    2,  // _strcat
    2,  // _strchr
    2,  // _strcmp
    2,  // _strcpy
    1,  // _strlen
    3,  // _strncat
    3,  // _strncmp
    3,  // _strncpy
    2,  // _strpbrk
    2,  // _strrchr
    0,  // _stub_binding_helper_ptr_in_dyld
    1,  // _time
    1,  // _times
    1,  // _umask
    2,  // _ungetc
    4,  // _vsnprintf
    3,  // _vsprintf
    3,  // _write
} };

inline constexpr std::array<std::pair<std::string_view, import::Known_Import_Entry>, Known_Import_Names.size()>
    Name_To_Import_Item_Flat{ []() {
        std::array<std::pair<std::string_view, import::Known_Import_Entry>, Known_Import_Names.size()> result{};
        for (size_t idx{ 0 }; idx < Known_Import_Names.size(); idx++)
            result[idx] = { Known_Import_Names[idx], Import_Items[idx] };
        return result;
    }() };

// 0xF0000000: 0xF0000004
// 0xF0000004: 0x4E, 0x80, 0x00, 0x20,  blr
// means ImportEntrySizePow2 == 3 ( 1u << 3)
inline constexpr uint32_t Import_Entry_Size{ []() -> uint32_t {
    auto itemDataSize{ []( const Known_Import_Entry &importData ) { return importData.data.size(); } };
    auto maxDataSizeIt{ std::ranges::max_element( Import_Items, std::less<>{}, itemDataSize ) };
    // optimization for shift right later in code as API dispatch code is really hot
    return std::bit_ceil( sizeof( Runtime_Import_Table_Entry::ptrToData ) + maxDataSizeIt->data.size() ); // aligned
}() };
inline constexpr int Import_Entry_Size_Pow2{ []() { return std::countr_zero( Import_Entry_Size ); }() };
inline constexpr size_t Import_Table_Size{ Import_Entry_Size * Import_Items.size() +
                                           Import_Entry_Size }; // additional Import_Entry_Size for unknown imports

// dynamic imports e.g obtained by dyld_func_lookup

inline constexpr size_t Known_Dynamic_Import_Count{ 1 };
inline constexpr std::array<std::string_view, Known_Dynamic_Import_Count> Dynamic_Imports_Names{
    "__dyld_make_delayed_module_initializer_calls",
};

} // namespace import
