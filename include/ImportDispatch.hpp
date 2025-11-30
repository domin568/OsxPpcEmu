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
using CallbackPtr = bool ( * )( uc_engine *, memory::CMemory *mem );
#define callback( name ) bool name( uc_engine *, memory::CMemory * )
callback( keymgr_dwarf2_register_sections );
callback( cthread_init_routine );
callback( dyld_make_delayed_module_initializer_calls );
callback( dyld_func_lookup );
callback( atexit );
callback( exit );
callback( fwrite );
callback( fstat );
callback( ioctl );
callback( mach_init_routine );
callback( memcpy );
callback( memmove );
callback( memset );
callback( puts );
callback( setvbuf );
callback( signal );
callback( stat );
callback( strcat );
callback( strchr );
callback( strcpy );
callback( strlen );
callback( strrchr );
callback( strncpy );
callback( dyld_stub_binding_helper );
callback( vsnprintf );

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
    auto opts {
        std::make_tuple( ( [uc, mem]<std::size_t idx, typename T>() -> std::optional<T> {
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
        }.template operator()<I, std::tuple_element_t<I, std::tuple<Args...>>>() )... )
    };

    const bool ok{ ( ... && static_cast<bool>( std::get<I>( opts ) ) ) };
    if (!ok)
        return {};
    return std::make_optional( std::make_tuple( ( *std::get<I>( opts ) )... ) );
}

template <typename... Args> std::optional<std::tuple<Args...>> get_arguments( uc_engine *uc, memory::CMemory *mem )
{
    return read_arguments_idx<Args...>( uc, mem, std::index_sequence_for<Args...>{} );
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
    "___keymgr_dwarf2_register_sections",
    "___sF",
    "__cthread_init_routine",
    "__dyld_make_delayed_module_initializer_calls",
    "_atexit",
    "_dyld_func_lookup_ptr_in_dyld",
    "_errno",
    "_exit",
    "_fstat",
    "_fwrite",
    "_ioctl",
    "_mach_init_routine",
    "_memcpy",
    "_memmove",
    "_memset",
    "_puts",
    "_setvbuf",
    "_signal",
    "_stat",
    "_strcat",
    "_strchr",
    "_strcpy",
    "_strlen",
    "_strncpy",
    "_strrchr",
    "_stub_binding_helper_ptr_in_dyld",
    "_vsnprintf",
} ) };
static_assert( std::ranges::is_sorted( ( Known_Import_Names ) ) );

inline constexpr std::array<Known_Import_Entry, Known_Import_Names.size()> Import_Items{ {
    { data::Blr_Opcode, callback::keymgr_dwarf2_register_sections }, // ___keymgr_dwarf2_register_sections
    { data::Dword_Mem, nullptr },                                    // ___sF
    { data::Blr_Opcode, callback::cthread_init_routine },            // __cthread_init_routine
    { data::Blr_Opcode,
      callback::dyld_make_delayed_module_initializer_calls }, // __dyld_make_delayed_module_initializer_calls
    { data::Blr_Opcode, callback::atexit },                   // _atexit
    { data::Blr_Opcode, callback::dyld_func_lookup },         // _dyld_func_lookup_ptr_in_dyld
    { data::Dword_Mem, nullptr },                             // _errno
    { data::Trap_Opcode, callback::exit },                    // _exit
    { data::Blr_Opcode, callback::fstat },                    // _fstat
    { data::Blr_Opcode, callback::fwrite },                   // _fwrite
    { data::Blr_Opcode, callback::ioctl },                    // _ioctl
    { data::Blr_Opcode, callback::mach_init_routine },        // _mach_init_routine
    { data::Blr_Opcode, callback::memcpy },                   // _memcpy
    { data::Blr_Opcode, callback::memmove },                  // _memmove
    { data::Blr_Opcode, callback::memset },                   // _memset
    { data::Blr_Opcode, callback::puts },                     // _puts
    { data::Blr_Opcode, callback::setvbuf },                  // _setvbuf
    { data::Blr_Opcode, callback::signal },                   // _signal
    { data::Blr_Opcode, callback::stat },                     // _stat
    { data::Blr_Opcode, callback::strcat },                   // _strcat
    { data::Blr_Opcode, callback::strchr },                   // _strchr
    { data::Blr_Opcode, callback::strcpy },                   // _strcpy
    { data::Blr_Opcode, callback::strlen },                   // _strlen
    { data::Blr_Opcode, callback::strncpy },                  // _strncpy
    { data::Blr_Opcode, callback::strrchr },                  // _strrchr
    { data::Blr_Opcode, callback::dyld_stub_binding_helper }, // _stub_binding_helper_ptr_in_dyld
    { data::Blr_Opcode, callback::vsnprintf },                // _vsnprintf
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
