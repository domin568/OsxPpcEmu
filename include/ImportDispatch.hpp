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
#include <vector>

namespace import
{

namespace callback
{

using CallbackPtr = bool ( * )( uc_engine *, CMachoLoader *macho );
bool unknown( uc_engine *uc );
bool keymgr_dwarf2_register_sections( uc_engine *uc, CMachoLoader *macho );
bool cthread_init_routine( uc_engine *uc, CMachoLoader *macho );
bool dyld_make_delayed_module_initializer_calls( uc_engine *uc, CMachoLoader *macho );
bool dyld_func_lookup( uc_engine *uc, CMachoLoader *macho );
bool atexit( uc_engine *uc, CMachoLoader *macho );
bool exit( uc_engine *uc, CMachoLoader *macho );
bool mach_init_routine( uc_engine *uc, CMachoLoader *macho );
bool dyld_stub_binding_helper( uc_engine *uc, CMachoLoader *emu );

} // namespace callback

namespace data
{
inline constexpr std::array<uint8_t, 4> Blr_Opcode{ 0x4E, 0x80, 0x00, 0x20 };
inline constexpr std::array<uint8_t, 4> Dword_Mem{ 0x00, 0x00, 0x00, 0x00 };
inline constexpr std::array<uint8_t, 4> Trap_Opcode{ 0x7F, 0xE0, 0x00, 0x08 };
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
inline constexpr size_t Known_Static_Import_Count{ 9 };
inline constexpr std::array<std::string_view, Known_Static_Import_Count> Known_Import_Names{
    "___keymgr_dwarf2_register_sections",
    "__cthread_init_routine",
    "__dyld_make_delayed_module_initializer_calls",
    "_atexit",
    "_dyld_func_lookup_ptr_in_dyld",
    "_errno",
    "_exit",
    "_mach_init_routine",
    "_stub_binding_helper_ptr_in_dyld",
};
static_assert( std::ranges::is_sorted( ( Known_Import_Names ) ) );

inline constexpr std::array<Known_Import_Entry, Known_Static_Import_Count> Import_Items{ {
    // crt1.o stub
    { data::Blr_Opcode, callback::keymgr_dwarf2_register_sections }, // ___keymgr_dwarf2_register_sections
    { data::Blr_Opcode, callback::cthread_init_routine },            // __cthread_init_routine
    { data::Blr_Opcode,
      callback::dyld_make_delayed_module_initializer_calls }, // __dyld_make_delayed_module_initializer_calls
    { data::Blr_Opcode, callback::atexit },                   // _atexit
    { data::Blr_Opcode, callback::dyld_func_lookup },         // _dyld_func_lookup_ptr_in_dyld
    { data::Dword_Mem, nullptr },                             // _errno
    { data::Trap_Opcode, callback::exit },                    // _exit
    { data::Blr_Opcode, callback::mach_init_routine },        // _mach_init_routine
    { data::Blr_Opcode, callback::dyld_stub_binding_helper }, // _stub_binding_helper_ptr_in_dyld
} };

inline constexpr std::array<std::pair<std::string_view, import::Known_Import_Entry>, Known_Static_Import_Count>
    Name_To_Import_Item_Flat{ []() {
        std::array<std::pair<std::string_view, import::Known_Import_Entry>, Known_Static_Import_Count> result{};
        for (size_t idx{ 0 }; idx < Known_Static_Import_Count; idx++)
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
