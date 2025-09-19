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

inline bool unknown( uc_engine *uc )
{
    return true;
}

inline bool keymgr_dwarf2_register_sections( uc_engine *uc, CMachoLoader *macho )
{
    return true;
}

inline bool cthread_init_routine( uc_engine *uc, CMachoLoader *macho )
{
    return true;
}

inline bool dyld_make_delayed_module_initializer_calls( uc_engine *uc, CMachoLoader *macho )
{
    return true;
}

inline bool dyld_func_lookup( uc_engine *uc, CMachoLoader *macho )
{
    uint32_t nameAddress{};
    if (uc_reg_read( uc, UC_PPC_REG_3, &nameAddress ) != UC_ERR_OK)
    {
        std::cerr << "Could not read dyld_func_lookup function name pointer" << std::endl;
        return false;
    }
    const std::optional<LIEF::MachO::Section> sec{ macho->get_section_for_va( nameAddress ) };
    if (!sec.has_value())
    {
        std::cerr << "Could not find section for address = 0x" << std::hex << nameAddress << std::endl;
        return false;
    }
    static constexpr size_t Max_Func_Name_Size{ 0x100 };
    const size_t leftBytesInSection{ sec->virtual_address() + sec->size() - nameAddress };
    const size_t toRead{ std::min<size_t>( Max_Func_Name_Size, leftBytesInSection ) };
    std::string name{};
    name.resize( toRead );
    if (uc_mem_read( uc, nameAddress, name.data(), name.size() ) != UC_ERR_OK)
    {
        std::cerr << "Could not read dyld_func_lookup function name" << std::endl;
        return false;
    }
    name.resize( strnlen( name.c_str(), name.size() ) );

    uint32_t callbackAddress{}; // TODO calculate address of API in import table
    if (uc_reg_write( uc, UC_PPC_REG_4, &callbackAddress ) != UC_ERR_OK)
    {
        std::cerr << "Could not write dyld_func_lookup resolved address" << std::endl;
        return false;
    }
    return true;
}

inline bool atexit( uc_engine *uc, CMachoLoader *macho )
{
    return true;
}

inline bool exit( uc_engine *uc, CMachoLoader *macho )
{
    return true;
}

inline bool mach_init_routine( uc_engine *uc, CMachoLoader *macho )
{
    return true;
}

inline bool dyld_stub_binding_helper( uc_engine *uc, CMachoLoader *emu )
{
    return true;
}

} // namespace callback

namespace data
{
static const std::array<uint8_t, 4> Blr_Opcode{ 0x4E, 0x80, 0x00, 0x20 };
static const std::array<uint8_t, 4> Dword_Mem{ 0x00, 0x00, 0x00, 0x00 };
} // namespace data

struct Known_Import_Entry
{
    std::span<const uint8_t> data{}; // code for functions, memory for variables
    callback::CallbackPtr hook{};
};

struct Runtime_Import_Table_Entry
{
    uint32_t ptrToData{};            // points to
    std::span<const uint8_t> data{}; // <- here in runtime
};

// BEWARE! items must be sorted in Known_Import_Names and Import_Items
static constexpr size_t Unknown_Import_Index{ 0 };
static constexpr size_t Unknown_Import_Shift{ 1 };
static constexpr size_t Known_Import_Count{ 9 };
static constexpr std::array<std::string_view, Known_Import_Count> Known_Import_Names{
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

static constexpr std::array<Known_Import_Entry, Known_Import_Count> Import_Items{ {
    // crt1.o stub
    { data::Blr_Opcode, callback::keymgr_dwarf2_register_sections }, // ___keymgr_dwarf2_register_sections
    { data::Blr_Opcode, callback::cthread_init_routine },            // __cthread_init_routine
    { data::Blr_Opcode,
      callback::dyld_make_delayed_module_initializer_calls }, // __dyld_make_delayed_module_initializer_calls
    { data::Blr_Opcode, callback::atexit },                   // _atexit
    { data::Blr_Opcode, callback::dyld_func_lookup },         // _dyld_func_lookup_ptr_in_dyld
    { data::Dword_Mem, nullptr },                             // _errno
    { data::Blr_Opcode, callback::exit },                     // _exit
    { data::Blr_Opcode, callback::mach_init_routine },        // _mach_init_routine
    { data::Blr_Opcode, callback::dyld_stub_binding_helper }, // _stub_binding_helper_ptr_in_dyld
} };

static constexpr std::array<std::pair<std::string_view, import::Known_Import_Entry>, Known_Import_Count>
    Name_To_Import_Item_Flat{ []() {
        std::array<std::pair<std::string_view, import::Known_Import_Entry>, Known_Import_Count> result{};
        for (size_t idx{ 0 }; idx < Known_Import_Count; idx++)
        {
            result[idx] = { Known_Import_Names[idx], Import_Items[idx] };
        }
        return result;
    }() };

// 0xF0000000: 0xF0000004
// 0xF0000004: 0x4E, 0x80, 0x00, 0x20,  blr
// means ImportEntrySizePow2 == 3 ( 1u << 3)
static constexpr uint32_t Import_Entry_Size{ []() -> int {
    auto itemDataSize{ []( const Known_Import_Entry &importData ) { return importData.data.size(); } };
    auto maxDataSizeIt{ std::ranges::max_element( Import_Items, std::less<>{}, itemDataSize ) };
    // optimization for shift right later in code as API dispatch code is really hot
    return std::bit_ceil( sizeof( Runtime_Import_Table_Entry::ptrToData ) + maxDataSizeIt->data.size() ); // aligned
}() };
static constexpr uint32_t Import_Entry_Size_Pow2{ []() { return std::countr_zero( Import_Entry_Size ); }() };
static constexpr size_t Import_Table_Size{ Import_Entry_Size * Import_Items.size() +
                                           Import_Entry_Size }; // additional Import_Entry_Size for unknown imports

} // namespace import
