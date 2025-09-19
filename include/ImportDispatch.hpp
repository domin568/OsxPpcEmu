/**
 * Author:    domin568
 * Created:   15.09.2025
 * Brief:     redirected API implementations
 **/
#pragma once

#include "CMachoLoader.hpp"
#include <unicorn/unicorn.h>
#include <vector>

namespace import
{

using ApiPtr = bool ( * )( uc_engine * );

enum class Type
{
    Code,
    Data,
};

struct Import_Dispatch_Data
{
    uint32_t apiDispatchTableVa{};
    int apiRedirectEntrySizePow2{};
    const std::span<const import::ApiPtr> apiRedirectEntries{};
};

struct Import_Item
{
    std::span<const uint8_t> data{}; // code for functions, memory for variables
    ApiPtr hook{};
};

struct Import_Entry
{
    uint32_t ptrToData{};
    std::span<const uint8_t> data{};
};

static bool api_unknown( uc_engine *uc )
{
    return true;
}
static bool api_mach_init_routine( uc_engine *uc )
{
    return true;
}

static bool api_cthread_init_routine( uc_engine *uc )
{
    return true;
}

static bool api_keymgr_dwarf2_register_sections( uc_engine *uc )
{
    return true;
}

static bool api_atexit( uc_engine *uc )
{
    return true;
}

static bool api_exit( uc_engine *uc )
{
    return true;
}

static const std::array<uint8_t, 4> Blr_Opcode{ 0x4E, 0x80, 0x00, 0x20 };
static const std::array<uint8_t, 4> Dword_Mem{ 0x00, 0x00, 0x00, 0x00 };
static const Import_Item Unknown_Api{
    .data{ Blr_Opcode },
    .hook = api_unknown,
};

static constexpr size_t Known_Import_Count{ 7 };
static constexpr std::array<std::string_view, Known_Import_Count> Known_Import_Names{
    "unknown",
    "_mach_init_routine",
    "_errno",
    "__cthread_init_routine",
    "___keymgr_dwarf2_register_sections",
    "_atexit",
    "_exit" };

static constexpr std::array<Import_Item, Known_Import_Count> Import_Items{ {
    { Blr_Opcode, api_unknown }, // unknown
    // crt1.o stub
    { Blr_Opcode, api_mach_init_routine },               // mach_init_routine
    { Dword_Mem, nullptr },                              // errno
    { Blr_Opcode, api_cthread_init_routine },            // cthread_init_routine
    { Blr_Opcode, api_keymgr_dwarf2_register_sections }, // keymgr_dwarf2_register_sections
    { Blr_Opcode, api_atexit },                          // atexit
    { Blr_Opcode, api_exit },                            // exit
} };

static constexpr std::array<std::pair<std::string_view, import::Import_Item>, Known_Import_Count>
    Name_To_Import_Item_Flat{ []() {
        std::array<std::pair<std::string_view, import::Import_Item>, Known_Import_Count> result{};
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
    auto itemDataSize{ []( const Import_Item &importData ) { return importData.data.size(); } };
    auto maxDataSizeIt{ std::ranges::max_element( Import_Items, std::less<>{}, itemDataSize ) };
    // optimization for shift right later in code as API dispatch code is really hot
    return std::bit_ceil( sizeof( Import_Entry::ptrToData ) + maxDataSizeIt->data.size() ); // aligned
}() };
static constexpr uint32_t Import_Entry_Size_Pow2{ []() { return std::countr_zero( Import_Entry_Size ); }() };
static constexpr size_t Import_Table_Size{ Import_Entry_Size * Import_Items.size() };

static_assert( Known_Import_Names.size() == Known_Import_Count && Import_Items.size() == Known_Import_Count &&
               Name_To_Import_Item_Flat.size() == Known_Import_Count );

} // namespace import
