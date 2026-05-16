/**
 * Author:    domin568
 * Created:   15.09.2025
 * Brief:     redirected API implementations
 **/
#pragma once

#include "CMachoLoader.hpp"
#include "Common.hpp"
#include "shims/ShimContext.hpp"
#include "shims/carbon/CarbonShims.hpp"
#include "shims/dyld/DyldShims.hpp"
#include "shims/libc/LibcShims.hpp"
#include <algorithm>
#include <iostream>
#include <string_view>
#include <unicorn/unicorn.h>

namespace import
{

namespace callback
{

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
} // namespace data

namespace helpers
{
std::string_view DereferenceCString( void * );
}

inline constexpr int Variadic_Args{ -1 };

struct Known_Import_Entry
{
    std::span<const uint8_t> data{}; // stub opcodes (functions) or zero-initialised memory (variables)
    callback::CallbackPtr hook{};
    int arg_count{};
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

inline constexpr auto All_Imports = std::to_array<std::pair<std::string_view, Known_Import_Entry>>( {
    { "_BlockMoveData", { data::Blr_Opcode, callback::BlockMoveData, 3 } },
    { "_CloseResFile", { data::Blr_Opcode, callback::CloseResFile, 1 } },
    { "_DetachResource", { data::Blr_Opcode, callback::DetachResource, 1 } },
    { "_DisposeHandle", { data::Blr_Opcode, callback::DisposeHandle, 1 } },
    { "_FSClose", { data::Blr_Opcode, callback::FSClose, 1 } },
    { "_FSGetCatalogInfo", { data::Blr_Opcode, callback::FSGetCatalogInfo, 6 } },
    { "_FSPathMakeRef", { data::Blr_Opcode, callback::FSPathMakeRef, 3 } },
    { "_FSWrite", { data::Blr_Opcode, callback::FSWrite, 4 } },
    { "_FSpGetFInfo", { data::Blr_Opcode, callback::FSpGetFInfo, 2 } },
    { "_FSpOpenRF", { data::Blr_Opcode, callback::FSpOpenRF, 2 } },
    { "_FSpOpenResFile", { data::Blr_Opcode, callback::FSpOpenResFile, 2 } },
    { "_FSpSetFInfo", { data::Blr_Opcode, callback::FSpSetFInfo, 2 } },
    { "_Get1Resource", { data::Blr_Opcode, callback::Get1Resource, 2 } },
    { "_GetHandleSize", { data::Blr_Opcode, callback::GetHandleSize, 1 } },
    { "_HLock", { data::Blr_Opcode, callback::HLock, 1 } },
    { "_HLockHi", { data::Blr_Opcode, callback::HLockHi, 1 } },
    { "_HUnlock", { data::Blr_Opcode, callback::HUnlock, 1 } },
    { "_HandAndHand", { data::Blr_Opcode, callback::HandAndHand, 2 } },
    { "_MemError", { data::Blr_Opcode, callback::MemError, 0 } },
    { "_NewHandle", { data::Blr_Opcode, callback::NewHandle, 1 } },
    { "_NewHandleClear", { data::Blr_Opcode, callback::NewHandleClear, 1 } },
    { "_PBGetCatInfoSync", { data::Blr_Opcode, callback::PBGetCatInfoSync, 1 } },
    { "_PtrAndHand", { data::Blr_Opcode, callback::PtrAndHand, 3 } },
    { "_SetHandleSize", { data::Blr_Opcode, callback::SetHandleSize, 2 } },
    { "_TempNewHandle", { data::Blr_Opcode, callback::TempNewHandle, 2 } },
    { "__DefaultRuneLocale", { data::Dword_Mem, nullptr, 0 } },
    { "___error", { data::Blr_Opcode, callback::___error, 0 } },
    { "___isctype", { data::Blr_Opcode, callback::___isctype, 2 } },
    { "___istype", { data::Blr_Opcode, callback::___istype, 2 } },
    { "___keymgr_dwarf2_register_sections", { data::Blr_Opcode, callback::keymgr_dwarf2_register_sections, 0 } },
    { "___sF", { data::Dword_Mem, nullptr, 0 } },
    { "___tolower", { data::Blr_Opcode, callback::___tolower, 1 } },
    { "___toupper", { data::Blr_Opcode, callback::___toupper, 1 } },
    { "__cthread_init_routine", { data::Blr_Opcode, callback::cthread_init_routine, 0 } },
    { "__dyld_make_delayed_module_initializer_calls",
      { data::Blr_Opcode, callback::dyld_make_delayed_module_initializer_calls, 0 } },
    { "_abs", { data::Blr_Opcode, callback::abs, 1 } },
    { "_atexit", { data::Blr_Opcode, callback::atexit, 1 } },
    { "_atoi", { data::Blr_Opcode, callback::atoi, 1 } },
    { "_bsearch", { data::Blr_Opcode, callback::bsearch, 5 } },
    { "_calloc", { data::Blr_Opcode, callback::calloc, 2 } },
    { "_chmod", { data::Blr_Opcode, callback::chmod, 2 } },
    { "_clock", { data::Blr_Opcode, callback::clock, 0 } },
    { "_close", { data::Blr_Opcode, callback::close, 1 } },
    { "_closedir", { data::Blr_Opcode, callback::closedir, 1 } },
    { "_dyld_func_lookup_ptr_in_dyld", { data::Blr_Opcode, callback::dyld_func_lookup, 2 } },
    { "_errno", { data::Dword_Mem, nullptr, 0 } },
    { "_execve", { data::Blr_Opcode, callback::execve, 3 } },
    { "_exit", { data::Trap_Opcode, callback::exit, 1 } },
    { "_fclose", { data::Blr_Opcode, callback::fclose, 1 } },
    { "_fflush", { data::Blr_Opcode, callback::fflush, 1 } },
    { "_fgetc", { data::Blr_Opcode, callback::fgetc, 1 } },
    { "_fopen", { data::Blr_Opcode, callback::fopen, 2 } },
    { "_fork", { data::Blr_Opcode, callback::fork, 0 } },
    { "_fprintf", { data::Blr_Opcode, callback::fprintf, Variadic_Args } },
    { "_free", { data::Blr_Opcode, callback::free, 1 } },
    { "_fstat", { data::Blr_Opcode, callback::fstat, 2 } },
    { "_fwrite", { data::Blr_Opcode, callback::fwrite, 4 } },
    { "_getcwd", { data::Blr_Opcode, callback::getcwd, 2 } },
    { "_getdtablesize", { data::Blr_Opcode, callback::getdtablesize, 0 } },
    { "_getenv", { data::Blr_Opcode, callback::getenv, 1 } },
    { "_gethostbyname", { data::Blr_Opcode, callback::gethostbyname, 1 } },
    { "_gethostname", { data::Blr_Opcode, callback::gethostname, 2 } },
    { "_ioctl", { data::Blr_Opcode, callback::ioctl, Variadic_Args } },
    { "_localtime", { data::Blr_Opcode, callback::localtime, 1 } },
    { "_longjmp", { data::Blr_Opcode, callback::_longjmp, 2 } },
    { "_lseek", { data::Blr_Opcode, callback::lseek, 3 } },
    { "_lstat", { data::Blr_Opcode, callback::lstat, 2 } },
    { "_mach_init_routine", { data::Blr_Opcode, callback::mach_init_routine, 0 } },
    { "_malloc", { data::Blr_Opcode, callback::malloc, 1 } },
    { "_memcmp", { data::Blr_Opcode, callback::memcmp, 3 } },
    { "_memcpy", { data::Blr_Opcode, callback::memcpy, 3 } },
    { "_memmove", { data::Blr_Opcode, callback::memmove, 3 } },
    { "_memset", { data::Blr_Opcode, callback::memset, 3 } },
    { "_mktime", { data::Blr_Opcode, callback::mktime, 1 } },
    { "_open", { data::Blr_Opcode, callback::open, 3 } },
    { "_opendir", { data::Blr_Opcode, callback::opendir, 1 } },
    { "_printf", { data::Blr_Opcode, callback::printf, Variadic_Args } },
    { "_puts", { data::Blr_Opcode, callback::puts, 1 } },
    { "_qsort", { data::Blr_Opcode, callback::qsort, 4 } },
    { "_read", { data::Blr_Opcode, callback::read, 3 } },
    { "_readdir", { data::Blr_Opcode, callback::readdir, 1 } },
    { "_readlink", { data::Blr_Opcode, callback::readlink, 3 } },
    { "_realloc", { data::Blr_Opcode, callback::realloc, 2 } },
    { "_setjmp", { data::Blr_Opcode, callback::_setjmp, 1 } },
    { "_setlocale", { data::Blr_Opcode, callback::setlocale, 2 } },
    { "_setvbuf", { data::Blr_Opcode, callback::setvbuf, 4 } },
    { "_signal", { data::Blr_Opcode, callback::signal, 2 } },
    { "_snprintf", { data::Blr_Opcode, callback::snprintf, Variadic_Args } },
    { "_sprintf", { data::Blr_Opcode, callback::sprintf, Variadic_Args } },
    { "_sscanf", { data::Blr_Opcode, callback::sscanf, Variadic_Args } },
    { "_stat", { data::Blr_Opcode, callback::stat, 2 } },
    { "_strcat", { data::Blr_Opcode, callback::strcat, 2 } },
    { "_strchr", { data::Blr_Opcode, callback::strchr, 2 } },
    { "_strcmp", { data::Blr_Opcode, callback::strcmp, 2 } },
    { "_strcpy", { data::Blr_Opcode, callback::strcpy, 2 } },
    { "_strdup", { data::Blr_Opcode, callback::strdup, 1 } },
    { "_strerror", { data::Blr_Opcode, callback::strerror, 1 } },
    { "_strlen", { data::Blr_Opcode, callback::strlen, 1 } },
    { "_strncat", { data::Blr_Opcode, callback::strncat, 3 } },
    { "_strncmp", { data::Blr_Opcode, callback::strncmp, 3 } },
    { "_strncpy", { data::Blr_Opcode, callback::strncpy, 3 } },
    { "_strpbrk", { data::Blr_Opcode, callback::strpbrk, 2 } },
    { "_strrchr", { data::Blr_Opcode, callback::strrchr, 2 } },
    { "_strstr", { data::Blr_Opcode, callback::strstr, 2 } },
    { "_strtod", { data::Blr_Opcode, callback::strtod, 2 } },
    { "_strtol", { data::Blr_Opcode, callback::strtol, 3 } },
    { "_stub_binding_helper_ptr_in_dyld", { data::Blr_Opcode, callback::dyld_stub_binding_helper, 0 } },
    { "_time", { data::Blr_Opcode, callback::time, 1 } },
    { "_times", { data::Blr_Opcode, callback::times, 1 } },
    { "_tmpnam", { data::Blr_Opcode, callback::tmpnam, 1 } },
    { "_umask", { data::Blr_Opcode, callback::umask, 1 } },
    { "_ungetc", { data::Blr_Opcode, callback::ungetc, 2 } },
    { "_unlink", { data::Blr_Opcode, callback::unlink, 1 } },
    { "_utime", { data::Blr_Opcode, callback::utime, 2 } },
    { "_vsnprintf", { data::Blr_Opcode, callback::vsnprintf, 4 } },
    { "_vsprintf", { data::Blr_Opcode, callback::vsprintf, 3 } },
    { "_write", { data::Blr_Opcode, callback::write, 3 } },
} );

static_assert( std::ranges::is_sorted( All_Imports, std::less<>{}, []( const auto &p ) { return p.first; } ),
               "All_Imports must be sorted lexicographically by name" );

// Projected views

inline constexpr auto Known_Import_Names = []() {
    std::array<std::string_view, All_Imports.size()> result{};
    for (std::size_t i = 0; i < All_Imports.size(); ++i)
        result[i] = All_Imports[i].first;
    return result;
}();

inline constexpr auto Import_Items = []() {
    std::array<Known_Import_Entry, All_Imports.size()> result{};
    for (std::size_t i = 0; i < All_Imports.size(); ++i)
        result[i] = All_Imports[i].second;
    return result;
}();

inline constexpr auto Import_Arg_Counts = []() {
    std::array<int, All_Imports.size()> result{};
    for (std::size_t i = 0; i < All_Imports.size(); ++i)
        result[i] = All_Imports[i].second.arg_count;
    return result;
}();

inline constexpr std::size_t Unknown_Import_Index{ 0 };
inline constexpr std::size_t Unknown_Import_Shift{ 1 };

// 0xF0000000: 0xF0000004
// 0xF0000004: 0x4E, 0x80, 0x00, 0x20,  blr
// means ImportEntrySizePow2 == 3 ( 1u << 3)
inline constexpr uint32_t Import_Entry_Size{ []() -> uint32_t {
    auto itemDataSize{ []( const Known_Import_Entry &e ) { return e.data.size(); } };
    auto maxIt{ std::ranges::max_element( Import_Items, std::less<>{}, itemDataSize ) };
    // optimisation: power-of-two size enables fast shift in the hot dispatch path
    return std::bit_ceil( sizeof( Runtime_Import_Table_Entry::ptrToData ) + maxIt->data.size() );
}() };
inline constexpr int Import_Entry_Size_Pow2{ []() { return std::countr_zero( Import_Entry_Size ); }() };
inline constexpr std::size_t Import_Table_Size{ Import_Entry_Size * Import_Items.size() +
                                                Import_Entry_Size }; // +1 for the "unknown import" sentinel slot

// dynamic imports e.g obtained by dyld_func_lookup

inline constexpr std::size_t Known_Dynamic_Import_Count{ 1 };
inline constexpr std::array<std::string_view, Known_Dynamic_Import_Count> Dynamic_Imports_Names{
    "__dyld_make_delayed_module_initializer_calls",
};

} // namespace import
