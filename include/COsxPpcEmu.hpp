/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Emulator for Mach-O PowerPC object files
 **/
#pragma once
#include "../include/CMachoLoader.hpp"
#include "../include/Common.hpp"
#include "../include/ImportDispatch.hpp"
#include <expected>
#include <flat_map>
#include <unicorn/unicorn.h>
#include <unordered_map>

class COsxPpcEmu
{
  public:
    static std::expected<COsxPpcEmu, common::Error> init( int argc, const char **argv,
                                                          const std::span<const std::string> env );
    bool print_vm_map( std::ostream &os );
    bool run();

    // public for unicorn hooks
    static constexpr uint32_t Import_Dispatch_Table_Address{ 0xF0'00'00'00 };
#ifndef DEBUG
  private:
#endif
    CMachoLoader m_loader;

  private:
    COsxPpcEmu( uc_engine *uc, CMachoLoader &&loader );

    // limits, addresses, sizes
    static constexpr uint32_t Stack_Max_Address{ 0xC0'00'00'00 };
    static constexpr uint32_t Stack_Size{ 2u * 0x1000 * 0x1000 }; // 2MB
    static constexpr uint32_t Stack_Region_Start_Address{ Stack_Max_Address - Stack_Size };
    static constexpr uint32_t Stack_Dyld_Region_Size{ 0x1000'0 };
    static constexpr uint32_t Stack_Dyld_Region_Start_Address{
        Stack_Max_Address - Stack_Dyld_Region_Size }; // it is also initial stack address

    uc_engine *m_uc;
    uc_hook m_instructionHook{};
    uc_hook m_basicBlockHook{};
    uc_hook m_interruptHook{};
    uc_hook m_memInvalidHook{};

    // static initialization functions
    static std::optional<size_t> get_max_import_data_size(
        const std::span<const std::pair<std::string_view, import::Import_Item>> &knownImports );

    static bool set_stack( uc_engine *uc, const std::span<const std::string> args,
                           const std::span<const std::string> env );
    static bool set_args_on_stack( uc_engine *uc, const std::span<const std::string> args,
                                   const std::span<const std::string> env );

    static bool resolve_imports( uc_engine *uc, CMachoLoader &loader );
    static bool write_import_entry( uc_engine *uc, size_t offset, const import::Import_Entry &entry );
    static bool patch_import_indirect_ptr( uc_engine *uc, size_t offset, uint32_t symbolAddress );
};

// unicorn hooks
static void hook_block( uc_engine *uc, uint64_t address, uint32_t size, void *user_data );
static void hook_code( uc_engine *uc, uint64_t address, uint32_t size, COsxPpcEmu *user_data );
static void hook_intr( uc_engine *uc, uint32_t intno, void *user_data );
static void hook_mem_invalid( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value,
                              void *user_data );