/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Emulator for Mach-O PowerPC object files
 **/
#pragma once
#include "../include/ApiDispatch.hpp"
#include "../include/CMachoLoader.hpp"
#include "../include/Common.hpp"
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
    api::Api_Dispatch_Data m_redirectApiData;
#ifndef DEBUG
  private:
#endif
    CMachoLoader m_loader;

    static constexpr size_t Api_Count{ 2 };
    static constexpr std::array<std::string, Api_Count> Api_Names{ "unknown", "_mach_init_routine" };
    static constexpr std::array<api::Api_Item, Api_Count> Api_Items{ {
        { api::Blr_Opcode, api::api_unknown },
        { api::Blr_Opcode, api::api_mach_init_routine },
    } };

    static const inline std::unordered_map<std::string, api::Api_Item> Name_To_Api_Item{ []() {
        static const std::unordered_map<std::string, api::Api_Item> cached{ []( const auto &k, const auto &v ) {
            std::unordered_map<std::string, api::Api_Item> tmp{};
            for (std::size_t i = 0; i < k.size(); ++i)
                tmp.emplace( k[i], v[i] );
            return tmp;
        }( Api_Names, Api_Items ) };
        return cached;
    }() };

    /*
    static inline const std::map<std::string, api::Api_Item> Name_To_Api_Hook{ {
        { "unknown", { api::Blr_Opcode, api::api_unknown } },
        { "_mach_init_routine", { api::Blr_Opcode, api::api_mach_init_routine } },
    } };
    */

  private:
    COsxPpcEmu( uc_engine *uc, CMachoLoader &&loader, const api::Api_Dispatch_Data &redirectApiData );

    // limits, addresses, sizes
    static constexpr uint32_t Stack_Max_Address{ 0xC0'00'00'00 };
    static constexpr uint32_t Api_Dispatch_Table_Address{ 0xF0'00'00'00 };
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
    static std::optional<size_t> get_max_ppc_code_entry_size(
        const std::unordered_map<std::string, api::Api_Item> &map );

    static bool set_stack( uc_engine *uc, const std::span<const std::string> args,
                           const std::span<const std::string> env );
    static bool set_args_on_stack( uc_engine *uc, const std::span<const std::string> args,
                                   const std::span<const std::string> env );

    static std::optional<api::Api_Dispatch_Data> redirect_apis( uc_engine *uc, CMachoLoader &loader );
    static bool write_import_dispatch_entry( uc_engine *uc, size_t offset, uint32_t ptrToPpcCode,
                                             const std::span<const uint8_t> data );
    static bool patch_symbol_indirect_ptr( uc_engine *uc, size_t offset, uint32_t symbolAddress, bool knownSymbol );
};

// unicorn hooks
static void hook_block( uc_engine *uc, uint64_t address, uint32_t size, void *user_data );
static void hook_code( uc_engine *uc, uint64_t address, uint32_t size, COsxPpcEmu *user_data );
static void hook_intr( uc_engine *uc, uint32_t intno, void *user_data );
static void hook_mem_invalid( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value,
                              void *user_data );