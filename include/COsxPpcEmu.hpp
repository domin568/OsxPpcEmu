/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Emulator for Mach-O PowerPC object files
 **/
#pragma once
#include "../include/CMachoLoader.hpp"
#include "../include/Common.hpp"
#include "../include/ImportDispatch.hpp"
#ifdef DEBUG
#include "../include/CDebugger.hpp"
#include "../include/CGdbServer.hpp"
#endif
#include <expected>
#include <unicorn/unicorn.h>

namespace emu
{

struct Error
{
    enum Type
    {
        FileNotFound,
        Bad_Arguments,
        MemoryError,
        ImageLoaderError,
        UnicornOpenError,
        ImportRedirectionError,
        StackInitializationError,
    };
    Type type;
    std::string message{};
};

class COsxPpcEmu
{
  public:
    static std::expected<COsxPpcEmu, Error> init( int argc, const char **argv, const std::span<const std::string> env );
    bool run();
#ifdef DEBUG
    void init_debugger();
#endif

    memory::CMemory m_mem;
    loader::CMachoLoader m_loader;
#ifdef DEBUG
    std::unique_ptr<debug::CDebugger> m_debugger{};
    std::unique_ptr<gdb::CGdbServer> m_gdb_server{};
#endif

  private:
    COsxPpcEmu( uc_engine *uc, loader::CMachoLoader &&loader, memory::CMemory mem );
    uc_engine *m_uc;
    uc_hook m_apiHook{};
    uc_hook m_interruptHook{};
    uc_hook m_memInvalidHook{};
#ifdef DEBUG
    uc_hook m_traceHook{};
    uc_hook m_debugHook{};
    uc_hook m_watchpointHook{};
#endif

    // static initialization functions
    static std::optional<size_t> get_max_import_data_size(
        const std::span<const std::pair<std::string_view, import::Known_Import_Entry>> &knownImports );
    static bool set_stack( uc_engine *uc, const std::span<const std::string> args,
                           const std::span<const std::string> env, memory::CMemory &mem );
    static bool set_args_on_stack( uc_engine *uc, const std::span<const std::string> args,
                                   const std::span<const std::string> env, memory::CMemory &mem );

    static bool resolve_imports( uc_engine *uc, loader::CMachoLoader &loader, memory::CMemory &mem );
    static bool redirect_imports(
        uc_engine *uc,
        const std::span<const std::pair<std::string, std::pair<uint32_t, common::ImportType>>> &allImports,
        memory::CMemory &mem );
    static bool write_unknown_import_entry( uc_engine *uc, memory::CMemory &mem );
    static bool write_dynamic_import_entries( uc_engine *uc, memory::CMemory &mem );
    static bool write_import_entry( uc_engine *uc, size_t offset, const import::Runtime_Import_Table_Entry entry,
                                    memory::CMemory &mem );
    static bool patch_import_ptr( uc_engine *uc, size_t offset, uint32_t symbolAddress, memory::CMemory &mem );
    static bool init_default_rune_locale(
        uc_engine *uc,
        const std::span<const std::pair<std::string, std::pair<uint32_t, common::ImportType>>> &staticImports,
        memory::CMemory &mem );
};

// unicorn hooks
static void hook_api( uc_engine *uc, uint64_t address, uint32_t size, COsxPpcEmu *emu );

static void hook_intr( uc_engine *uc, uint32_t intno, void *user_data );
static void hook_mem_invalid( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value,
                              void *user_data );
#ifdef DEBUG
static void hook_debug( uc_engine *uc, uint64_t address, uint32_t size, COsxPpcEmu *emu );

static void print_api_call_source( uc_engine *uc, uint64_t address, size_t idx, COsxPpcEmu *emu );
static void print_context( uc_engine *uc );
static void print_api_return( uc_engine *uc, size_t idx );
#endif
} // namespace emu