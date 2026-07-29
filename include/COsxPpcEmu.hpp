/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Emulator for Mach-O PowerPC object files
 **/
#pragma once
#include "../include/loader/CMachoLoader.hpp"
#include "../include/Common.hpp"
#include "../include/hook/EmuHooks.hpp"
#include "../include/hook/HookContext.hpp"
#include "../include/hook/ImportDispatch.hpp"
#ifdef DEBUGGER_ENABLED
#include "../include/debug/CDebugger.hpp"
#include "../include/debug/CGdbServer.hpp"
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
    static std::expected<COsxPpcEmu, Error> init( int argc, const char **argv, std::span<const std::string> env );
    bool run();
#ifdef DEBUGGER_ENABLED
    void init_debugger();
#endif

  private:
    COsxPpcEmu( uc_engine *uc, loader::CMachoLoader &&loader, memory::CMemory mem );
    uc_engine *m_uc;
    memory::CMemory m_mem;
    loader::CMachoLoader m_loader;
    // TODO populated lazily in run(): HookContext holds pointers into *this
    hooks::HookContext m_hookCtx{};
    hooks::CHookManager m_hooks{};
#ifdef DEBUGGER_ENABLED
    std::unique_ptr<debug::CDebugger> m_debugger{};
    std::unique_ptr<gdb::CGdbServer> m_gdb_server{};
    std::FILE *m_trace_file{};
#endif

    // static initialization functions
    static bool set_stack( uc_engine *uc, std::span<const std::string> args,
                           std::span<const std::string> env, memory::CMemory &mem );
    static bool set_args_on_stack( std::span<const std::string> args, std::span<const std::string> env,
                                   memory::CMemory &mem );
#ifdef DEBUGGER_ENABLED
    void start_debug_session( std::uint32_t ep );
#endif
};

} // namespace emu


