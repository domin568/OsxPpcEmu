/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Emulator for Mach-O PowerPC object files
 **/

#include "../include/COsxPpcEmu.hpp"
#include "../include/Common.hpp"
#include "../include/hook/EmuHooks.hpp"
#include "../include/hook/ImportTable.hpp"
#include "../include/loader/CMachoLoader.hpp"
#include "../include/mem/CMemory.hpp"
#include "../include/mem/StackLayout.hpp"
#include <filesystem>
#include <iostream>
#include <ranges>

namespace emu
{

COsxPpcEmu::COsxPpcEmu( uc_engine *uc, loader::CMachoLoader &&loader, memory::CMemory mem )
    : m_uc( uc ), m_mem( std::move( mem ) ), m_loader( std::move( loader ) )
{
}

#ifdef DEBUGGER_ENABLED
void COsxPpcEmu::init_debugger()
{
    m_debugger = std::make_unique<debug::CDebugger>( m_uc, &m_mem, &m_loader, &m_trace_file );

    // Check if GDB server mode is enabled via environment variable
    const char *gdb_mode = std::getenv( "GDB_SERVER" );
    bool enable_gdb = ( gdb_mode != nullptr && std::string( gdb_mode ) == "1" );

    if (enable_gdb)
    {
        m_gdb_server = std::make_unique<gdb::CGdbServer>( m_uc, &m_mem, &m_loader, m_debugger.get() );
        m_gdb_server->set_packet_logging( true );
        // Start GDB server
        if (m_gdb_server->start())
        {
            std::cout << "GDB server started successfully" << std::endl;
            std::cout << "Connect from IDA Pro: Debugger -> Attach -> Remote GDB debugger -> localhost:23947"
                      << std::endl;
        }
        else
        {
            std::cerr << "Failed to start GDB server" << std::endl;
        }
    }
    else
    {
        std::cout << "GDB server disabled. Using interactive debugger." << std::endl;
        std::cout << "To enable GDB server: export GDB_SERVER=1" << std::endl;
    }
}
#endif

std::expected<COsxPpcEmu, Error> COsxPpcEmu::init( int argc, const char **argv, const std::span<const std::string> env,
                                                   common::HeapMode heapMode )
{
    if (argc < 2 || argv == nullptr || env.data() == nullptr)
        return std::unexpected( Error{ Error::Type::Bad_Arguments, "Could not parse command line arguments" } );

    const std::vector<std::string> args( argv, argv + argc );
    const std::string &emuTarget{ args[1] };
    if (!std::filesystem::exists( emuTarget ))
        return std::unexpected( Error{ Error::Type::FileNotFound, "File not found." } );

    uc_err err{};
    uc_engine *uc{};
    uc_mode ppcMode{ static_cast<uc_mode>( UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN ) };
    err = uc_open( UC_ARCH_PPC, ppcMode, &uc );
    if (err != UC_ERR_OK)
        return std::unexpected( Error{ Error::Type::UnicornOpenError, "Could not create ppc32 unicorn emulator." } );

    if (!enable_floating_point_ops( uc ))
    {
        uc_close( uc );
        return std::unexpected( Error{ Error::Type::UnicornOpenError, "Could not enable floating-point operations." } );
    }

    std::expected<loader::CMachoLoader, loader::Error> loader{ loader::CMachoLoader::init( emuTarget ) };
    if (!loader)
        return std::unexpected{ Error{ Error::Type::ImageLoaderError, std::move( loader.error().message ) } };

    std::expected<memory::CMemory, memory::Error> memory{
        memory::CMemory::init( uc, common::Guest_Virtual_Memory_Size ) };
    if (!memory)
        return std::unexpected( Error{ Error::Type::MemoryError, std::move( memory.error().message ) } );

    if (!memory->initialize_heap( heapMode ))
        return std::unexpected( Error{ Error::Type::MemoryError, "Could not initialize guest heap." } );

    if (!loader->map_image_memory( uc, *memory ))
        return std::unexpected( Error{ Error::Type::ImageLoaderError, "Could not map image memory." } );

    if (!loader->set_unix_thread( uc ))
        return std::unexpected{ Error{ Error::Type::ImageLoaderError, "Could not set Unix thread context." } };

    std::expected<std::vector<std::pair<std::string, std::pair<uint32_t, common::ImportType>>>, loader::Error>
        staticImports{ loader->get_imports() }; // imports from parsed MachO file
    if (!staticImports)
        return std::unexpected( Error{ Error::Type::ImageLoaderError, std::move( staticImports.error().message ) } );

    const std::expected<void, std::string> importSetup{ import::setup::build_import_table( *staticImports, *memory ) };
    if (!importSetup)
        return std::unexpected( Error{ Error::Type::ImportRedirectionError, importSetup.error() } );

    if (!set_stack( uc, args, env, *memory ))
        return std::unexpected(
            Error{ Error::Type::StackInitializationError, "Stack initialization error (argc, argv, envp)." } );

    return COsxPpcEmu{ uc, std::move( *loader ), std::move( *memory ) };
}

bool COsxPpcEmu::run()
{
    const std::optional<std::pair<uint64_t, uint64_t>> textSegment{ m_loader.get_text_segment_va_range() };
    if (!textSegment.has_value())
        return false;
    const auto [textSegStart, textSegEnd]{ *textSegment };

    // populated lazily here (not in the constructor): COsxPpcEmu::init() returns *this by
    // value, and HookContext holds pointers into *this, so populating any earlier would
    // leave m_hookCtx pointing at a moved-from (or not-yet-relocated) object.
    m_hookCtx.uc = m_uc;
    m_hookCtx.mem = &m_mem;
    m_hookCtx.loader = &m_loader;
#ifdef DEBUGGER_ENABLED
    m_hookCtx.debugger = m_debugger.get();
    m_hookCtx.gdbServer = m_gdb_server.get();
    m_hookCtx.traceFile = &m_trace_file;
#endif

    if (const auto res{ m_hooks.install_all( m_hookCtx, textSegStart, textSegEnd ) }; !res)
    {
        std::cerr << res.error() << std::endl;
        return false;
    }

#ifdef DEBUGGER_ENABLED
    start_debug_session( m_loader.get_ep() );
#endif

    return uc_emu_start( m_uc, m_loader.get_ep(), textSegEnd, 0, 0 ) == UC_ERR_OK;
}

#ifdef DEBUGGER_ENABLED
void COsxPpcEmu::start_debug_session( std::uint32_t ep )
{
    // Start with interactive debugger prompt (unless GDB server will handle it)
    std::cout << "\n=== Interactive Debugger ===" << std::endl;
    std::cout << "Set breakpoints before running. Type 'h' for help, 'c' to start execution." << std::endl;
    std::cout << "Entry point: 0x" << std::hex << ep << std::dec << std::endl;

    // Set PC to entry point so debugger shows correct context
    uc_reg_write( m_uc, UC_PPC_REG_PC, &ep );

    // Enter interactive mode to set breakpoints (only if GDB not connected)
    // If GDB server is running, it will handle the initial stop
    if (!m_gdb_server || !m_gdb_server->is_running())
    {
        m_debugger->interactive_prompt();
    }
    else
    {
        // GDB server will control execution
        // Add a temporary breakpoint at entry point so debugger is active
        // This will cause the emulator to stop immediately when it starts
        m_debugger->add_breakpoint( ep );
        std::cout << "Waiting for GDB client commands (will stop at entry point 0x" << std::hex << ep << std::dec
                  << ")..." << std::endl;
    }
}
#endif

bool COsxPpcEmu::set_stack( uc_engine *uc, const std::span<const std::string> args,
                            const std::span<const std::string> env, memory::CMemory &mem )
{
    uc_err err{ uc_reg_write( uc, UC_PPC_REG_1, &common::Stack_Dyld_Region_Start_Address ) };
    if (err != UC_ERR_OK)
    {
        std::cerr << "Could not set stack register R1." << std::endl;
        return false;
    }

    if (!mem.commit( common::Stack_Region_Start_Address, common::Stack_Size, UC_PROT_ALL ))
    {
        std::cerr << "Could not map stack region." << std::endl;
        return false;
    }

    if (!set_args_on_stack( args, env, mem ))
        return false;

    return true;
}

bool COsxPpcEmu::set_args_on_stack( const std::span<const std::string> args, const std::span<const std::string> env,
                                    memory::CMemory &mem )
{
    const auto targetArgsView{ args | std::views::drop( 1 ) };
    const std::vector<std::string> targetArgs( targetArgsView.begin(), targetArgsView.end() );

    const std::expected<emu::detail::StackImage, std::string> image{ emu::detail::build_stack_image(
        targetArgs, env, common::Stack_Dyld_Region_Start_Address, common::Stack_Dyld_Region_Size ) };
    if (!image)
    {
        std::cerr << "Could not build initial stack: " << image.error() << std::endl;
        return false;
    }

    if (!mem.check( common::Stack_Dyld_Region_Start_Address, image->bytes.size() ))
    {
        std::cerr << "Initial stack image does not fit in committed memory." << std::endl;
        return false;
    }

    mem.write( common::Stack_Dyld_Region_Start_Address, image->bytes.data(), image->bytes.size() );
    return true;
}

bool COsxPpcEmu::enable_floating_point_ops( uc_engine *uc )
{
    uc_err err{};
    // Enable floating-point operations by setting the FP bit (bit 13) in MSR
    // MSR bits: FP=0x2000 (bit 13)
    uint32_t msr = 0x2000;
    err = uc_reg_write( uc, UC_PPC_REG_MSR, &msr );
    if (err != UC_ERR_OK)
    {
        return false;
    }
    return true;
}

} // namespace emu
