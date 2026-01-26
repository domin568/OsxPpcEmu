/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Emulator for Mach-O PowerPC object files
 **/

#include "../include/COsxPpcEmu.hpp"
#include "../include/CMachoLoader.hpp"
#include "../include/CMemory.hpp"
#include "../include/Common.hpp"
#include "../include/ImportDispatch.hpp"
#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <ranges>
#include <sstream>

std::atomic<uint32_t> g_lastAddr{ 0 };

namespace emu
{
// Forward declarations for hook functions
void hook_watchpoint( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data );
COsxPpcEmu::COsxPpcEmu( uc_engine *uc, loader::CMachoLoader &&loader, memory::CMemory mem )
    : m_uc( uc ), m_loader( std::move( loader ) ), m_mem( std::move( mem ) )
{
}

#ifdef DEBUG
void COsxPpcEmu::init_debugger()
{
    m_debugger = std::make_unique<debug::CDebugger>( m_uc, &m_mem, &m_loader );

    // Check if GDB server mode is enabled via environment variable
    const char *gdb_mode = std::getenv( "GDB_SERVER" );
    bool enable_gdb = ( gdb_mode != nullptr && std::string( gdb_mode ) == "1" );

    if (enable_gdb)
    {
        m_gdb_server = std::make_unique<gdb::CGdbServer>( m_uc, &m_mem, &m_loader, m_debugger.get() );

        // Start GDB server
        if (m_gdb_server->start())
        {
            std::cout << "GDB server started successfully" << std::endl;
            std::cout << "Connect from IDA Pro: Debugger -> Attach -> Remote GDB debugger -> localhost:23946"
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

std::expected<COsxPpcEmu, Error> COsxPpcEmu::init( int argc, const char **argv, const std::span<const std::string> env )
{
    if (argc < 2 || argv == nullptr || env.data() == nullptr)
        return std::unexpected( Error{ Error::Type::Bad_Arguments, "Could not parse command line arguments" } );

    const std::vector<std::string> args( argv, argv + argc );
    const std::string &emuTarget{ args[1] };
    if (!std::filesystem::exists( emuTarget ))
        return std::unexpected( Error{ Error::Type::FileNotFound, "File not found." } );

    uc_err err;
    uc_engine *uc;
    uc_mode ppcMode{ static_cast<uc_mode>( UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN ) };
    err = uc_open( UC_ARCH_PPC, ppcMode, &uc );
    if (err != UC_ERR_OK)
        return std::unexpected( Error{ Error::Type::UnicornOpenError, "Could not create ppc32 unicorn emulator." } );

    // Enable floating-point operations by setting the FP bit (bit 13) in MSR
    // MSR bits: FP=0x2000 (bit 13)
    uint32_t msr = 0x2000;
    err = uc_reg_write( uc, UC_PPC_REG_MSR, &msr );
    if (err != UC_ERR_OK)
    {
        uc_close( uc );
        return std::unexpected( Error{ Error::Type::UnicornOpenError, "Could not set MSR register." } );
    }

    std::expected<loader::CMachoLoader, loader::Error> loader{ loader::CMachoLoader::init( emuTarget ) };
    if (!loader)
        return std::unexpected{ Error{ Error::Type::ImageLoaderError, std::move( loader.error().message ) } };

    std::expected<memory::CMemory, memory::Error> memory{
        memory::CMemory::init( uc, common::Guest_Virtual_Memory_Size ) };
    if (!memory)
        return std::unexpected( Error{ Error::Type::MemoryError, std::move( memory.error().message ) } );

    memory->initialize_heap();

    if (!loader->map_image_memory( uc, *memory ))
        return std::unexpected( Error{ Error::Type::ImageLoaderError, "Could not map image memory." } );

    if (!loader->set_unix_thread( uc ))
        return std::unexpected{ Error{ Error::Type::ImageLoaderError, "Could not set Unix thread context." } };

    const bool importResolveSuccess{ resolve_imports( uc, *loader, *memory ) };
    if (!importResolveSuccess)
        return std::unexpected{ Error{ Error::Type::ImportRedirectionError, "Could not redirect imports." } };

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

    uc_err errApiHook{ uc_hook_add( m_uc, &m_apiHook, UC_HOOK_CODE, reinterpret_cast<void *>( hook_api ), this,
                                    common::Import_Dispatch_Table_Address,
                                    common::Import_Dispatch_Table_Address + import::Import_Table_Size ) };

    uc_err errIntHook{ uc_hook_add( m_uc, &m_interruptHook, UC_HOOK_INTR, reinterpret_cast<void *>( hook_intr ), this,
                                    textSegStart, textSegEnd ) };

    uc_err errMemInvalidHook{ uc_hook_add( m_uc, &m_memInvalidHook, UC_HOOK_MEM_INVALID,
                                           reinterpret_cast<void *>( hook_mem_invalid ), this, 1, 0 ) };
#ifdef DEBUG
    uc_err errDebugHook{ uc_hook_add( m_uc, &m_debugHook, UC_HOOK_CODE, reinterpret_cast<void *>( hook_debug ), this,
                                      textSegStart, textSegEnd ) };
    if (errDebugHook != UC_ERR_OK)
    {
        std::cerr << "Could not create debug hook." << std::endl;
        return false;
    }

    // Add memory write hook for watchpoints
    uc_err errWatchpointHook{ uc_hook_add( m_uc, &m_watchpointHook, UC_HOOK_MEM_WRITE,
                                           reinterpret_cast<void *>( hook_watchpoint ), this, 1, 0 ) };
    if (errWatchpointHook != UC_ERR_OK)
    {
        std::cerr << "Could not create watchpoint hook." << std::endl;
        return false;
    }

    // Start with interactive debugger prompt (unless GDB server will handle it)
    std::cout << "\n=== Interactive Debugger ===" << std::endl;
    std::cout << "Set breakpoints before running. Type 'h' for help, 'c' to start execution." << std::endl;
    std::cout << "Entry point: 0x" << std::hex << m_loader.get_ep() << std::dec << std::endl;

    // Set PC to entry point so debugger shows correct context
    uint32_t ep = m_loader.get_ep();
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
#endif

    if (errApiHook != UC_ERR_OK)
    {
        std::cerr << "Could not create API hook." << std::endl;
        return false;
    }

#ifdef DEBUG
    if (errIntHook != UC_ERR_OK && errMemInvalidHook != UC_ERR_OK)
    {
        std::cerr << "Could not create other debug hooks" << std::endl;
        return false;
    }
#endif
    return uc_emu_start( m_uc, m_loader.get_ep(), textSegEnd, 0, 0 ) == UC_ERR_OK;
}

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

    if (!set_args_on_stack( uc, args, env, mem ))
        return false;

    return true;
}
/*
 * The stack frame layout is:
 *
 *	+-------------+
 * sp->	| argc    |
 *	+-------------+
 *	|    arg[0]   |
 *	+-------------+
 *	       :
 *	       :
 *	+-------------+
 *	| arg[argc-1] |
 *	+-------------+
 *	|      0      |
 *	+-------------+
 *	|    env[0]   |
 *	+-------------+
 *	       :
 *	       :
 *	+-------------+
 *	|    env[n]   |
 *	+-------------+
 *	|      0      |
 *	+-------------+
 *	|  exec_path  |
 *	+-------------+ *	|      0      |
 *	| STRING AREA |
 *	       :
 *	|             |
 *	+-------------+
 */
bool COsxPpcEmu::set_args_on_stack( uc_engine *uc, const std::span<const std::string> args,
                                    const std::span<const std::string> env, memory::CMemory &mem )
{
    // calculate offsets
    const auto targetArgs{ args | std::views::drop( 1 ) };

    const size_t argcOffset{ 0 };
    const size_t argsPtrsOffset{ argcOffset + sizeof( uint32_t ) }; // 4
    const size_t envPtrsOffset{ argsPtrsOffset + targetArgs.size() * sizeof( uint32_t ) +
                                sizeof( uint32_t ) }; // argc + argv + null
    const size_t execPathOffset{ envPtrsOffset + env.size() * sizeof( uint32_t ) +
                                 sizeof( uint32_t ) }; // argc + argv + null + env + null
    const size_t stringAreaOffset{ common::align_up( execPathOffset + sizeof( uint32_t ), 0x10 ) };

    // place strings
    std::vector<uint8_t> targetArgsBuf{}, envBuf{};
    std::vector<size_t> targetArgOffsets{}, envOffsets{};

    targetArgOffsets.reserve( targetArgs.size() );
    envOffsets.reserve( env.size() );

    size_t pos{ 0 };
    for (const auto &s : targetArgs)
    {
        targetArgOffsets.push_back( pos );
        targetArgsBuf.insert( targetArgsBuf.end(), s.begin(), s.end() );
        targetArgsBuf.push_back( 0 );
        pos += s.size() + 1;
    }

    for (const auto &s : env)
    {
        envOffsets.push_back( pos );
        envBuf.insert( envBuf.end(), s.begin(), s.end() );
        envBuf.push_back( 0 );
        pos += s.size() + 1;
    }

    std::vector<uint8_t> ptrsBuf( stringAreaOffset );

    // place argc
    *reinterpret_cast<uint32_t *>( ptrsBuf.data() + argcOffset ) =
        common::ensure_endianness( static_cast<uint32_t>( targetArgs.size() ), std::endian::big );

    // place argv
    size_t off{ argsPtrsOffset };
    uint32_t execPathAddress{};
    for (size_t idx{ 0 }; idx < targetArgs.size(); idx++)
    {
        const uint32_t address{ static_cast<uint32_t>( common::Stack_Dyld_Region_Start_Address + stringAreaOffset +
                                                       targetArgOffsets[idx] ) };
        const uint32_t addressBe{ common::ensure_endianness( static_cast<uint32_t>( address ), std::endian::big ) };
        if (idx == 0)
            execPathAddress = addressBe;
        *reinterpret_cast<uint32_t *>( ptrsBuf.data() + off ) = addressBe;
        off += sizeof( uint32_t );
    }
    *reinterpret_cast<uint32_t *>( ptrsBuf.data() + off ) = 0;

    // place env
    off = envPtrsOffset;
    for (size_t idx{ 0 }; idx < env.size(); idx++)
    {
        const uint32_t address{
            static_cast<uint32_t>( common::Stack_Dyld_Region_Start_Address + stringAreaOffset + envOffsets[idx] ) };
        const uint32_t addressBe{ common::ensure_endianness( static_cast<uint32_t>( address ), std::endian::big ) };
        *reinterpret_cast<uint32_t *>( ptrsBuf.data() + off ) = addressBe;
        off += sizeof( uint32_t );
    }
    *reinterpret_cast<uint32_t *>( ptrsBuf.data() + off ) = 0;

    // place exec path

    off = execPathOffset;
    *reinterpret_cast<uint32_t *>( ptrsBuf.data() + off ) = execPathAddress;

    std::array<std::span<uint8_t>, 3> stackDataArr{ ptrsBuf, targetArgsBuf, envBuf };
    const auto stackDataView{ stackDataArr | std::views::join };
    std::vector<uint8_t> stackData( stackDataView.begin(), stackDataView.end() );

    if (stackData.size() > common::Stack_Dyld_Region_Size)
    {
        std::cerr << "Dyld stack is too small, size: " << std::hex << stackData.size() << std::endl;
        return false;
    }

    mem.write( common::Stack_Dyld_Region_Start_Address, stackData.data(), stackData.size() );
    return true;
}

bool COsxPpcEmu::resolve_imports( uc_engine *uc, loader::CMachoLoader &loader, memory::CMemory &mem )
{
    const std::expected<std::vector<std::pair<std::string, std::pair<uint32_t, common::ImportType>>>, loader::Error>
        staticImports{ loader.get_imports() }; // imports from parsed MachO file
    if (!staticImports)
    {
        std::cerr << staticImports.error().message << std::endl;
        return false;
    }

    if (!mem.commit( common::Import_Dispatch_Table_Address, common::page_align_up( import::Import_Table_Size ),
                     UC_PROT_ALL ))
    {
        std::cerr << "Could not map import entries memory." << std::endl;
        return false;
    }
    // first import is always "unknown API" entry at 0xF0000000
    if (!write_unknown_import_entry( uc, mem ))
        return false;
    // then known static imports (got by parsing MachO) are resolved and import entries table filled
    if (!redirect_known_imports( uc, *staticImports, mem ))
        return false;
    // then fill entries for dynamic imoprts (e.g. using dyld_lookup_func)
    if (!write_dynamic_import_entries( uc, mem ))
        return false;
    return true;
}

bool COsxPpcEmu::redirect_known_imports(
    uc_engine *uc, const std::span<const std::pair<std::string, std::pair<uint32_t, common::ImportType>>> &allImports,
    memory::CMemory &mem )
{
    for (const auto &[name, addressAndType] : allImports)
    {
        const auto [address, type] = addressAndType;

        auto importNameMatches{
            []( const std::pair<std::string_view, import::Known_Import_Entry> &p ) { return p.first; } };
        const auto importIt{
            std::ranges::lower_bound( import::Name_To_Import_Item_Flat, name, std::less<>{}, importNameMatches ) };
        const bool knownImport{ importIt != import::Name_To_Import_Item_Flat.end() && importIt->first == name };
        const ptrdiff_t idx{ std::distance( import::Name_To_Import_Item_Flat.begin(), importIt ) };

        const uint32_t currentImportEntryOffset{
            knownImport ? common::Import_Dispatch_Table_Address + import::Import_Entry_Size +
                              static_cast<uint32_t>( idx ) * import::Import_Entry_Size
                        : common::Import_Dispatch_Table_Address };
        if (currentImportEntryOffset + import::Import_Entry_Size >
            common::Import_Dispatch_Table_Address + import::Import_Table_Size)
        {
            std::cerr << "Not enough mapped memory for API trampoline." << std::endl;
            return false;
        }

        uint32_t offset{
            type == common::ImportType::Indirect
                ? currentImportEntryOffset
                : currentImportEntryOffset +
                      static_cast<uint32_t>(
                          sizeof( import::Runtime_Import_Table_Entry::ptrToData ) ) }; // point to ptr or data directly?
        if (!patch_import_ptr( uc, offset, address, mem ))
        {
            std::cerr << "Could not update pointer to API dispatch entry for " << name << " at " << std::hex
                      << currentImportEntryOffset << std::endl;
            return false;
        }
        if (knownImport)
        {
            uint32_t ptrToData{ currentImportEntryOffset +
                                static_cast<uint32_t>( sizeof( import::Runtime_Import_Table_Entry::ptrToData ) ) };
            import::Runtime_Import_Table_Entry knownImportEntry{
                .ptrToData = type == common::ImportType::Indirect ? ptrToData : 0,
                // points in memory, e.g. 0xF0000004
                .data{ importIt->second.data }, // <- here
            };
            if (!write_import_entry( uc, currentImportEntryOffset, knownImportEntry, mem ))
            {
                std::cerr << "Could not write API dispatch entry for " << name << " at " << std::hex
                          << currentImportEntryOffset << std::endl;
                return false;
            }
        }
    }
    return true;
}

bool COsxPpcEmu::write_unknown_import_entry( uc_engine *uc, memory::CMemory &mem )
{
    import::Runtime_Import_Table_Entry unknownImportEntry{
        .ptrToData = common::Import_Dispatch_Table_Address +
                     sizeof( import::Runtime_Import_Table_Entry::ptrToData ), // points in memory
        .data{ import::data::Blr_Opcode },                                    // <- here
    };
    if (!write_import_entry( uc, common::Import_Dispatch_Table_Address, unknownImportEntry, mem ))
    {
        std::cerr << "Could not write first API dispatch entry (unknown API) at " << std::hex
                  << common::Import_Dispatch_Table_Address << std::endl;
        return false;
    }
    return true;
}

bool COsxPpcEmu::write_dynamic_import_entries( uc_engine *uc,
                                               memory::CMemory &mem ) // TODO refactor to not duplicate code
{
    for (const std::string_view s : import::Dynamic_Imports_Names)
    {
        auto importNameMatches{
            []( const std::pair<std::string_view, import::Known_Import_Entry> &p ) { return p.first; } };
        const auto importIt{
            std::ranges::lower_bound( import::Name_To_Import_Item_Flat, s, std::less<>{}, importNameMatches ) };
        const bool knownImport{ importIt != import::Name_To_Import_Item_Flat.end() && importIt->first == s };
        if (!knownImport)
        {
            std::cerr << "Missing dynamic import entry for " << s << std::endl;
            return false;
        }

        const ptrdiff_t idx{ std::distance( import::Name_To_Import_Item_Flat.begin(), importIt ) };
        const uint32_t currentImportEntryOffset{ common::Import_Dispatch_Table_Address + import::Import_Entry_Size +
                                                 static_cast<uint32_t>( idx ) * import::Import_Entry_Size };

        import::Runtime_Import_Table_Entry knownImportEntry{
            .ptrToData = 0,
            // points in memory, e.g. 0xF0000004
            .data{ importIt->second.data }, // <- here
        };
        if (!write_import_entry( uc, currentImportEntryOffset, knownImportEntry, mem ))
        {
            std::cerr << "Could not write API dispatch entry for " << s << " at " << std::hex
                      << currentImportEntryOffset << std::endl;
            return false;
        }
    }
    return true;
}

bool COsxPpcEmu::write_import_entry( uc_engine *uc, size_t offset, const import::Runtime_Import_Table_Entry entry,
                                     memory::CMemory &mem )
{
    if (entry.ptrToData != 0)
    {
        const uint32_t ptrToDataBe{
            common::ensure_endianness( static_cast<uint32_t>( entry.ptrToData ), std::endian::big ) };
        mem.write( offset, &ptrToDataBe, sizeof( ptrToDataBe ) );
    }
    mem.write( offset + sizeof( entry.ptrToData ), entry.data.data(), entry.data.size() );
    return true;
}

bool COsxPpcEmu::patch_import_ptr( uc_engine *uc, size_t importEntryOffset, uint32_t symbolAddress,
                                   memory::CMemory &mem )
{
    // e.g. 0xF0000000
    uint32_t ptrToImportData{
        common::ensure_endianness( static_cast<uint32_t>( importEntryOffset ), std::endian::big ) };
    mem.write( symbolAddress, &ptrToImportData, sizeof( ptrToImportData ) );
    return true;
}

void hook_api( uc_engine *uc, uint64_t address, uint32_t size, COsxPpcEmu *emu )
{
    const size_t idx{ ( address - common::Import_Dispatch_Table_Address ) >> import::Import_Entry_Size_Pow2 };
#ifdef DEBUG
    g_lastAddr.store( address, std::memory_order_relaxed );
    if (emu->m_debugger->is_trace_mode())
        print_api_call_source( uc, address, idx, emu );
#endif
    if (idx > 0)
        import::Import_Items[idx - import::Unknown_Import_Shift].hook( uc,
                                                                       &emu->m_mem ); // call API dispatch function
#ifdef DEBUG
    if (emu->m_debugger->is_trace_mode())
        print_api_return( uc, idx );
#endif
}

void hook_intr( uc_engine *uc, uint32_t intno, void *user_data )
{
    COsxPpcEmu *emu = static_cast<COsxPpcEmu *>( user_data );
    uint32_t addr{ g_lastAddr.load() };
    uint32_t lr, pc;

    std::cout << ">>> interrupt/exception #" << intno << std::endl;
#ifdef DEBUG
    if (emu)
    {
        const std::optional<std::string> callerName{ emu->m_loader.get_symbol_name_for_va(
            lr, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
        if (callerName.has_value())
            std::cout << " <" << *callerName << ">";
    }
    std::cout << std::endl;

    // Check if address is in import dispatch table
    if (addr >= common::Import_Dispatch_Table_Address &&
        addr < common::Import_Dispatch_Table_Address + import::Import_Table_Size)
    {
        const size_t idx{ ( addr - common::Import_Dispatch_Table_Address ) >> import::Import_Entry_Size_Pow2 };
        if (idx == import::Unknown_Import_Index)
        {
            std::cout << "API: (unknown)" << std::endl;
        }
        else if (idx - import::Unknown_Import_Shift < import::Known_Import_Names.size())
        {
            std::cout << "API: " << import::Known_Import_Names[idx - import::Unknown_Import_Shift] << std::endl;
        }
    }

    // Show instruction bytes at fault address
    std::vector<uint8_t> buf( 4 );
    if (uc_mem_read( uc, addr, buf.data(), buf.size() ) == UC_ERR_OK)
    {
        std::cerr << "bytes:";
        for (auto b : buf)
            std::fprintf( stderr, " %02x", b );
        std::cerr << "\n";
    }
    else
    {
        std::cerr << "cannot read bytes at 0x" << std::hex << addr << "\n";
    }

    // Show call stack
    if (emu && emu->m_debugger)
    {
        std::cout << "Call stack:" << std::endl;
        std::cout << "  #0  0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << pc;

        const std::optional<std::string> pcName{ emu->m_loader.get_symbol_name_for_va(
            pc, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
        if (pcName.has_value())
            std::cout << " <" << *pcName << ">";
        std::cout << std::endl;

        std::vector<uint32_t> addresses = emu->m_debugger->get_callstack_addresses( 5 );
        for (size_t i = 0; i < addresses.size(); i++)
        {
            std::cout << "  #" << ( i + 1 ) << "  0x" << std::hex << std::setfill( '0' ) << std::setw( 8 )
                      << addresses[i];
            const std::optional<std::string> funcName{ emu->m_loader.get_symbol_name_for_va(
                addresses[i], LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
            if (funcName.has_value())
                std::cout << " <" << *funcName << ">";
            std::cout << std::endl;
        }
    }
#endif
}

void hook_mem_invalid( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data )
{
    COsxPpcEmu *emu = static_cast<COsxPpcEmu *>( user_data );
    uint32_t pc, lr;

    uc_reg_read( uc, UC_PPC_REG_PC, &pc );
    uc_reg_read( uc, UC_PPC_REG_LR, &lr );

    std::cerr << "\n>>> MEMORY ACCESS VIOLATION <<<" << std::endl;

    // Decode memory access type
    const char *access_type = "UNKNOWN";
    switch (type)
    {
    case UC_MEM_READ_UNMAPPED:
        access_type = "READ from UNMAPPED";
        break;
    case UC_MEM_WRITE_UNMAPPED:
        access_type = "WRITE to UNMAPPED";
        break;
    case UC_MEM_FETCH_UNMAPPED:
        access_type = "FETCH from UNMAPPED";
        break;
    case UC_MEM_READ_PROT:
        access_type = "READ PROTECTED";
        break;
    case UC_MEM_WRITE_PROT:
        access_type = "WRITE PROTECTED";
        break;
    case UC_MEM_FETCH_PROT:
        access_type = "FETCH PROTECTED";
        break;
    default:
        break;
    }

    std::cerr << "Type:    " << access_type << " (" << type << ")" << std::endl;
    std::cerr << "Address: 0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << address << std::endl;
    std::cerr << "Size:    " << std::dec << size << " bytes" << std::endl;
    std::cerr << "Value:   0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << value << std::endl;
    std::cerr << "PC:      0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << pc;

#ifdef DEBUG
    if (emu)
    {
        const std::optional<std::string> pcName{ emu->m_loader.get_symbol_name_for_va(
            pc, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
        if (pcName.has_value())
            std::cerr << " <" << *pcName << ">";
    }
    std::cerr << std::endl;

    std::cerr << "LR:      0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << lr;

    // Show symbol name for LR (caller)
    if (emu)
    {
        const std::optional<std::string> callerName{ emu->m_loader.get_symbol_name_for_va(
            lr, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
        if (callerName.has_value())
            std::cerr << " <" << *callerName << ">";
    }
    std::cerr << std::endl;

    // Show instruction bytes at PC
    std::vector<uint8_t> buf( 4 );
    if (uc_mem_read( uc, pc, buf.data(), buf.size() ) == UC_ERR_OK)
    {
        std::cerr << "Instruction: ";
        for (auto b : buf)
            std::fprintf( stderr, "%02x ", b );
        std::cerr << std::endl;
    }

    // Show call stack
    if (emu && emu->m_debugger)
    {
        std::cerr << "\nCall stack:" << std::endl;
        std::cerr << "  #0  0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << pc;

        const std::optional<std::string> pcName{ emu->m_loader.get_symbol_name_for_va(
            pc, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
        if (pcName.has_value())
            std::cerr << " <" << *pcName << ">";
        std::cerr << std::endl;

        std::vector<uint32_t> addresses = emu->m_debugger->get_callstack_addresses( 10 );
        for (size_t i = 0; i < addresses.size(); i++)
        {
            std::cerr << "  #" << ( i + 1 ) << "  0x" << std::hex << std::setfill( '0' ) << std::setw( 8 )
                      << addresses[i];
            const std::optional<std::string> funcName{ emu->m_loader.get_symbol_name_for_va(
                addresses[i], LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
            if (funcName.has_value())
                std::cerr << " <" << *funcName << ">";
            std::cerr << std::endl;
        }
    }
    std::cerr << std::dec << std::endl;
#endif
}

#ifdef DEBUG
static std::string format_arg_value( uc_engine *uc, uint32_t argValue )
{
    std::ostringstream oss;
    oss << "0x" << std::hex << argValue;

    // Try to read as string if it looks like a pointer
    if (argValue >= 0x1000 && argValue < 0xF0000000)
    {
        constexpr size_t maxCheck = 64;
        char buffer[maxCheck + 1];
        uc_err err = uc_mem_read( uc, argValue, buffer, maxCheck );
        if (err == UC_ERR_OK)
        {
            buffer[maxCheck] = '\0';
            bool isAscii = true;
            size_t len = 0;
            for (len = 0; len < maxCheck && buffer[len] != '\0'; len++)
            {
                char c = buffer[len];
                if (c < 0x20 || c > 0x7E)
                {
                    isAscii = false;
                    break;
                }
            }
            if (isAscii && len > 0 && len <= maxCheck)
            {
                oss << " (\"";
                oss.write( buffer, len );
                oss << "\")";
            }
        }
    }
    return oss.str();
}

static void print_api_call_source( uc_engine *uc, uint64_t address, size_t idx, COsxPpcEmu *emu )
{
    // Build callstack string (API <- caller <- caller's caller <- ...)
    std::ostringstream callstack;

    // Add API name
    if (idx == import::Unknown_Import_Index)
    {
        callstack << "0x" << std::hex << address << " (unknown)";
    }
    else if (idx - import::Unknown_Import_Shift < import::Known_Import_Names.size())
    {
        const size_t apiIdx = idx - import::Unknown_Import_Shift;
        callstack << import::Known_Import_Names[apiIdx];
    }
    else
    {
        std::cerr << "Could not read API name." << std::endl;
        return;
    }

    // Get callstack addresses using debugger utility
    if (emu->m_debugger)
    {
        std::vector<uint32_t> addresses = emu->m_debugger->get_callstack_addresses( 10 );

        for (uint32_t addr : addresses)
        {
            callstack << " <- ";
            const std::optional<std::string> funcName{ emu->m_loader.get_symbol_name_for_va(
                addr, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
            if (funcName.has_value())
                callstack << *funcName << "[0x" << std::hex << addr << "]";
            else
                callstack << "0x" << std::hex << addr;
        }
    }

    // Print header with callstack
    std::cout << "┌─ " << callstack.str() << std::dec << std::endl;

    // Print arguments
    if (idx != import::Unknown_Import_Index && idx - import::Unknown_Import_Shift < import::Known_Import_Names.size())
    {
        const size_t apiIdx = idx - import::Unknown_Import_Shift;
        const int argCount = import::Import_Arg_Counts[apiIdx];
        const int regsToRead = ( argCount == -1 ) ? 8 : argCount;

        for (int i = 0; i < regsToRead; i++)
        {
            uint32_t argValue;
            if (uc_reg_read( uc, UC_PPC_REG_3 + i, &argValue ) == UC_ERR_OK)
            {
                std::cout << "│  arg" << i << ": " << format_arg_value( uc, argValue ) << std::endl;
            }
        }
    }
}

static void print_api_return( uc_engine *uc, size_t idx )
{
    if (idx == import::Unknown_Import_Index || idx - import::Unknown_Import_Shift >= import::Known_Import_Names.size())
    {
        return;
    }

    uint32_t retValue;
    if (uc_reg_read( uc, UC_PPC_REG_3, &retValue ) == UC_ERR_OK)
    {
        std::cout << "└─ return: " << format_arg_value( uc, retValue ) << std::endl;
    }
}

static void print_context( uc_engine *uc )
{
    uint32_t pc{};
    uc_reg_read( uc, UC_PPC_REG_PC, &pc );
    uint32_t pcOpcodeBe{};
    uc_mem_read( uc, pc, &pcOpcodeBe, sizeof( pcOpcodeBe ) );
    uint32_t pcOpcodeHost{ common::ensure_endianness( pcOpcodeBe, std::endian::big ) };
    std::cout << "PC=0x" << std::hex << pc << " -> 0x" << pcOpcodeHost << std::endl;

    for (size_t i{ UC_PPC_REG_0 }; i < UC_PPC_REG_31; i++)
    {
        uint32_t reg{};
        uc_reg_read( uc, static_cast<int>( i ), &reg );
        std::cout << "R" << std::dec << i - 2 << "=0x" << std::hex << reg << " ";
        if (i % 10 == 0)
            std::cout << std::endl;
    }
    std::cout << std::endl;
    uint32_t reg{};
    uc_reg_read( uc, UC_PPC_REG_LR, &reg );
    std::cout << "LR=0x" << std::hex << reg << std::endl;
    uc_reg_read( uc, UC_PPC_REG_XER, &reg );
    std::cout << "XER=0x" << std::hex << reg << std::endl;
    uc_reg_read( uc, UC_PPC_REG_CTR, &reg );
    std::cout << "CTR=0x" << std::hex << reg << std::endl;
    uc_reg_read( uc, UC_PPC_REG_MSR, &reg );
    std::cout << "MSR=0x" << std::hex << reg << std::endl;
    uc_reg_read( uc, UC_PPC_REG_FPSCR, &reg );
    std::cout << "FPSCR=0x" << std::hex << reg << std::endl;
    uc_reg_read( uc, UC_PPC_REG_CR, &reg );
    std::cout << "CR=0x" << std::hex << reg << std::endl;
}

void hook_watchpoint( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data )
{
    // Only interested in writes
    if (type != UC_MEM_WRITE && type != UC_MEM_WRITE_UNMAPPED && type != UC_MEM_WRITE_PROT)
        return;

    COsxPpcEmu *emu = static_cast<COsxPpcEmu *>( user_data );
    if (!emu || !emu->m_debugger)
        return;

    // Check if this write hits a watchpoint
    if (emu->m_debugger->check_watchpoint_write( static_cast<uint32_t>( address ), static_cast<size_t>( size ),
                                                 static_cast<uint64_t>( value ) ))
    {
        // Watchpoint hit - enter interactive mode
        bool gdb_active = emu->m_gdb_server && emu->m_gdb_server->is_running();

        if (gdb_active)
        {
            emu->m_gdb_server->notify_breakpoint( static_cast<uint32_t>( address ) );
            emu->m_gdb_server->wait_for_continue();
        }
        else
        {
            emu->m_debugger->interactive_prompt();
        }
    }
}

void hook_debug( uc_engine *uc, uint64_t address, uint32_t size, COsxPpcEmu *emu )
{
    // Early exit if debugger is not active (no breakpoints or stepping)
    // This keeps overhead minimal when debugger is not in use
    if (!emu || !emu->m_debugger || !emu->m_debugger->is_active())
        return;

    // Check if GDB server is waiting for execution to stop
    bool gdb_active = emu->m_gdb_server && emu->m_gdb_server->is_running();

    if (emu->m_debugger->should_break( static_cast<uint32_t>( address ) ))
    {
        // Notify GDB server if it's running
        if (gdb_active)
        {
            // Check if it's a step or breakpoint
            if (emu->m_gdb_server->is_execution_stopped())
            {
                // Already stopped, wait for continue command
                emu->m_gdb_server->wait_for_continue();
                return;
            }

            std::cout << "[Debug Hook] Breaking at 0x" << std::hex << address << std::dec << std::endl;

            // Determine if this is a step or breakpoint
            if (emu->m_debugger->is_breakpoint( static_cast<uint32_t>( address ) ))
            {
                emu->m_gdb_server->notify_breakpoint( static_cast<uint32_t>( address ) );
            }
            else
            {
                // It's a step completion
                emu->m_gdb_server->notify_step_complete( static_cast<uint32_t>( address ) );
            }

            // Now wait for continue command from GDB client
            emu->m_gdb_server->wait_for_continue();
        }
        else
        {
            // Show interactive prompt - emulation will continue after user input
            emu->m_debugger->interactive_prompt();
        }
    }
}
#endif

} // namespace emu