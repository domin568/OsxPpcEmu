/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Emulator for Mach-O PowerPC object files
 **/

#include "../include/COsxPpcEmu.hpp"
#include "../include/CMachoLoader.hpp"
#include "../include/Common.hpp"
#include "../include/ImportDispatch.hpp"
#include <filesystem>
#include <iostream>
#include <ranges>

std::atomic<uint32_t> g_lastAddr{ 0 };

COsxPpcEmu::COsxPpcEmu( uc_engine *uc, CMachoLoader &&loader ) : m_uc( uc ), m_loader( std::move( loader ) )
{
}

std::expected<COsxPpcEmu, common::Error> COsxPpcEmu::init( int argc, const char **argv,
                                                           const std::span<const std::string> env )
{
    if (argc < 2 || argv == nullptr || env.data() == nullptr)
        return std::unexpected(
            common::Error{ common::Error::Type::Argument_Parsing_Error, "Could not parse command line arguments" } );

    const std::vector<std::string> args( argv, argv + argc );
    const std::string &emuTarget{ args[1] };
    if (!std::filesystem::exists( emuTarget ))
        return std::unexpected( common::Error{ common::Error::Type::NotFound, "File not found." } );

    std::expected<CMachoLoader, common::Error> loader{ CMachoLoader::init( emuTarget ) };
    if (!loader)
        return std::unexpected{ std::move( loader ).error() };

    uc_err err;
    uc_engine *uc;
    uc_mode ppcMode{ static_cast<uc_mode>( UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN ) };
    err = uc_open( UC_ARCH_PPC, ppcMode, &uc );
    if (err != UC_ERR_OK)
        return std::unexpected(
            common::Error{ common::Error::Type::Unicorn_Open_Error, "Could not create ppc32 unicorn emulator." } );

    if (!loader->map_image_memory( uc ))
        return std::unexpected( common::Error{ common::Error::Type::Memory_Map_Error, "Could not map memory." } );

    if (!loader->set_unix_thread( uc ))
        return std::unexpected{
            common::Error{ common::Error::Type::No_Unix_Thread_Command_Error, "Could not set Unix thread context." } };

    const std::optional<import::Import_Dispatch_Data> redirectApiData{ resolve_imports( uc, *loader ) };
    if (!redirectApiData)
        return std::unexpected{
            common::Error{ common::Error::Type::Redirect_Api_Error, "Could not set up API calls." } };

    if (!set_stack( uc, args, env ))
        return std::unexpected( common::Error{ common::Error::Type::Stack_Map_Error, "Could not map memory." } );

    return COsxPpcEmu{ uc, std::move( loader.value() ) };
}

bool COsxPpcEmu::print_vm_map( std::ostream &os )
{
    uc_mem_region *regions;
    uint32_t count{};
    if (uc_mem_regions( m_uc, &regions, &count ) != UC_ERR_OK)
        return false;

    for (uint32_t i = 0; i < count; i++)
    {
        const auto &r = regions[i];

        os << std::hex << " [0x" << r.begin << " - 0x" << r.end << "]"
           << " perms=";
        if (r.perms & UC_PROT_READ)
            os << "R";
        if (r.perms & UC_PROT_WRITE)
            os << "W";
        if (r.perms & UC_PROT_EXEC)
            os << "X";
        os << "\n";
    }
    return true;
}

bool COsxPpcEmu::run()
{
    const std::optional<std::pair<uint64_t, uint64_t>> textSegment{ m_loader.get_text_segment_va_range() };
    if (!textSegment.has_value())
        return false;
    const auto [textSegStart, textSegEnd]{ *textSegment };

    uc_err errApiHook{ uc_hook_add( m_uc, &m_instructionHook, UC_HOOK_CODE, reinterpret_cast<void *>( hook_code ), this,
                                    Import_Dispatch_Table_Address,
                                    Import_Dispatch_Table_Address + import::Import_Table_Size ) };
    uc_err errIntHook{ uc_hook_add( m_uc, &m_interruptHook, UC_HOOK_INTR, reinterpret_cast<void *>( hook_intr ),
                                    nullptr, textSegStart, textSegEnd ) }; // delete reinterpret cast

    uc_err errMemInvalidHook{ uc_hook_add( m_uc, &m_memInvalidHook, UC_HOOK_MEM_INVALID,
                                           reinterpret_cast<void *>( hook_mem_invalid ), nullptr, 1, 0 ) };

    if (errApiHook != UC_ERR_OK && errIntHook != UC_ERR_OK && errMemInvalidHook != UC_ERR_OK)
    {
        std::cerr << "Could not create hooks." << std::endl;
        return false;
    }
    return uc_emu_start( m_uc, m_loader.get_ep(), textSegEnd, 0, 0 ) == UC_ERR_OK;
}

bool COsxPpcEmu::set_stack( uc_engine *uc, const std::span<const std::string> args,
                            const std::span<const std::string> env )
{
    uc_err err{ uc_reg_write( uc, UC_PPC_REG_1, &Stack_Dyld_Region_Start_Address ) };
    if (err != UC_ERR_OK)
    {
        std::cerr << "Could not set stack register R1." << std::endl;
        return false;
    }

    err = uc_mem_map( uc, Stack_Region_Start_Address, Stack_Size, UC_PROT_ALL );
    if (err != UC_ERR_OK)
    {
        std::cerr << "Could not map stack region." << std::endl;
        return false;
    }

    if (!set_args_on_stack( uc, args, env ))
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
                                    const std::span<const std::string> env )
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
        const uint32_t address{
            static_cast<uint32_t>( Stack_Dyld_Region_Start_Address + stringAreaOffset + targetArgOffsets[idx] ) };
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
            static_cast<uint32_t>( Stack_Dyld_Region_Start_Address + stringAreaOffset + envOffsets[idx] ) };
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

    if (stackData.size() > Stack_Dyld_Region_Size)
    {
        std::cerr << "Dyld stack is too small, size: " << std::hex << stackData.size() << std::endl;
        return false;
    }
    uc_err err{ uc_mem_write( uc, Stack_Dyld_Region_Start_Address, stackData.data(), stackData.size() ) };
    if (err != UC_ERR_OK)
    {
        std::cerr << "Could not write commandline arguments onto stack, size: " << std::hex << stackData.size()
                  << std::endl;
        return false;
    }
    return true;
}

bool COsxPpcEmu::resolve_imports( uc_engine *uc, CMachoLoader &loader )
{
    const std::expected<std::map<std::string, uint32_t>, common::Error> importFncPtrs{ loader.get_import_ptrs() };
    if (!importFncPtrs)
    {
        std::cerr << importFncPtrs.error().message << std::endl;
        return false;
    }

    uc_err err{ uc_mem_map( uc, Import_Dispatch_Table_Address, common::page_align_up( import::Import_Table_Size ),
                            UC_PROT_ALL ) };
    if (err != UC_ERR_OK)
    {
        std::cerr << "Could not map api trampoline memory." << std::endl;
        return false;
    }

    // first API is always "unknown API" entry
    import::Import_Entry unknownImportEntry{
        .ptrToData = Import_Dispatch_Table_Address + sizeof( import::Import_Entry::ptrToData ), // points in memory
        .data{ import::Blr_Opcode },                                                            // <- here
    };
    if (!write_import_entry( uc, Import_Dispatch_Table_Address, unknownImportEntry ))
    {
        std::cerr << "Could not write first API dispatch entry (unknown API) at " << std::hex
                  << Import_Dispatch_Table_Address << std::endl;
        return false;
    }

    for (const auto &[name, address] : *importFncPtrs)
    {
        auto importNameMatches{
            [&name]( const std::pair<std::string_view, import::Import_Item> &p ) { return p.first == name; } };
        const auto importIt{
            std::ranges::find_if( import::Name_To_Import_Item_Flat, importNameMatches ) }; // O(n), index matters
        const bool knownImport{ importIt != import::Name_To_Import_Item_Flat.end() };
        const ptrdiff_t idx{ std::distance( import::Name_To_Import_Item_Flat.begin(), importIt ) };

        const uint32_t currentImportEntryOffset{
            knownImport ? Import_Dispatch_Table_Address + static_cast<uint32_t>( idx ) * import::Import_Entry_Size
                        : Import_Dispatch_Table_Address };
        if (currentImportEntryOffset + import::Import_Entry_Size >
            Import_Dispatch_Table_Address + import::Import_Table_Size)
        {
            std::cerr << "Not enough mapped memory for API trampoline." << std::endl;
            return false;
        }

        if (!patch_import_indirect_ptr( uc, currentImportEntryOffset, address ))
        {
            std::cerr << "Could not update pointer to API dispatch entry for " << name << " at " << std::hex
                      << currentImportEntryOffset << std::endl;
            return false;
        }
        if (knownImport)
        {
            import::Import_Entry knownImportEntry{
                .ptrToData =
                    currentImportEntryOffset + static_cast<uint32_t>( sizeof( import::Import_Entry::ptrToData ) ),
                // points in memory, e.g. 0xF0000004
                .data{ importIt->second.data }, // <- here
            };
            if (!write_import_entry( uc, currentImportEntryOffset, knownImportEntry ))
            {
                std::cerr << "Could not write API dispatch entry for " << name << " at " << std::hex
                          << currentImportEntryOffset << std::endl;
                return false;
            }
        }
    }
    return true;
}

bool COsxPpcEmu::write_import_entry( uc_engine *uc, size_t offset, const import::Import_Entry &entry )
{
    const uint32_t ptrToDataBe{
        common::ensure_endianness( static_cast<uint32_t>( entry.ptrToData ), std::endian::big ) };
    uc_err err{ uc_mem_write( uc, offset, &ptrToDataBe, sizeof( ptrToDataBe ) ) };
    if (err != UC_ERR_OK)
        return false;
    err = uc_mem_write( uc, offset + sizeof( ptrToDataBe ), entry.data.data(), entry.data.size() );
    return err == UC_ERR_OK;
}

bool COsxPpcEmu::patch_import_indirect_ptr( uc_engine *uc, size_t importEntryOffset, uint32_t symbolAddress )
{
    // e.g. 0xF0000000
    uint32_t ptrToImportData{
        common::ensure_endianness( static_cast<uint32_t>( importEntryOffset ), std::endian::big ) };
    uc_err err{ uc_mem_write( uc, symbolAddress, &ptrToImportData, sizeof( ptrToImportData ) ) };
    return err == UC_ERR_OK;
}

std::optional<size_t> COsxPpcEmu::get_max_import_data_size(
    const std::span<const std::pair<std::string_view, import::Import_Item>> &knownImports )
{
    if (knownImports.empty())
        return std::nullopt;
    const auto values{ knownImports | std::views::values };
    size_t max{ 0 };
    for (const auto &val : values)
    {
        if (val.data.size() > max)
            max = val.data.size();
    }
    return max;
}

void hook_code( uc_engine *uc, uint64_t address, uint32_t size, COsxPpcEmu *emu )
{
    const size_t idx{ ( address - emu->Import_Dispatch_Table_Address ) >> import::Import_Entry_Size_Pow2 };
#ifdef DEBUG
    g_lastAddr.store( address, std::memory_order_relaxed );

    uint32_t callerVa{};
    uc_err err{ uc_reg_read( uc, UC_PPC_REG_LR, &callerVa ) };
    if (err != UC_ERR_OK)
    {
        std::cerr << "Could not read caller function address." << std::endl;
        return;
    }

    std::cout << callerVa;
    const std::optional<std::string> funcName{ emu->m_loader.get_symbol_name_for_va(
        callerVa, LIEF::MachO::Symbol::TYPE::SECTION, CMachoLoader::SymbolSection::TEXT ) };
    if (funcName.has_value())
        std::cout << " (" << *funcName << ")";
    std::cout << " -> 0x" << std::hex << address;

    if (idx >= import::Known_Import_Names.size())
    {
        std::cerr << std::endl << "Could not read API name." << std::endl;
        return;
    }
    std::cout << " (" << import::Known_Import_Names[idx] << ")" << std::endl;
#endif

    import::Import_Items[idx].hook( uc );
}

void hook_intr( uc_engine *uc, uint32_t intno, void *user_data )
{
    uint32_t addr{ g_lastAddr.load() };
    // std::cout << ">>> interrupt/exception #" << intno << std::endl;
    std::cout << "addr = " << std::hex << addr << std::endl;
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
}

void hook_mem_invalid( uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data )
{
    std::cerr << "MEM_INVALID type=" << type << " @ 0x" << std::hex << address << " size=" << size << std::dec << "\n";
}