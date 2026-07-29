/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     builds the guest import-dispatch table at common::Import_Dispatch_Table_Address
 **/
#include "ImportTable.hpp"
#include "DefaultRuneLocale.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace import::setup
{

namespace
{

std::string to_hex( std::uint32_t v )
{
    std::ostringstream oss;
    oss << "0x" << std::hex << v;
    return oss.str();
}

// GOT-slot target: an Indirect import's slot must contain the entry's own address
// (so the caller loads the pointer, then dereferences it a second time to reach ptrToData);
// a Direct import's slot must contain the address of the entry's data payload directly.
constexpr std::uint32_t got_target_address( std::uint32_t entryAddress, common::ImportType type )
{
    return type == common::ImportType::Indirect ? entryAddress : entryAddress + Import_Entry_Data_Offset;
}

} // namespace

std::expected<void, std::string> write_import_pointer( memory::CMemory &mem, std::uint32_t gotSlotAddress,
                                                       std::uint32_t importEntryAddress )
{
    if (!mem.check( gotSlotAddress, sizeof( importEntryAddress ) ))
        return std::unexpected( "cannot write import pointer at " + to_hex( gotSlotAddress ) +
                                " (unmapped or out of bounds)" );
    const std::uint32_t be{ common::ensure_endianness( importEntryAddress, std::endian::big ) };
    mem.write( gotSlotAddress, &be, sizeof( be ) );
    return {};
}

std::expected<void, std::string> write_import_entry( memory::CMemory &mem, std::uint32_t entryAddress,
                                                     const Runtime_Import_Table_Entry &entry )
{
    if (entry.ptrToData != 0)
    {
        if (!mem.check( entryAddress, sizeof( entry.ptrToData ) ))
            return std::unexpected( "cannot write import entry pointer at " + to_hex( entryAddress ) );
        const std::uint32_t be{ common::ensure_endianness( entry.ptrToData, std::endian::big ) };
        mem.write( entryAddress, &be, sizeof( be ) );
    }
    const std::uint32_t dataAddress{ entryAddress + Import_Entry_Data_Offset };
    if (!mem.check( dataAddress, entry.data.size() ))
        return std::unexpected( "cannot write import entry data at " + to_hex( dataAddress ) );
    mem.write( dataAddress, entry.data.data(), entry.data.size() );
    return {};
}

std::expected<void, std::string> write_unknown_import_entry( memory::CMemory &mem )
{
    const Runtime_Import_Table_Entry unknownImportEntry{
        .ptrToData = common::Import_Dispatch_Table_Address + Import_Entry_Data_Offset, // points in memory
        .data{ data::Blr_Opcode },                                                    // <- here
    };
    if (auto res{ write_import_entry( mem, common::Import_Dispatch_Table_Address, unknownImportEntry ) }; !res)
        return std::unexpected( "could not write first API dispatch entry (unknown API): " + res.error() );
    return {};
}

std::expected<void, std::string> redirect_static_imports( std::span<const StaticImport> staticImports,
                                                          memory::CMemory &mem )
{
    for (const auto &[name, addressAndType] : staticImports)
    {
        const auto [gotSlotAddress, type] = addressAndType;
        const std::optional<std::size_t> idx{ find_known_import( name ) };
        const bool knownImport{ idx.has_value() };

        const std::uint32_t entryAddress{ knownImport ? import_entry_address( *idx )
                                                       : common::Import_Dispatch_Table_Address };
        if (entryAddress + Import_Entry_Size > common::Import_Dispatch_Table_Address + Import_Table_Size)
            return std::unexpected( "not enough mapped memory for API trampoline for " + name );

        if (auto res{ write_import_pointer( mem, gotSlotAddress, got_target_address( entryAddress, type ) ) }; !res)
            return std::unexpected( "could not update pointer to API dispatch entry for " + name + " at " +
                                    to_hex( entryAddress ) + ": " + res.error() );

        if (knownImport)
        {
            // entry's own ptrToData always points at its data payload, regardless of `type`;
            // it is simply left at 0 (unused) when the GOT slot already points at the data directly.
            const std::uint32_t entryDataAddress{ entryAddress + Import_Entry_Data_Offset };
            const Runtime_Import_Table_Entry knownImportEntry{
                .ptrToData = type == common::ImportType::Indirect ? entryDataAddress : 0,
                .data{ All_Imports[*idx].second.data },
            };
            if (auto res{ write_import_entry( mem, entryAddress, knownImportEntry ) }; !res)
                return std::unexpected( "could not write API dispatch entry for " + name + " at " +
                                        to_hex( entryAddress ) + ": " + res.error() );
        }
    }
    return {};
}

std::expected<void, std::string> write_dynamic_import_entries( memory::CMemory &mem )
{
    for (const std::string_view s : Dynamic_Imports_Names)
    {
        const std::optional<std::size_t> idx{ find_known_import( s ) };
        if (!idx)
            return std::unexpected( "missing dynamic import entry for " + std::string{ s } );

        const std::uint32_t entryAddress{ import_entry_address( *idx ) };
        const Runtime_Import_Table_Entry knownImportEntry{
            .ptrToData = 0,
            .data{ All_Imports[*idx].second.data },
        };
        if (auto res{ write_import_entry( mem, entryAddress, knownImportEntry ) }; !res)
            return std::unexpected( "could not write API dispatch entry for " + std::string{ s } + " at " +
                                    to_hex( entryAddress ) + ": " + res.error() );
    }
    return {};
}

std::expected<void, std::string> init_default_rune_locale( std::span<const StaticImport> staticImports,
                                                           memory::CMemory &mem )
{
    const auto importIt{ std::ranges::find_if(
        staticImports, []( const auto &imp ) { return imp.first == "__DefaultRuneLocale"; } ) };
    if (importIt == staticImports.end())
        return {};
    const std::uint32_t symbolAddress{ importIt->second.first };

    const std::uint32_t runeLocaleAddr{ mem.heap_alloc( data::Default_Rune_Locale.size() ) };
    if (runeLocaleAddr == 0)
        return std::unexpected( "could not allocate memory for __DefaultRuneLocale" );

    if (!mem.check( runeLocaleAddr, data::Default_Rune_Locale.size() ))
        return std::unexpected( "could not write __DefaultRuneLocale table at " + to_hex( runeLocaleAddr ) );
    mem.write( runeLocaleAddr, data::Default_Rune_Locale.data(), data::Default_Rune_Locale.size() );

    if (auto res{ write_import_pointer( mem, symbolAddress, runeLocaleAddr ) }; !res)
        return std::unexpected( "could not write __DefaultRuneLocale pointer: " + res.error() );
    return {};
}

std::expected<void, std::string> build_import_table( std::span<const StaticImport> staticImports,
                                                     memory::CMemory &mem )
{
    if (!mem.commit( common::Import_Dispatch_Table_Address, common::page_align_up( Import_Table_Size ), UC_PROT_ALL ))
        return std::unexpected( "could not map import entries memory" );

    // first import is always "unknown API" entry at 0xF0000000
    if (auto res{ write_unknown_import_entry( mem ) }; !res)
        return res;
    // then known static imports (got by parsing MachO) are resolved and import entries table filled
    if (auto res{ redirect_static_imports( staticImports, mem ) }; !res)
        return res;
    // then fill entries for dynamic imports (e.g. using dyld_lookup_func)
    if (auto res{ write_dynamic_import_entries( mem ) }; !res)
        return res;
    // initialize __DefaultRuneLocale_ptr with a valid locale table
    if (auto res{ init_default_rune_locale( staticImports, mem ) }; !res)
        return res;
    return {};
}

} // namespace import::setup


