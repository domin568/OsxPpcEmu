/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     builds the guest import-dispatch table at common::Import_Dispatch_Table_Address
 **/
#pragma once

#include "CMemory.hpp"
#include "Common.hpp"
#include "Expected.hpp"
#include "ImportDispatch.hpp"

#include <span>
#include <string>
#include <utility>

namespace import::setup
{

// One static import as produced by CMachoLoader::get_imports().
using StaticImport = std::pair<std::string, std::pair<std::uint32_t, common::ImportType>>;

/**
 * Commits the import-dispatch region and fills it:
 *   [0]            -> "unknown import" sentinel (blr)
 *   [1 .. N]       -> one slot per entry of import::All_Imports
 * then patches every GOT slot named by `staticImports` to point at its slot,
 * fills the slots reachable only through dyld_func_lookup, and initialises
 * __DefaultRuneLocale.
 */
compat::expected<void, std::string> build_import_table( std::span<const StaticImport> staticImports,
                                                     memory::CMemory &mem );

// ── exposed for unit tests / reuse ──────────────────────────────────────
compat::expected<void, std::string> write_unknown_import_entry( memory::CMemory &mem );
compat::expected<void, std::string> redirect_static_imports( std::span<const StaticImport> staticImports,
                                                          memory::CMemory &mem );
compat::expected<void, std::string> write_dynamic_import_entries( memory::CMemory &mem );
compat::expected<void, std::string> init_default_rune_locale( std::span<const StaticImport> staticImports,
                                                           memory::CMemory &mem );

compat::expected<void, std::string> write_import_entry( memory::CMemory &mem, std::uint32_t entryAddress,
                                                     const Runtime_Import_Table_Entry &entry );
compat::expected<void, std::string> write_import_pointer( memory::CMemory &mem, std::uint32_t gotSlotAddress,
                                                       std::uint32_t importEntryAddress );

} // namespace import::setup
