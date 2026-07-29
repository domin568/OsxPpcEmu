/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     Unit tests for import::setup (ImportTable.hpp) and the ImportDispatch.hpp helpers
 *            it depends on (find_known_import, import_entry_address, Import_Entry_Data_Offset).
 **/
#include "DefaultRuneLocale.hpp"
#include "ImportTable.hpp"

#include <gtest/gtest.h>

namespace
{

std::uint32_t read_u32_be( void *hostPtr )
{
    std::uint32_t v{};
    std::memcpy( &v, hostPtr, sizeof( v ) );
    return common::ensure_endianness( v, std::endian::big );
}

struct EmuMemoryFixture : ::testing::Test
{
    uc_engine *uc{ nullptr };
    std::optional<memory::CMemory> mem{};

    void SetUp() override
    {
        const uc_mode ppcMode{ static_cast<uc_mode>( UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN ) };
        ASSERT_EQ( uc_open( UC_ARCH_PPC, ppcMode, &uc ), UC_ERR_OK );
        auto memRes{ memory::CMemory::init( uc, common::Guest_Virtual_Memory_Size ) };
        ASSERT_TRUE( memRes.has_value() );
        mem.emplace( std::move( *memRes ) );
        ASSERT_TRUE( mem->initialize_heap() );
    }

    void TearDown() override
    {
        mem.reset();
        if (uc)
            uc_close( uc );
    }
};

} // namespace

// ── pure helpers (ImportDispatch.hpp), no Unicorn required ─────────────

TEST( ImportTable, FindKnownImportFindsMalloc )
{
    const std::optional<std::size_t> idx{ import::find_known_import( "_malloc" ) };
    ASSERT_TRUE( idx.has_value() );
    EXPECT_EQ( import::All_Imports[*idx].first, "_malloc" );
}

TEST( ImportTable, FindKnownImportRejectsUnknownName )
{
    EXPECT_FALSE( import::find_known_import( "_definitely_not_a_known_import" ).has_value() );
}

TEST( ImportTable, FindKnownImportAgreesWithLinearScan )
{
    for (std::size_t i{ 0 }; i < import::All_Imports.size(); ++i)
    {
        const std::string_view name{ import::All_Imports[i].first };
        const std::optional<std::size_t> idx{ import::find_known_import( name ) };
        ASSERT_TRUE( idx.has_value() ) << name;
        EXPECT_EQ( *idx, i ) << name;
    }
}

TEST( ImportTable, ImportEntryAddressSlotZeroIsSentinelPlusOne )
{
    EXPECT_EQ( import::import_entry_address( 0 ), common::Import_Dispatch_Table_Address + import::Import_Entry_Size );
}

TEST( ImportTable, ImportEntryAddressLastSlotFitsInTable )
{
    const std::size_t lastIdx{ import::All_Imports.size() - 1 };
    EXPECT_LE( import::import_entry_address( lastIdx ) + import::Import_Entry_Size,
               common::Import_Dispatch_Table_Address + import::Import_Table_Size );
}

TEST( ImportTable, GetImportEntryVaByNameAgreesWithImportEntryAddress )
{
    for (const auto &[name, entry] : import::All_Imports)
    {
        const std::optional<std::uint32_t> va{ common::get_import_entry_va_by_name( std::string{ name } ) };
        ASSERT_TRUE( va.has_value() ) << name;
        const std::optional<std::size_t> idx{ import::find_known_import( name ) };
        ASSERT_TRUE( idx.has_value() ) << name;
        EXPECT_EQ( *va, import::import_entry_address( *idx ) ) << name;
    }
}

TEST_F( EmuMemoryFixture, BuildImportTableWritesUnknownEntrySentinel )
{
    const std::vector<import::setup::StaticImport> noStaticImports{};
    const auto result{ import::setup::build_import_table( noStaticImports, *mem ) };
    ASSERT_TRUE( result.has_value() ) << ( result.has_value() ? "" : result.error() );

    // slot 0 (unknown import): ptrToData == Import_Dispatch_Table_Address + 4, data == Blr_Opcode
    void *slot0{ mem->get( common::Import_Dispatch_Table_Address ) };
    EXPECT_EQ( read_u32_be( slot0 ), common::Import_Dispatch_Table_Address + import::Import_Entry_Data_Offset );

    void *slot0Data{ mem->get( common::Import_Dispatch_Table_Address + import::Import_Entry_Data_Offset ) };
    EXPECT_EQ( std::memcmp( slot0Data, import::data::Blr_Opcode.data(), import::data::Blr_Opcode.size() ), 0 );
}

TEST_F( EmuMemoryFixture, BuildImportTableRedirectsIndirectStaticImport )
{
    // Pick a GOT slot address inside the already-committed heap region so mem.get() is valid.
    const std::uint32_t gotSlotAddress{ mem->heap_alloc( sizeof( std::uint32_t ) ) };
    ASSERT_NE( gotSlotAddress, 0u );

    const std::optional<std::size_t> mallocIdx{ import::find_known_import( "_malloc" ) };
    ASSERT_TRUE( mallocIdx.has_value() );

    const std::vector<import::setup::StaticImport> staticImports{
        { "_malloc", { gotSlotAddress, common::ImportType::Indirect } },
    };
    const auto result{ import::setup::build_import_table( staticImports, *mem ) };
    ASSERT_TRUE( result.has_value() ) << ( result.has_value() ? "" : result.error() );

    const std::uint32_t expectedEntryAddress{ import::import_entry_address( *mallocIdx ) };
    void *gotSlot{ mem->get( gotSlotAddress ) };
    EXPECT_EQ( read_u32_be( gotSlot ), expectedEntryAddress );

    // entry's own ptrToData must point at its data payload (Indirect case)
    void *entrySlot{ mem->get( expectedEntryAddress ) };
    EXPECT_EQ( read_u32_be( entrySlot ), expectedEntryAddress + import::Import_Entry_Data_Offset );
}

TEST_F( EmuMemoryFixture, BuildImportTableRedirectsDirectStaticImport )
{
    const std::uint32_t gotSlotAddress{ mem->heap_alloc( sizeof( std::uint32_t ) ) };
    ASSERT_NE( gotSlotAddress, 0u );

    const std::optional<std::size_t> mallocIdx{ import::find_known_import( "_malloc" ) };
    ASSERT_TRUE( mallocIdx.has_value() );

    const std::vector<import::setup::StaticImport> staticImports{
        { "_malloc", { gotSlotAddress, common::ImportType::Direct } },
    };
    const auto result{ import::setup::build_import_table( staticImports, *mem ) };
    ASSERT_TRUE( result.has_value() ) << ( result.has_value() ? "" : result.error() );

    const std::uint32_t expectedEntryAddress{ import::import_entry_address( *mallocIdx ) };
    // Direct: GOT slot points straight at the entry's data payload.
    void *gotSlot{ mem->get( gotSlotAddress ) };
    EXPECT_EQ( read_u32_be( gotSlot ), expectedEntryAddress + import::Import_Entry_Data_Offset );
}

TEST_F( EmuMemoryFixture, BuildImportTableWritesDynamicImportEntries )
{
    const std::vector<import::setup::StaticImport> noStaticImports{};
    const auto result{ import::setup::build_import_table( noStaticImports, *mem ) };
    ASSERT_TRUE( result.has_value() ) << ( result.has_value() ? "" : result.error() );

    for (const std::string_view dynName : import::Dynamic_Imports_Names)
    {
        const std::optional<std::size_t> idx{ import::find_known_import( dynName ) };
        ASSERT_TRUE( idx.has_value() ) << dynName;
        const std::uint32_t entryAddress{ import::import_entry_address( *idx ) };
        void *dataSlot{ mem->get( entryAddress + import::Import_Entry_Data_Offset ) };
        EXPECT_EQ( std::memcmp( dataSlot, import::All_Imports[*idx].second.data.data(),
                                import::All_Imports[*idx].second.data.size() ),
                   0 )
            << dynName;
    }
}

TEST_F( EmuMemoryFixture, InitDefaultRuneLocaleWritesBlobAndPointer )
{
    const std::uint32_t symbolAddress{ mem->heap_alloc( sizeof( std::uint32_t ) ) };
    ASSERT_NE( symbolAddress, 0u );

    const std::vector<import::setup::StaticImport> staticImports{
        { "__DefaultRuneLocale", { symbolAddress, common::ImportType::Indirect } },
    };
    const auto result{ import::setup::init_default_rune_locale( staticImports, *mem ) };
    ASSERT_TRUE( result.has_value() ) << ( result.has_value() ? "" : result.error() );

    void *symbolSlot{ mem->get( symbolAddress ) };
    const std::uint32_t runeLocaleAddr{ read_u32_be( symbolSlot ) };
    ASSERT_NE( runeLocaleAddr, 0u );

    void *runeLocaleData{ mem->get( runeLocaleAddr ) };
    EXPECT_EQ( std::memcmp( runeLocaleData, import::data::Default_Rune_Locale.data(),
                            import::data::Default_Rune_Locale.size() ),
               0 );
}

TEST_F( EmuMemoryFixture, InitDefaultRuneLocaleNoOpWhenSymbolNotImported )
{
    const std::vector<import::setup::StaticImport> staticImports{};
    const auto result{ import::setup::init_default_rune_locale( staticImports, *mem ) };
    EXPECT_TRUE( result.has_value() ) << ( result.has_value() ? "" : result.error() );
}
