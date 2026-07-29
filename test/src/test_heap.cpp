/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     Unit tests for memory::CHeap
 **/
#include "CMemory.hpp"

#include <gtest/gtest.h>
#include <iostream>
#include <random>
#include <vector>

namespace
{

struct HeapFixture : ::testing::Test
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

    void drain_quarantine()
    {
        for (int i{ 0 }; i < 8; ++i)
        {
            const std::uint32_t filler{ mem->heap_alloc( 1u << 20 ) }; // 1 MiB
            ASSERT_NE( filler, 0u );
            ASSERT_TRUE( mem->heap_free( filler ) );
        }
    }
};

} // namespace

// ── heap mode name/parse round-trip ─────────────────────────────────────

TEST( HeapModeString, RoundTripsAndRejectsGarbage )
{
    for (common::HeapMode m : { common::HeapMode::Bump, common::HeapMode::Quarantine, common::HeapMode::Real })
    {
        const std::string_view name{ common::heap_mode_name( m ) };
        const std::optional<common::HeapMode> parsed{ common::heap_mode_from_string( name ) };
        ASSERT_TRUE( parsed.has_value() );
        EXPECT_EQ( *parsed, m );
    }
    EXPECT_FALSE( common::heap_mode_from_string( "not-a-mode" ).has_value() );
    EXPECT_FALSE( common::heap_mode_from_string( "" ).has_value() );
    // Case-insensitive
    EXPECT_EQ( common::heap_mode_from_string( "BuMp" ), common::HeapMode::Bump );
}

// ── alignment / ABI ─────────────────────────────────────────────────────

TEST_F( HeapFixture, AllocationsAreSixteenByteAligned )
{
    for (std::size_t size : { 1u, 2u, 7u, 15u, 16u, 17u, 100u, 4096u })
    {
        const std::uint32_t p{ mem->heap_alloc( size ) };
        ASSERT_NE( p, 0u ) << size;
        EXPECT_EQ( p % 16, 0u ) << size;
    }
}

TEST_F( HeapFixture, AllocZeroReturnsUniqueNonNullBlock )
{
    const std::uint32_t a{ mem->heap_alloc( 0 ) };
    const std::uint32_t b{ mem->heap_alloc( 0 ) };
    ASSERT_NE( a, 0u );
    ASSERT_NE( b, 0u );
    EXPECT_NE( a, b );
}

// ── correctness ──────────────────────────────────────────────────────────

TEST_F( HeapFixture, FreeThenAllocReusesChunk )
{
    const std::uint32_t a{ mem->heap_alloc( 64 ) };
    ASSERT_NE( a, 0u );
    ASSERT_TRUE( mem->heap_free( a ) );
    drain_quarantine(); // force `a` out of quarantine so it becomes reusable
    const std::uint32_t b{ mem->heap_alloc( 64 ) };
    ASSERT_NE( b, 0u );
    EXPECT_EQ( a, b );
}

TEST_F( HeapFixture, FreeIsQuarantinedNotImmediatelyReusable )
{
    const std::uint32_t a{ mem->heap_alloc( 64 ) };
    ASSERT_NE( a, 0u );
    ASSERT_TRUE( mem->heap_free( a ) );
    // Immediately after free, `a` must not be handed back out - it's poisoned and quarantined,
    // which is what gives a stale-pointer bug a chance to be noticed instead of immediately
    // aliasing fresh data.
    const std::uint32_t b{ mem->heap_alloc( 64 ) };
    ASSERT_NE( b, 0u );
    EXPECT_NE( a, b );
    EXPECT_GT( mem->heap_stats().quarantineBytes, 0u );
}

TEST_F( HeapFixture, FreeingAdjacentChunksCoalesces )
{
    const std::uint32_t a{ mem->heap_alloc( 64 ) };
    const std::uint32_t b{ mem->heap_alloc( 64 ) };
    const std::uint32_t c{ mem->heap_alloc( 64 ) };
    ASSERT_NE( a, 0u );
    ASSERT_NE( b, 0u );
    ASSERT_NE( c, 0u );

    ASSERT_TRUE( mem->heap_free( a ) );
    ASSERT_TRUE( mem->heap_free( b ) );
    drain_quarantine(); // force a/b out of quarantine so they coalesce and become reusable

    // a+b coalesced should satisfy an allocation bigger than either alone, at address a.
    const std::uint32_t combined{ mem->heap_alloc( 64 + 64 + 16 /* header room from coalesced chunk */ ) };
    ASSERT_NE( combined, 0u );
    EXPECT_EQ( combined, a );

    ASSERT_TRUE( mem->heap_free( combined ) );
    ASSERT_TRUE( mem->heap_free( c ) );
}

TEST_F( HeapFixture, UsableSizeMatchesRequestRoundedUp )
{
    const std::uint32_t p{ mem->heap_alloc( 20 ) };
    ASSERT_NE( p, 0u );
    EXPECT_GE( mem->get_alloc_size( p ), 20u );
    EXPECT_EQ( mem->get_alloc_size( p ) % 16, 0u );
}

TEST_F( HeapFixture, ReallocGrowPreservesContents )
{
    const std::uint32_t p{ mem->heap_alloc( 16 ) };
    ASSERT_NE( p, 0u );
    auto *hostPtr{ static_cast<std::uint8_t *>( mem->get( p ) ) };
    for (int i{ 0 }; i < 16; ++i)
        hostPtr[i] = static_cast<std::uint8_t>( i );

    const std::uint32_t grown{ mem->heap_realloc( p, 256 ) };
    ASSERT_NE( grown, 0u );
    auto *grownHost{ static_cast<std::uint8_t *>( mem->get( grown ) ) };
    for (int i{ 0 }; i < 16; ++i)
        EXPECT_EQ( grownHost[i], static_cast<std::uint8_t>( i ) ) << i;
}

TEST_F( HeapFixture, ReallocShrinkPreservesContentsAndIsReusable )
{
    const std::uint32_t p{ mem->heap_alloc( 256 ) };
    ASSERT_NE( p, 0u );
    auto *hostPtr{ static_cast<std::uint8_t *>( mem->get( p ) ) };
    for (int i{ 0 }; i < 16; ++i)
        hostPtr[i] = static_cast<std::uint8_t>( i + 1 );

    const std::uint32_t shrunk{ mem->heap_realloc( p, 16 ) };
    ASSERT_NE( shrunk, 0u );
    EXPECT_EQ( shrunk, p );
    auto *shrunkHost{ static_cast<std::uint8_t *>( mem->get( shrunk ) ) };
    for (int i{ 0 }; i < 16; ++i)
        EXPECT_EQ( shrunkHost[i], static_cast<std::uint8_t>( i + 1 ) ) << i;

    // The remainder split off by the shrink must be usable.
    const std::uint32_t other{ mem->heap_alloc( 64 ) };
    EXPECT_NE( other, 0u );
}

TEST_F( HeapFixture, ReallocExpandsInPlaceWhenNextChunkFree )
{
    const std::uint32_t a{ mem->heap_alloc( 32 ) };
    const std::uint32_t b{ mem->heap_alloc( 32 ) };
    ASSERT_NE( a, 0u );
    ASSERT_NE( b, 0u );
    ASSERT_TRUE( mem->heap_free( b ) );
    drain_quarantine(); // force `b` out of quarantine so realloc(a, ...) can absorb it

    const std::uint32_t grown{ mem->heap_realloc( a, 48 ) };
    ASSERT_NE( grown, 0u );
    EXPECT_EQ( grown, a ) << "expected in-place expansion into the freed next chunk";
}

TEST_F( HeapFixture, ReallocNullBehavesLikeAlloc )
{
    const std::uint32_t p{ mem->heap_realloc( 0, 32 ) };
    EXPECT_NE( p, 0u );
}

TEST_F( HeapFixture, ReallocZeroSizeFreesAndReturnsZero )
{
    const std::uint32_t p{ mem->heap_alloc( 32 ) };
    ASSERT_NE( p, 0u );
    EXPECT_EQ( mem->heap_realloc( p, 0 ), 0u );
    EXPECT_FALSE( mem->heap_owns( p ) );
}

TEST_F( HeapFixture, RandomizedStressWalkStaysValid )
{
    std::mt19937 rng{ 1234 };
    std::uniform_int_distribution<int> sizeDist{ 1, 4096 };
    std::uniform_int_distribution<int> opDist{ 0, 2 };
    std::vector<std::uint32_t> live{};

    for (int i{ 0 }; i < 20000; ++i)
    {
        const int op{ live.empty() ? 0 : opDist( rng ) };
        if (op == 0)
        {
            const std::uint32_t p{ mem->heap_alloc( static_cast<std::size_t>( sizeDist( rng ) ) ) };
            if (p != 0)
                live.push_back( p );
        }
        else if (op == 1 && !live.empty())
        {
            std::uniform_int_distribution<std::size_t> idxDist{ 0, live.size() - 1 };
            const std::size_t idx{ idxDist( rng ) };
            ASSERT_TRUE( mem->heap_free( live[idx] ) );
            live.erase( live.begin() + static_cast<long>( idx ) );
        }
        else if (!live.empty())
        {
            std::uniform_int_distribution<std::size_t> idxDist{ 0, live.size() - 1 };
            const std::size_t idx{ idxDist( rng ) };
            const std::uint32_t newPtr{ mem->heap_realloc( live[idx], static_cast<std::size_t>( sizeDist( rng ) ) ) };
            ASSERT_NE( newPtr, 0u );
            live[idx] = newPtr;
        }
    }
}

// ── hostile input ────────────────────────────────────────────────────────

TEST_F( HeapFixture, DoubleFreeIsRefusedAndCounted )
{
    const std::uint32_t p{ mem->heap_alloc( 32 ) };
    ASSERT_NE( p, 0u );
    ASSERT_TRUE( mem->heap_free( p ) );
    EXPECT_FALSE( mem->heap_free( p ) );
    EXPECT_EQ( mem->heap_stats().doubleFrees, 1u );
}

TEST_F( HeapFixture, FreeOfNonHeapPointerIsRefused )
{
    EXPECT_FALSE( mem->heap_free( 0x1234 ) );
    EXPECT_GE( mem->heap_stats().invalidFrees, 1u );
}

TEST_F( HeapFixture, FreeOfMisalignedPointerIsRefused )
{
    const std::uint32_t p{ mem->heap_alloc( 64 ) };
    ASSERT_NE( p, 0u );
    EXPECT_FALSE( mem->heap_free( p + 1 ) );
}

TEST_F( HeapFixture, FreeNullIsNoOpSuccess )
{
    EXPECT_TRUE( mem->heap_free( 0 ) );
}

// ── growth ───────────────────────────────────────────────────────────────

TEST_F( HeapFixture, AllocationAcrossMultipleGrowthsSucceeds )
{
    // Heap_Initial_Commit is 1 MiB; force at least 3 growth boundaries.
    std::vector<std::uint32_t> blocks{};
    for (int i{ 0 }; i < 8; ++i)
    {
        const std::uint32_t p{ mem->heap_alloc( 1u << 20 ) }; // 1 MiB each
        ASSERT_NE( p, 0u ) << i;
        blocks.push_back( p );
    }
    EXPECT_GE( mem->heap_stats().growCount, 3u );
}

TEST_F( HeapFixture, ExhaustionReturnsZeroAndHeapStaysUsable )
{
    std::vector<std::uint32_t> blocks{};
    std::uint32_t p{};
    do
    {
        p = mem->heap_alloc( 1u << 22 ); // 4 MiB chunks
        if (p != 0)
            blocks.push_back( p );
    } while (p != 0 && blocks.size() < 100);

    ASSERT_FALSE( blocks.empty() );
    ASSERT_TRUE( mem->heap_free( blocks.front() ) );
    const std::uint32_t reused{ mem->heap_alloc( 64 ) };
    EXPECT_NE( reused, 0u );
}

// ── mode-parameterised: invariants that must hold under every mode ───────

namespace
{

struct HeapModeFixture : ::testing::TestWithParam<common::HeapMode>
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
        ASSERT_TRUE( mem->initialize_heap( GetParam() ) );
    }

    void TearDown() override
    {
        mem.reset();
        if (uc)
            uc_close( uc );
    }
};

} // namespace

TEST_P( HeapModeFixture, ModeIsReportedCorrectly )
{
    EXPECT_EQ( mem->heap().mode(), GetParam() );
}

TEST_P( HeapModeFixture, AllocationsAreSixteenByteAligned )
{
    for (std::size_t size : { 1u, 7u, 100u, 4096u })
    {
        const std::uint32_t p{ mem->heap_alloc( size ) };
        ASSERT_NE( p, 0u ) << size;
        EXPECT_EQ( p % 16, 0u ) << size;
    }
}

TEST_P( HeapModeFixture, RoundTripsContentsThroughAllocWriteRead )
{
    const std::uint32_t p{ mem->heap_alloc( 64 ) };
    ASSERT_NE( p, 0u );
    auto *hostPtr{ static_cast<std::uint8_t *>( mem->get( p ) ) };
    for (int i{ 0 }; i < 64; ++i)
        hostPtr[i] = static_cast<std::uint8_t>( i );
    for (int i{ 0 }; i < 64; ++i)
        EXPECT_EQ( hostPtr[i], static_cast<std::uint8_t>( i ) ) << i;
}

TEST_P( HeapModeFixture, DoubleFreeIsRefusedAndCounted )
{
    const std::uint32_t p{ mem->heap_alloc( 32 ) };
    ASSERT_NE( p, 0u );
    ASSERT_TRUE( mem->heap_free( p ) );
    EXPECT_FALSE( mem->heap_free( p ) );
    EXPECT_EQ( mem->heap_stats().doubleFrees, 1u );
}

TEST_P( HeapModeFixture, FreeOfNonHeapPointerIsRefused )
{
    EXPECT_FALSE( mem->heap_free( 0x1234 ) );
    EXPECT_GE( mem->heap_stats().invalidFrees, 1u );
}

TEST_P( HeapModeFixture, FreeOfMisalignedPointerIsRefused )
{
    const std::uint32_t p{ mem->heap_alloc( 64 ) };
    ASSERT_NE( p, 0u );
    EXPECT_FALSE( mem->heap_free( p + 1 ) );
}

TEST_P( HeapModeFixture, FreeNullIsNoOpSuccess )
{
    EXPECT_TRUE( mem->heap_free( 0 ) );
}

TEST_P( HeapModeFixture, ExhaustionReturnsZeroAndHeapStaysUsable )
{
    std::vector<std::uint32_t> blocks{};
    std::uint32_t p{};
    do
    {
        p = mem->heap_alloc( 1u << 22 ); // 4 MiB chunks
        if (p != 0)
            blocks.push_back( p );
    } while (p != 0 && blocks.size() < 100);

    ASSERT_FALSE( blocks.empty() );
    ASSERT_TRUE( mem->heap_free( blocks.front() ) );
}

// This is the test that catches the "two physically-adjacent free/retired chunks" invariant
// trap: Bump mode never coalesces, so a long run of allocs/frees produces many adjacent
// permanently-retired chunks, which must NOT be reported as a missed-coalesce corruption.
TEST_P( HeapModeFixture, RandomizedStressWalkStaysValid )
{
    std::mt19937 rng{ 4242 };
    std::uniform_int_distribution<int> sizeDist{ 1, 2048 };
    std::uniform_int_distribution<int> opDist{ 0, 2 };
    std::vector<std::uint32_t> live{};

    for (int i{ 0 }; i < 5000; ++i)
    {
        const int op{ live.empty() ? 0 : opDist( rng ) };
        if (op == 0)
        {
            const std::uint32_t p{ mem->heap_alloc( static_cast<std::size_t>( sizeDist( rng ) ) ) };
            if (p != 0)
                live.push_back( p );
        }
        else if (op == 1 && !live.empty())
        {
            std::uniform_int_distribution<std::size_t> idxDist{ 0, live.size() - 1 };
            const std::size_t idx{ idxDist( rng ) };
            ASSERT_TRUE( mem->heap_free( live[idx] ) );
            live.erase( live.begin() + static_cast<long>( idx ) );
        }
        else if (!live.empty())
        {
            std::uniform_int_distribution<std::size_t> idxDist{ 0, live.size() - 1 };
            const std::size_t idx{ idxDist( rng ) };
            const std::uint32_t newPtr{ mem->heap_realloc( live[idx], static_cast<std::size_t>( sizeDist( rng ) ) ) };
            ASSERT_NE( newPtr, 0u );
            live[idx] = newPtr;
        }
    }

    std::string report;
    EXPECT_TRUE( mem->heap().validate( &report ) ) << report;
}

INSTANTIATE_TEST_SUITE_P( AllModes, HeapModeFixture,
                          ::testing::Values( common::HeapMode::Bump, common::HeapMode::Quarantine,
                                             common::HeapMode::Real ),
                          []( const ::testing::TestParamInfo<common::HeapMode> &info ) {
                              return std::string{ common::heap_mode_name( info.param ) };
                          } );

// ── mode-specific behaviour ───────────────────────────────────────────────

TEST( HeapBumpMode, FreeThenAllocDoesNotReuseAndIsCountedAsRetired )
{
    uc_engine *uc{ nullptr };
    const uc_mode ppcMode{ static_cast<uc_mode>( UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN ) };
    ASSERT_EQ( uc_open( UC_ARCH_PPC, ppcMode, &uc ), UC_ERR_OK );
    auto memRes{ memory::CMemory::init( uc, common::Guest_Virtual_Memory_Size ) };
    ASSERT_TRUE( memRes.has_value() );
    memory::CMemory mem{ std::move( *memRes ) };
    ASSERT_TRUE( mem.initialize_heap( common::HeapMode::Bump ) );

    const std::uint32_t a{ mem.heap_alloc( 64 ) };
    ASSERT_NE( a, 0u );
    ASSERT_TRUE( mem.heap_free( a ) );
    const std::uint32_t b{ mem.heap_alloc( 64 ) };
    ASSERT_NE( b, 0u );
    EXPECT_NE( a, b );
    EXPECT_GT( mem.heap_stats().retiredBytes, 0u );
    EXPECT_EQ( mem.heap_stats().quarantineBytes, 0u );

    uc_close( uc );
}

TEST( HeapRealMode, FreeThenAllocImmediatelyReusesSameAddress )
{
    uc_engine *uc{ nullptr };
    const uc_mode ppcMode{ static_cast<uc_mode>( UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN ) };
    ASSERT_EQ( uc_open( UC_ARCH_PPC, ppcMode, &uc ), UC_ERR_OK );
    auto memRes{ memory::CMemory::init( uc, common::Guest_Virtual_Memory_Size ) };
    ASSERT_TRUE( memRes.has_value() );
    memory::CMemory mem{ std::move( *memRes ) };
    ASSERT_TRUE( mem.initialize_heap( common::HeapMode::Real ) );

    const std::uint32_t a{ mem.heap_alloc( 64 ) };
    ASSERT_NE( a, 0u );
    ASSERT_TRUE( mem.heap_free( a ) );
    const std::uint32_t b{ mem.heap_alloc( 64 ) };
    ASSERT_NE( b, 0u );
    EXPECT_EQ( a, b );
    EXPECT_EQ( mem.heap_stats().quarantineBytes, 0u );

    uc_close( uc );
}

TEST( HeapRealMode, AdjacentFreesCoalesceImmediately )
{
    uc_engine *uc{ nullptr };
    const uc_mode ppcMode{ static_cast<uc_mode>( UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN ) };
    ASSERT_EQ( uc_open( UC_ARCH_PPC, ppcMode, &uc ), UC_ERR_OK );
    auto memRes{ memory::CMemory::init( uc, common::Guest_Virtual_Memory_Size ) };
    ASSERT_TRUE( memRes.has_value() );
    memory::CMemory mem{ std::move( *memRes ) };
    ASSERT_TRUE( mem.initialize_heap( common::HeapMode::Real ) );

    const std::uint32_t a{ mem.heap_alloc( 64 ) };
    const std::uint32_t b{ mem.heap_alloc( 64 ) };
    const std::uint32_t c{ mem.heap_alloc( 64 ) };
    ASSERT_NE( a, 0u );
    ASSERT_NE( b, 0u );
    ASSERT_NE( c, 0u );

    ASSERT_TRUE( mem.heap_free( a ) );
    ASSERT_TRUE( mem.heap_free( b ) );

    // No drain_quarantine() needed in Real mode: coalescing is immediate.
    const std::uint32_t combined{ mem.heap_alloc( 64 + 64 + 16 ) };
    ASSERT_NE( combined, 0u );
    EXPECT_EQ( combined, a );

    ASSERT_TRUE( mem.heap_free( combined ) );
    ASSERT_TRUE( mem.heap_free( c ) );

    uc_close( uc );
}

