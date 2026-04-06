/**
 * Author:    domin568
 * Created:   06.04.2026
 * Brief:     Tests for bsearch shim — verifies that the guest PPC comparator is invoked correctly.
 **/

#include "CMemory.hpp"
#include "Common.hpp"
#include "ImportDispatch.hpp"
#include <gtest/gtest.h>
#include <unicorn/unicorn.h>

namespace
{

// ── PPC machine‑code for a simple int comparator ────────────────────────
// int compare_ints(const void *a, const void *b)
//   lwz   r5, 0(r3)          ; r5 = *a
//   lwz   r6, 0(r4)          ; r6 = *b
//   subf  r3, r6, r5         ; r3 = r5 − r6
//   blr
constexpr uint8_t Compare_Ints_Ppc[] = {
    0x80, 0xA3, 0x00, 0x00, // lwz  r5, 0(r3)
    0x80, 0xC4, 0x00, 0x00, // lwz  r6, 0(r4)
    0x7C, 0x66, 0x28, 0x50, // subf r3, r6, r5
    0x4E, 0x80, 0x00, 0x20, // blr
};

// Layout constants
constexpr uint32_t Code_Address = 0x0010'0000;
constexpr uint32_t Code_Size = 0x1000;
constexpr uint32_t Data_Address = 0x0020'0000; // sorted array
constexpr uint32_t Data_Size = 0x1000;
constexpr uint32_t Key_Address = 0x0020'1000; // search key lives here
constexpr uint32_t Key_Size = 0x1000;
constexpr uint32_t Stack_Address = 0x00FF'0000;
constexpr uint32_t Stack_Size = 0x1000;
constexpr uint32_t Sentinel_Address = common::Inner_Emulation_Sentinel;
constexpr uint32_t Sentinel_Size = 0x1000;

// For the nested emulation test
constexpr uint32_t Caller_Address = 0x0030'0000;
constexpr uint32_t Caller_Size = 0x1000;
constexpr uint32_t Hook_Address = 0x0040'0000;
constexpr uint32_t Hook_Size = 0x1000;

struct PpcTestEnv
{
    uc_engine *uc{};
    std::optional<memory::CMemory> mem;

    bool init()
    {
        uc_err err = uc_open( UC_ARCH_PPC, static_cast<uc_mode>( UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN ), &uc );
        if (err != UC_ERR_OK)
            return false;

        auto memResult = memory::CMemory::init( uc, common::Guest_Virtual_Memory_Size );
        if (!memResult)
            return false;
        mem.emplace( std::move( *memResult ) );

        if (!mem->commit( Code_Address, Code_Size, UC_PROT_ALL ))
            return false;
        if (!mem->commit( Data_Address, Data_Size + Key_Size, UC_PROT_ALL ))
            return false;
        if (!mem->commit( Stack_Address, Stack_Size, UC_PROT_ALL ))
            return false;
        if (!mem->commit( Sentinel_Address, Sentinel_Size, UC_PROT_ALL ))
            return false;
        return true;
    }

    bool init_with_caller()
    {
        if (!init())
            return false;
        if (!mem->commit( Caller_Address, Caller_Size, UC_PROT_ALL ))
            return false;
        if (!mem->commit( Hook_Address, Hook_Size, UC_PROT_ALL ))
            return false;
        return true;
    }

    ~PpcTestEnv()
    {
        mem.reset();
        if (uc)
            uc_close( uc );
    }

    void write_be32( uint32_t guestAddr, uint32_t value )
    {
        uint32_t be = common::ensure_endianness( value, std::endian::big );
        mem->write( guestAddr, &be, sizeof( be ) );
    }

    uint32_t read_be32( uint32_t guestAddr )
    {
        uint32_t raw;
        void *ptr = mem->get( guestAddr );
        std::memcpy( &raw, ptr, sizeof( raw ) );
        return common::ensure_endianness( raw, std::endian::big );
    }

    // Helper: write a sorted array, write the key, set up registers for bsearch,
    // call bsearch, and return the guest-address result from r3.
    uint32_t run_bsearch( const uint32_t *sortedArr, size_t n, uint32_t searchKey )
    {
        mem->write( Code_Address, Compare_Ints_Ppc, sizeof( Compare_Ints_Ppc ) );

        for (size_t i = 0; i < n; i++)
            write_be32( Data_Address + static_cast<uint32_t>( i * 4 ), sortedArr[i] );

        write_be32( Key_Address, searchKey );

        // bsearch(key, base, num, width, compare)
        // PPC ABI: r3=key, r4=base, r5=num, r6=width, r7=compare
        uint32_t r3 = Key_Address;
        uint32_t r4 = Data_Address;
        uint32_t r5 = static_cast<uint32_t>( n );
        uint32_t r6 = 4;
        uint32_t r7 = Code_Address;
        uint32_t sp = Stack_Address + Stack_Size - 64;
        uc_reg_write( uc, UC_PPC_REG_3, &r3 );
        uc_reg_write( uc, UC_PPC_REG_4, &r4 );
        uc_reg_write( uc, UC_PPC_REG_5, &r5 );
        uc_reg_write( uc, UC_PPC_REG_6, &r6 );
        uc_reg_write( uc, UC_PPC_REG_7, &r7 );
        uc_reg_write( uc, UC_PPC_REG_1, &sp );

        import::callback::bsearch( uc, &*mem, nullptr );

        uint32_t result;
        uc_reg_read( uc, UC_PPC_REG_3, &result );
        return result;
    }
};

} // namespace

// ── Test: find an element that exists ──────────────────────────────────
TEST( Bsearch, FindExistingElement )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init() );

    constexpr uint32_t sorted[] = { 1, 7, 23, 42, 99 };
    uint32_t result = env.run_bsearch( sorted, std::size( sorted ), 23 );

    // bsearch returns a pointer to the found element in the array.
    // 23 is at index 2 → guest address = Data_Address + 2*4
    EXPECT_EQ( result, Data_Address + 2 * 4 );
}

// ── Test: find the first element ───────────────────────────────────────
TEST( Bsearch, FindFirstElement )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init() );

    constexpr uint32_t sorted[] = { 1, 7, 23, 42, 99 };
    uint32_t result = env.run_bsearch( sorted, std::size( sorted ), 1 );

    EXPECT_EQ( result, Data_Address );
}

// ── Test: find the last element ────────────────────────────────────────
TEST( Bsearch, FindLastElement )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init() );

    constexpr uint32_t sorted[] = { 1, 7, 23, 42, 99 };
    uint32_t result = env.run_bsearch( sorted, std::size( sorted ), 99 );

    EXPECT_EQ( result, Data_Address + 4 * 4 );
}

// ── Test: element not found returns NULL (0) ───────────────────────────
TEST( Bsearch, ElementNotFound )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init() );

    constexpr uint32_t sorted[] = { 1, 7, 23, 42, 99 };
    uint32_t result = env.run_bsearch( sorted, std::size( sorted ), 50 );

    EXPECT_EQ( result, 0u );
}

// ── Test: single element — found ───────────────────────────────────────
TEST( Bsearch, SingleElementFound )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init() );

    constexpr uint32_t sorted[] = { 42 };
    uint32_t result = env.run_bsearch( sorted, 1, 42 );

    EXPECT_EQ( result, Data_Address );
}

// ── Test: single element — not found ───────────────────────────────────
TEST( Bsearch, SingleElementNotFound )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init() );

    constexpr uint32_t sorted[] = { 42 };
    uint32_t result = env.run_bsearch( sorted, 1, 7 );

    EXPECT_EQ( result, 0u );
}

// ── Test: registers are preserved ──────────────────────────────────────
TEST( Bsearch, RegistersPreserved )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init() );

    env.mem->write( Code_Address, Compare_Ints_Ppc, sizeof( Compare_Ints_Ppc ) );

    constexpr uint32_t sorted[] = { 1, 7, 23, 42, 99 };
    for (size_t i = 0; i < std::size( sorted ); i++)
        env.write_be32( Data_Address + static_cast<uint32_t>( i * 4 ), sorted[i] );
    env.write_be32( Key_Address, 23 );

    uint32_t r3 = Key_Address;
    uint32_t r4 = Data_Address;
    uint32_t r5 = std::size( sorted );
    uint32_t r6 = 4;
    uint32_t r7 = Code_Address;
    uint32_t sp = Stack_Address + Stack_Size - 64;
    uc_reg_write( env.uc, UC_PPC_REG_3, &r3 );
    uc_reg_write( env.uc, UC_PPC_REG_4, &r4 );
    uc_reg_write( env.uc, UC_PPC_REG_5, &r5 );
    uc_reg_write( env.uc, UC_PPC_REG_6, &r6 );
    uc_reg_write( env.uc, UC_PPC_REG_7, &r7 );
    uc_reg_write( env.uc, UC_PPC_REG_1, &sp );

    // Set non-volatile registers to sentinel values
    uint32_t r13_before = 0xDEAD0013;
    uint32_t r31_before = 0xDEAD001F;
    uint32_t lr_before = 0xCAFEBABE;
    uc_reg_write( env.uc, UC_PPC_REG_13, &r13_before );
    uc_reg_write( env.uc, UC_PPC_REG_31, &r31_before );
    uc_reg_write( env.uc, UC_PPC_REG_LR, &lr_before );

    bool ok = import::callback::bsearch( env.uc, &*env.mem, nullptr );
    ASSERT_TRUE( ok );

    uint32_t r13_after, r31_after, lr_after, sp_after;
    uc_reg_read( env.uc, UC_PPC_REG_13, &r13_after );
    uc_reg_read( env.uc, UC_PPC_REG_31, &r31_after );
    uc_reg_read( env.uc, UC_PPC_REG_LR, &lr_after );
    uc_reg_read( env.uc, UC_PPC_REG_1, &sp_after );

    EXPECT_EQ( r13_after, r13_before ) << "r13 was not preserved";
    EXPECT_EQ( r31_after, r31_before ) << "r31 was not preserved";
    EXPECT_EQ( lr_after, lr_before ) << "LR was not preserved";
    EXPECT_EQ( sp_after, sp ) << "SP (r1) was not preserved";
}

// ── Test: nested emulation (outer uc_emu_start → hook → bsearch → inner uc_emu_start) ──
namespace
{

struct BsearchNestedUserData
{
    PpcTestEnv *env;
    bool bsearch_ok;
    uint32_t bsearch_result;
};

void bsearch_nested_hook( uc_engine *uc, uint64_t address, uint32_t /*size*/, void *user_data )
{
    if (static_cast<uint32_t>( address ) != Hook_Address)
        return;

    auto *ud = static_cast<BsearchNestedUserData *>( user_data );
    auto *mem = &*ud->env->mem;

    // Set up registers: bsearch(Key_Address, Data_Address, 5, 4, Code_Address)
    uint32_t r3 = Key_Address;
    uint32_t r4 = Data_Address;
    uint32_t r5 = 5;
    uint32_t r6 = 4;
    uint32_t r7 = Code_Address;
    uc_reg_write( uc, UC_PPC_REG_3, &r3 );
    uc_reg_write( uc, UC_PPC_REG_4, &r4 );
    uc_reg_write( uc, UC_PPC_REG_5, &r5 );
    uc_reg_write( uc, UC_PPC_REG_6, &r6 );
    uc_reg_write( uc, UC_PPC_REG_7, &r7 );

    ud->bsearch_ok = import::callback::bsearch( uc, mem, nullptr );

    uc_reg_read( uc, UC_PPC_REG_3, &ud->bsearch_result );
}

} // namespace

TEST( Bsearch, NestedEmulation )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init_with_caller() );

    // Write comparator
    env.mem->write( Code_Address, Compare_Ints_Ppc, sizeof( Compare_Ints_Ppc ) );

    // Sorted array: { 1, 7, 23, 42, 99 }
    constexpr uint32_t sorted[] = { 1, 7, 23, 42, 99 };
    for (size_t i = 0; i < std::size( sorted ); i++)
        env.write_be32( Data_Address + static_cast<uint32_t>( i * 4 ), sorted[i] );

    // Key to search for: 42
    env.write_be32( Key_Address, 42 );

    // Build caller stub:
    //   Caller_Address+0x00: li r7, 0xAA
    //   Caller_Address+0x04: b Hook_Address (absolute)
    {
        uint32_t li_r7_aa = common::ensure_endianness(
            static_cast<uint32_t>( ( 14u << 26 ) | ( 7u << 21 ) | ( 0u << 16 ) | 0xAAu ), std::endian::big );
        env.mem->write( Caller_Address, &li_r7_aa, 4 );

        uint32_t b_hook = common::ensure_endianness(
            static_cast<uint32_t>( ( 18u << 26 ) | ( Hook_Address & 0x03FFFFFFu ) | 0x2u ), std::endian::big );
        env.mem->write( Caller_Address + 4, &b_hook, 4 );
    }

    // Build hook region:
    //   Hook_Address+0x00: nop            ; hook fires here
    //   Hook_Address+0x04: li r7, 0xBB    ; runs after hook returns
    //   Hook_Address+0x08: blr            ; used as `until`
    {
        uint32_t nop = common::ensure_endianness( 0x60000000u, std::endian::big );
        env.mem->write( Hook_Address, &nop, 4 );

        uint32_t li_r7_bb = common::ensure_endianness(
            static_cast<uint32_t>( ( 14u << 26 ) | ( 7u << 21 ) | ( 0u << 16 ) | 0xBBu ), std::endian::big );
        env.mem->write( Hook_Address + 4, &li_r7_bb, 4 );

        uint32_t blr = common::ensure_endianness( 0x4E800020u, std::endian::big );
        env.mem->write( Hook_Address + 8, &blr, 4 );
    }

    uint32_t sp = Stack_Address + Stack_Size - 64;
    uc_reg_write( env.uc, UC_PPC_REG_1, &sp );

    BsearchNestedUserData ud{ &env, false, 0 };
    uc_hook hh{};
    ASSERT_EQ( uc_hook_add( env.uc, &hh, UC_HOOK_CODE, reinterpret_cast<void *>( bsearch_nested_hook ), &ud,
                            Hook_Address, Hook_Address + Hook_Size ),
               UC_ERR_OK );

    // Outer emulation
    uc_err err = uc_emu_start( env.uc, Caller_Address, Hook_Address + 8, 0, 0 );
    ASSERT_EQ( err, UC_ERR_OK ) << "Outer uc_emu_start failed: " << uc_strerror( err );

    // Verify bsearch succeeded inside the hook
    EXPECT_TRUE( ud.bsearch_ok ) << "bsearch shim returned false inside hook";

    // 42 is at index 3 → guest address = Data_Address + 3*4
    EXPECT_EQ( ud.bsearch_result, Data_Address + 3 * 4 ) << "bsearch returned wrong pointer";

    // Verify outer emulation resumed: r7 should be 0xBB
    uint32_t r7{};
    uc_reg_read( env.uc, UC_PPC_REG_7, &r7 );
    EXPECT_EQ( r7, 0xBBu ) << "Outer emulation did not resume correctly after nested bsearch";

    uc_hook_del( env.uc, hh );
}

