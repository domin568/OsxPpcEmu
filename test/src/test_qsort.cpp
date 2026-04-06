/**
 * Author:    domin568
 * Created:   06.04.2026
 * Brief:     Tests for qsort shim — verifies that the guest PPC comparator is invoked correctly.
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
// {
//     return *(int*)a - *(int*)b;
// }
//
// PPC assembly (big‑endian encoding):
//   lwz   r5, 0(r3)          ; r5 = *a
//   lwz   r6, 0(r4)          ; r6 = *b
//   subf  r3, r6, r5         ; r3 = r5 − r6  (rD = rB − rA)
//   blr                      ; return
constexpr uint8_t Compare_Ints_Ppc[] = {
    0x80, 0xA3, 0x00, 0x00, // lwz  r5, 0(r3)
    0x80, 0xC4, 0x00, 0x00, // lwz  r6, 0(r4)
    0x7C, 0x66, 0x28, 0x50, // subf r3, r6, r5
    0x4E, 0x80, 0x00, 0x20, // blr
};

// ── Reverse comparator: *b − *a ────────────────────────────────────────
// subf r3, r5, r6  → r3 = r6 − r5
constexpr uint8_t Compare_Ints_Reverse_Ppc[] = {
    0x80, 0xA3, 0x00, 0x00, // lwz  r5, 0(r3)
    0x80, 0xC4, 0x00, 0x00, // lwz  r6, 0(r4)
    0x7C, 0x65, 0x30, 0x50, // subf r3, r5, r6
    0x4E, 0x80, 0x00, 0x20, // blr
};

// Layout constants (must not overlap)
constexpr uint32_t Code_Address = 0x0010'0000; // comparator lives here
constexpr uint32_t Code_Size = 0x1000;
constexpr uint32_t Data_Address = 0x0020'0000; // array to sort lives here
constexpr uint32_t Data_Size = 0x1000;
constexpr uint32_t Stack_Address = 0x00FF'0000; // stack (grows downward)
constexpr uint32_t Stack_Size = 0x1000;
constexpr uint32_t Sentinel_Address = common::Import_Dispatch_Table_Address;
constexpr uint32_t Sentinel_Size = 0x1000;

// Caller stub lives at a separate address (used by the nested emulation test)
constexpr uint32_t Caller_Address = 0x0030'0000;
constexpr uint32_t Caller_Size = 0x1000;

// Hook trigger address — a single instruction that the outer emulation will hit.
// We place a "trap" (tw 31,0,0) there; the code hook intercepts it.
constexpr uint32_t Hook_Address = 0x0040'0000;
constexpr uint32_t Hook_Size = 0x1000;

// Helper: RAII wrapper for a unicorn + CMemory test environment
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

        // Commit regions: code, data, stack, sentinel
        if (!mem->commit( Code_Address, Code_Size, UC_PROT_ALL ))
            return false;
        if (!mem->commit( Data_Address, Data_Size, UC_PROT_ALL ))
            return false;
        if (!mem->commit( Stack_Address, Stack_Size, UC_PROT_ALL ))
            return false;
        if (!mem->commit( Sentinel_Address, Sentinel_Size, UC_PROT_ALL ))
            return false;
        return true;
    }

    // Extended init that also maps caller and hook regions
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
        mem.reset(); // release CMemory (munmap) before closing unicorn
        if (uc)
            uc_close( uc );
    }

    // Write a big‑endian uint32 to guest memory
    void write_be32( uint32_t guestAddr, uint32_t value )
    {
        uint32_t be = common::ensure_endianness( value, std::endian::big );
        mem->write( guestAddr, &be, sizeof( be ) );
    }

    // Read a big‑endian uint32 from guest memory and return in host order
    uint32_t read_be32( uint32_t guestAddr )
    {
        uint32_t raw;
        void *ptr = mem->get( guestAddr );
        std::memcpy( &raw, ptr, sizeof( raw ) );
        return common::ensure_endianness( raw, std::endian::big );
    }
};

} // namespace

// ── Test: ascending sort with 5 unsigned integers ──────────────────────
TEST( Qsort, AscendingSortIntegers )
{
    // ...existing code...

    PpcTestEnv env;
    ASSERT_TRUE( env.init() );

    // Write comparator code
    env.mem->write( Code_Address, Compare_Ints_Ppc, sizeof( Compare_Ints_Ppc ) );

    // Prepare unsorted array in guest memory: { 42, 7, 99, 1, 23 }
    constexpr uint32_t values[] = { 42, 7, 99, 1, 23 };
    constexpr size_t N = std::size( values );
    for (size_t i = 0; i < N; i++)
        env.write_be32( Data_Address + static_cast<uint32_t>( i * 4 ), values[i] );

    // Set up PPC registers as if the program called qsort(base, N, 4, compare)
    // PPC ABI: r3 = base, r4 = nmemb, r5 = size, r6 = comparator
    uint32_t r3 = Data_Address;
    uint32_t r4 = N;
    uint32_t r5 = 4;
    uint32_t r6 = Code_Address;
    uint32_t sp = Stack_Address + Stack_Size - 64; // near top of stack
    uc_reg_write( env.uc, UC_PPC_REG_3, &r3 );
    uc_reg_write( env.uc, UC_PPC_REG_4, &r4 );
    uc_reg_write( env.uc, UC_PPC_REG_5, &r5 );
    uc_reg_write( env.uc, UC_PPC_REG_6, &r6 );
    uc_reg_write( env.uc, UC_PPC_REG_1, &sp );

    // Call the qsort shim directly
    bool ok = import::callback::qsort( env.uc, &*env.mem, nullptr );
    ASSERT_TRUE( ok );

    // Verify result: { 1, 7, 23, 42, 99 }
    constexpr uint32_t expected[] = { 1, 7, 23, 42, 99 };
    for (size_t i = 0; i < N; i++)
    {
        uint32_t actual = env.read_be32( Data_Address + static_cast<uint32_t>( i * 4 ) );
        EXPECT_EQ( actual, expected[i] ) << "Mismatch at index " << i;
    }
}

// ── Test: descending sort using reverse comparator ─────────────────────
TEST( Qsort, DescendingSortIntegers )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init() );

    env.mem->write( Code_Address, Compare_Ints_Reverse_Ppc, sizeof( Compare_Ints_Reverse_Ppc ) );

    constexpr uint32_t values[] = { 42, 7, 99, 1, 23 };
    constexpr size_t N = std::size( values );
    for (size_t i = 0; i < N; i++)
        env.write_be32( Data_Address + static_cast<uint32_t>( i * 4 ), values[i] );

    uint32_t r3 = Data_Address;
    uint32_t r4 = N;
    uint32_t r5 = 4;
    uint32_t r6 = Code_Address;
    uint32_t sp = Stack_Address + Stack_Size - 64;
    uc_reg_write( env.uc, UC_PPC_REG_3, &r3 );
    uc_reg_write( env.uc, UC_PPC_REG_4, &r4 );
    uc_reg_write( env.uc, UC_PPC_REG_5, &r5 );
    uc_reg_write( env.uc, UC_PPC_REG_6, &r6 );
    uc_reg_write( env.uc, UC_PPC_REG_1, &sp );

    bool ok = import::callback::qsort( env.uc, &*env.mem, nullptr );
    ASSERT_TRUE( ok );

    constexpr uint32_t expected[] = { 99, 42, 23, 7, 1 };
    for (size_t i = 0; i < N; i++)
    {
        uint32_t actual = env.read_be32( Data_Address + static_cast<uint32_t>( i * 4 ) );
        EXPECT_EQ( actual, expected[i] ) << "Mismatch at index " << i;
    }
}

// ── Test: already‑sorted array stays unchanged ─────────────────────────
TEST( Qsort, AlreadySorted )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init() );

    env.mem->write( Code_Address, Compare_Ints_Ppc, sizeof( Compare_Ints_Ppc ) );

    constexpr uint32_t values[] = { 1, 2, 3, 4, 5 };
    constexpr size_t N = std::size( values );
    for (size_t i = 0; i < N; i++)
        env.write_be32( Data_Address + static_cast<uint32_t>( i * 4 ), values[i] );

    uint32_t r3 = Data_Address;
    uint32_t r4 = N;
    uint32_t r5 = 4;
    uint32_t r6 = Code_Address;
    uint32_t sp = Stack_Address + Stack_Size - 64;
    uc_reg_write( env.uc, UC_PPC_REG_3, &r3 );
    uc_reg_write( env.uc, UC_PPC_REG_4, &r4 );
    uc_reg_write( env.uc, UC_PPC_REG_5, &r5 );
    uc_reg_write( env.uc, UC_PPC_REG_6, &r6 );
    uc_reg_write( env.uc, UC_PPC_REG_1, &sp );

    bool ok = import::callback::qsort( env.uc, &*env.mem, nullptr );
    ASSERT_TRUE( ok );

    for (size_t i = 0; i < N; i++)
    {
        uint32_t actual = env.read_be32( Data_Address + static_cast<uint32_t>( i * 4 ) );
        EXPECT_EQ( actual, values[i] ) << "Mismatch at index " << i;
    }
}

// ── Test: single element ───────────────────────────────────────────────
TEST( Qsort, SingleElement )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init() );

    env.mem->write( Code_Address, Compare_Ints_Ppc, sizeof( Compare_Ints_Ppc ) );

    env.write_be32( Data_Address, 42 );

    uint32_t r3 = Data_Address;
    uint32_t r4 = 1;
    uint32_t r5 = 4;
    uint32_t r6 = Code_Address;
    uint32_t sp = Stack_Address + Stack_Size - 64;
    uc_reg_write( env.uc, UC_PPC_REG_3, &r3 );
    uc_reg_write( env.uc, UC_PPC_REG_4, &r4 );
    uc_reg_write( env.uc, UC_PPC_REG_5, &r5 );
    uc_reg_write( env.uc, UC_PPC_REG_6, &r6 );
    uc_reg_write( env.uc, UC_PPC_REG_1, &sp );

    bool ok = import::callback::qsort( env.uc, &*env.mem, nullptr );
    ASSERT_TRUE( ok );

    EXPECT_EQ( env.read_be32( Data_Address ), 42u );
}

// ── Test: registers are preserved across qsort ─────────────────────────
TEST( Qsort, RegistersPreserved )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init() );

    env.mem->write( Code_Address, Compare_Ints_Ppc, sizeof( Compare_Ints_Ppc ) );

    constexpr uint32_t values[] = { 3, 1 };
    constexpr size_t N = std::size( values );
    for (size_t i = 0; i < N; i++)
        env.write_be32( Data_Address + static_cast<uint32_t>( i * 4 ), values[i] );

    uint32_t r3 = Data_Address;
    uint32_t r4 = N;
    uint32_t r5 = 4;
    uint32_t r6 = Code_Address;
    uint32_t sp = Stack_Address + Stack_Size - 64;
    uc_reg_write( env.uc, UC_PPC_REG_3, &r3 );
    uc_reg_write( env.uc, UC_PPC_REG_4, &r4 );
    uc_reg_write( env.uc, UC_PPC_REG_5, &r5 );
    uc_reg_write( env.uc, UC_PPC_REG_6, &r6 );
    uc_reg_write( env.uc, UC_PPC_REG_1, &sp );

    // Set some non‑volatile registers to known sentinel values
    uint32_t r13_before = 0xDEAD0013;
    uint32_t r31_before = 0xDEAD001F;
    uint32_t lr_before = 0xCAFEBABE;
    uc_reg_write( env.uc, UC_PPC_REG_13, &r13_before );
    uc_reg_write( env.uc, UC_PPC_REG_31, &r31_before );
    uc_reg_write( env.uc, UC_PPC_REG_LR, &lr_before );

    bool ok = import::callback::qsort( env.uc, &*env.mem, nullptr );
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

// ── Test: true nested emulation (outer uc_emu_start → hook → qsort → inner uc_emu_start) ──
//
// This test sets up a real two‑level emulation scenario:
//
//   Caller_Address+0x00:  li r7, 0xAA          ; mark: before hook
//   Caller_Address+0x04:  b  Hook_Address       ; jump to hook region
//
//   Hook_Address+0x00:    nop                   ; hook fires here, calls qsort (inner emu)
//   Hook_Address+0x04:    li r7, 0xBB           ; mark: after hook — proves outer resumed
//   Hook_Address+0x08:    blr                   ; end (we use this as `until`)
//
// A code hook at Hook_Address intercepts the nop, sets up registers, and calls the
// qsort shim synchronously.  The qsort shim invokes uc_emu_start for each comparison
// (the inner level).  After the hook returns, outer emulation resumes at Hook_Address+0x04.

namespace
{

struct NestedTestUserData
{
    PpcTestEnv *env;
    bool qsort_ok;
};

void nested_test_hook( uc_engine *uc, uint64_t address, uint32_t /*size*/, void *user_data )
{
    if (static_cast<uint32_t>( address ) != Hook_Address)
        return;

    auto *ud = static_cast<NestedTestUserData *>( user_data );
    auto *mem = &*ud->env->mem;

    // Set up registers as if the program called qsort(base, 5, 4, comparator)
    uint32_t r3 = Data_Address;
    uint32_t r4 = 5;
    uint32_t r5 = 4;
    uint32_t r6 = Code_Address;
    uc_reg_write( uc, UC_PPC_REG_3, &r3 );
    uc_reg_write( uc, UC_PPC_REG_4, &r4 );
    uc_reg_write( uc, UC_PPC_REG_5, &r5 );
    uc_reg_write( uc, UC_PPC_REG_6, &r6 );

    ud->qsort_ok = import::callback::qsort( uc, mem, nullptr );
}

} // namespace

TEST( Qsort, NestedEmulation )
{
    PpcTestEnv env;
    ASSERT_TRUE( env.init_with_caller() );

    // Write comparator code (ascending int compare)
    env.mem->write( Code_Address, Compare_Ints_Ppc, sizeof( Compare_Ints_Ppc ) );

    // Prepare unsorted array: { 42, 7, 99, 1, 23 }
    constexpr uint32_t values[] = { 42, 7, 99, 1, 23 };
    for (size_t i = 0; i < std::size( values ); i++)
        env.write_be32( Data_Address + static_cast<uint32_t>( i * 4 ), values[i] );

    // ── Build caller stub ──────────────────────────────────────────
    // Caller_Address+0x00: li r7, 0xAA  →  addi r7, 0, 0xAA  =  (14 << 26)|(7 << 21)|(0 << 16)|0xAA
    // Caller_Address+0x04: b Hook_Address  →  (18 << 26) | ((Hook_Address - (Caller_Address+4)) & 0x03FFFFFC)
    {
        // li r7, 0xAA  →  opcode 14 (addi), rD=7, rA=0, SIMM=0xAA
        uint32_t li_r7_aa = common::ensure_endianness(
            static_cast<uint32_t>( ( 14u << 26 ) | ( 7u << 21 ) | ( 0u << 16 ) | 0xAAu ), std::endian::big );
        env.mem->write( Caller_Address, &li_r7_aa, 4 );

        // b Hook_Address (absolute branch, AA=1)  →  opcode 18, target, AA=1, LK=0
        // I‑form: (18 << 26) | (target & 0x03FFFFFC) | AA | LK
        uint32_t b_hook = common::ensure_endianness(
            static_cast<uint32_t>( ( 18u << 26 ) | ( Hook_Address & 0x03FFFFFFu ) | 0x2u ), std::endian::big );
        env.mem->write( Caller_Address + 4, &b_hook, 4 );
    }

    // ── Build hook‑region code ─────────────────────────────────────
    // Hook_Address+0x00: nop (ori 0,0,0 = 0x60000000)
    // Hook_Address+0x04: li r7, 0xBB
    // Hook_Address+0x08: blr (0x4E800020) — used as `until`
    {
        uint32_t nop = common::ensure_endianness( 0x60000000u, std::endian::big );
        env.mem->write( Hook_Address, &nop, 4 );

        uint32_t li_r7_bb = common::ensure_endianness(
            static_cast<uint32_t>( ( 14u << 26 ) | ( 7u << 21 ) | ( 0u << 16 ) | 0xBBu ), std::endian::big );
        env.mem->write( Hook_Address + 4, &li_r7_bb, 4 );

        uint32_t blr = common::ensure_endianness( 0x4E800020u, std::endian::big );
        env.mem->write( Hook_Address + 8, &blr, 4 );
    }

    // Set up stack
    uint32_t sp = Stack_Address + Stack_Size - 64;
    uc_reg_write( env.uc, UC_PPC_REG_1, &sp );

    // Register code hook over the hook region
    NestedTestUserData ud{ &env, false };
    uc_hook hh{};
    ASSERT_EQ( uc_hook_add( env.uc, &hh, UC_HOOK_CODE, reinterpret_cast<void *>( nested_test_hook ), &ud,
                            Hook_Address, Hook_Address + Hook_Size ),
               UC_ERR_OK );

    // ── Outer uc_emu_start ─────────────────────────────────────────
    // Runs: li r7,0xAA → b Hook_Address → [hook fires, qsort runs] → nop → li r7,0xBB → (stop at blr)
    uc_err err = uc_emu_start( env.uc, Caller_Address, Hook_Address + 8, 0, 0 );
    ASSERT_EQ( err, UC_ERR_OK ) << "Outer uc_emu_start failed: " << uc_strerror( err );

    // Verify the qsort shim succeeded inside the hook
    EXPECT_TRUE( ud.qsort_ok ) << "qsort shim returned false inside hook";

    // Verify the array was sorted: { 1, 7, 23, 42, 99 }
    constexpr uint32_t expected[] = { 1, 7, 23, 42, 99 };
    for (size_t i = 0; i < std::size( expected ); i++)
    {
        uint32_t actual = env.read_be32( Data_Address + static_cast<uint32_t>( i * 4 ) );
        EXPECT_EQ( actual, expected[i] ) << "Sort mismatch at index " << i;
    }

    // Verify the outer emulation resumed correctly after the hook:
    // r7 should be 0xBB (set by the instruction AFTER the nop)
    uint32_t r7{};
    uc_reg_read( env.uc, UC_PPC_REG_7, &r7 );
    EXPECT_EQ( r7, 0xBBu ) << "Outer emulation did not resume correctly after nested qsort";

    uc_hook_del( env.uc, hh );
}
