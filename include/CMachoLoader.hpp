/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     Loader for Mach-O object files (PPC)
 **/
#pragma once
#include "../include/Common.hpp"
#include <LIEF/MachO.hpp>
#include <expected>
#include <flat_map>
#include <optional>
#include <span>
#include <unicorn/unicorn.h>

struct ppc_thread_state32_t
{
    uint32_t srr0;
    uint32_t srr1;
    uint32_t r0;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r4;
    uint32_t r5;
    uint32_t r6;
    uint32_t r7;
    uint32_t r8;
    uint32_t r9;
    uint32_t r10;
    uint32_t r11;
    uint32_t r12;
    uint32_t r13;
    uint32_t r14;
    uint32_t r15;
    uint32_t r16;
    uint32_t r17;
    uint32_t r18;
    uint32_t r19;
    uint32_t r20;
    uint32_t r21;
    uint32_t r22;
    uint32_t r23;
    uint32_t r24;
    uint32_t r25;
    uint32_t r26;
    uint32_t r27;
    uint32_t r28;
    uint32_t r29;
    uint32_t r30;
    uint32_t r31;
    uint32_t cr;
    uint32_t xer;
    uint32_t lr;
    uint32_t ctr;
    uint32_t mq;
    uint32_t vrsave;

    static ppc_thread_state32_t from_bytes( const std::span<const uint8_t> &raw, std::endian order )
    {
        ppc_thread_state32_t st{};
        if (raw.size() > sizeof( st ))
            return {};
        std::memcpy( &st, raw.data(), raw.size() );
        return {
            .srr0{ common::ensure_endianness( st.srr0, order ) },
            .srr1{ common::ensure_endianness( st.srr1, order ) },
            .r0{ common::ensure_endianness( st.r0, order ) },
            .r1{ common::ensure_endianness( st.r1, order ) },
            .r2{ common::ensure_endianness( st.r2, order ) },
            .r3{ common::ensure_endianness( st.r3, order ) },
            .r4{ common::ensure_endianness( st.r4, order ) },
            .r5{ common::ensure_endianness( st.r5, order ) },
            .r6{ common::ensure_endianness( st.r6, order ) },
            .r7{ common::ensure_endianness( st.r7, order ) },
            .r8{ common::ensure_endianness( st.r8, order ) },
            .r9{ common::ensure_endianness( st.r9, order ) },
            .r10{ common::ensure_endianness( st.r10, order ) },
            .r11{ common::ensure_endianness( st.r11, order ) },
            .r12{ common::ensure_endianness( st.r12, order ) },
            .r13{ common::ensure_endianness( st.r13, order ) },
            .r14{ common::ensure_endianness( st.r14, order ) },
            .r15{ common::ensure_endianness( st.r15, order ) },
            .r16{ common::ensure_endianness( st.r16, order ) },
            .r17{ common::ensure_endianness( st.r17, order ) },
            .r18{ common::ensure_endianness( st.r18, order ) },
            .r19{ common::ensure_endianness( st.r19, order ) },
            .r20{ common::ensure_endianness( st.r20, order ) },
            .r21{ common::ensure_endianness( st.r21, order ) },
            .r22{ common::ensure_endianness( st.r22, order ) },
            .r23{ common::ensure_endianness( st.r23, order ) },
            .r24{ common::ensure_endianness( st.r24, order ) },
            .r25{ common::ensure_endianness( st.r25, order ) },
            .r26{ common::ensure_endianness( st.r26, order ) },
            .r27{ common::ensure_endianness( st.r27, order ) },
            .r28{ common::ensure_endianness( st.r28, order ) },
            .r29{ common::ensure_endianness( st.r29, order ) },
            .r30{ common::ensure_endianness( st.r30, order ) },
            .r31{ common::ensure_endianness( st.r31, order ) },
            .cr{ common::ensure_endianness( st.cr, order ) },
            .xer{ common::ensure_endianness( st.xer, order ) },
            .lr{ common::ensure_endianness( st.lr, order ) },
            .ctr{ common::ensure_endianness( st.ctr, order ) },
            .mq{ common::ensure_endianness( st.mq, order ) },
            .vrsave{ common::ensure_endianness( st.vrsave, order ) },
        };
    }
};

class CMachoLoader
{
  public:
    static std::expected<CMachoLoader, common::Error> init( const std::string &path );
    bool map_image_memory( uc_engine *uc );
    bool set_unix_thread( uc_engine *uc );
    std::expected<std::map<std::string, uint32_t>, common::Error> get_import_fnc_ptrs();
    uint32_t get_ep();
    std::optional<std::pair<uint64_t, uint64_t>> get_text_segment_va_range();
    std::optional<std::string> get_text_symbol_name_for_va( uint32_t va );

  private:
    explicit CMachoLoader( std::unique_ptr<LIEF::MachO::Binary> executable,
                           std::optional<std::flat_map<uint32_t, std::string>> symbols );

    static constexpr size_t Max_Segment_File_Size{ 0x100'000 };
    static constexpr size_t Ppc_Thread_State{ 1 };
    static constexpr size_t Dyld_Section_Symbol_Count{ 2 };
    static constexpr std::string Non_Lazy_Symbols_Ptr_Section_Name{ "__nl_symbol_ptr" };
    static constexpr std::string Lazy_Symbols_Ptr_Section_Name{ "__la_symbol_ptr" };
    static constexpr std::string Dyld_Symbol_Ptr_Section_Name{ "__dyld" };
    static constexpr std::string Text_Segment_Name{ "__TEXT" };

    uint32_t m_ep{};
    std::unique_ptr<LIEF::MachO::Binary> m_executable;
    std::optional<std::flat_map<uint32_t, std::string>> m_symbols;

    // initialize functions
    static std::optional<LIEF::MachO::SegmentCommand> get_text_segment( LIEF::MachO::Binary &executable );
    static std::optional<std::flat_map<uint32_t, std::string>> parse_symbols( LIEF::MachO::Binary &executable );
};