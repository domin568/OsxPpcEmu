/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     Loader for Mach-O object files (PPC)
 **/
#pragma once
#include "../include/Common.hpp"
#include <LIEF/MachO.hpp>
#include <expected>
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
            .srr0{ common::to_host( st.srr0, order ) },
            .srr1{ common::to_host( st.srr1, order ) },
            .r0{ common::to_host( st.r0, order ) },
            .r1{ common::to_host( st.r1, order ) },
            .r2{ common::to_host( st.r2, order ) },
            .r3{ common::to_host( st.r3, order ) },
            .r4{ common::to_host( st.r4, order ) },
            .r5{ common::to_host( st.r5, order ) },
            .r6{ common::to_host( st.r6, order ) },
            .r7{ common::to_host( st.r7, order ) },
            .r8{ common::to_host( st.r8, order ) },
            .r9{ common::to_host( st.r9, order ) },
            .r10{ common::to_host( st.r10, order ) },
            .r11{ common::to_host( st.r11, order ) },
            .r12{ common::to_host( st.r12, order ) },
            .r13{ common::to_host( st.r13, order ) },
            .r14{ common::to_host( st.r14, order ) },
            .r15{ common::to_host( st.r15, order ) },
            .r16{ common::to_host( st.r16, order ) },
            .r17{ common::to_host( st.r17, order ) },
            .r18{ common::to_host( st.r18, order ) },
            .r19{ common::to_host( st.r19, order ) },
            .r20{ common::to_host( st.r20, order ) },
            .r21{ common::to_host( st.r21, order ) },
            .r22{ common::to_host( st.r22, order ) },
            .r23{ common::to_host( st.r23, order ) },
            .r24{ common::to_host( st.r24, order ) },
            .r25{ common::to_host( st.r25, order ) },
            .r26{ common::to_host( st.r26, order ) },
            .r27{ common::to_host( st.r27, order ) },
            .r28{ common::to_host( st.r28, order ) },
            .r29{ common::to_host( st.r29, order ) },
            .r30{ common::to_host( st.r30, order ) },
            .r31{ common::to_host( st.r31, order ) },
            .cr{ common::to_host( st.cr, order ) },
            .xer{ common::to_host( st.xer, order ) },
            .lr{ common::to_host( st.lr, order ) },
            .ctr{ common::to_host( st.ctr, order ) },
            .mq{ common::to_host( st.mq, order ) },
            .vrsave{ common::to_host( st.vrsave, order ) },
        };
    }
};

class CMachoLoader
{
  public:
    static std::expected<CMachoLoader, common::Error> init( const std::string &path );
    bool mapMemory( uc_engine *uc );
    bool setUnixThread( uc_engine *uc );

  private:
    explicit CMachoLoader( std::unique_ptr<LIEF::MachO::Binary> executable );

    static constexpr size_t Max_Segment_File_Size{ 0x100'000 };
    static constexpr size_t Ppc_Thread_State{ 1 };

    std::unique_ptr<LIEF::MachO::Binary> m_executable;
};