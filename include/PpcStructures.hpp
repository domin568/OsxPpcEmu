/**
 * Author:    domin568
 * Created:   18.01.2026
 * Brief:     Mac OS X 10.4 PPC structures (from SDK)
 **/
#include "../include/Common.hpp"

namespace guest
{
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
            .srr0 = common::ensure_endianness( st.srr0, order ),
            .srr1 = common::ensure_endianness( st.srr1, order ),
            .r0 = common::ensure_endianness( st.r0, order ),
            .r1 = common::ensure_endianness( st.r1, order ),
            .r2 = common::ensure_endianness( st.r2, order ),
            .r3 = common::ensure_endianness( st.r3, order ),
            .r4 = common::ensure_endianness( st.r4, order ),
            .r5 = common::ensure_endianness( st.r5, order ),
            .r6 = common::ensure_endianness( st.r6, order ),
            .r7 = common::ensure_endianness( st.r7, order ),
            .r8 = common::ensure_endianness( st.r8, order ),
            .r9 = common::ensure_endianness( st.r9, order ),
            .r10 = common::ensure_endianness( st.r10, order ),
            .r11 = common::ensure_endianness( st.r11, order ),
            .r12 = common::ensure_endianness( st.r12, order ),
            .r13 = common::ensure_endianness( st.r13, order ),
            .r14 = common::ensure_endianness( st.r14, order ),
            .r15 = common::ensure_endianness( st.r15, order ),
            .r16 = common::ensure_endianness( st.r16, order ),
            .r17 = common::ensure_endianness( st.r17, order ),
            .r18 = common::ensure_endianness( st.r18, order ),
            .r19 = common::ensure_endianness( st.r19, order ),
            .r20 = common::ensure_endianness( st.r20, order ),
            .r21 = common::ensure_endianness( st.r21, order ),
            .r22 = common::ensure_endianness( st.r22, order ),
            .r23 = common::ensure_endianness( st.r23, order ),
            .r24 = common::ensure_endianness( st.r24, order ),
            .r25 = common::ensure_endianness( st.r25, order ),
            .r26 = common::ensure_endianness( st.r26, order ),
            .r27 = common::ensure_endianness( st.r27, order ),
            .r28 = common::ensure_endianness( st.r28, order ),
            .r29 = common::ensure_endianness( st.r29, order ),
            .r30 = common::ensure_endianness( st.r30, order ),
            .r31 = common::ensure_endianness( st.r31, order ),
            .cr = common::ensure_endianness( st.cr, order ),
            .xer = common::ensure_endianness( st.xer, order ),
            .lr = common::ensure_endianness( st.lr, order ),
            .ctr = common::ensure_endianness( st.ctr, order ),
            .mq = common::ensure_endianness( st.mq, order ),
            .vrsave = common::ensure_endianness( st.vrsave, order ),
        };
    }

    struct stat
    {
    };
};

struct timespec
{
    std::uint32_t tv_sec;
    std::uint32_t tv_nsec;
};

struct stat
{
    std::int32_t st_dev;          /* [XSI] ID of device containing file */
    std::uint32_t st_ino;         /* [XSI] File serial number */
    std::uint16_t st_mode;        /* [XSI] Mode of file (see below) */
    std::uint16_t st_nlink;       /* [XSI] Number of hard links */
    std::uint32_t st_uid;         /* [XSI] User ID of the file */
    std::uint32_t st_gid;         /* [XSI] Group ID of the file */
    std::int32_t st_rdev;         /* [XSI] Device ID */
    struct timespec st_atimespec; /* time of last access */
    struct timespec st_mtimespec; /* time of last data modification */
    struct timespec st_ctimespec; /* time of last status change */
    std::int64_t st_size;         /* [XSI] file size, in bytes */
    std::int64_t st_blocks;       /* [XSI] blocks allocated for file */
    std::int32_t st_blksize;      /* [XSI] optimal blocksize for I/O */
    std::uint32_t st_flags;       /* user defined flags for file */
    std::uint32_t st_gen;         /* file generation number */
    std::int32_t st_lspare;       /* RESERVED: DO NOT USE! */
    std::int64_t st_qspare[2];    /* RESERVED: DO NOT USE! */
};

// PowerPC jmp_buf structure for setjmp/longjmp
// Based on Mac OS X 10.4 PPC ABI
struct jmp_buf
{
    uint32_t r1;   // Stack pointer (r1)
    uint32_t r2;   // TOC pointer (r2)
    uint32_t r13;  // Reserved (r13)
    uint32_t r14;  // Non-volatile GPRs (r14-r31)
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
    uint32_t cr;   // Condition register
    uint32_t lr;   // Link register (return address)
    uint32_t ctr;  // Count register (optional)
    uint32_t xer;  // Fixed-point exception register (optional)
    // Total: 26 words = 104 bytes (matches typical PowerPC jmp_buf size)
};

} // namespace guest