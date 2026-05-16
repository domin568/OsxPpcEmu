/**
 * Author:    domin568
 * Brief:     redirected API implementations
 **/

#include "COsxPpcEmu.hpp"
#include "ImportDispatch.hpp"
#include "PpcStructures.hpp"
#include "shims/ShimContext.hpp"
#include <array>
#include <climits>
#include <dirent.h>
#include <netdb.h>
#include <numeric>
#include <span>
#include <string_view>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <unistd.h>
#include <unordered_map>
#include <utime.h>
#include <vector>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <sys/xattr.h>
#endif
#include <cassert>
#include <locale.h>

namespace import::callback
{
// int *___error(void);
// Returns a pointer to the errno variable
bool ___error( ShimContext &ctx )
{
    // Get the address of the _errno import entry
    std::optional<uint32_t> errnoVa{ common::get_import_entry_va_by_name( "_errno" ) };
    if (!errnoVa.has_value())
    {
        std::cerr << "Could not find _errno symbol" << std::endl;
        return false;
    }

    return ctx.ret( *errnoVa );
}

// int ___isctype(int c, unsigned long mask);
// Check if character has certain properties based on bitmask (same as ___istype)
// This is an alias for ___istype on macOS
bool ___isctype( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int, uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [c, mask] = *args;

    uint32_t chartype = 0;

    if (c >= 'A' && c <= 'Z')
        chartype |= _CTYPE_U | _CTYPE_X;
    if (c >= 'a' && c <= 'z')
        chartype |= _CTYPE_L | _CTYPE_X;
    if (c >= '0' && c <= '9')
        chartype |= _CTYPE_D | _CTYPE_X;
    if (c >= 'A' && c <= 'F')
        chartype |= _CTYPE_X;
    if (c >= 'a' && c <= 'f')
        chartype |= _CTYPE_X;
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v')
        chartype |= _CTYPE_S;
    if (c == ' ' || c == '\t')
        chartype |= _CTYPE_B;
    if (( c >= 0 && c <= 31 ) || c == 127)
        chartype |= _CTYPE_C;
    if (( c >= 33 && c <= 47 ) || ( c >= 58 && c <= 64 ) || ( c >= 91 && c <= 96 ) || ( c >= 123 && c <= 126 ))
        chartype |= _CTYPE_P;

    // Check if any of the requested mask bits are set
    uint32_t result = ( chartype & mask ) != 0 ? 1 : 0;

    return ctx.ret( result );
}

// int __istype(int c, unsigned long mask);
// Check if character has certain properties based on bitmask
bool ___istype( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int, uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [c, mask] = *args;

    uint32_t chartype = 0;

    if (c >= 'A' && c <= 'Z')
        chartype |= _CTYPE_U | _CTYPE_X;
    if (c >= 'a' && c <= 'z')
        chartype |= _CTYPE_L | _CTYPE_X;
    if (c >= '0' && c <= '9')
        chartype |= _CTYPE_D | _CTYPE_X;
    if (c >= 'A' && c <= 'F')
        chartype |= _CTYPE_X;
    if (c >= 'a' && c <= 'f')
        chartype |= _CTYPE_X;
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v')
        chartype |= _CTYPE_S;
    if (c == ' ' || c == '\t')
        chartype |= _CTYPE_B;
    if (( c >= 0 && c <= 31 ) || c == 127)
        chartype |= _CTYPE_C;
    if (( c >= 33 && c <= 47 ) || ( c >= 58 && c <= 64 ) || ( c >= 91 && c <= 96 ) || ( c >= 123 && c <= 126 ))
        chartype |= _CTYPE_P;

    // Check if any of the requested mask bits are set
    uint32_t result = ( chartype & mask ) != 0 ? 1 : 0;
    return ctx.ret( result );
}

// int ___tolower(int c);
// Converts uppercase letter to lowercase
bool ___tolower( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int>() };
    if (!args.has_value())
        return false;
    const auto [c] = *args;

    // Convert to lowercase if uppercase letter
    uint32_t result = ( c >= 'A' && c <= 'Z' ) ? ( c + 32 ) : c;

    return ctx.ret( result );
}

// int ___toupper(int c);
// Converts lowercase letter to uppercase
bool ___toupper( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int>() };
    if (!args.has_value())
        return false;
    const auto [c] = *args;

    // Convert to uppercase if lowercase letter
    uint32_t result = ( c >= 'a' && c <= 'z' ) ? ( c - 32 ) : c;

    return ctx.ret( result );
}

// int _setjmp(jmp_buf env);
// Save calling environment for later use by longjmp
bool _setjmp( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *>() };
    if (!args.has_value())
        return false;
    const auto [envPtr] = *args;

    if (!envPtr)
    {
        std::cerr << "_setjmp: null jmp_buf pointer" << std::endl;
        return false;
    }

    auto *jmpBuf = static_cast<guest::jmp_buf *>( envPtr );

    // Save registers to jmp_buf
    uint32_t r1, r2, r13, r14, r15, r16, r17, r18, r19, r20, r21;
    uint32_t r22, r23, r24, r25, r26, r27, r28, r29, r30, r31;
    uint32_t cr, lr, ctr, xer;

    uc_reg_read( ctx.uc, UC_PPC_REG_1, &r1 );
    uc_reg_read( ctx.uc, UC_PPC_REG_2, &r2 );
    uc_reg_read( ctx.uc, UC_PPC_REG_13, &r13 );
    uc_reg_read( ctx.uc, UC_PPC_REG_14, &r14 );
    uc_reg_read( ctx.uc, UC_PPC_REG_15, &r15 );
    uc_reg_read( ctx.uc, UC_PPC_REG_16, &r16 );
    uc_reg_read( ctx.uc, UC_PPC_REG_17, &r17 );
    uc_reg_read( ctx.uc, UC_PPC_REG_18, &r18 );
    uc_reg_read( ctx.uc, UC_PPC_REG_19, &r19 );
    uc_reg_read( ctx.uc, UC_PPC_REG_20, &r20 );
    uc_reg_read( ctx.uc, UC_PPC_REG_21, &r21 );
    uc_reg_read( ctx.uc, UC_PPC_REG_22, &r22 );
    uc_reg_read( ctx.uc, UC_PPC_REG_23, &r23 );
    uc_reg_read( ctx.uc, UC_PPC_REG_24, &r24 );
    uc_reg_read( ctx.uc, UC_PPC_REG_25, &r25 );
    uc_reg_read( ctx.uc, UC_PPC_REG_26, &r26 );
    uc_reg_read( ctx.uc, UC_PPC_REG_27, &r27 );
    uc_reg_read( ctx.uc, UC_PPC_REG_28, &r28 );
    uc_reg_read( ctx.uc, UC_PPC_REG_29, &r29 );
    uc_reg_read( ctx.uc, UC_PPC_REG_30, &r30 );
    uc_reg_read( ctx.uc, UC_PPC_REG_31, &r31 );
    uc_reg_read( ctx.uc, UC_PPC_REG_CR, &cr );
    uc_reg_read( ctx.uc, UC_PPC_REG_LR, &lr );
    uc_reg_read( ctx.uc, UC_PPC_REG_CTR, &ctr );
    uc_reg_read( ctx.uc, UC_PPC_REG_XER, &xer );

    // Store in big-endian format
    jmpBuf->r1 = common::ensure_endianness( r1, std::endian::big );
    jmpBuf->r2 = common::ensure_endianness( r2, std::endian::big );
    jmpBuf->r13 = common::ensure_endianness( r13, std::endian::big );
    jmpBuf->r14 = common::ensure_endianness( r14, std::endian::big );
    jmpBuf->r15 = common::ensure_endianness( r15, std::endian::big );
    jmpBuf->r16 = common::ensure_endianness( r16, std::endian::big );
    jmpBuf->r17 = common::ensure_endianness( r17, std::endian::big );
    jmpBuf->r18 = common::ensure_endianness( r18, std::endian::big );
    jmpBuf->r19 = common::ensure_endianness( r19, std::endian::big );
    jmpBuf->r20 = common::ensure_endianness( r20, std::endian::big );
    jmpBuf->r21 = common::ensure_endianness( r21, std::endian::big );
    jmpBuf->r22 = common::ensure_endianness( r22, std::endian::big );
    jmpBuf->r23 = common::ensure_endianness( r23, std::endian::big );
    jmpBuf->r24 = common::ensure_endianness( r24, std::endian::big );
    jmpBuf->r25 = common::ensure_endianness( r25, std::endian::big );
    jmpBuf->r26 = common::ensure_endianness( r26, std::endian::big );
    jmpBuf->r27 = common::ensure_endianness( r27, std::endian::big );
    jmpBuf->r28 = common::ensure_endianness( r28, std::endian::big );
    jmpBuf->r29 = common::ensure_endianness( r29, std::endian::big );
    jmpBuf->r30 = common::ensure_endianness( r30, std::endian::big );
    jmpBuf->r31 = common::ensure_endianness( r31, std::endian::big );
    jmpBuf->cr = common::ensure_endianness( cr, std::endian::big );
    jmpBuf->lr = common::ensure_endianness( lr, std::endian::big );
    jmpBuf->ctr = common::ensure_endianness( ctr, std::endian::big );
    jmpBuf->xer = common::ensure_endianness( xer, std::endian::big );

    // Return 0 for setjmp
    uint32_t ret = 0;
    return ctx.ret( ret );
}

// void _longjmp(jmp_buf env, int val);
// Restore environment saved by setjmp and return to that point
bool _longjmp( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *, int>() };
    if (!args.has_value())
        return false;
    const auto [envPtr, val] = *args;

    if (!envPtr)
    {
        std::cerr << "_longjmp: null jmp_buf pointer" << std::endl;
        return false;
    }

    auto *jmpBuf = static_cast<guest::jmp_buf *>( envPtr );

    // Restore registers from jmp_buf (convert from big-endian)
    uint32_t r1 = common::ensure_endianness( jmpBuf->r1, std::endian::big );
    uint32_t r2 = common::ensure_endianness( jmpBuf->r2, std::endian::big );
    uint32_t r13 = common::ensure_endianness( jmpBuf->r13, std::endian::big );
    uint32_t r14 = common::ensure_endianness( jmpBuf->r14, std::endian::big );
    uint32_t r15 = common::ensure_endianness( jmpBuf->r15, std::endian::big );
    uint32_t r16 = common::ensure_endianness( jmpBuf->r16, std::endian::big );
    uint32_t r17 = common::ensure_endianness( jmpBuf->r17, std::endian::big );
    uint32_t r18 = common::ensure_endianness( jmpBuf->r18, std::endian::big );
    uint32_t r19 = common::ensure_endianness( jmpBuf->r19, std::endian::big );
    uint32_t r20 = common::ensure_endianness( jmpBuf->r20, std::endian::big );
    uint32_t r21 = common::ensure_endianness( jmpBuf->r21, std::endian::big );
    uint32_t r22 = common::ensure_endianness( jmpBuf->r22, std::endian::big );
    uint32_t r23 = common::ensure_endianness( jmpBuf->r23, std::endian::big );
    uint32_t r24 = common::ensure_endianness( jmpBuf->r24, std::endian::big );
    uint32_t r25 = common::ensure_endianness( jmpBuf->r25, std::endian::big );
    uint32_t r26 = common::ensure_endianness( jmpBuf->r26, std::endian::big );
    uint32_t r27 = common::ensure_endianness( jmpBuf->r27, std::endian::big );
    uint32_t r28 = common::ensure_endianness( jmpBuf->r28, std::endian::big );
    uint32_t r29 = common::ensure_endianness( jmpBuf->r29, std::endian::big );
    uint32_t r30 = common::ensure_endianness( jmpBuf->r30, std::endian::big );
    uint32_t r31 = common::ensure_endianness( jmpBuf->r31, std::endian::big );
    uint32_t cr = common::ensure_endianness( jmpBuf->cr, std::endian::big );
    uint32_t lr = common::ensure_endianness( jmpBuf->lr, std::endian::big );
    uint32_t ctr = common::ensure_endianness( jmpBuf->ctr, std::endian::big );
    uint32_t xer = common::ensure_endianness( jmpBuf->xer, std::endian::big );

    // Restore all registers
    uc_reg_write( ctx.uc, UC_PPC_REG_1, &r1 );
    uc_reg_write( ctx.uc, UC_PPC_REG_2, &r2 );
    uc_reg_write( ctx.uc, UC_PPC_REG_13, &r13 );
    uc_reg_write( ctx.uc, UC_PPC_REG_14, &r14 );
    uc_reg_write( ctx.uc, UC_PPC_REG_15, &r15 );
    uc_reg_write( ctx.uc, UC_PPC_REG_16, &r16 );
    uc_reg_write( ctx.uc, UC_PPC_REG_17, &r17 );
    uc_reg_write( ctx.uc, UC_PPC_REG_18, &r18 );
    uc_reg_write( ctx.uc, UC_PPC_REG_19, &r19 );
    uc_reg_write( ctx.uc, UC_PPC_REG_20, &r20 );
    uc_reg_write( ctx.uc, UC_PPC_REG_21, &r21 );
    uc_reg_write( ctx.uc, UC_PPC_REG_22, &r22 );
    uc_reg_write( ctx.uc, UC_PPC_REG_23, &r23 );
    uc_reg_write( ctx.uc, UC_PPC_REG_24, &r24 );
    uc_reg_write( ctx.uc, UC_PPC_REG_25, &r25 );
    uc_reg_write( ctx.uc, UC_PPC_REG_26, &r26 );
    uc_reg_write( ctx.uc, UC_PPC_REG_27, &r27 );
    uc_reg_write( ctx.uc, UC_PPC_REG_28, &r28 );
    uc_reg_write( ctx.uc, UC_PPC_REG_29, &r29 );
    uc_reg_write( ctx.uc, UC_PPC_REG_30, &r30 );
    uc_reg_write( ctx.uc, UC_PPC_REG_31, &r31 );
    uc_reg_write( ctx.uc, UC_PPC_REG_CR, &cr );
    uc_reg_write( ctx.uc, UC_PPC_REG_LR, &lr );
    uc_reg_write( ctx.uc, UC_PPC_REG_CTR, &ctr );
    uc_reg_write( ctx.uc, UC_PPC_REG_XER, &xer );

    // Set PC to the return address (LR from setjmp)
    uc_reg_write( ctx.uc, UC_PPC_REG_PC, &lr );

    // Return val (or 1 if val is 0)
    uint32_t retVal = ( val == 0 ) ? 1 : val;
    return ctx.ret( retVal );
}

bool keymgr_dwarf2_register_sections( ShimContext &ctx )
{
    return true;
}

bool cthread_init_routine( ShimContext &ctx )
{
    return true;
}

// int abs(int n);
bool abs( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int>() };
    if (!args.has_value())
        return false;
    const auto [n] = *args;

    int ret{ ::abs( n ) };
    return ctx.ret( ret );
}

// int atexit(void (*func)(void));
bool atexit( ShimContext &ctx )
{
    return true;
}

// int atoi(const char *str);
// Converts string to integer
bool atoi( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *>() };
    if (!args.has_value())
        return false;
    const auto [str] = *args;

    // Use standard C library atoi
    int result = ::atoi( str );
    return ctx.ret( result );
}

bool exit( ShimContext &ctx )
{
    uc_emu_stop( ctx.uc );
    return true;
}

// pid_t fork(void);
// Shim: always returns 0 (pretend to be the child process)
bool fork( ShimContext &ctx )
{
    std::cout << "[OsxPpcEmu] fork() shim called, returning 0 (child)" << std::endl;
    return ctx.ret( 0 );
}

// int execve(const char *path, char *const argv[], char *const envp[]);
// Redirects execution of PPC binaries through the emulator
bool execve( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, std::uint32_t, std::uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [path, guestArgvAddr, guestEnvpAddr] = *args;

    // Resolve the emulator's own executable path
    char emuPath[4096]{};
    std::uint32_t emuPathSize{ sizeof( emuPath ) };
#ifdef __APPLE__
    bool resolved{ _NSGetExecutablePath( emuPath, &emuPathSize ) == 0 };
#else
    ssize_t len{ ::readlink( "/proc/self/exe", emuPath, sizeof( emuPath ) - 1 ) };
    bool resolved{ len != -1 };
    if (resolved)
        emuPath[len] = '\0';
#endif
    if (!resolved)
    {
        std::cerr << "[OsxPpcEmu] execve: could not resolve emulator path" << std::endl;
        set_guest_errno( ctx.mem, ENOENT );
        std::int32_t ret{ -1 };
        uc_reg_write( ctx.uc, UC_PPC_REG_3, &ret );
        return true;
    }

    // Read null-terminated guest argv: array of big-endian 32-bit pointers
    std::vector<const char *> guestArgv;
    for (std::uint32_t cur{ guestArgvAddr }; cur != 0;)
    {
        std::uint32_t ptrBe{};
        ::memcpy( &ptrBe, ctx.mem->get( cur ), sizeof( ptrBe ) );
        std::uint32_t ptr{ common::ensure_endianness( ptrBe, std::endian::big ) };
        if (ptr == 0)
            break;
        guestArgv.push_back( reinterpret_cast<const char *>( ctx.mem->get( ptr ) ) );
        cur += 4;
    }

    // Build new argv: emulator, target binary, then original args (skip argv[0])
    std::vector<const char *> newArgv{ emuPath, path };
    for (std::size_t i{ 1 }; i < guestArgv.size(); ++i)
        newArgv.push_back( guestArgv[i] );
    newArgv.push_back( nullptr );

    std::cout << "[OsxPpcEmu] execve: redirecting " << path << " through " << emuPath << std::endl;

    ::execv( emuPath, const_cast<char *const *>( newArgv.data() ) );

    // Only reached on failure
    std::cerr << "[OsxPpcEmu] execve failed: " << ::strerror( errno ) << std::endl;
    set_guest_errno( ctx.mem, errno );
    return ctx.ret( -1 );
}

// int fclose(FILE *stream);
bool fclose( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *>() };
    if (!args.has_value())
        return false;
    const auto [stream] = *args;

    FILE *f{ common::resolve_file_stream( ctx.mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );
    int ret{ ::fclose( f ) };

    if (ret == EOF)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// int fflush(FILE *stream);
bool fflush( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *>() };
    if (!args.has_value())
        return false;
    const auto [stream] = *args;

    FILE *f{ common::resolve_file_stream( ctx.mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );

    int ret{ ::fflush( f ) };

    if (ret == EOF)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// int fgetc(FILE *stream);
bool fgetc( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *>() };
    if (!args.has_value())
        return false;
    const auto [stream] = *args;

    FILE *f{ common::resolve_file_stream( ctx.mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );

    int ret{ ::fgetc( f ) };

    if (ret == EOF)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// FILE *fopen(const char *filename, const char *mode);
bool fopen( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, const char *>() };
    if (!args.has_value())
        return false;
    const auto [filename, mode] = *args;

    FILE *ret{ ::fopen( filename, mode ) };

    if (ret == nullptr)
    {
        set_guest_errno( ctx.mem, errno );
    }

    // Store the FILE* in guest memory and return pointer to it
    uint32_t retGuest{ 0 };
    if (ret != nullptr)
    {
        // Allocate space for the FILE* on the heap
        retGuest = ctx.mem->heap_alloc( sizeof( FILE * ) );
        if (retGuest != 0)
        {
            FILE **filePtr{ static_cast<FILE **>( ctx.mem->get( retGuest ) ) };
            if (filePtr)
            {
                *filePtr = ret;
            }
            else
            {
                ::fclose( ret );
                retGuest = 0;
            }
        }
        else
        {
            ::fclose( ret );
        }
    }

    return ctx.ret( retGuest );
}

// size_t fwrite( const void * buffer, size_t size, size_t count, FILE * stream );
bool fwrite( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const void *, std::size_t, std::size_t, void *>() };
    if (!args.has_value())
        return false;
    const auto [buffer, size, count, stream] = *args;

    FILE *f{ common::resolve_file_stream( ctx.mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );

    std::size_t ret{ ::fwrite( buffer, size, count, f ) };

    // fwrite returns less than count on error
    if (ret < count)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// int fstat(int fd, struct stat *buf);
bool fstat( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int, void *>() };
    if (!args.has_value())
        return false;
    const auto [fd, buf] = *args;

    struct stat hostStat{};
    int ret{ ::fstat( fd, &hostStat ) };

    if (ret == 0 && buf != nullptr)
    {
        auto *guestStat{ static_cast<guest::stat *>( buf ) };
        ::memset( guestStat, 0, sizeof( guest::stat ) );
        guestStat->st_dev = common::ensure_endianness( hostStat.st_dev, std::endian::big );
        guestStat->st_ino = common::ensure_endianness( hostStat.st_ino, std::endian::big );
        guestStat->st_mode = common::ensure_endianness( hostStat.st_mode, std::endian::big );
        guestStat->st_nlink = common::ensure_endianness( hostStat.st_nlink, std::endian::big );
        guestStat->st_uid = common::ensure_endianness( hostStat.st_uid, std::endian::big );
        guestStat->st_gid = common::ensure_endianness( hostStat.st_gid, std::endian::big );
        guestStat->st_rdev = common::ensure_endianness( hostStat.st_rdev, std::endian::big );
        guestStat->st_size = common::ensure_endianness( hostStat.st_size, std::endian::big );
        guestStat->st_blksize = common::ensure_endianness( hostStat.st_blksize, std::endian::big );
        guestStat->st_blocks = common::ensure_endianness( hostStat.st_blocks, std::endian::big );
    }
    else if (ret == -1)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// int ioctl(int fd, unsigned long op, ...);
bool ioctl( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int, uint32_t, void *>() };
    if (!args.has_value())
        return false;

    const auto [fd, op, ptr]{ *args };

    static constexpr std::uint32_t Get_Window_Size_Op{ 0x40087468 };
    struct winsize
    {
        unsigned short ws_row;    /* rows, in characters */
        unsigned short ws_col;    /* columns, in characters */
        unsigned short ws_xpixel; /* horizontal size, pixels */
        unsigned short ws_ypixel; /* vertical size, pixels */
    };
    std::int32_t ret{};
    if (op == Get_Window_Size_Op)
    {
        reinterpret_cast<winsize *>( ptr )->ws_row = common::ensure_endianness<short>( 25, std::endian::big );
        reinterpret_cast<winsize *>( ptr )->ws_col = common::ensure_endianness<short>( 80, std::endian::big );
        reinterpret_cast<winsize *>( ptr )->ws_xpixel = 0;
        reinterpret_cast<winsize *>( ptr )->ws_ypixel = 0;
        ret = 0;
    }
    else
    {
        ret = -1;
        assert( "Missing implementation for ioctl" );
    }
    return ctx.ret( ret );
}

bool malloc( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::size_t>() };
    if (!args.has_value())
        return false;
    const auto [size]{ *args };

    uint32_t ret{ ctx.mem->heap_alloc( size ) };

    // Set errno if allocation failed
    if (ret == 0)
    {
        set_guest_errno( ctx.mem, ENOMEM );
    }

    return ctx.ret( ret );
}

// void* calloc(std::size_t num, std::size_t size);
bool calloc( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::size_t, std::size_t>() };
    if (!args.has_value())
        return false;
    const auto [num, size]{ *args };

    uint32_t ret{ ctx.mem->heap_alloc( num * size ) };
    // calloc zeros the memory
    void *ptr{ ctx.mem->get( ret ) };
    if (ptr)
        ::memset( ptr, 0, num * size );
    else if (ret == 0)
    {
        set_guest_errno( ctx.mem, ENOMEM );
    }

    return ctx.ret( ret );
}

// void* realloc(void* ptr, std::size_t size);
bool realloc( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *, std::size_t>() };
    if (!args.has_value())
        return false;
    const auto [ptr, size]{ *args };

    // If ptr is NULL, realloc behaves like malloc
    if (!ptr)
    {
        uint32_t ret{ ctx.mem->heap_alloc( size ) };
        if (ret == 0)
        {
            set_guest_errno( ctx.mem, ENOMEM );
        }
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
        {
            std::cerr << "Could not write realloc return" << std::endl;
            return false;
        }
        return true;
    }

    // If size is 0, realloc behaves like free (but we return NULL since we don't actually free)
    if (size == 0)
    {
        uint32_t ret{ 0 };
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
        {
            std::cerr << "Could not write realloc return" << std::endl;
            return false;
        }
        return true;
    }

    // Allocate new memory and copy old data
    uint32_t oldGuestPtr{ ctx.mem->to_guest( ptr ) };
    std::size_t oldSize{ ctx.mem->get_alloc_size( oldGuestPtr ) };

    uint32_t newPtr{ ctx.mem->heap_alloc( size ) };
    void *newHostPtr{ ctx.mem->get( newPtr ) };

    if (newHostPtr && ptr)
    {
        // Copy old data to new location
        // Copy the minimum of old size and new size to avoid reading/writing out of bounds
        std::size_t copySize{ oldSize > 0 ? std::min( oldSize, size ) : size };
        ::memcpy( newHostPtr, ptr, copySize );
    }
    else if (newPtr == 0)
    {
        set_guest_errno( ctx.mem, ENOMEM );
    }

    return ctx.ret( newPtr );
}

// void* memcpy(void * destination, const void * source, size_t num);
bool memcpy( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *, const void *, std::size_t>() };
    if (!args.has_value())
        return false;
    const auto [dest, source, count] = *args;
    ::memcpy( dest, source, count );
    uint32_t retGuest{ ctx.mem->to_guest( dest ) };
    return ctx.ret( retGuest );
}

// void* memmove( void* dest, const void* src, std::size_t count );
bool memmove( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *, const void *, std::size_t>() };
    if (!args.has_value())
        return false;
    const auto [dest, source, count] = *args;
    ::memmove( dest, source, count );
    uint32_t retGuest{ ctx.mem->to_guest( dest ) };
    return ctx.ret( retGuest );
}

// void *memset(void *str, int c, size_t n)
bool memset( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *, int, std::size_t>() };
    if (!args.has_value())
        return false;
    const auto [str, c, n] = *args;
    ::memset( str, c, n * sizeof( char ) );
    uint32_t retGuest{ ctx.mem->to_guest( str ) };
    return ctx.ret( retGuest );
}

// int puts(const char *str);
bool puts( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *>() };
    if (!args.has_value())
        return false;
    const auto [str] = *args;
    int ret{ ::puts( str ) };
    return ctx.ret( ret );
}

// int setvbuf( FILE * stream, char * buffer, int mode, size_t size );
bool setvbuf( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *, char *, int, size_t>() };
    if (!args.has_value())
        return false;
    // TODO
    return ctx.ret( 0 );
}

// sighandler_t signal(int signum, sighandler_t handler);
bool signal( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int, void *>() };
    if (!args.has_value())
        return false;
    // TODO
    return true;
}

// int sprintf(char * buffer, const char * format, ...);
bool sprintf( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *, const char *>() };
    if (!args.has_value())
        return false;

    auto [buffer, format]{ *args };

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( ctx.uc, ctx.mem, format, UC_PPC_REG_5, false ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsprintf( buffer, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    return ctx.ret( ret );
}

// int printf(const char *format, ...)
bool printf( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *>() };
    if (!args.has_value())
        return false;
    auto [format]{ *args };

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( ctx.uc, ctx.mem, format, UC_PPC_REG_4, false ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vprintf( format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    return ctx.ret( ret );
}

// int vsprintf(char * buffer, const char * format, va_list ap);
bool vsprintf( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *, const char *, void *>() };
    if (!args.has_value())
        return false;
    const auto &[s, format, apPtr] = *args;
    std::vector formatArgs{ common::get_va_arguments( ctx.mem, apPtr, format ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsprintf( s, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    return ctx.ret( ret );
}

// int stat(const char * restrict path,	struct stat * restrict sb);
bool stat( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, void *>() };
    if (!args.has_value())
        return false;
    const auto [path, sb] = *args;

    // Call host stat
    struct stat hostStat;
    int ret{ ::stat( path, &hostStat ) };

    if (ret == 0 && sb != nullptr)
    {
        auto *guestStat{ static_cast<guest::stat *>( sb ) };
        guestStat->st_dev = common::ensure_endianness( hostStat.st_dev, std::endian::big );
        guestStat->st_ino = common::ensure_endianness( hostStat.st_ino, std::endian::big );
        guestStat->st_mode = common::ensure_endianness( hostStat.st_mode, std::endian::big );
        guestStat->st_nlink = common::ensure_endianness( hostStat.st_nlink, std::endian::big );
        guestStat->st_uid = common::ensure_endianness( hostStat.st_uid, std::endian::big );
        guestStat->st_gid = common::ensure_endianness( hostStat.st_gid, std::endian::big );
        guestStat->st_rdev = common::ensure_endianness( hostStat.st_rdev, std::endian::big );
        guestStat->st_size = common::ensure_endianness( hostStat.st_size, std::endian::big );
        guestStat->st_blksize = common::ensure_endianness( hostStat.st_blksize, std::endian::big );
        guestStat->st_blocks = common::ensure_endianness( hostStat.st_blocks, std::endian::big );
    }
    else if (ret == -1)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// int lstat(const char * restrict path, struct stat * restrict sb);
// Like stat but doesn't follow symbolic links
bool lstat( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, void *>() };
    if (!args.has_value())
        return false;
    const auto [path, sb] = *args;

    // Call host lstat
    struct stat hostStat{};
    int ret{ ::lstat( path, &hostStat ) };

    if (ret == 0 && sb != nullptr)
    {
        auto *guestStat{ static_cast<guest::stat *>( sb ) };
        guestStat->st_dev = common::ensure_endianness( hostStat.st_dev, std::endian::big );
        guestStat->st_ino = common::ensure_endianness( hostStat.st_ino, std::endian::big );
        guestStat->st_mode = common::ensure_endianness( hostStat.st_mode, std::endian::big );
        guestStat->st_nlink = common::ensure_endianness( hostStat.st_nlink, std::endian::big );
        guestStat->st_uid = common::ensure_endianness( hostStat.st_uid, std::endian::big );
        guestStat->st_gid = common::ensure_endianness( hostStat.st_gid, std::endian::big );
        guestStat->st_rdev = common::ensure_endianness( hostStat.st_rdev, std::endian::big );
        guestStat->st_size = common::ensure_endianness( hostStat.st_size, std::endian::big );
        guestStat->st_blksize = common::ensure_endianness( hostStat.st_blksize, std::endian::big );
        guestStat->st_blocks = common::ensure_endianness( hostStat.st_blocks, std::endian::big );
    }
    else if (ret == -1)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// char * strcat( char * destination, const char * source );
bool strcat( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *, const char *>() };
    if (!args.has_value())
        return false;
    const auto [dest, src] = *args;
    char *ret{ ::strcat( dest, src ) };
    uint32_t retGuest{ ret != nullptr ? ctx.mem->to_guest( ret ) : 0 };
    return ctx.ret( retGuest );
}

// char * strchr( const char * str, int ch );
bool strchr( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *, int>() };
    if (!args.has_value())
        return false;
    const auto [str, ch] = *args;
    char *ret{ ::strchr( str, ch ) };
    uint32_t retGuest{ ret != nullptr ? ctx.mem->to_guest( ret ) : 0 };
    return ctx.ret( retGuest );
}

// size_t strlen( const char * str );
bool strlen( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *>() };
    if (!args.has_value())
        return false;
    const auto [str] = *args;
    std::size_t ret{ ::strlen( str ) };
    return ctx.ret( ret );
}

// char *strpbrk(const char *str1, const char *str2);
// Finds the first character in str1 that matches any character in str2
bool strpbrk( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, const char *>() };
    if (!args.has_value())
        return false;
    const auto [str1, str2] = *args;
    const char *ret{ ::strpbrk( str1, str2 ) };
    uint32_t retGuest{ ret != nullptr ? ctx.mem->to_guest( ret ) : 0 };
    return ctx.ret( retGuest );
}

// char * strrchr( const char * str, int ch );
bool strrchr( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *, int>() };
    if (!args.has_value())
        return false;
    const auto [str, ch] = *args;

    char *ret{ ::strrchr( str, ch ) };
    uint32_t retGuest{ ret != nullptr ? ctx.mem->to_guest( ret ) : 0 };
    return ctx.ret( retGuest );
}

// char *strstr(const char *haystack, const char *needle);
bool strstr( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, const char *>() };
    if (!args.has_value())
        return false;
    const auto [haystack, needle] = *args;

    const char *ret{ ::strstr( haystack, needle ) };
    uint32_t retGuest{ ret != nullptr ? ctx.mem->to_guest( ret ) : 0 };
    return ctx.ret( retGuest );
}

// char *strcpy( char *dest, const char *src );
bool strcpy( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *, const char *>() };
    if (!args.has_value())
        return false;
    const auto [dest, source] = *args;

    char *ret{ ::strcpy( dest, source ) };
    uint32_t retGuest{ ret != nullptr ? ctx.mem->to_guest( ret ) : 0 };
    return ctx.ret( retGuest );
}

// char *strdup( const char *s );
// Duplicates a string by allocating memory and copying the contents
bool strdup( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *>() };
    if (!args.has_value())
        return false;
    const auto [str] = *args;

    if (!str)
    {
        uint32_t ret{ 0 };
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
        {
            std::cerr << "Could not write strdup return value" << std::endl;
            return false;
        }
        return true;
    }

    std::size_t len{ ::strlen( str ) };
    uint32_t guestPtr{ ctx.mem->heap_alloc( len + 1 ) };

    if (guestPtr == 0)
    {
        set_guest_errno( ctx.mem, ENOMEM );
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &guestPtr ) != UC_ERR_OK)
        {
            std::cerr << "Could not write strdup return value" << std::endl;
            return false;
        }
        return true;
    }

    char *dest{ static_cast<char *>( ctx.mem->get( guestPtr ) ) };
    if (dest)
    {
        ::memcpy( dest, str, len + 1 );
    }

    return ctx.ret( guestPtr );
}

// char *strerror(int errnum);
// Returns a pointer to the textual representation of the current errno value
bool strerror( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int>() };
    if (!args.has_value())
        return false;
    const auto [errnum] = *args;

    const char *ret{ ::strerror( errnum ) };
    uint32_t retGuest{ 0 };

    if (ret != nullptr)
    {
        std::size_t len{ ::strlen( ret ) + 1 };
        char *heap_ptr{ reinterpret_cast<char *>( ctx.mem->to_host( ctx.mem->heap_alloc( len ) ) ) };
        ::memcpy( heap_ptr, ret, len );
        retGuest = ctx.mem->to_guest( heap_ptr );
    }

    return ctx.ret( retGuest );
}

// char * strncpy ( char * destination, const char * source, size_t num );
bool strncpy( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *, const char *, std::size_t>() };
    if (!args.has_value())
        return false;
    const auto [dest, source, num] = *args;

    char *ret{ ::strncpy( dest, source, num ) };
    uint32_t retGuest{ ret != nullptr ? ctx.mem->to_guest( ret ) : 0 };
    return ctx.ret( retGuest );
}

bool vsnprintf( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *, size_t, const char *, void *>() };
    if (!args.has_value())
        return false;
    const auto &[s, n, format, apPtr] = *args;
    std::vector formatArgs{ common::get_va_arguments( ctx.mem, apPtr, format ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsnprintf( s, n, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    return ctx.ret( ret );
}

// char *getcwd(char *buf, size_t size);
bool getcwd( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *, size_t>() };
    if (!args.has_value())
        return false;
    const auto [buf, size] = *args;
    char *ret{ ::getcwd( buf, size ) };

    if (ret == nullptr)
    {
        set_guest_errno( ctx.mem, errno );
    }

    uint32_t retGuest{ ret != nullptr ? ctx.mem->to_guest( ret ) : 0 };
    return ctx.ret( retGuest );
}

// void free(void *ptr);
bool free( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *>() };
    if (!args.has_value())
        return false;
    // Do not actually free memory
    return true;
}

// int strcmp( const char *lhs, const char *rhs );
bool strcmp( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, const char *>() };
    if (!args.has_value())
        return false;
    const auto [lhs, rhs] = *args;
    int ret{ ::strcmp( lhs, rhs ) };
    return ctx.ret( ret );
}

// int strncmp(const char *s1, const char *s2, size_t n);
bool strncmp( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, const char *, size_t>() };
    if (!args.has_value())
        return false;
    const auto [s1, s2, n] = *args;
    int ret{ ::strncmp( s1, s2, n ) };
    return ctx.ret( ret );
}

// int fprintf(FILE *stream, const char *format, ...);
bool fprintf( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *, const char *>() };
    if (!args.has_value())
        return false;

    auto [stream, format]{ *args };

    FILE *f{ common::resolve_file_stream( ctx.mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( ctx.uc, ctx.mem, format, UC_PPC_REG_5, false ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vfprintf( f, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    return ctx.ret( ret );
}

// ssize_t readlink(const char *path, char *buf, size_t bufsiz);
bool readlink( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, char *, size_t>() };
    if (!args.has_value())
        return false;
    const auto [path, buf, bufsiz] = *args;

    ssize_t ret{ ::readlink( path, buf, bufsiz ) };

    if (ret == -1)
    {
        set_guest_errno( ctx.mem, errno );
    }

    std::int32_t retVal{ static_cast<std::int32_t>( ret ) };
    return ctx.ret( retVal );
}

// off_t lseek(int fd, off_t offset, int whence);
bool lseek( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int, std::uint32_t, std::uint32_t, int>() };
    if (!args.has_value())
        return false;
    const auto [fd, offsetHi, offsetLo, whence] = *args;

    std::int64_t offset{ offsetLo | ( static_cast<std::int64_t>( offsetHi ) << 32 ) };
    off_t ret{ ::lseek( fd, static_cast<off_t>( offset ), whence ) };

    if (ret == static_cast<off_t>( -1 ))
    {
        set_guest_errno( ctx.mem, errno );
    }

    uint32_t retGuest = static_cast<uint32_t>( ret );
    return ctx.ret( retGuest );
}

// char *getenv(const char *name);
bool getenv( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *>() };
    if (!args.has_value())
        return false;
    const auto [name] = *args;

    char *ret{ ::getenv( name ) };
    uint32_t retGuest{ 0 };
    if (name != nullptr && std::strlen( name ) >= 7 && !std::memcmp( name, "DISPLAY", 7 ))
    {
        static constexpr std::string_view retStr{ ":0" };
        char *heap_ptr{ reinterpret_cast<char *>( ctx.mem->to_host( ctx.mem->heap_alloc( retStr.size() + 1 ) ) ) };
        ::memcpy( heap_ptr, retStr.data(), retStr.size() );
        heap_ptr[retStr.size()] = '\0';
        retGuest = ctx.mem->to_guest( heap_ptr );
    }
    else if (ret != nullptr)
    {
        char *heap_ptr{ reinterpret_cast<char *>( ctx.mem->to_host( ctx.mem->heap_alloc( ::strlen( ret ) + 1 ) ) ) };
        ::memcpy( heap_ptr, ret, ::strlen( ret ) + 1 );
        retGuest = ctx.mem->to_guest( heap_ptr );
    }
    return ctx.ret( retGuest );
}

// int open(const char *path, int flags, ...);
bool open( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, int, int>() };
    if (!args.has_value())
        return false;
    const auto [path, flags, mode] = *args;

    int ret{ ::open( path, flags, mode ) };

    if (ret == -1)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// DIR *opendir(const char *path);
bool opendir( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *>() };
    if (!args.has_value())
        return false;
    const auto [path] = *args;

    DIR *hostDir{ ::opendir( path ) };

    std::uint32_t retPtr{ 0 };
    if (hostDir == nullptr)
    {
        set_guest_errno( ctx.mem, errno );
    }
    else
    {
        DIR *hostDirDst{ reinterpret_cast<DIR *>( ctx.mem->to_host( ctx.mem->heap_alloc( sizeof( DIR ) ) ) ) };
        ::memcpy( hostDirDst, hostDir, sizeof( DIR ) );
        retPtr = ctx.mem->to_guest( hostDirDst );
    }

    return ctx.ret( retPtr );
}

// struct dirent *readdir(DIR *dirp);
bool readdir( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [guestDirPtr] = *args;

    std::uint32_t retPtr{ 0 };
    if (guestDirPtr == 0)
    {
        set_guest_errno( ctx.mem, EBADF );
    }
    else
    {
        DIR *hostDir{ reinterpret_cast<DIR *>( ctx.mem->to_host( guestDirPtr ) ) };
        struct dirent *hostEntry{ ::readdir( hostDir ) };

        if (hostEntry == nullptr)
        {
            if (errno != 0)
                set_guest_errno( ctx.mem, errno );
            // NULL return with errno=0 means end of directory
        }
        else
        {
            std::uint32_t guestEntryVa{ ctx.mem->heap_alloc( sizeof( guest::dirent ) ) };
            guest::dirent *guestEntry{ reinterpret_cast<guest::dirent *>( ctx.mem->to_host( guestEntryVa ) ) };
            if (!guestEntry)
            {
                set_guest_errno( ctx.mem, ENOMEM );
            }
            else
            {
                std::memset( guestEntry, 0, sizeof( guest::dirent ) );
                guestEntry->d_ino =
                    common::ensure_endianness( static_cast<uint32_t>( hostEntry->d_ino ), std::endian::big );
                guestEntry->d_reclen =
                    common::ensure_endianness( static_cast<uint16_t>( hostEntry->d_reclen ), std::endian::big );
                guestEntry->d_type = hostEntry->d_type;
                guestEntry->d_namlen =
                    common::ensure_endianness( static_cast<uint16_t>( hostEntry->d_namlen ), std::endian::big );
                std::strncpy( guestEntry->d_name, hostEntry->d_name, sizeof( guestEntry->d_name ) - 1 );
                guestEntry->d_name[sizeof( guestEntry->d_name ) - 1] = '\0';

                retPtr = guestEntryVa;
            }
        }
    }

    return ctx.ret( retPtr );
}

// int closedir(DIR *dirp);
bool closedir( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<std::uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [guestDir] = *args;

    int ret{ 0 };
    if (guestDir == 0)
    {
        set_guest_errno( ctx.mem, EBADF );
    }
    else
    {
        // no ::closedir as it calls free on non heap address
    }

    return ctx.ret( ret );
}

// int unlink(const char *pathname);
// Deletes a name from the filesystem
bool unlink( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *>() };
    if (!args.has_value())
        return false;
    const auto [pathname] = *args;

    int ret{ ::unlink( pathname ) };

    if (ret == -1)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// int utime(const char *filename, const struct utimbuf *times);
// Set file access and modification times
// TODO fix, not working, bad date, why?
bool utime( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, const void *>() };
    if (!args.has_value())
        return false;
    const auto [filename, times] = *args;

    const guest::utimbuf *timesPtr{ reinterpret_cast<const guest::utimbuf *>( times ) };
    utimbuf hostTimes{};
    if (times != nullptr)
    {
        hostTimes.actime = common::ensure_endianness( static_cast<std::int32_t>( timesPtr->actime ), std::endian::big );
        hostTimes.modtime =
            common::ensure_endianness( static_cast<std::int32_t>( timesPtr->modtime ), std::endian::big );
    }

    int ret{ ::utime( filename, &hostTimes ) };

    if (ret == -1)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// int chmod(const char *path, mode_t mode);
bool chmod( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [path, mode] = *args;

    int ret{ ::chmod( path, static_cast<mode_t>( mode ) ) };

    if (ret == -1)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// int close(int fd);
bool close( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int>() };
    if (!args.has_value())
        return false;
    const auto [fd] = *args;

    int ret{ ::close( fd ) };

    if (ret == -1)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// ssize_t read(int fd, void *buf, size_t count);
bool read( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int, void *, size_t>() };
    if (!args.has_value())
        return false;
    const auto [fd, buf, count] = *args;

    ssize_t ret{ ::read( fd, buf, count ) };

    if (ret == -1)
    {
        set_guest_errno( ctx.mem, errno );
    }

    std::int32_t retVal{ static_cast<std::int32_t>( ret ) };
    return ctx.ret( retVal );
}

// ssize_t write(int fd, const void *buf, size_t count);
bool write( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int, const void *, size_t>() };
    if (!args.has_value())
        return false;
    const auto [fd, buf, count] = *args;

    ssize_t ret{ ::write( fd, buf, count ) };

    if (ret == -1)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// int memcmp(const void *s1, const void *s2, size_t n);
bool memcmp( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const void *, const void *, size_t>() };
    if (!args.has_value())
        return false;
    const auto [s1, s2, n] = *args;

    int ret{ ::memcmp( s1, s2, n ) };

    return ctx.ret( ret );
}

// time_t time(time_t *tloc);
bool time( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<time_t *>() };
    if (!args.has_value())
        return false;
    const auto [tloc] = *args;

    time_t ret{ ::time( nullptr ) };
    std::uint32_t guestTime{ common::ensure_endianness( static_cast<std::uint32_t>( ret ), std::endian::big ) };
    if (tloc != nullptr)
    {
        ::memcpy( tloc, &guestTime, sizeof( guestTime ) );
    }

    std::uint32_t retNative{ static_cast<std::uint32_t>( ret ) };
    return ctx.ret( retNative );
}

// clock_t times(struct tms *buf);
bool times( ShimContext &ctx )
{
    // TODO
    /*
    const auto args{ ctx.get_arguments<struct tms *>() };
    if (!args.has_value())
        return false;
    const auto [buf] = *args;

    clock_t ret{ ::times( buf ) };
    std::uint32_t guestRet{ common::ensure_endianness( static_cast<std::uint32_t>( ret ), std::endian::big ) };
    if (ret == static_cast<clock_t>( -1 ))
    {
        set_guest_errno( ctx.mem, errno );
    }

    if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &guestRet ) != UC_ERR_OK)
    {
        std::cerr << "Could not write times return value" << std::endl;
        return false;
    }
    */
    return true;
}

// char *tmpnam(char *s);
bool tmpnam( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *>() };
    if (!args.has_value())
        return false;
    const auto [s] = *args;

    char *ret{ ::tmpnam( s ) };

    std::uint32_t guestRet{ ret ? ctx.mem->to_guest( ret ) : 0 };
    return ctx.ret( guestRet );
}

// int getdtablesize(void);
bool getdtablesize( ShimContext &ctx )
{
    int ret{ ::getdtablesize() };
    std::uint32_t retGuest{ static_cast<std::uint32_t>( ret ) };
    return ctx.ret( retGuest );
}

// mode_t umask(mode_t mask);
bool umask( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [mask] = *args;

    mode_t ret{ ::umask( static_cast<mode_t>( mask ) ) };
    uint32_t retGuest = static_cast<uint32_t>( ret );

    return ctx.ret( retGuest );
}

// struct tm *localtime(const time_t *timep);
bool localtime( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const time_t *>() };
    if (!args.has_value())
        return false;
    const auto [timep] = *args;

    // Read the time_t value from guest memory (big-endian)
    time_t hostTime{};
    if (timep != nullptr)
    {
        uint32_t guestTime;
        ::memcpy( &guestTime, timep, sizeof( guestTime ) );
        hostTime = static_cast<time_t>( common::ensure_endianness( guestTime, std::endian::big ) );
    }
    else
    {
        hostTime = ::time( nullptr );
    }
    struct tm *ret{ ::localtime( &hostTime ) };
    void *zone_ptr{ nullptr };
    if (ret->tm_zone != nullptr)
    {
        zone_ptr = reinterpret_cast<void *>( ctx.mem->to_host( ctx.mem->heap_alloc( ::strlen( ret->tm_zone ) + 1 ) ) );
        ::memcpy( zone_ptr, ret->tm_zone, ::strlen( ret->tm_zone ) + 1 );
    }
    guest::tm tmGuest{ .tm_sec = common::ensure_endianness( ret->tm_sec, std::endian::big ),
                       .tm_min = common::ensure_endianness( ret->tm_min, std::endian::big ),
                       .tm_hour = common::ensure_endianness( ret->tm_hour, std::endian::big ),
                       .tm_mday = common::ensure_endianness( ret->tm_mday, std::endian::big ),
                       .tm_mon = common::ensure_endianness( ret->tm_mon, std::endian::big ),
                       .tm_year = common::ensure_endianness( ret->tm_year, std::endian::big ),
                       .tm_wday = common::ensure_endianness( ret->tm_wday, std::endian::big ),
                       .tm_yday = common::ensure_endianness( ret->tm_yday, std::endian::big ),
                       .tm_isdst = common::ensure_endianness( ret->tm_isdst, std::endian::big ),
                       .tm_gmtoff =
                           common::ensure_endianness( static_cast<std::int32_t>( ret->tm_gmtoff ), std::endian::big ),
                       .tm_zone = ctx.mem->to_guest( zone_ptr ) };
    void *retPtrHost{ reinterpret_cast<void *>( ctx.mem->to_host( ctx.mem->heap_alloc( sizeof( guest::tm ) ) ) ) };
    ::memcpy( retPtrHost, &tmGuest, sizeof( guest::tm ) );
    uint32_t retGuest{ ctx.mem->to_guest( retPtrHost ) };
    return ctx.ret( retGuest );
}

// struct hostent *gethostbyname(const char *name);
bool gethostbyname( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *>() };
    if (!args.has_value())
        return false;
    const auto [name] = *args;

    struct hostent *ret{ ::gethostbyname( name ) };

    if (!ret)
    {
        uint32_t nullPtr{ 0 };
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &nullPtr ) != UC_ERR_OK)
        {
            std::cerr << "Could not write gethostbyname return value" << std::endl;
            return false;
        }
        return true;
    }
    uint32_t namePtr{ 0 };
    if (ret->h_name)
    {
        size_t nameLen{ ::strlen( ret->h_name ) + 1 };
        void *nameHost{ reinterpret_cast<void *>( ctx.mem->to_host( ctx.mem->heap_alloc( nameLen ) ) ) };
        ::memcpy( nameHost, ret->h_name, nameLen );
        namePtr = ctx.mem->to_guest( nameHost );
    }

    uint32_t aliasesPtr{ 0 };
    if (ret->h_aliases)
    {
        size_t aliasCount{ 0 };
        while (ret->h_aliases[aliasCount])
            aliasCount++;

        // Allocate array of guest pointers (aliasCount + 1 for NULL terminator)
        void *aliasArrayHost{ reinterpret_cast<void *>(
            ctx.mem->to_host( ctx.mem->heap_alloc( ( aliasCount + 1 ) * sizeof( uint32_t ) ) ) ) };
        uint32_t *aliasArray{ static_cast<uint32_t *>( aliasArrayHost ) };

        for (size_t i = 0; i < aliasCount; i++)
        {
            size_t aliasLen{ ::strlen( ret->h_aliases[i] ) + 1 };
            void *aliasHost{ reinterpret_cast<void *>( ctx.mem->to_host( ctx.mem->heap_alloc( aliasLen ) ) ) };
            ::memcpy( aliasHost, ret->h_aliases[i], aliasLen );
            aliasArray[i] = common::ensure_endianness( ctx.mem->to_guest( aliasHost ), std::endian::big );
        }
        aliasArray[aliasCount] = 0; // NULL terminator
        aliasesPtr = ctx.mem->to_guest( aliasArrayHost );
    }

    uint32_t addrListPtr{ 0 };
    if (ret->h_addr_list)
    {
        size_t addrCount{ 0 };
        while (ret->h_addr_list[addrCount])
            addrCount++;

        // Allocate array of guest pointers (addrCount + 1 for NULL terminator)
        void *addrArrayHost{ reinterpret_cast<void *>(
            ctx.mem->to_host( ctx.mem->heap_alloc( ( addrCount + 1 ) * sizeof( uint32_t ) ) ) ) };
        uint32_t *addrArray{ static_cast<uint32_t *>( addrArrayHost ) };

        for (size_t i = 0; i < addrCount; i++)
        {
            void *addrHost{ reinterpret_cast<void *>( ctx.mem->to_host( ctx.mem->heap_alloc( ret->h_length ) ) ) };
            ::memcpy( addrHost, ret->h_addr_list[i], ret->h_length );
            addrArray[i] = common::ensure_endianness( ctx.mem->to_guest( addrHost ), std::endian::big );
        }
        addrArray[addrCount] = 0; // NULL terminator
        addrListPtr = ctx.mem->to_guest( addrArrayHost );
    }

    guest::hostent guestHostent{ .h_name = common::ensure_endianness( namePtr, std::endian::big ),
                                 .h_aliases = common::ensure_endianness( aliasesPtr, std::endian::big ),
                                 .h_addrtype = common::ensure_endianness( ret->h_addrtype, std::endian::big ),
                                 .h_length = common::ensure_endianness( ret->h_length, std::endian::big ),
                                 .h_addr_list = common::ensure_endianness( addrListPtr, std::endian::big ) };

    void *hostentHost{
        reinterpret_cast<void *>( ctx.mem->to_host( ctx.mem->heap_alloc( sizeof( guest::hostent ) ) ) ) };
    ::memcpy( hostentHost, &guestHostent, sizeof( guest::hostent ) );
    uint32_t hostentGuest{ ctx.mem->to_guest( hostentHost ) };

    return ctx.ret( hostentGuest );
}

// int gethostname(char *name, size_t namelen);
bool gethostname( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *, std::size_t>() };
    if (!args.has_value())
        return false;
    const auto [name, namelen] = *args;

    int ret{ ::gethostname( name, namelen ) };

    if (ret == -1)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// int ungetc( int character, FILE * stream );
bool ungetc( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int, void *>() };
    if (!args.has_value())
        return false;
    const auto [character, stream] = *args;

    FILE *f{ common::resolve_file_stream( ctx.mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );
    int ret{ ::ungetc( character, f ) };

    if (ret == EOF)
    {
        set_guest_errno( ctx.mem, errno );
    }

    return ctx.ret( ret );
}

// int sscanf(const char *str, const char *format, ...);
bool sscanf( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, const char *>() };
    if (!args.has_value())
        return false;
    const auto [str, format] = *args;

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( ctx.uc, ctx.mem, format, UC_PPC_REG_5, true ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsscanf( str, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };

    return ctx.ret( ret );
}

// time_t mktime(struct tm *timeptr);
bool mktime( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *>() };
    if (!args.has_value())
        return false;
    const auto [timeptrGuest] = *args;

    if (!timeptrGuest)
    {
        uint32_t ret{ static_cast<uint32_t>( -1 ) };
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
        {
            std::cerr << "Could not write mktime return value" << std::endl;
            return false;
        }
        return true;
    }

    auto *tmGuest{ static_cast<guest::tm *>( timeptrGuest ) };
    struct tm tmHost{};
    tmHost.tm_sec = common::ensure_endianness( tmGuest->tm_sec, std::endian::big );
    tmHost.tm_min = common::ensure_endianness( tmGuest->tm_min, std::endian::big );
    tmHost.tm_hour = common::ensure_endianness( tmGuest->tm_hour, std::endian::big );
    tmHost.tm_mday = common::ensure_endianness( tmGuest->tm_mday, std::endian::big );
    tmHost.tm_mon = common::ensure_endianness( tmGuest->tm_mon, std::endian::big );
    tmHost.tm_year = common::ensure_endianness( tmGuest->tm_year, std::endian::big );
    tmHost.tm_wday = common::ensure_endianness( tmGuest->tm_wday, std::endian::big );
    tmHost.tm_yday = common::ensure_endianness( tmGuest->tm_yday, std::endian::big );
    tmHost.tm_isdst = common::ensure_endianness( tmGuest->tm_isdst, std::endian::big );

    time_t result{ ::mktime( &tmHost ) };
    uint32_t resultGuest{ static_cast<uint32_t>( result ) };

    return ctx.ret( resultGuest );
}

// void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
bool qsort( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *, size_t, size_t, uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [base, nmemb, size, comparGuestPtr] = *args;

    if (!base || nmemb <= 1 || size == 0)
        return true;

    const uint32_t baseGuest{ ctx.mem->to_guest( base ) };
    auto *baseBytes{ static_cast<uint8_t *>( base ) };

    uc_context *uc_ctx{};
    if (uc_context_alloc( ctx.uc, &uc_ctx ) != UC_ERR_OK)
    {
        std::cerr << "qsort: uc_context_alloc failed" << std::endl;
        return false;
    }
    if (uc_context_save( ctx.uc, uc_ctx ) != UC_ERR_OK)
    {
        std::cerr << "qsort: uc_context_save failed" << std::endl;
        uc_context_free( uc_ctx );
        return false;
    }
    // Read SP from the saved context for comparator calls
    uint32_t sp{};
    uc_context_reg_read( uc_ctx, UC_PPC_REG_1, &sp );

    // Sentinel: uc_emu_start stops when PC reaches this address (before executing / firing hooks)
    const uint32_t sentinel{ common::Inner_Emulation_Sentinel };

    std::vector<size_t> indices( nmemb );
    std::iota( indices.begin(), indices.end(), 0 );

    auto pred{ [&]( size_t i, size_t j ) {
        uint32_t ptrA{ baseGuest + static_cast<uint32_t>( i * size ) };
        uint32_t ptrB{ baseGuest + static_cast<uint32_t>( j * size ) };

        // Set up PPC state for comparator call
        uc_reg_write( ctx.uc, UC_PPC_REG_3, &ptrA ); // arg1 = pointer to element a
        uc_reg_write( ctx.uc, UC_PPC_REG_4, &ptrB ); // arg2 = pointer to element b
        uc_reg_write( ctx.uc, UC_PPC_REG_1, &sp );   // restore stack pointer
        uc_reg_write( ctx.uc, UC_PPC_REG_LR, &sentinel );

        uc_emu_start( ctx.uc, comparGuestPtr, sentinel, 0, 0 );

        uint32_t result{};
        uc_reg_read( ctx.uc, UC_PPC_REG_3, &result );
        return static_cast<int32_t>( result ) < 0;
    } };

    std::sort( indices.begin(), indices.end(), pred );

    std::vector<uint8_t> sorted( nmemb * size );
    for (std::size_t i{ 0 }; i < nmemb; i++)
        std::memcpy( sorted.data() + i * size, baseBytes + indices[i] * size, size );
    std::memcpy( baseBytes, sorted.data(), nmemb * size );

    uc_context_restore( ctx.uc, uc_ctx );
    uc_context_free( uc_ctx );

    return true;
}

// clock_t clock(void);
bool clock( ShimContext &ctx )
{
    clock_t ret{ ::clock() };
    uint32_t retGuest{ static_cast<uint32_t>( ret ) };

    return ctx.ret( retGuest );
}

// char *setlocale(int category, const char *locale);
bool setlocale( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<int, const char *>() };
    if (!args.has_value())
        return false;
    const auto [category, locale] = *args;

    char *ret{ ::setlocale( category, locale ) };
    uint32_t retGuest{ 0 };

    if (ret != nullptr)
    {
        size_t len{ ::strlen( ret ) + 1 };
        void *localeHost{ reinterpret_cast<void *>( ctx.mem->to_host( ctx.mem->heap_alloc( len ) ) ) };
        ::memcpy( localeHost, ret, len );
        retGuest = ctx.mem->to_guest( localeHost );
    }

    return ctx.ret( retGuest );
}

// int snprintf(char *str, size_t size, const char *format, ...);
bool snprintf( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *, size_t, const char *>() };
    if (!args.has_value())
        return false;
    const auto [str, size, format] = *args;

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( ctx.uc, ctx.mem, format, UC_PPC_REG_6, false ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsnprintf( str, size, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };

    return ctx.ret( ret );
}

// char *strncat(char *dest, const char *src, size_t n);
bool strncat( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<char *, const char *, size_t>() };
    if (!args.has_value())
        return false;
    const auto [dest, src, n] = *args;

    char *ret{ ::strncat( dest, src, n ) };
    uint32_t retGuest{ ret != nullptr ? ctx.mem->to_guest( ret ) : 0 };

    return ctx.ret( retGuest );
}

// void *bsearch(const void *key, const void *base, size_t num, size_t width, int (*compare)(const void *, const void
// *))
bool bsearch( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<void *, void *, std::size_t, std::size_t, uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [key, base, num, width, comparGuestPtr] = *args;

    if (!key || !base || num == 0 || width == 0)
    {
        uint32_t result{ 0 };
        if (uc_reg_write( ctx.uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
        {
            std::cerr << "Could not write bsearch return value" << std::endl;
            return false;
        }
        return true;
    }

    const uint32_t keyGuest{ ctx.mem->to_guest( const_cast<void *>( key ) ) };
    const uint32_t baseGuest{ ctx.mem->to_guest( const_cast<void *>( base ) ) };

    uc_context *uc_ctx{};
    if (uc_context_alloc( ctx.uc, &uc_ctx ) != UC_ERR_OK)
    {
        std::cerr << "bsearch: uc_context_alloc failed" << std::endl;
        return false;
    }
    if (uc_context_save( ctx.uc, uc_ctx ) != UC_ERR_OK)
    {
        std::cerr << "bsearch: uc_context_save failed" << std::endl;
        uc_context_free( uc_ctx );
        return false;
    }

    uint32_t sp{};
    uc_context_reg_read( uc_ctx, UC_PPC_REG_1, &sp );

    const uint32_t sentinel{ common::Inner_Emulation_Sentinel };

    size_t left{ 0 };
    size_t right{ num };
    uint32_t resultGuest{ 0 }; // NULL — not found

    while (left < right)
    {
        size_t mid{ left + ( right - left ) / 2 };
        uint32_t midElemGuest{ baseGuest + static_cast<uint32_t>( mid * width ) };

        // Call guest comparator(key, &array[mid])
        uc_reg_write( ctx.uc, UC_PPC_REG_3, &keyGuest );
        uc_reg_write( ctx.uc, UC_PPC_REG_4, &midElemGuest );
        uc_reg_write( ctx.uc, UC_PPC_REG_1, &sp );
        uc_reg_write( ctx.uc, UC_PPC_REG_LR, &sentinel );

        uc_emu_start( ctx.uc, comparGuestPtr, sentinel, 0, 0 );

        uint32_t cmpRaw{};
        uc_reg_read( ctx.uc, UC_PPC_REG_3, &cmpRaw );
        const int32_t cmp{ static_cast<int32_t>( cmpRaw ) };

        if (cmp == 0)
        {
            resultGuest = midElemGuest;
            break;
        }
        else if (cmp < 0)
        {
            right = mid;
        }
        else
        {
            left = mid + 1;
        }
    }

    uc_context_restore( ctx.uc, uc_ctx );
    uc_context_free( uc_ctx );

    return ctx.ret( resultGuest );
}

// double strtod(const char *str, char **endptr);
// Converts string to double
bool strtod( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, std::uint32_t>() };
    if (!args.has_value())
        return false;
    const auto [str, endptr] = *args;

    char *hostEndPtr{ nullptr };
    double ret{ ::strtod( str, &hostEndPtr ) };

    if (endptr != 0 && hostEndPtr != nullptr)
    {
        std::uint32_t guestEndPtr{ common::ensure_endianness( ctx.mem->to_guest( hostEndPtr ), std::endian::big ) };

        std::uint32_t *endptrHost{ reinterpret_cast<std::uint32_t *>( ctx.mem->to_host( endptr ) ) };
        *endptrHost = guestEndPtr;
    }

    // Return double in FPR1 (PPC calling convention for floating point return values)
    return ctx.ret( ret );
}

// long strtol(const char *str, char **endptr, int base);
// Converts string to long integer
bool strtol( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, std::uint32_t, int>() };
    if (!args.has_value())
        return false;
    const auto [str, endptr, base] = *args;

    char *hostEndPtr{ nullptr };
    long ret{ ::strtol( str, &hostEndPtr, base ) };

    if (endptr != 0 && hostEndPtr != nullptr)
    {
        std::uint32_t guestEndPtr{ common::ensure_endianness( ctx.mem->to_guest( hostEndPtr ), std::endian::big ) };

        std::uint32_t *endptrHost{ reinterpret_cast<std::uint32_t *>( ctx.mem->to_host( endptr ) ) };
        *endptrHost = guestEndPtr;
    }
    std::uint32_t retVal{ static_cast<std::uint32_t>( ret ) };
    return ctx.ret( retVal );
}
} // namespace import::callback
