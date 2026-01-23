/**
 * Author:    domin568
 * Created:   21.09.2025
 * Brief:     redirected API implementations
 **/

#include "../include/ImportDispatch.hpp"
#include "../include/COsxPpcEmu.hpp"
#include "../include/PpcStructures.hpp"
#include <sys/stat.h>

namespace import::callback
{
// int *___error(void);
// Returns a pointer to the errno variable
bool ___error( uc_engine *uc, memory::CMemory *mem )
{
    // Get the address of the _errno import entry
    std::optional<uint32_t> errnoVa{ common::get_import_entry_va_by_name( "_errno" ) };
    if (!errnoVa.has_value())
    {
        std::cerr << "Could not find _errno symbol" << std::endl;
        return false;
    }

    // Return pointer to the errno location in r3
    uint32_t errnoAddr = *errnoVa;
    if (uc_reg_write( uc, UC_PPC_REG_3, &errnoAddr ) != UC_ERR_OK)
    {
        std::cerr << "Could not write ___error return value" << std::endl;
        return false;
    }
    return true;
}

// int _setjmp(jmp_buf env);
// Save calling environment for later use by longjmp
bool _setjmp( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
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

    uc_reg_read( uc, UC_PPC_REG_1, &r1 );
    uc_reg_read( uc, UC_PPC_REG_2, &r2 );
    uc_reg_read( uc, UC_PPC_REG_13, &r13 );
    uc_reg_read( uc, UC_PPC_REG_14, &r14 );
    uc_reg_read( uc, UC_PPC_REG_15, &r15 );
    uc_reg_read( uc, UC_PPC_REG_16, &r16 );
    uc_reg_read( uc, UC_PPC_REG_17, &r17 );
    uc_reg_read( uc, UC_PPC_REG_18, &r18 );
    uc_reg_read( uc, UC_PPC_REG_19, &r19 );
    uc_reg_read( uc, UC_PPC_REG_20, &r20 );
    uc_reg_read( uc, UC_PPC_REG_21, &r21 );
    uc_reg_read( uc, UC_PPC_REG_22, &r22 );
    uc_reg_read( uc, UC_PPC_REG_23, &r23 );
    uc_reg_read( uc, UC_PPC_REG_24, &r24 );
    uc_reg_read( uc, UC_PPC_REG_25, &r25 );
    uc_reg_read( uc, UC_PPC_REG_26, &r26 );
    uc_reg_read( uc, UC_PPC_REG_27, &r27 );
    uc_reg_read( uc, UC_PPC_REG_28, &r28 );
    uc_reg_read( uc, UC_PPC_REG_29, &r29 );
    uc_reg_read( uc, UC_PPC_REG_30, &r30 );
    uc_reg_read( uc, UC_PPC_REG_31, &r31 );
    uc_reg_read( uc, UC_PPC_REG_CR, &cr );
    uc_reg_read( uc, UC_PPC_REG_LR, &lr );
    uc_reg_read( uc, UC_PPC_REG_CTR, &ctr );
    uc_reg_read( uc, UC_PPC_REG_XER, &xer );

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
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write _setjmp return value" << std::endl;
        return false;
    }

    return true;
}

// void _longjmp(jmp_buf env, int val);
// Restore environment saved by setjmp and return to that point
bool _longjmp( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<void *, int>( uc, mem ) };
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
    uc_reg_write( uc, UC_PPC_REG_1, &r1 );
    uc_reg_write( uc, UC_PPC_REG_2, &r2 );
    uc_reg_write( uc, UC_PPC_REG_13, &r13 );
    uc_reg_write( uc, UC_PPC_REG_14, &r14 );
    uc_reg_write( uc, UC_PPC_REG_15, &r15 );
    uc_reg_write( uc, UC_PPC_REG_16, &r16 );
    uc_reg_write( uc, UC_PPC_REG_17, &r17 );
    uc_reg_write( uc, UC_PPC_REG_18, &r18 );
    uc_reg_write( uc, UC_PPC_REG_19, &r19 );
    uc_reg_write( uc, UC_PPC_REG_20, &r20 );
    uc_reg_write( uc, UC_PPC_REG_21, &r21 );
    uc_reg_write( uc, UC_PPC_REG_22, &r22 );
    uc_reg_write( uc, UC_PPC_REG_23, &r23 );
    uc_reg_write( uc, UC_PPC_REG_24, &r24 );
    uc_reg_write( uc, UC_PPC_REG_25, &r25 );
    uc_reg_write( uc, UC_PPC_REG_26, &r26 );
    uc_reg_write( uc, UC_PPC_REG_27, &r27 );
    uc_reg_write( uc, UC_PPC_REG_28, &r28 );
    uc_reg_write( uc, UC_PPC_REG_29, &r29 );
    uc_reg_write( uc, UC_PPC_REG_30, &r30 );
    uc_reg_write( uc, UC_PPC_REG_31, &r31 );
    uc_reg_write( uc, UC_PPC_REG_CR, &cr );
    uc_reg_write( uc, UC_PPC_REG_LR, &lr );
    uc_reg_write( uc, UC_PPC_REG_CTR, &ctr );
    uc_reg_write( uc, UC_PPC_REG_XER, &xer );

    // Set PC to the return address (LR from setjmp)
    uc_reg_write( uc, UC_PPC_REG_PC, &lr );

    // Return val (or 1 if val is 0)
    uint32_t retVal = (val == 0) ? 1 : val;
    if (uc_reg_write( uc, UC_PPC_REG_3, &retVal ) != UC_ERR_OK)
    {
        std::cerr << "Could not write _longjmp return value" << std::endl;
        return false;
    }

    return true;
}

bool keymgr_dwarf2_register_sections( uc_engine *uc, memory::CMemory *mem )
{
    return true;
}

bool cthread_init_routine( uc_engine *uc, memory::CMemory *mem )
{
    return true;
}

bool dyld_make_delayed_module_initializer_calls( uc_engine *uc, memory::CMemory *mem )
{
    return true;
}

// int _dyld_func_lookup(const char *dyld_func_name, void **address);
bool dyld_func_lookup( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<const char *, uint64_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [namePtr, callbackAddress] = *args;
    std::string name( namePtr );

    std::optional<uint32_t> importEntryVa{ common::get_import_entry_va_by_name( name ) };
    if (!importEntryVa.has_value())
        // TODO fix? crt1 code check for null every function except __dyld_make_delayed_module_initializer_calls
        importEntryVa.emplace( 0 );
    else
        *importEntryVa += sizeof( uint32_t ); // + sizeof(uint32_t) as it is direct import

    uint32_t callbackAddressBe{ common::ensure_endianness( *importEntryVa, std::endian::big ) };
    if (uc_mem_write( uc, callbackAddress, &callbackAddressBe, sizeof( callbackAddressBe ) ) != UC_ERR_OK)
    {
        std::cerr << "Could not write dyld_func_lookup resolved address to memory" << std::endl;
        return false;
    }
    return true;
}

bool atexit( uc_engine *uc, memory::CMemory *mem )
{
    return true;
}

bool exit( uc_engine *uc, memory::CMemory *mem )
{
    uc_emu_stop( uc );
    return true;
}

// size_t fwrite( const void * buffer, size_t size, size_t count, FILE * stream );
bool fwrite( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<const void *, std::size_t, std::size_t, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [buffer, size, count, stream] = *args;

    FILE *f{ common::resolve_file_stream( mem->to_guest( stream ) ) };
    if (!f)
        return false;

    std::size_t ret{ ::fwrite( buffer, size, count, f ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fwrite return value" << std::endl;
        return false;
    }
    return true;
}

// int fstat(int fd, struct stat *buf);
bool fstat( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<int, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [fd, buf] = *args;

    struct stat hostStat;
    int ret{ ::fstat( fd, &hostStat ) };

    if (ret == 0 && buf != nullptr)
    {
        auto *guestStat{ static_cast<guest::stat *>( buf ) };
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

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fstat return value" << std::endl;
        return false;
    }
    return true;
}

// int ioctl(int fd, unsigned long op, ...);
bool ioctl( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<int, uint32_t, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    // TODO
    return true;
}

bool mach_init_routine( uc_engine *uc, memory::CMemory *mem )
{
    return true;
}

// void* malloc(std::size_t size);
bool malloc( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [size]{ *args };

    uint32_t ret{ mem->heap_alloc( size ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write malloc return" << std::endl;
        return false;
    }
    return true;
}

// void* calloc(std::size_t num, std::size_t size);
bool calloc( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<std::size_t, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [num, size]{ *args };

    uint32_t ret{ mem->heap_alloc( num * size ) };
    // calloc zeros the memory
    void *ptr{ mem->get( ret ) };
    if (ptr)
        ::memset( ptr, 0, num * size );

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write calloc return" << std::endl;
        return false;
    }
    return true;
}

// void* memcpy(void * destination, const void * source, size_t num);
bool memcpy( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<void *, const void *, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, source, count] = *args;
    ::memcpy( dest, source, count );
    return true;
}

// void* memmove( void* dest, const void* src, std::size_t count );
bool memmove( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<void *, const void *, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, source, count] = *args;
    ::memmove( dest, source, count );
    return true;
}

// void *memset(void *str, int c, size_t n)
bool memset( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<void *, int, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, c, n] = *args;
    ::memset( str, c, n * sizeof( char ) );
    if (uc_reg_write( uc, UC_PPC_REG_3, &str ) != UC_ERR_OK)
    {
        std::cerr << "Could not write memset return" << std::endl;
        return true;
    }
    return true;
}

// int puts(const char *str);
bool puts( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str] = *args;
    ::puts( str );
    return true;
}

// int setvbuf( FILE * stream, char * buffer, int mode, size_t size );
bool setvbuf( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<void *, char *, int, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    // TODO
    uint32_t success{ 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &success ) != UC_ERR_OK)
    {
        std::cerr << "Could not write return value of setvbuf" << std::endl;
        return true;
    }
    return true;
}

// sighandler_t signal(int signum, sighandler_t handler);
bool signal( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<int, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    // TODO
    return true;
}

// int sprintf(char * buffer, const char * format, ...);
bool sprintf( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;

    auto [buffer, format]{ *args };

    std::vector<uint64_t> formatArgs{ common::get_sprintf_arguments( uc, mem, format ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsprintf( buffer, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write sprintf return value" << std::endl;
        return false;
    }
    return true;
}

// int stat(const char * restrict path,	struct stat * restrict sb);
bool stat( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<const char *, void *>( uc, mem ) };
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

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write stat return value" << std::endl;
        return false;
    }
    return true;
}

// char * strcat( char * destination, const char * source );
bool strcat( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, src] = *args;
    char *ret{ ::strcat( dest, src ) };
    uint32_t retGuest{ mem->to_guest( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strcat return value" << std::endl;
        return false;
    }
    return true;
}

// char * strchr( const char * str, int ch );
bool strchr( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<char *, int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, ch] = *args;
    char *ret{ ::strchr( str, ch ) };
    uint32_t retGuest{ mem->to_guest( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strchr return value" << std::endl;
        return false;
    }
    return true;
}

// size_t strlen( const char * str );
bool strlen( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str] = *args;
    std::size_t ret{ ::strlen( str ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strlen return value" << std::endl;
        return false;
    }
    return true;
}

// char * strrchr( const char * str, int ch );
bool strrchr( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<char *, int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, ch] = *args;

    char *ret{ ::strrchr( str, ch ) };
    uint32_t retGuest{ mem->to_guest( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strrchr return value" << std::endl;
        return false;
    }
    return true;
}

// char *strcpy( char *dest, const char *src );
bool strcpy( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, source] = *args;

    char *ret{ ::strcpy( dest, source ) };
    uint32_t retGuest{ mem->to_guest( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strcpy return value" << std::endl;
        return false;
    }
    return true;
}

// char * strncpy ( char * destination, const char * source, size_t num );
bool strncpy( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<char *, const char *, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, source, num] = *args;

    char *ret{ ::strncpy( dest, source, num ) };
    uint32_t retGuest{ mem->to_guest( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strncpy return value" << std::endl;
        return false;
    }
    return true;
}

bool dyld_stub_binding_helper( uc_engine *uc, memory::CMemory *mem )
{
    return true;
}

bool vsnprintf( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<char *, size_t, const char *, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto &[s, n, format, apPtr] = *args;
    std::vector formatArgs{ common::get_format_arguments( mem, apPtr, format ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsnprintf( s, n, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write vsnprintf return value" << std::endl;
        return false;
    }
    return true;
}

// char *getcwd(char *buf, size_t size);
bool getcwd( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<char *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [buf, size] = *args;
    char *ret{ ::getcwd( buf, size ) };
    uint32_t retGuest{ mem->to_guest( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write getcwd return value" << std::endl;
        return false;
    }
    return true;
}

// void free(void *ptr);
bool free( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    // Do not actually free memory
    return true;
}

// int strcmp( const char *lhs, const char *rhs );
bool strcmp( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<const char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [lhs, rhs] = *args;
    int ret{ ::strcmp( lhs, rhs ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strcmp return value" << std::endl;
        return false;
    }
    return true;
}

// int fprintf(FILE *stream, const char *format, ...);
bool fprintf( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<void *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;

    auto [stream, format]{ *args };

    FILE *f{ common::resolve_file_stream( mem->to_guest( stream ) ) };
    if (!f)
        return false;

    std::vector<uint64_t> formatArgs{ common::get_sprintf_arguments( uc, mem, format ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vfprintf( f, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fprintf return value" << std::endl;
        return false;
    }
    return true;
}
} // namespace import::callback