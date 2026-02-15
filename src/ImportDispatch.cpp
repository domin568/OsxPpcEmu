/**
 * Author:    domin568
 * Created:   21.09.2025
 * Brief:     redirected API implementations
 **/

#include "../include/ImportDispatch.hpp"
#include "../include/COsxPpcEmu.hpp"
#include "../include/PpcStructures.hpp"

#include <netdb.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/times.h>

namespace import::callback
{
// int *___error(void);
// Returns a pointer to the errno variable
bool ___error( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
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

// int ___tolower(int c);
// Converts uppercase letter to lowercase
bool ___tolower( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [c] = *args;

    // Convert to lowercase if uppercase letter
    uint32_t result = ( c >= 'A' && c <= 'Z' ) ? ( c + 32 ) : c;

    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write ___tolower return value" << std::endl;
        return false;
    }
    return true;
}

// int ___toupper(int c);
// Converts lowercase letter to uppercase
bool ___toupper( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [c] = *args;

    // Convert to uppercase if lowercase letter
    uint32_t result = ( c >= 'a' && c <= 'z' ) ? ( c - 32 ) : c;

    if (uc_reg_write( uc, UC_PPC_REG_3, &result ) != UC_ERR_OK)
    {
        std::cerr << "Could not write ___toupper return value" << std::endl;
        return false;
    }
    return true;
}

// int _setjmp(jmp_buf env);
// Save calling environment for later use by longjmp
bool _setjmp( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
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
bool _longjmp( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
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
    uint32_t retVal = ( val == 0 ) ? 1 : val;
    if (uc_reg_write( uc, UC_PPC_REG_3, &retVal ) != UC_ERR_OK)
    {
        std::cerr << "Could not write _longjmp return value" << std::endl;
        return false;
    }

    return true;
}

bool keymgr_dwarf2_register_sections( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    return true;
}

bool cthread_init_routine( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    return true;
}

bool dyld_make_delayed_module_initializer_calls( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    static constexpr std::uint8_t Stack_Frame_Size{ 0x20 };
    static constexpr std::array<std::uint8_t, 12> prolog{
        0x7C, 0x08, 0x02, 0xA6,                     // mflr      r0
        0x90, 0x01, 0x00, 0x08,                     // stw r0, 8( r1 )
        0x94, 0x21, 0xFF, 0x100 - Stack_Frame_Size, // stwu r1 -0x20( r1 )
    };
    static constexpr std::array<std::uint8_t, 16> epilog{
        0x80, 0x01, 0x00, Stack_Frame_Size + 8, // lwz       r0, 0x28(r1)
        0x38, 0x21, 0x00, Stack_Frame_Size,     // addi      r1, r1, 0x20
        0x7C, 0x08, 0x03, 0xA6,                 // mtlr      r0
        0x4E, 0x80, 0x00, 0x20,                 // blr
    };
    static constexpr std::array<std::uint8_t, 16> constructor_call{
        0x3D, 0x80, 0x00, 0x00, // lis r12,XXXX (FUNC1 hi)  <-- patch
        0x39, 0x8C, 0x00, 0x00, // addi r12,r12,XXXX (FUNC1 lo) <-- patch
        0x7D, 0x89, 0x03, 0xA6, // mtctr r12
        0x4E, 0x80, 0x04, 0x21, // bctrl
    };

    std::vector<std::uint8_t> trampoline_mem{};
    std::copy( prolog.begin(), prolog.end(), std::back_inserter( trampoline_mem ) );

    std::vector<std::uint32_t> static_constructor_arr{ loader->get_static_constructors() };
    for (const std::uint32_t constructor_va : static_constructor_arr)
    {
        std::array<uint8_t, 16> current_constructor_call{ constructor_call };
        std::uint16_t hi{ static_cast<std::uint16_t>( ( constructor_va + 0x8000 ) >> 16 ) };
        std::uint16_t lo{ static_cast<std::uint16_t>( constructor_va & 0xFFFF ) };
        current_constructor_call[2] = static_cast<std::uint8_t>( hi >> 8 );
        current_constructor_call[3] = static_cast<std::uint8_t>( hi & 0xFF );
        current_constructor_call[6] = static_cast<std::uint8_t>( lo >> 8 );
        current_constructor_call[7] = static_cast<std::uint8_t>( lo & 0xFF );
        std::copy( current_constructor_call.begin(), current_constructor_call.end(),
                   std::back_inserter( trampoline_mem ) );
    }
    std::copy( epilog.begin(), epilog.end(), std::back_inserter( trampoline_mem ) );

    std::uint32_t trampoline_guest_addr{ mem->heap_alloc( trampoline_mem.size() ) };
    void *trampoline_host_addr{ reinterpret_cast<void *>( mem->to_host( trampoline_guest_addr ) ) };

    std::memcpy( trampoline_host_addr, trampoline_mem.data(), trampoline_mem.size() );

    if (uc_reg_write( uc, UC_PPC_REG_PC, &trampoline_guest_addr ) != UC_ERR_OK)
    {
        std::cerr << "Could not write trampoline return address" << std::endl;
        return false;
    }
    return true;
}

// int _dyld_func_lookup(const char *dyld_func_name, void **address);
bool dyld_func_lookup( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
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

bool atexit( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    return true;
}

bool exit( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    uc_emu_stop( uc );
    return true;
}

// int fclose(FILE *stream);
bool fclose( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [stream] = *args;

    FILE *f{ static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) ) };
    int ret{ ::fclose( f ) };

    if (ret == EOF)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fgetc return value" << std::endl;
        return false;
    }
    return true;
}

// int fflush(FILE *stream);
bool fflush( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [stream] = *args;

    FILE *f{ common::resolve_file_stream( mem->to_guest( stream ) ) };
    if (!f)
        return false;

    int ret{ ::fflush( f ) };

    if (ret == EOF)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fflush return value" << std::endl;
        return false;
    }
    return true;
}

// int fgetc(FILE *stream);
bool fgetc( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [stream] = *args;

    FILE *f{ common::resolve_file_stream( mem->to_guest( stream ) ) };
    if (!f)
        f = static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) );

    int ret{ ::fgetc( f ) };

    if (ret == EOF)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fgetc return value" << std::endl;
        return false;
    }
    return true;
}

// FILE *fopen(const char *filename, const char *mode);
bool fopen( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [filename, mode] = *args;

    FILE *ret{ ::fopen( filename, mode ) };

    if (ret == nullptr)
    {
        set_guest_errno( mem, errno );
    }

    // Store the FILE* in guest memory and return pointer to it
    uint32_t retGuest{ 0 };
    if (ret != nullptr)
    {
        // Allocate space for the FILE* on the heap
        retGuest = mem->heap_alloc( sizeof( FILE * ) );
        if (retGuest != 0)
        {
            FILE **filePtr{ static_cast<FILE **>( mem->get( retGuest ) ) };
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

    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fopen return value" << std::endl;
        return false;
    }
    return true;
}

// size_t fwrite( const void * buffer, size_t size, size_t count, FILE * stream );
bool fwrite( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const void *, std::size_t, std::size_t, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [buffer, size, count, stream] = *args;

    FILE *f{ common::resolve_file_stream( mem->to_guest( stream ) ) };
    if (!f)
        return false;

    std::size_t ret{ ::fwrite( buffer, size, count, f ) };

    // fwrite returns less than count on error
    if (ret < count)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fwrite return value" << std::endl;
        return false;
    }
    return true;
}

// int fstat(int fd, struct stat *buf);
bool fstat( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
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
    else if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fstat return value" << std::endl;
        return false;
    }
    return true;
}

// int ioctl(int fd, unsigned long op, ...);
bool ioctl( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, uint32_t, void *>( uc, mem ) };
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
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write malloc return" << std::endl;
        return false;
    }
    return true;
}

bool mach_init_routine( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    return true;
}

// void* malloc(std::size_t size);
bool malloc( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [size]{ *args };

    uint32_t ret{ mem->heap_alloc( size ) };

    // Set errno if allocation failed
    if (ret == 0)
    {
        set_guest_errno( mem, ENOMEM );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write malloc return" << std::endl;
        return false;
    }
    return true;
}

// void* calloc(std::size_t num, std::size_t size);
bool calloc( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
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
    else if (ret == 0)
    {
        set_guest_errno( mem, ENOMEM );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write calloc return" << std::endl;
        return false;
    }
    return true;
}

// void* realloc(void* ptr, std::size_t size);
bool realloc( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [ptr, size]{ *args };

    // If ptr is NULL, realloc behaves like malloc
    if (!ptr)
    {
        uint32_t ret{ mem->heap_alloc( size ) };
        if (ret == 0)
        {
            set_guest_errno( mem, ENOMEM );
        }
        if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
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
        if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
        {
            std::cerr << "Could not write realloc return" << std::endl;
            return false;
        }
        return true;
    }

    // Allocate new memory and copy old data
    uint32_t oldGuestPtr{ mem->to_guest( ptr ) };
    std::size_t oldSize{ mem->get_alloc_size( oldGuestPtr ) };

    uint32_t newPtr{ mem->heap_alloc( size ) };
    void *newHostPtr{ mem->get( newPtr ) };

    if (newHostPtr && ptr)
    {
        // Copy old data to new location
        // Copy the minimum of old size and new size to avoid reading/writing out of bounds
        std::size_t copySize{ oldSize > 0 ? std::min( oldSize, size ) : size };
        ::memcpy( newHostPtr, ptr, copySize );
    }
    else if (newPtr == 0)
    {
        set_guest_errno( mem, ENOMEM );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &newPtr ) != UC_ERR_OK)
    {
        std::cerr << "Could not write realloc return" << std::endl;
        return false;
    }
    return true;
}

// void* memcpy(void * destination, const void * source, size_t num);
bool memcpy( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, const void *, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, source, count] = *args;
    ::memcpy( dest, source, count );
    if (uc_reg_write( uc, UC_PPC_REG_3, &dest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write memcpy return" << std::endl;
        return false;
    }
    return true;
}

// void* memmove( void* dest, const void* src, std::size_t count );
bool memmove( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, const void *, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, source, count] = *args;
    ::memmove( dest, source, count );
    return true;
}

// void *memset(void *str, int c, size_t n)
bool memset( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, int, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, c, n] = *args;
    ::memset( str, c, n * sizeof( char ) );
    if (uc_reg_write( uc, UC_PPC_REG_3, &str ) != UC_ERR_OK)
    {
        std::cerr << "Could not write memset return" << std::endl;
        return false;
    }
    return true;
}

// int puts(const char *str);
bool puts( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str] = *args;
    ::puts( str );
    return true;
}

// int setvbuf( FILE * stream, char * buffer, int mode, size_t size );
bool setvbuf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, char *, int, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    // TODO
    uint32_t success{ 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &success ) != UC_ERR_OK)
    {
        std::cerr << "Could not write return value of setvbuf" << std::endl;
        return false;
    }
    return true;
}

// sighandler_t signal(int signum, sighandler_t handler);
bool signal( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    // TODO
    return true;
}

// int sprintf(char * buffer, const char * format, ...);
bool sprintf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;

    auto [buffer, format]{ *args };

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( uc, mem, format, UC_PPC_REG_5, false ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsprintf( buffer, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write sprintf return value" << std::endl;
        return false;
    }
    return true;
}

// int printf(const char *format, ...)
bool printf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    auto [format]{ *args };

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( uc, mem, format, UC_PPC_REG_4, false ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vprintf( format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write printf return value" << std::endl;
        return false;
    }
    return true;
}

// int vsprintf(char * buffer, const char * format, va_list ap);
bool vsprintf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, const char *, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto &[s, format, apPtr] = *args;
    std::vector formatArgs{ common::get_va_arguments( mem, apPtr, format ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsprintf( s, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write vsprintf return value" << std::endl;
        return false;
    }
    return true;
}

// int stat(const char * restrict path,	struct stat * restrict sb);
bool stat( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
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
    else if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write stat return value" << std::endl;
        return false;
    }
    return true;
}

// char * strcat( char * destination, const char * source );
bool strcat( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, src] = *args;
    char *ret{ ::strcat( dest, src ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strcat return value" << std::endl;
        return false;
    }
    return true;
}

// char * strchr( const char * str, int ch );
bool strchr( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, ch] = *args;
    char *ret{ ::strchr( str, ch ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strchr return value" << std::endl;
        return false;
    }
    return true;
}

// size_t strlen( const char * str );
bool strlen( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
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
bool strrchr( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, ch] = *args;

    char *ret{ ::strrchr( str, ch ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strrchr return value" << std::endl;
        return false;
    }
    return true;
}

// char *strcpy( char *dest, const char *src );
bool strcpy( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, source] = *args;

    char *ret{ ::strcpy( dest, source ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strcpy return value" << std::endl;
        return false;
    }
    return true;
}

// char * strncpy ( char * destination, const char * source, size_t num );
bool strncpy( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, const char *, std::size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, source, num] = *args;

    char *ret{ ::strncpy( dest, source, num ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strncpy return value" << std::endl;
        return false;
    }
    return true;
}

bool dyld_stub_binding_helper( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    return true;
}

bool vsnprintf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, size_t, const char *, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto &[s, n, format, apPtr] = *args;
    std::vector formatArgs{ common::get_va_arguments( mem, apPtr, format ) };

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
bool getcwd( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [buf, size] = *args;
    char *ret{ ::getcwd( buf, size ) };

    if (ret == nullptr)
    {
        set_guest_errno( mem, errno );
    }

    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write getcwd return value" << std::endl;
        return false;
    }
    return true;
}

// void free(void *ptr);
bool free( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    // Do not actually free memory
    return true;
}

// int strcmp( const char *lhs, const char *rhs );
bool strcmp( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
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
bool fprintf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;

    auto [stream, format]{ *args };

    FILE *f{ common::resolve_file_stream( mem->to_guest( stream ) ) };
    if (!f)
        return false;

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( uc, mem, format, UC_PPC_REG_5, false ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vfprintf( f, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fprintf return value" << std::endl;
        return false;
    }
    return true;
}

// ssize_t readlink(const char *path, char *buf, size_t bufsiz);
bool readlink( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, char *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [path, buf, bufsiz] = *args;

    ssize_t ret{ ::readlink( path, buf, bufsiz ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write readlink return value" << std::endl;
        return false;
    }
    return true;
}

// char *getenv(const char *name);
bool getenv( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [name] = *args;

    char *ret{ ::getenv( name ) };
    uint32_t retGuest{ 0 };
    if (name != nullptr && std::strlen( name ) >= 7 && !std::memcmp( name, "DISPLAY", 7 ))
    {
        static constexpr std::string_view retStr{ ":0" };
        char *heap_ptr{ reinterpret_cast<char *>( mem->to_host( mem->heap_alloc( retStr.size() + 1 ) ) ) };
        ::memcpy( heap_ptr, retStr.data(), retStr.size() );
        heap_ptr[retStr.size()] = '\0';
        retGuest = mem->to_guest( heap_ptr );
    }
    else if (ret != nullptr)
    {
        char *heap_ptr{ reinterpret_cast<char *>( mem->to_host( mem->heap_alloc( ::strlen( ret ) ) ) ) };
        ::memcpy( heap_ptr, ret, ::strlen( ret ) + 1 );
        retGuest = mem->to_guest( heap_ptr );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write getenv return value" << std::endl;
        return false;
    }
    return true;
}

// int open(const char *path, int flags, ...);
bool open( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, int, int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [path, flags, mode] = *args;

    int ret{ ::open( path, flags, mode ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write open return value" << std::endl;
        return false;
    }
    return true;
}

// int close(int fd);
bool close( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [fd] = *args;

    int ret{ ::close( fd ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write close return value" << std::endl;
        return false;
    }
    return true;
}

// ssize_t read(int fd, void *buf, size_t count);
bool read( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, void *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [fd, buf, count] = *args;

    ssize_t ret{ ::read( fd, buf, count ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write read return value" << std::endl;
        return false;
    }
    return true;
}

// ssize_t write(int fd, const void *buf, size_t count);
bool write( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, const void *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [fd, buf, count] = *args;

    ssize_t ret{ ::write( fd, buf, count ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write write return value" << std::endl;
        return false;
    }
    return true;
}

// int memcmp(const void *s1, const void *s2, size_t n);
bool memcmp( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const void *, const void *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [s1, s2, n] = *args;

    int ret{ ::memcmp( s1, s2, n ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write memcmp return value" << std::endl;
        return false;
    }
    return true;
}

// time_t time(time_t *tloc);
bool time( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<time_t *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [tloc] = *args;

    time_t ret{ ::time( nullptr ) };
    std::uint32_t guestTime{ common::ensure_endianness( static_cast<std::uint32_t>( ret ), std::endian::big ) };
    if (tloc != nullptr)
    {
        ::memcpy( tloc, &guestTime, sizeof( guestTime ) );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &guestTime ) != UC_ERR_OK)
    {
        std::cerr << "Could not write time return value" << std::endl;
        return false;
    }
    return true;
}

// clock_t times(struct tms *buf);
bool times( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    // TODO
    /*
    const auto args{ get_arguments<struct tms *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [buf] = *args;

    clock_t ret{ ::times( buf ) };
    std::uint32_t guestRet{ common::ensure_endianness( static_cast<std::uint32_t>( ret ), std::endian::big ) };
    if (ret == static_cast<clock_t>( -1 ))
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &guestRet ) != UC_ERR_OK)
    {
        std::cerr << "Could not write times return value" << std::endl;
        return false;
    }
    */
    return true;
}

// int getdtablesize(void);
bool getdtablesize( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    int ret{ ::getdtablesize() };
    std::uint32_t retGuest{ common::ensure_endianness( static_cast<std::uint32_t>( ret ), std::endian::big ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write getdtablesize return value" << std::endl;
        return false;
    }
    return true;
}

// struct tm *localtime(const time_t *timep);
bool localtime( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const time_t *>( uc, mem ) };
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
        zone_ptr = reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( ::strlen( ret->tm_zone ) + 1 ) ) );
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
                       .tm_gmtoff = common::ensure_endianness( ret->tm_isdst, std::endian::big ),
                       .tm_zone = mem->to_guest( zone_ptr ) };
    void *retPtrHost{ reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( sizeof( guest::tm ) ) ) ) };
    ::memcpy( retPtrHost, &tmGuest, sizeof( guest::tm ) );
    uint32_t retGuest{ mem->to_guest( retPtrHost ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write localtime return value" << std::endl;
        return false;
    }
    return true;
}

// struct hostent *gethostbyname(const char *name);
bool gethostbyname( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [name] = *args;

    struct hostent *ret{ ::gethostbyname( name ) };

    if (!ret)
    {
        uint32_t nullPtr{ 0 };
        if (uc_reg_write( uc, UC_PPC_REG_3, &nullPtr ) != UC_ERR_OK)
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
        void *nameHost{ reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( nameLen ) ) ) };
        ::memcpy( nameHost, ret->h_name, nameLen );
        namePtr = mem->to_guest( nameHost );
    }

    uint32_t aliasesPtr{ 0 };
    if (ret->h_aliases)
    {
        size_t aliasCount{ 0 };
        while (ret->h_aliases[aliasCount])
            aliasCount++;

        // Allocate array of guest pointers (aliasCount + 1 for NULL terminator)
        void *aliasArrayHost{
            reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( ( aliasCount + 1 ) * sizeof( uint32_t ) ) ) ) };
        uint32_t *aliasArray{ static_cast<uint32_t *>( aliasArrayHost ) };

        for (size_t i = 0; i < aliasCount; i++)
        {
            size_t aliasLen{ ::strlen( ret->h_aliases[i] ) + 1 };
            void *aliasHost{ reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( aliasLen ) ) ) };
            ::memcpy( aliasHost, ret->h_aliases[i], aliasLen );
            aliasArray[i] = common::ensure_endianness( mem->to_guest( aliasHost ), std::endian::big );
        }
        aliasArray[aliasCount] = 0; // NULL terminator
        aliasesPtr = mem->to_guest( aliasArrayHost );
    }

    uint32_t addrListPtr{ 0 };
    if (ret->h_addr_list)
    {
        size_t addrCount{ 0 };
        while (ret->h_addr_list[addrCount])
            addrCount++;

        // Allocate array of guest pointers (addrCount + 1 for NULL terminator)
        void *addrArrayHost{
            reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( ( addrCount + 1 ) * sizeof( uint32_t ) ) ) ) };
        uint32_t *addrArray{ static_cast<uint32_t *>( addrArrayHost ) };

        for (size_t i = 0; i < addrCount; i++)
        {
            void *addrHost{ reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( ret->h_length ) ) ) };
            ::memcpy( addrHost, ret->h_addr_list[i], ret->h_length );
            addrArray[i] = common::ensure_endianness( mem->to_guest( addrHost ), std::endian::big );
        }
        addrArray[addrCount] = 0; // NULL terminator
        addrListPtr = mem->to_guest( addrArrayHost );
    }

    guest::hostent guestHostent{ .h_name = common::ensure_endianness( namePtr, std::endian::big ),
                                 .h_aliases = common::ensure_endianness( aliasesPtr, std::endian::big ),
                                 .h_addrtype = common::ensure_endianness( ret->h_addrtype, std::endian::big ),
                                 .h_length = common::ensure_endianness( ret->h_length, std::endian::big ),
                                 .h_addr_list = common::ensure_endianness( addrListPtr, std::endian::big ) };

    void *hostentHost{ reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( sizeof( guest::hostent ) ) ) ) };
    ::memcpy( hostentHost, &guestHostent, sizeof( guest::hostent ) );
    uint32_t hostentGuest{ mem->to_guest( hostentHost ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &hostentGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write gethostbyname return value" << std::endl;
        return false;
    }
    return true;
}

// int gethostname(char *name, size_t namelen);
bool gethostname( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [name, namelen] = *args;

    int ret{ ::gethostname( name, namelen ) };

    if (ret == -1)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write gethostname return value" << std::endl;
        return false;
    }
    return true;
}

// int ungetc( int character, FILE * stream );
bool ungetc( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [character, stream] = *args;

    FILE *f{ static_cast<FILE *>( *reinterpret_cast<FILE **>( stream ) ) };
    int ret{ ::ungetc( character, f ) };

    if (ret == EOF)
    {
        set_guest_errno( mem, errno );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write gethostname return value" << std::endl;
        return false;
    }
    return true;
}

// int sscanf(const char *str, const char *format, ...);
bool sscanf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<const char *, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, format] = *args;

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( uc, mem, format, UC_PPC_REG_5, true ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsscanf( str, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write sscanf return value" << std::endl;
        return false;
    }
    return true;
}

// time_t mktime(struct tm *timeptr);
bool mktime( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [timeptrGuest] = *args;

    if (!timeptrGuest)
    {
        uint32_t ret{ static_cast<uint32_t>( -1 ) };
        if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
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
    uint32_t resultGuest{ common::ensure_endianness( static_cast<uint32_t>( result ), std::endian::big ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &resultGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write mktime return value" << std::endl;
        return false;
    }
    return true;
}

// void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
bool qsort( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<void *, size_t, size_t, uint32_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [base, nmemb, size, comparGuestPtr] = *args;

    if (!base || nmemb == 0 || size == 0)
        return true;
    // TODO implement if needed
    return true;
}

// clock_t clock(void);
bool clock( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    clock_t ret{ ::clock() };
    uint32_t retGuest{ common::ensure_endianness( static_cast<uint32_t>( ret ), std::endian::big ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write clock return value" << std::endl;
        return false;
    }
    return true;
}

// char *setlocale(int category, const char *locale);
bool setlocale( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<int, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [category, locale] = *args;

    char *ret{ ::setlocale( category, locale ) };
    uint32_t retGuest{ 0 };

    if (ret != nullptr)
    {
        size_t len{ ::strlen( ret ) + 1 };
        void *localeHost{ reinterpret_cast<void *>( mem->to_host( mem->heap_alloc( len ) ) ) };
        ::memcpy( localeHost, ret, len );
        retGuest = mem->to_guest( localeHost );
    }

    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write setlocale return value" << std::endl;
        return false;
    }
    return true;
}

// int snprintf(char *str, size_t size, const char *format, ...);
bool snprintf( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, size_t, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [str, size, format] = *args;

    std::vector<uint64_t> formatArgs{ common::get_ellipsis_arguments( uc, mem, format, UC_PPC_REG_6, false ) };

    // UB but for now works for arm64 mac os / x86_64 windows
    int ret{ ::vsnprintf( str, size, format, reinterpret_cast<va_list>( formatArgs.data() ) ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write snprintf return value" << std::endl;
        return false;
    }
    return true;
}

// char *strncat(char *dest, const char *src, size_t n);
bool strncat( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
{
    const auto args{ get_arguments<char *, const char *, size_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [dest, src, n] = *args;

    char *ret{ ::strncat( dest, src, n ) };
    uint32_t retGuest{ ret != nullptr ? mem->to_guest( ret ) : 0 };

    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strncat return value" << std::endl;
        return false;
    }
    return true;
}
} // namespace import::callback