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