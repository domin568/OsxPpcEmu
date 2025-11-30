/**
 * Author:    domin568
 * Created:   21.09.2025
 * Brief:     redirected API implementations
 **/

#include "../include/ImportDispatch.hpp"
#include "../include/COsxPpcEmu.hpp"
#include <sys/stat.h>

namespace import::callback
{
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
    const auto args{ get_arguments<const void *, std::size_t, std::size_t, std::ptrdiff_t>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [buffer, size, count, stream] = *args;

    // TODO change
    const auto it{ std::find( import::Known_Import_Names.begin(), import::Known_Import_Names.end(), "___sF" ) };
    if (it == import::Known_Import_Names.end())
        return false;
    const std::ptrdiff_t sfIdx{ std::distance( import::Known_Import_Names.begin(), it ) };
    const std::ptrdiff_t sfAddr{ sfIdx * Import_Entry_Size +
                                 static_cast<std::ptrdiff_t>( Unknown_Import_Shift * Import_Entry_Size ) };

    const std::ptrdiff_t inSfOffset{ stream - static_cast<std::ptrdiff_t>( common::Import_Dispatch_Table_Address ) -
                                     sfAddr };

    static const std::ptrdiff_t fileObjSize{ 0x58 };

#ifdef DEBUG
    std::cout << "fwrite buffer " << buffer << std::endl;
    std::cout << "fwrite stream " << stream << std::endl;
    std::cout << "fwrite size " << size << std::endl;
    std::cout << "fwrite count " << count << std::endl;
#endif

    FILE *f{};
    if (inSfOffset == 0)
        f = stdin;
    else if (inSfOffset == fileObjSize)
        f = stdout;
    else if (inSfOffset == fileObjSize * 2)
        f = stderr;

    std::size_t ret{ fwrite( buffer, size, count, f ) };

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write fwrite return" << std::endl;
        return true;
    }
    return true;
}

// int fstat(int fd, struct stat *buf);
bool fstat( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<int, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    // TODO
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

// int stat(const char * restrict path,	struct stat * restrict sb);
bool stat( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<const char *, void *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto [path, sb] = *args;

#ifdef DEBUG
    std::cout << "stat path: " << path << std::endl;
#endif
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
#ifdef DEBUG
    std::cout << "strcat src " << src << std::endl;
    std::cout << "strcat return " << ret << std::endl;
#endif
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
#ifdef DEBUG
    std::cout << "strchr str " << str << std::endl;
    std::cout << "strchr return " << ret << std::endl;
#endif
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
#ifdef DEBUG
    std::cout << "strlen str " << str << std::endl;
    std::cout << "strlen return " << ret << std::endl;
#endif
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
#ifdef DEBUG
    std::cout << "strrchr str " << str << std::endl;
    std::cout << "strrchr return " << ret << std::endl;
#endif
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
#ifdef DEBUG
    std::cout << "strcpy source :" << source << std::endl;
#endif
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

#ifdef DEBUG
    std::cout << "strncpy source : " << source << std::endl;
#endif
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

#ifdef DEBUG
    std::cout << "vsnprintf format :" << format << std::endl;
    std::cout << "vsnprintf s :" << s << std::endl;
#endif
    return true;
}
} // namespace import::callback