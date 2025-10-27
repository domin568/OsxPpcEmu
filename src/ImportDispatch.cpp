/**
 * Author:    domin568
 * Created:   21.09.2025
 * Brief:     redirected API implementations
 **/

#include "../include/ImportDispatch.hpp"
#include "../include/COsxPpcEmu.hpp"
#include <algorithm>
#include <iostream>

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
    const auto args{ get_arguments<2>( uc ) };
    if (!args.has_value())
        return false;
    const auto [nameVa, callbackAddressPtr] = *args;

    const std::optional<std::string> name{ common::read_string_at_va( uc, nameVa ) };
    if (!name.has_value())
    {
        std::cerr << "Could not read string at VA: 0x" << std::hex << nameVa << std::endl;
        return false;
    }

    std::optional<uint32_t> importEntryVa{ common::get_import_entry_va_by_name( *name ) };
    if (!importEntryVa.has_value())
        // TODO fix? crt1 code check for null every function except __dyld_make_delayed_module_initializer_calls
        *importEntryVa = 0;
    else
        *importEntryVa += sizeof( uint32_t ); // + sizeof(uint32_t) as it is direct import

    uint32_t callbackAddressBe{ common::ensure_endianness( *importEntryVa, std::endian::big ) };
    if (uc_mem_write( uc, callbackAddressPtr, &callbackAddressBe, sizeof( callbackAddressBe ) ) != UC_ERR_OK)
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

bool mach_init_routine( uc_engine *uc, memory::CMemory *mem )
{
    return true;
}

// void* memmove( void* dest, const void* src, std::size_t count );
bool memmove( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<3>( uc ) };
    if (!args.has_value())
        return false;
    const auto [destVa, sourceVa, count] = *args;

#ifdef DEBUG
    std::vector<uint8_t> buffer( count );
    if (uc_mem_read( uc, sourceVa, buffer.data(), count ) != UC_ERR_OK)
    {
        std::cerr << "Could not read source data" << std::endl;
        return false;
    }
    for (const auto &b : buffer)
    {
        std::cout << std::hex << b << "";
    }
    std::cout << std::endl;
#endif
    ::memmove( mem->get( destVa ), mem->get( sourceVa ), count );
    return true;
}

// void *memset(void *str, int c, size_t n)
bool memset( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<3>( uc ) };
    if (!args.has_value())
        return false;
    const auto [strVa, c, n] = *args;
    ::memset( mem->get( strVa ), c, n * sizeof( char ) );
    if (uc_reg_write( uc, UC_PPC_REG_3, &strVa ) != UC_ERR_OK)
    {
        std::cerr << "Could not write memset return" << std::endl;
        return true;
    }
    return true;
}

// int puts(const char *str);
bool puts( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<1>( uc ) };
    if (!args.has_value())
        return false;
    const auto [nameVa] = *args;
    ::puts( reinterpret_cast<const char *>( mem->get( nameVa ) ) );
    return true;
}

// int setvbuf( FILE * stream, char * buffer, int mode, size_t size );
bool setvbuf( uc_engine *uc, memory::CMemory *mem )
{
    uint32_t success{ 0 };
    if (uc_reg_write( uc, UC_PPC_REG_3, &success ) != UC_ERR_OK)
    {
        std::cerr << "Could not write return value of setvbuf" << std::endl;
        return true;
    }
    return true;
}

// char * strcat( char * destination, const char * source );
bool strcat( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<2>( uc ) };
    if (!args.has_value())
        return false;
    const auto [dest, src] = *args;
    char *ret{
        ::strcat( reinterpret_cast<char *>( mem->get( dest ) ), reinterpret_cast<const char *>( mem->get( src ) ) ) };

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
    const auto args{ get_arguments<2>( uc ) };
    if (!args.has_value())
        return false;
    const auto [strVa, ch] = *args;
    char *ret{ ::strchr( reinterpret_cast<char *>( mem->get( strVa ) ), ch ) };
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
    const auto args{ get_arguments<1>( uc ) };
    if (!args.has_value())
        return false;
    const auto [strVa] = *args;
    size_t ret{ ::strlen( reinterpret_cast<const char *>( mem->get( strVa ) ) ) };
#ifdef DEBUG
    std::optional<std::string> str{ common::read_string_at_va( uc, strVa ) };
    if (!str.has_value())
    {
        std::cerr << "Could not read string at VA: 0x" << std::hex << strVa << std::endl;
        return false;
    }

    std::cout << "str " << *str << std::endl;
    std::cout << "return " << ret << std::endl;
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
    const auto args{ get_arguments<2>( uc ) };
    if (!args.has_value())
        return false;
    const auto [strVa, ch] = *args;

    char *ret{ ::strrchr( reinterpret_cast<char *>( mem->get( strVa ) ), ch ) };
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
    const auto args{ get_arguments<2>( uc ) };
    if (!args.has_value())
        return false;
    const auto [destVa, sourceVa] = *args;

    char *ret{ ::strcpy( reinterpret_cast<char *>( mem->get( destVa ) ),
                         reinterpret_cast<const char *>( mem->get( sourceVa ) ) ) };
    uint32_t retGuest{ mem->to_guest( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strcpy return value" << std::endl;
        return false;
    }
#ifdef DEBUG
    const std::optional<std::string> source{ common::read_string_at_va( uc, sourceVa ) };
    if (!source.has_value())
    {
        std::cerr << "Could not read string at VA: 0x" << std::hex << sourceVa << std::endl;
        return false;
    }
    std::cout << "source " << *source << std::endl;
#endif
    return true;
}

// char * strncpy ( char * destination, const char * source, size_t num );
bool strncpy( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<3>( uc ) };
    if (!args.has_value())
        return false;
    const auto [destVa, sourceVa, num] = *args;

    char *ret{ ::strncpy( reinterpret_cast<char *>( mem->get( destVa ) ),
                          reinterpret_cast<const char *>( mem->get( sourceVa ) ), num ) };
    uint32_t retGuest{ mem->to_guest( ret ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &retGuest ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strrchr return value" << std::endl;
        return false;
    }

#ifdef DEBUG
    std::optional<std::string> source{ common::read_string_at_va( uc, sourceVa ) };
    if (!source.has_value())
    {
        std::cerr << "Could not read string at VA: 0x" << std::hex << sourceVa << std::endl;
        return false;
    }
    std::cout << "source " << *source << std::endl;
#endif
    return true;
}

bool dyld_stub_binding_helper( uc_engine *uc, memory::CMemory *mem )
{
    return true;
}
/*
bool vsnprintf( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments<4>( uc ) };
    if (!args.has_value())
        return false;
    const auto &[sOrg, n, formatOrg, apOrg] = *args;

    char *s{ reinterpret_cast<char *>( mem->get( sOrg ) ) };
    const char *format{ reinterpret_cast<const char *>( mem->get( formatOrg ) ) };

    int ret{ ::vsnprintf( s, n, format, ap ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write vsnprintf return value" << std::endl;
        return false;
    }
    return true;
}
*/

bool vsnprintf( uc_engine *uc, memory::CMemory *mem )
{
    const auto args{ get_arguments_var<char *, size_t, const char *>( uc, mem ) };
    if (!args.has_value())
        return false;
    const auto &[s, n, format] = *args;

    int ret{ ::vsnprintf( s, n, format, nullptr ) };
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write vsnprintf return value" << std::endl;
        return false;
    }
    return true;
}
} // namespace import::callback