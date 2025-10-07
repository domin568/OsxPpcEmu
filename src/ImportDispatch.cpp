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
bool unknown( uc_engine *uc )
{
    return true;
}

bool keymgr_dwarf2_register_sections( uc_engine *uc, loader::CMachoLoader *macho )
{
    return true;
}

bool cthread_init_routine( uc_engine *uc, loader::CMachoLoader *macho )
{
    return true;
}

bool dyld_make_delayed_module_initializer_calls( uc_engine *uc, loader::CMachoLoader *macho )
{
    return true;
}

// int _dyld_func_lookup(const char *dyld_func_name, void **address);
bool dyld_func_lookup( uc_engine *uc, loader::CMachoLoader *macho )
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

bool atexit( uc_engine *uc, loader::CMachoLoader *macho )
{
    return true;
}

bool exit( uc_engine *uc, loader::CMachoLoader *macho )
{
    uc_emu_stop( uc );
    return true;
}

bool mach_init_routine( uc_engine *uc, loader::CMachoLoader *macho )
{
    return true;
}

// void* memmove( void* dest, const void* src, std::size_t count );
bool memmove( uc_engine *uc, loader::CMachoLoader *macho )
{
    const auto args{ get_arguments<3>( uc ) };
    if (!args.has_value())
        return false;
    const auto [destVa, sourceVa, count] = *args;

    std::vector<uint8_t> buffer( count );
    if (uc_mem_read( uc, sourceVa, buffer.data(), count ) != UC_ERR_OK)
    {
        std::cerr << "Could not read source data" << std::endl;
        return false;
    }
#ifdef DEBUG
    for (const auto &b : buffer)
    {
        std::cout << std::hex << b << "";
    }
    std::cout << std::endl;
#endif
    if (uc_mem_write( uc, destVa, buffer.data(), count ) != UC_ERR_OK)
    {
        std::cerr << "Could not write memmove destination" << std::endl;
        return false;
    }
    return true;
}

// void *memset(void *str, int c, size_t n)
bool memset( uc_engine *uc, loader::CMachoLoader *macho )
{
    const auto args{ get_arguments<3>( uc ) };
    if (!args.has_value())
        return false;
    const auto [strVa, c, n] = *args;

    std::vector<uint8_t> buf( n );
    std::fill( buf.begin(), buf.end(), c );

    if (uc_mem_write( uc, strVa, buf.data(), buf.size() ) != UC_ERR_OK)
    {
        std::cerr << "Could not write memset str" << std::endl;
        return false;
    }
    if (uc_reg_write( uc, UC_PPC_REG_3, &strVa ) != UC_ERR_OK)
    {
        std::cerr << "Could not write memset return" << std::endl;
        return true;
    }
    return true;
}

// int puts(const char *str);
bool puts( uc_engine *uc, loader::CMachoLoader *macho )
{
    const auto args{ get_arguments<1>( uc ) };
    if (!args.has_value())
        return false;
    const auto [nameVa] = *args;

    const std::optional<std::string> name{ common::read_string_at_va( uc, nameVa ) };
    if (!name.has_value())
    {
        std::cerr << "Could not read string at VA: 0x" << std::hex << nameVa << std::endl;
        return false;
    }
    std::cout << name.value() << std::endl;
    return true;
}

// int setvbuf( FILE * stream, char * buffer, int mode, size_t size );
bool setvbuf( uc_engine *uc, loader::CMachoLoader *macho )
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
bool strcat( uc_engine *uc, loader::CMachoLoader *macho )
{
    const auto args{ get_arguments<2>( uc ) };
    if (!args.has_value())
        return false;
    const auto [dest, src] = *args;

    return true;
}

// char * strchr( const char * str, int ch );
bool strchr( uc_engine *uc, loader::CMachoLoader *macho )
{
    const auto args{ get_arguments<2>( uc ) };
    if (!args.has_value())
        return false;
    const auto [strVa, ch] = *args;

    std::optional<std::string> str{ common::read_string_at_va( uc, strVa ) };
    if (!str.has_value())
    {
        std::cerr << "Could not read string at VA: 0x" << std::hex << strVa << std::endl;
        return false;
    }

    size_t pos{ str->find( ch ) };
    uint32_t ret{ 0 };
    if (pos != std::string::npos)
    {
        ret = strVa + static_cast<uint32_t>( pos );
    }
    std::cout << "ret = " << ret << std::endl;
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strrchr return value" << std::endl;
    }
    return true;
}

// size_t strlen( const char * str );
bool strlen( uc_engine *uc, loader::CMachoLoader *macho )
{
    const auto args{ get_arguments<1>( uc ) };
    if (!args.has_value())
        return false;
    const auto [strVa] = *args;

    std::optional<std::string> str{ common::read_string_at_va( uc, strVa ) };
    if (!str.has_value())
    {
        std::cerr << "Could not read string at VA: 0x" << std::hex << strVa << std::endl;
        return false;
    }
    uint32_t ret{ static_cast<uint32_t>( str->size() ) };

    std::cout << "str " << *str << std::endl;
    std::cout << "return " << str->size() << std::endl;

    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strlen return value" << std::endl;
        return false;
    }
    return true;
}

// char * strrchr( const char * str, int ch );
bool strrchr( uc_engine *uc, loader::CMachoLoader *macho )
{
    const auto args{ get_arguments<2>( uc ) };
    if (!args.has_value())
        return false;
    const auto [strVa, ch] = *args;

    const std::optional<std::string> str{ common::read_string_at_va( uc, strVa ) };
    if (!str.has_value())
    {
        std::cerr << "Could not read string at VA: 0x" << std::hex << strVa << std::endl;
        return false;
    }
    size_t pos{ str->rfind( ch ) };
    uint32_t ret{ 0 };
    if (pos != std::string::npos)
    {
        ret = strVa + static_cast<uint32_t>( pos );
    }
    std::cout << "ret = " << ret << std::endl;
    if (uc_reg_write( uc, UC_PPC_REG_3, &ret ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strrchr return value" << std::endl;
    }
    return true;
}

// char *strcpy( char *dest, const char *src );
bool strcpy( uc_engine *uc, loader::CMachoLoader *macho )
{
    const auto args{ get_arguments<2>( uc ) };
    if (!args.has_value())
        return false;
    const auto [destVa, sourceVa] = *args;

    const std::optional<std::string> source{ common::read_string_at_va( uc, sourceVa ) };
    if (!source.has_value())
    {
        std::cerr << "Could not read string at VA: 0x" << std::hex << sourceVa << std::endl;
        return false;
    }

    if (uc_mem_write( uc, destVa, source->c_str(), source->size() ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strncpy destination" << std::endl;
        return false;
    }
    if (uc_reg_write( uc, UC_PPC_REG_3, &destVa ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strncpy return register r0" << std::endl;
        return false;
    }
    return true;
}

// char * strncpy ( char * destination, const char * source, size_t num );
bool strncpy( uc_engine *uc, loader::CMachoLoader *macho )
{
    const auto args{ get_arguments<3>( uc ) };
    if (!args.has_value())
        return false;
    const auto [destVa, sourceVa, num] = *args;

    std::optional<std::string> source{ common::read_string_at_va( uc, sourceVa ) };
    if (!source.has_value())
    {
        std::cerr << "Could not read string at VA: 0x" << std::hex << sourceVa << std::endl;
        return false;
    }

    source->resize( num );
    if (uc_mem_write( uc, destVa, source->c_str(), source->size() ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strncpy destination" << std::endl;
        return false;
    }
    if (uc_reg_write( uc, UC_PPC_REG_3, &destVa ) != UC_ERR_OK)
    {
        std::cerr << "Could not write strncpy return register r0" << std::endl;
        return false;
    }
    return true;
}

bool dyld_stub_binding_helper( uc_engine *uc, loader::CMachoLoader *emu )
{
    return true;
}
} // namespace import::callback