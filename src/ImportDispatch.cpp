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

bool keymgr_dwarf2_register_sections( uc_engine *uc, CMachoLoader *macho )
{
    return true;
}

bool cthread_init_routine( uc_engine *uc, CMachoLoader *macho )
{
    return true;
}

bool dyld_make_delayed_module_initializer_calls( uc_engine *uc, CMachoLoader *macho )
{
    return true;
}

bool dyld_func_lookup( uc_engine *uc, CMachoLoader *macho )
{
    uint32_t nameVa{};
    if (uc_reg_read( uc, UC_PPC_REG_3, &nameVa ) != UC_ERR_OK)
    {
        std::cerr << "Could not read dyld_func_lookup function name pointer" << std::endl;
        return false;
    }
    const std::expected<std::string, common::Error> name{ common::read_string_at_va( nameVa, uc, *macho ) };
    if (!name.has_value())
    {
        std::cerr << name.error().message << std::endl;
        return false;
    }

    std::optional<uint32_t> importEntryVa{ common::get_import_entry_va_by_name( *name ) };
    if (!importEntryVa.has_value())
        // TODO fix? crt1 code check for null every function except __dyld_make_delayed_module_initializer_calls
        *importEntryVa = 0;
    else
        *importEntryVa += sizeof( uint32_t ); // + sizeof(uint32_t) as it is direct import

    uint32_t callbackAddressPtr{};
    if (uc_reg_read( uc, UC_PPC_REG_4, &callbackAddressPtr ) != UC_ERR_OK)
    {
        std::cerr << "Could not write dyld_func_lookup resolved address" << std::endl;
        return false;
    }

    uint32_t callbackAddressBe{ common::ensure_endianness( *importEntryVa, std::endian::big ) };
    if (uc_mem_write( uc, callbackAddressPtr, &callbackAddressBe, sizeof( callbackAddressBe ) ) != UC_ERR_OK)
    {
        std::cerr << "Could not write dyld_func_lookup resolved address to memory" << std::endl;
        return false;
    }
    return true;
}

bool atexit( uc_engine *uc, CMachoLoader *macho )
{
    return true;
}

bool exit( uc_engine *uc, CMachoLoader *macho )
{
    uc_emu_stop( uc );
    return true;
}

bool mach_init_routine( uc_engine *uc, CMachoLoader *macho )
{
    return true;
}

bool dyld_stub_binding_helper( uc_engine *uc, CMachoLoader *emu )
{
    return true;
}
} // namespace import::callback