/**
 * Author:    domin568
 * Created:   21.09.2025
 * Brief:     redirected API implementations
 **/

#include "../include/ImportDispatch.hpp"

#include "../include/COsxPpcEmu.hpp"

#include <algorithm>
#include <iostream>
#include <optional>

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
    uint32_t nameAddress{};
    if (uc_reg_read( uc, UC_PPC_REG_3, &nameAddress ) != UC_ERR_OK)
    {
        std::cerr << "Could not read dyld_func_lookup function name pointer" << std::endl;
        return false;
    }
    const std::optional<LIEF::MachO::Section> sec{ macho->get_section_for_va( nameAddress ) };
    if (!sec.has_value())
    {
        std::cerr << "Could not find section for address = 0x" << std::hex << nameAddress << std::endl;
        return false;
    }
    static constexpr size_t Max_Func_Name_Size{ 0x100 };
    const size_t leftBytesInSection{ sec->virtual_address() + sec->size() - nameAddress };
    const size_t toRead{ std::min<size_t>( Max_Func_Name_Size, leftBytesInSection ) };
    std::string name{};
    name.resize( toRead );
    if (uc_mem_read( uc, nameAddress, name.data(), name.size() ) != UC_ERR_OK)
    {
        std::cerr << "Could not read dyld_func_lookup function name" << std::endl;
        return false;
    }
    name.resize( strnlen( name.c_str(), name.size() ) );

    auto importNameMatches{
        [&name]( const std::pair<std::string_view, import::Known_Import_Entry> &p ) { return p.first; } };
    const auto importIt{
        std::ranges::lower_bound( import::Name_To_Import_Item_Flat, name, std::less<>{}, importNameMatches ) };
    const bool found{ importIt != import::Name_To_Import_Item_Flat.end() && importIt->first == name };
    if (!found)
    {
        std::cerr << "Could not find dyld function: " << name << std::endl;
        return false;
    }
    const ptrdiff_t idx{ std::distance( import::Name_To_Import_Item_Flat.begin(), importIt ) };
    uint32_t callbackAddressBe{ common::ensure_endianness(
        static_cast<uint32_t>( COsxPpcEmu::Import_Dispatch_Table_Address +
                               ( idx + Unknown_Import_Shift ) * Import_Entry_Size + sizeof( uint32_t ) ),
        std::endian::big ) }; // + sizeof(uint32_t) as it is direct import

    uint32_t callbackAddressPtr{};
    if (uc_reg_read( uc, UC_PPC_REG_4, &callbackAddressPtr ) != UC_ERR_OK)
    {
        std::cerr << "Could not write dyld_func_lookup resolved address" << std::endl;
        return false;
    }

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