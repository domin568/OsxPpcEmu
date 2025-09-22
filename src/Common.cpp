/**
 * Author:    domin568
 * Created:   22.09.2025
 * Brief:     Common types
 **/

#include "../include/Common.hpp"
#include "../include/CMachoLoader.hpp"
#include "../include/ImportDispatch.hpp"

namespace common
{
uint64_t page_align_down( uint64_t a )
{
    uint64_t ps = 0x1000;
    return a & ~( ps - 1 );
}

uint64_t page_align_up( uint64_t a )
{
    uint64_t ps = 0x1000;
    return ( a + ps - 1 ) & ~( ps - 1 );
}

std::expected<std::string, common::Error> read_string_at_va( uint32_t va, uc_engine *uc, CMachoLoader &macho )
{
    const std::optional<LIEF::MachO::Section> sec{ macho.get_section_for_va( va ) };
    if (!sec.has_value())
    {
        return std::unexpected{
            common::Error{ common::Error::Type::Read_Memory_Error, "Could not find section for specific address" } };
    }
    static constexpr size_t Max_Func_Name_Size{ 0x100 };
    const size_t leftBytesInSection{ sec->virtual_address() + sec->size() - va };
    const size_t toRead{ std::min<size_t>( Max_Func_Name_Size, leftBytesInSection ) };
    std::string name{};
    name.resize( toRead );
    if (uc_mem_read( uc, va, name.data(), name.size() ) != UC_ERR_OK)
    {
        return std::unexpected{ common::Error{ common::Error::Type::Read_Memory_Error, "Could not read string" } };
    }
    name.resize( strnlen( name.c_str(), name.size() ) );
    return name;
}

std::optional<uint32_t> get_import_entry_va_by_name( const std::string &name )
{
    auto importNameMatches{
        []( const std::pair<std::string_view, import::Known_Import_Entry> &p ) { return p.first; } };
    const auto importIt{
        std::ranges::lower_bound( import::Name_To_Import_Item_Flat, name, std::less<>{}, importNameMatches ) };
    const bool found{ importIt != import::Name_To_Import_Item_Flat.end() && importIt->first == name };
    if (!found)
        return std::nullopt;
    const ptrdiff_t idx{ std::distance( import::Name_To_Import_Item_Flat.begin(), importIt ) };
    return static_cast<uint32_t>( common::Import_Dispatch_Table_Address +
                                  ( idx + import::Unknown_Import_Shift ) * import::Import_Entry_Size );
}

} // namespace common
