/**
 * Author:    domin568
 * Created:   22.09.2025
 * Brief:     Common types
 **/

#include "../include/Common.hpp"
#include "../include/CMachoLoader.hpp"
#include "../include/ImportDispatch.hpp"
#include <numeric>

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

std::optional<std::string> read_string_at_va( uc_engine *uc, uint32_t va )
{
    static constexpr size_t Max_String_Size{ 0x1000 };

    uc_mem_region *regions;
    uint32_t count{};
    if (uc_mem_regions( uc, &regions, &count ) != UC_ERR_OK)
        return {};
    std::optional<uint32_t> endVa{ std::nullopt };
    for (uint32_t i = 0; i < count; i++)
    {
        if (va >= regions[i].begin && va <= regions[i].end)
        {
            endVa = regions[i].end;
            break;
        }
    }
    if (!endVa)
        return {};

    const size_t leftBytesInRegion{ *endVa - va };
    const size_t toRead{ std::min<size_t>( Max_String_Size, leftBytesInRegion ) };
    std::string name{};
    name.resize( toRead );
    if (uc_mem_read( uc, va, name.data(), name.size() ) != UC_ERR_OK)
        return {};
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

std::size_t count_format_specifiers( std::string_view format )
{
    std::size_t count{ 0 };
    for (std::size_t p{ format.find( '%' ) }; p != std::string_view::npos; p = format.find( '%', p + 1 ))
    {
        if (p + 1 < format.size())
        {
            if (format[p + 1] == '%')
            {
                ++p;
                continue;
            }
            count++;
        }
    }
    return count;
};

std::vector<void *> get_format_arguments( memory::CMemory *mem, void *argsPtr, std::string_view format )
{
    std::vector<void *> args{};
    const std::size_t formatSpecifiersCount{ count_format_specifiers( format ) };
    const std::span<const uint32_t> argsGuest{ reinterpret_cast<uint32_t *>( argsPtr ), formatSpecifiersCount };
    for (const auto guestVaBe : argsGuest)
    {
        const uint32_t guestVa{ ensure_endianness( guestVaBe, std::endian::big ) };
        args.push_back( mem->get( guestVa ) );
    };
    return args;
}

} // namespace common
