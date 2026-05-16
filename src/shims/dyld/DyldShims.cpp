/**
 * Author:    domin568
 * Created:   16.05.2026
 * Brief:     redirected API implementations
 **/

#include "COsxPpcEmu.hpp"
#include "ImportDispatch.hpp"
#include "PpcStructures.hpp"
#include "shims/ShimContext.hpp"
#include <vector>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

namespace import::callback
{

bool dyld_make_delayed_module_initializer_calls( ShimContext &ctx )
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

    std::vector<std::uint32_t> static_constructor_arr{ ctx.loader->get_static_constructors() };
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

    std::uint32_t trampoline_guest_addr{ ctx.mem->heap_alloc( trampoline_mem.size() ) };
    void *trampoline_host_addr{ reinterpret_cast<void *>( ctx.mem->to_host( trampoline_guest_addr ) ) };

    std::memcpy( trampoline_host_addr, trampoline_mem.data(), trampoline_mem.size() );

    return ctx.ret( trampoline_guest_addr );
}

// int _dyld_func_lookup(const char *dyld_func_name, void **address);
bool dyld_func_lookup( ShimContext &ctx )
{
    const auto args{ ctx.get_arguments<const char *, uint64_t>() };
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
    if (uc_mem_write( ctx.uc, callbackAddress, &callbackAddressBe, sizeof( callbackAddressBe ) ) != UC_ERR_OK)
    {
        std::cerr << "Could not write dyld_func_lookup resolved address to memory" << std::endl;
        return false;
    }
    return true;
}

bool mach_init_routine( ShimContext &ctx )
{
    return true;
}

bool dyld_stub_binding_helper( ShimContext &ctx )
{
    return true;
}

} // namespace import::callback
