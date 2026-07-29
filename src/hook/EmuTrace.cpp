/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     Tracing hooks
 **/
#include "EmuTrace.hpp"
#include "Common.hpp"
#include "ImportDispatch.hpp"

#include <cstdio>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace emu::trace
{

using emu::hooks::HookContext;

void print_interrupt( const HookContext &ctx, uc_engine *uc, std::uint32_t intno )
{
    std::cout << ">>> interrupt/exception #" << intno << std::endl;
#ifdef DEBUGGER_ENABLED
    std::uint32_t pc{}, lr{};
    uc_reg_read( uc, UC_PPC_REG_PC, &pc );
    uc_reg_read( uc, UC_PPC_REG_LR, &lr );

    const std::optional<std::string> callerName{ ctx.loader->get_symbol_name_for_va(
        lr, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
    if (callerName.has_value())
        std::cout << " <" << *callerName << ">";
    std::cout << std::endl;

    // Check if address is in import dispatch table
    const std::uint32_t addr{ ctx.lastApiAddress };
    if (addr >= common::Import_Dispatch_Table_Address &&
        addr < common::Import_Dispatch_Table_Address + import::Import_Table_Size)
    {
        const std::size_t idx{ ( addr - common::Import_Dispatch_Table_Address ) >> import::Import_Entry_Size_Pow2 };
        if (idx == import::Unknown_Import_Index)
        {
            std::cout << "API: (unknown)" << std::endl;
        }
        else if (idx - import::Unknown_Import_Shift < import::Known_Import_Names.size())
        {
            std::cout << "API: " << import::Known_Import_Names[idx - import::Unknown_Import_Shift] << std::endl;
        }
    }

    // Show instruction bytes at fault address
    std::vector<std::uint8_t> buf( 4 );
    if (uc_mem_read( uc, addr, buf.data(), buf.size() ) == UC_ERR_OK)
    {
        std::cerr << "bytes:";
        for (auto b : buf)
            std::fprintf( stderr, " %02x", b );
        std::cerr << "\n";
    }
    else
    {
        std::cerr << "cannot read bytes at 0x" << std::hex << addr << "\n";
    }

    // Show call stack
    if (ctx.debugger)
    {
        std::cout << "Call stack:" << std::endl;
        std::cout << "  #0  0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << pc;

        const std::optional<std::string> pcName{ ctx.loader->get_symbol_name_for_va(
            pc, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
        if (pcName.has_value())
            std::cout << " <" << *pcName << ">";
        std::cout << std::endl;

        std::vector<std::uint32_t> addresses = ctx.debugger->get_callstack_addresses( 5 );
        for (std::size_t i = 0; i < addresses.size(); i++)
        {
            std::cout << "  #" << ( i + 1 ) << "  0x" << std::hex << std::setfill( '0' ) << std::setw( 8 )
                      << addresses[i];
            const std::optional<std::string> funcName{ ctx.loader->get_symbol_name_for_va(
                addresses[i], LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
            if (funcName.has_value())
                std::cout << " <" << *funcName << ">";
            std::cout << std::endl;
        }
    }
#endif
}

void print_mem_violation( const HookContext &ctx, uc_engine *uc, uc_mem_type type, std::uint64_t address, int size,
                          std::int64_t value )
{
    std::uint32_t pc{}, lr{};
    uc_reg_read( uc, UC_PPC_REG_PC, &pc );
    uc_reg_read( uc, UC_PPC_REG_LR, &lr );

    std::cerr << "\n>>> MEMORY ACCESS VIOLATION <<<" << std::endl;

    const char *access_type = "UNKNOWN";
    switch (type)
    {
    case UC_MEM_READ_UNMAPPED:
        access_type = "READ from UNMAPPED";
        break;
    case UC_MEM_WRITE_UNMAPPED:
        access_type = "WRITE to UNMAPPED";
        break;
    case UC_MEM_FETCH_UNMAPPED:
        access_type = "FETCH from UNMAPPED";
        break;
    case UC_MEM_READ_PROT:
        access_type = "READ PROTECTED";
        break;
    case UC_MEM_WRITE_PROT:
        access_type = "WRITE PROTECTED";
        break;
    case UC_MEM_FETCH_PROT:
        access_type = "FETCH PROTECTED";
        break;
    default:
        break;
    }

    std::cerr << "Type:    " << access_type << " (" << type << ")" << std::endl;
    std::cerr << "Address: 0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << address << std::endl;
    std::cerr << "Size:    " << std::dec << size << " bytes" << std::endl;
    std::cerr << "Value:   0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << value << std::endl;
    std::cerr << "PC:      0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << pc;

#ifdef DEBUGGER_ENABLED
    {
        const std::optional<std::string> pcName{ ctx.loader->get_symbol_name_for_va(
            pc, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
        if (pcName.has_value())
            std::cerr << " <" << *pcName << ">";
    }
    std::cerr << std::endl;

    std::cerr << "LR:      0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << lr;
    {
        const std::optional<std::string> callerName{ ctx.loader->get_symbol_name_for_va(
            lr, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
        if (callerName.has_value())
            std::cerr << " <" << *callerName << ">";
    }
    std::cerr << std::endl;

    std::vector<std::uint8_t> buf( 4 );
    if (uc_mem_read( uc, pc, buf.data(), buf.size() ) == UC_ERR_OK)
    {
        std::cerr << "Instruction: ";
        for (auto b : buf)
            std::fprintf( stderr, "%02x ", b );
        std::cerr << std::endl;
    }

    if (ctx.debugger)
    {
        std::cerr << "\nCall stack:" << std::endl;
        std::cerr << "  #0  0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << pc;

        const std::optional<std::string> pcName{ ctx.loader->get_symbol_name_for_va(
            pc, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
        if (pcName.has_value())
            std::cerr << " <" << *pcName << ">";
        std::cerr << std::endl;

        std::vector<std::uint32_t> addresses = ctx.debugger->get_callstack_addresses( 10 );
        for (std::size_t i = 0; i < addresses.size(); i++)
        {
            std::cerr << "  #" << ( i + 1 ) << "  0x" << std::hex << std::setfill( '0' ) << std::setw( 8 )
                      << addresses[i];
            const std::optional<std::string> funcName{ ctx.loader->get_symbol_name_for_va(
                addresses[i], LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
            if (funcName.has_value())
                std::cerr << " <" << *funcName << ">";
            std::cerr << std::endl;
        }
    }
    std::cerr << std::dec << std::endl;
#endif
}

#ifdef DEBUGGER_ENABLED

namespace
{

void write_arg_value( std::FILE *out, uc_engine *uc, std::uint32_t argValue )
{
    std::fprintf( out, "0x%x", argValue );

    // Try to read as string if it looks like a pointer
    if (argValue >= 0x1000 && argValue < 0xF0000000)
    {
        constexpr std::size_t maxCheck = 64;
        char buffer[maxCheck + 1];
        uc_err err = uc_mem_read( uc, argValue, buffer, maxCheck );
        if (err == UC_ERR_OK)
        {
            buffer[maxCheck] = '\0';
            bool isAscii = true;
            std::size_t len = 0;
            for (len = 0; len < maxCheck && buffer[len] != '\0'; len++)
            {
                char c = buffer[len];
                if (c < 0x20 || c > 0x7E)
                {
                    isAscii = false;
                    break;
                }
            }
            if (isAscii && len > 0 && len <= maxCheck)
            {
                std::fputs( " (\"", out );
                std::fwrite( buffer, 1, len, out );
                std::fputs( "\")", out );
            }
        }
    }
}

void write_callstack( std::FILE *out, const HookContext &ctx )
{
    if (ctx.debugger)
    {
        std::vector<std::uint32_t> addresses = ctx.debugger->get_callstack_addresses( 10 );
        for (std::uint32_t addr : addresses)
        {
            const std::optional<std::string> funcName{ ctx.loader->get_symbol_name_for_va(
                addr, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
            if (funcName.has_value())
                std::fprintf( out, " <- %s[0x%x]", funcName->c_str(), addr );
            else
                std::fprintf( out, " <- 0x%x", addr );
        }
    }
    std::fputc( '\n', out );
}

} // namespace

void print_api_call_source( const HookContext &ctx, uc_engine *uc, std::uint64_t address, std::size_t idx )
{
    const bool isUnknown = ( idx == import::Unknown_Import_Index );

    if (!isUnknown && !ctx.traceFile)
        return;

    if (isUnknown)
    {
        // Unknown API: output to stdout
        std::printf( "\xe2\x94\x8c\xe2\x94\x80 0x%llx (unknown)", address );
        write_callstack( stdout, ctx );
        if (ctx.traceFile)
        {
            std::fprintf( ctx.traceFile, "\xe2\x94\x8c\xe2\x94\x80 0x%llx (unknown)", address );
            write_callstack( ctx.traceFile, ctx );
        }
    }
    else if (idx - import::Unknown_Import_Shift < import::Known_Import_Names.size())
    {
        const std::size_t apiIdx = idx - import::Unknown_Import_Shift;
        std::FILE *tf = ctx.traceFile;

        // Known API: output to file only
        std::fprintf( tf, "\xe2\x94\x8c\xe2\x94\x80 %.*s",
                      static_cast<int>( import::Known_Import_Names[apiIdx].size() ),
                      import::Known_Import_Names[apiIdx].data() );
        write_callstack( tf, ctx );

        const int argCount = import::Import_Arg_Counts[apiIdx];
        const int regsToRead = ( argCount == -1 ) ? 8 : argCount;
        for (int i = 0; i < regsToRead; i++)
        {
            std::uint32_t argValue;
            if (uc_reg_read( uc, UC_PPC_REG_3 + i, &argValue ) == UC_ERR_OK)
            {
                std::fprintf( tf, "\xe2\x94\x82  arg%d: ", i );
                write_arg_value( tf, uc, argValue );
                std::fputc( '\n', tf );
            }
        }
    }
    else
    {
        std::puts( "Could not read API name." );
        if (ctx.traceFile)
            std::fputs( "Could not read API name.\n", ctx.traceFile );
    }
}

void print_api_return( const HookContext &ctx, uc_engine *uc, std::size_t idx )
{
    if (idx == import::Unknown_Import_Index || idx - import::Unknown_Import_Shift >= import::Known_Import_Names.size())
        return;

    if (!ctx.traceFile)
        return;

    std::uint32_t retValue;
    if (uc_reg_read( uc, UC_PPC_REG_3, &retValue ) == UC_ERR_OK)
    {
        std::fputs( "\xe2\x94\x94\xe2\x94\x80 return: ", ctx.traceFile );
        write_arg_value( ctx.traceFile, uc, retValue );
        std::fputc( '\n', ctx.traceFile );
    }
}

#endif

} // namespace emu::trace
