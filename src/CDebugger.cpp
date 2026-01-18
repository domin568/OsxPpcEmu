/**
 * Author:    domin568
 * Created:   17.01.2026
 * Brief:     Interactive debugger for PPC emulator (DEBUG builds only)
 **/

#ifdef DEBUG

#include "../include/CDebugger.hpp"
#include "../include/CMachoLoader.hpp"
#include "../include/Common.hpp"
#include <LIEF/MachO.hpp>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace debug
{

CDebugger::CDebugger( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader )
    : m_uc( uc ), m_mem( mem ), m_loader( loader ), m_stepMode( StepMode::None ), m_stepOutLR( 0 )
{
}

std::string CDebugger::get_symbol_name( uint32_t address ) const
{
    if (!m_loader)
        return "";

    const std::optional<std::string> funcName{
        m_loader->get_symbol_name_for_va( address, LIEF::MachO::Symbol::TYPE::SECTION,
                                          loader::CMachoLoader::SymbolSection::TEXT ) };
    if (funcName.has_value())
        return " <" + *funcName + ">";

    return "";
}

void CDebugger::add_breakpoint( uint32_t address )
{
    m_breakpoints.insert( address );
    std::cout << "Breakpoint added at 0x" << std::hex << address << std::dec << std::endl;
}

void CDebugger::remove_breakpoint( uint32_t address )
{
    if (m_breakpoints.erase( address ))
        std::cout << "Breakpoint removed at 0x" << std::hex << address << std::dec << std::endl;
    else
        std::cout << "No breakpoint at 0x" << std::hex << address << std::dec << std::endl;
}

void CDebugger::list_breakpoints() const
{
    if (m_breakpoints.empty())
    {
        std::cout << "No breakpoints set" << std::endl;
        return;
    }
    std::cout << "Breakpoints:" << std::endl;
    for (uint32_t addr : m_breakpoints)
        std::cout << "  0x" << std::hex << addr << std::dec << std::endl;
}

bool CDebugger::is_breakpoint( uint32_t address ) const
{
    return m_breakpoints.contains( address );
}

void CDebugger::step_in()
{
    m_stepMode = StepMode::StepIn;
}

void CDebugger::step_out()
{
    // Read current LR - we want to break when we return to it
    uc_reg_read( m_uc, UC_PPC_REG_LR, &m_stepOutLR );
    m_stepMode = StepMode::StepOut;
    std::cout << "Step out: will break when returning to 0x" << std::hex << m_stepOutLR << std::dec << std::endl;
}

void CDebugger::continue_execution()
{
    m_stepMode = StepMode::Continue;
    std::cout << "Continuing..." << std::endl;
}

bool CDebugger::is_active() const
{
    return m_stepMode != StepMode::None || !m_breakpoints.empty();
}

bool CDebugger::should_break( uint32_t address )
{
    switch (m_stepMode)
    {
    case StepMode::StepIn:
        m_stepMode = StepMode::None;
        return true;

    case StepMode::StepOut: {
        uint32_t pc;
        uc_reg_read( m_uc, UC_PPC_REG_PC, &pc );
        if (pc == m_stepOutLR)
        {
            m_stepMode = StepMode::None;
            return true;
        }
        return false;
    }

    case StepMode::Continue:
        if (is_breakpoint( address ))
        {
            m_stepMode = StepMode::None;
            return true;
        }
        return false;

    case StepMode::None:
        return is_breakpoint( address );
    }

    return false;
}

void CDebugger::hexdump( uint32_t address, size_t length ) const
{
    std::vector<uint8_t> buffer( length );
    uc_err err = uc_mem_read( m_uc, address, buffer.data(), length );

    if (err != UC_ERR_OK)
    {
        std::cerr << "Failed to read memory at 0x" << std::hex << address << std::dec << std::endl;
        return;
    }

    std::cout << "Hexdump at 0x" << std::hex << address << " (0x" << length << " bytes):" << std::dec << std::endl;

    for (size_t i = 0; i < length; i += 16)
    {
        // Address
        std::cout << std::hex << std::setfill( '0' ) << std::setw( 8 ) << ( address + i ) << "  ";

        // Hex bytes
        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < length)
                std::cout << std::setw( 2 ) << static_cast<int>( buffer[i + j] ) << " ";
            else
                std::cout << "   ";

            if (j == 7)
                std::cout << " ";
        }

        std::cout << " |";

        // ASCII
        for (size_t j = 0; j < 16 && i + j < length; j++)
        {
            uint8_t byte = buffer[i + j];
            if (byte >= 0x20 && byte <= 0x7E)
                std::cout << static_cast<char>( byte );
            else
                std::cout << ".";
        }

        std::cout << "|" << std::dec << std::endl;
    }
}

void CDebugger::show_registers() const
{
    std::cout << "Registers:" << std::endl;

    uint32_t pc, lr, ctr, cr, xer;
    uc_reg_read( m_uc, UC_PPC_REG_PC, &pc );
    uc_reg_read( m_uc, UC_PPC_REG_LR, &lr );
    uc_reg_read( m_uc, UC_PPC_REG_CTR, &ctr );
    uc_reg_read( m_uc, UC_PPC_REG_CR, &cr );
    uc_reg_read( m_uc, UC_PPC_REG_XER, &xer );

    std::cout << "  PC  = 0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << pc << std::endl;
    std::cout << "  LR  = 0x" << std::setw( 8 ) << lr << std::endl;
    std::cout << "  CTR = 0x" << std::setw( 8 ) << ctr << std::endl;
    std::cout << "  CR  = 0x" << std::setw( 8 ) << cr << std::endl;
    std::cout << "  XER = 0x" << std::setw( 8 ) << xer << std::dec << std::endl;

    // General purpose registers
    for (int i = 0; i < 32; i++)
    {
        uint32_t reg;
        uc_reg_read( m_uc, UC_PPC_REG_0 + i, &reg );
        std::cout << "  R" << std::dec << std::setfill( ' ' ) << std::setw( 2 ) << i << " = 0x" << std::hex
                  << std::setfill( '0' ) << std::setw( 8 ) << reg;
        if (i % 4 == 3)
            std::cout << std::endl;
        else
            std::cout << "  ";
    }
    std::cout << std::dec << std::endl;
}

std::vector<uint32_t> CDebugger::get_callstack_addresses( size_t maxDepth ) const
{
    std::vector<uint32_t> addresses;

    uint32_t sp, lr;
    uc_reg_read( m_uc, UC_PPC_REG_1, &sp );  // Stack pointer (R1)
    uc_reg_read( m_uc, UC_PPC_REG_LR, &lr ); // Link register

    // Walk the stack frames
    // On PowerPC Darwin ABI, the stack frame structure is:
    // [SP+0]  = saved SP (back chain pointer to previous frame)
    // [SP+4]  = saved CR
    // [SP+8]  = saved LR (return address to caller)

    uint32_t currentSP = sp;
    bool useLRfirst = (lr != 0);

    while (addresses.size() < maxDepth)
    {
        uint32_t returnAddr = 0;

        if (useLRfirst)
        {
            // First iteration: use LR register
            returnAddr = lr;
            useLRfirst = false;
        }
        else
        {
            // Read saved LR from current frame at offset +8
            uint32_t savedLR;
            if (uc_mem_read( m_uc, currentSP + 8, &savedLR, sizeof( savedLR ) ) != UC_ERR_OK)
                break;

            savedLR = common::ensure_endianness( savedLR, std::endian::big );

            if (savedLR == 0)
                break;

            returnAddr = savedLR;
        }

        addresses.push_back( returnAddr );

        // Read the back chain pointer (saved SP)
        uint32_t savedSP;
        if (uc_mem_read( m_uc, currentSP, &savedSP, sizeof( savedSP ) ) != UC_ERR_OK)
            break;

        savedSP = common::ensure_endianness( savedSP, std::endian::big );

        // Check for invalid stack pointer (end of chain)
        if (savedSP == 0 || savedSP <= currentSP)
            break;

        currentSP = savedSP;
    }

    return addresses;
}

void CDebugger::show_callstack( size_t maxDepth ) const
{
    std::cout << "Call stack:" << std::endl;

    uint32_t pc;
    uc_reg_read( m_uc, UC_PPC_REG_PC, &pc ); // Program counter

    // Frame 0: Current PC
    std::cout << "  #0  0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << pc << std::dec
              << get_symbol_name( pc ) << std::endl;

    // Get callstack addresses and display them
    std::vector<uint32_t> addresses = get_callstack_addresses( maxDepth );

    for (size_t i = 0; i < addresses.size(); i++)
    {
        std::cout << "  #" << (i + 1) << "  0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << addresses[i]
                  << std::dec << get_symbol_name( addresses[i] ) << std::endl;
    }

    if (addresses.size() == maxDepth)
        std::cout << "  ... (max depth reached)" << std::endl;
}

void CDebugger::print_help() const
{
    std::cout << "Debugger commands:" << std::endl;
    std::cout << "  b <addr>         - Set breakpoint at address (hex)" << std::endl;
    std::cout << "  d <addr>         - Delete breakpoint at address (hex)" << std::endl;
    std::cout << "  l                - List all breakpoints" << std::endl;
    std::cout << "  s / si           - Step in (execute one instruction)" << std::endl;
    std::cout << "  so               - Step out (run until return)" << std::endl;
    std::cout << "  c                - Continue execution" << std::endl;
    std::cout << "  r                - Show registers" << std::endl;
    std::cout << "  bt               - Show call stack (backtrace)" << std::endl;
    std::cout << "  x <addr> <len>   - Hexdump memory (addr and len in hex)" << std::endl;
    std::cout << "  h / ?            - Show this help" << std::endl;
    std::cout << "  q                - Quit emulator" << std::endl;
}

void CDebugger::handle_command( const std::string &cmd )
{
    std::istringstream iss( cmd );
    std::string command;
    iss >> command;

    if (command.empty())
    {
        step_in(); // Default: step in
    }
    else if (command == "b")
    {
        uint32_t addr;
        if (iss >> std::hex >> addr)
            add_breakpoint( addr );
        else
            std::cout << "Usage: b <address>" << std::endl;
    }
    else if (command == "d")
    {
        uint32_t addr;
        if (iss >> std::hex >> addr)
            remove_breakpoint( addr );
        else
            std::cout << "Usage: d <address>" << std::endl;
    }
    else if (command == "l")
    {
        list_breakpoints();
    }
    else if (command == "s" || command == "si")
    {
        step_in();
    }
    else if (command == "so")
    {
        step_out();
    }
    else if (command == "c")
    {
        continue_execution();
    }
    else if (command == "r")
    {
        show_registers();
    }
    else if (command == "bt")
    {
        show_callstack();
    }
    else if (command == "x")
    {
        uint32_t addr;
        size_t len;
        if (iss >> std::hex >> addr >> len)
            hexdump( addr, len );
        else
            std::cout << "Usage: x <address> <length>" << std::endl;
    }
    else if (command == "h" || command == "?")
    {
        print_help();
    }
    else if (command == "q")
    {
        std::cout << "Quitting..." << std::endl;
        uc_emu_stop( m_uc );
        std::exit( 0 );
    }
    else
    {
        std::cout << "Unknown command. Type 'h' for help." << std::endl;
    }
}

void CDebugger::interactive_prompt()
{
    uint32_t pc;
    uc_reg_read( m_uc, UC_PPC_REG_PC, &pc );

    std::cout << "\n=== Breakpoint at 0x" << std::hex << pc << std::dec << " ===" << std::endl;
    show_registers();

    // Show instruction bytes
    std::vector<uint8_t> instr( 4 );
    if (uc_mem_read( m_uc, pc, instr.data(), 4 ) == UC_ERR_OK)
    {
        std::cout << "Instruction: ";
        for (uint8_t byte : instr)
            std::cout << std::hex << std::setfill( '0' ) << std::setw( 2 ) << static_cast<int>( byte ) << " ";
        std::cout << std::dec << std::endl;
    }

    // Show callstack
    std::cout << std::endl;
    show_callstack();

    while (m_stepMode == StepMode::None)
    {
        std::cout << "\n(dbg) ";
        std::string line;
        if (!std::getline( std::cin, line ))
        {
            std::cout << std::endl;
            continue_execution();
            break;
        }

        handle_command( line );
    }
}

} // namespace debug

#endif // DEBUG
