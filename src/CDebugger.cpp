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

    const std::optional<std::string> funcName{ m_loader->get_symbol_name_for_va(
        address, LIEF::MachO::Symbol::TYPE::SECTION, loader::CMachoLoader::SymbolSection::TEXT ) };
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

void CDebugger::add_watchpoint( uint32_t address, size_t size )
{
    Watchpoint wp{ address, size };
    m_watchpoints.insert( wp );
    std::cout << "Watchpoint added at 0x" << std::hex << address << " (size: " << std::dec << size << " bytes)"
              << std::endl;
}

void CDebugger::remove_watchpoint( uint32_t address )
{
    auto it = std::find_if( m_watchpoints.begin(), m_watchpoints.end(),
                            [address]( const Watchpoint &wp ) { return wp.address == address; } );

    if (it != m_watchpoints.end())
    {
        m_watchpoints.erase( it );
        std::cout << "Watchpoint removed at 0x" << std::hex << address << std::dec << std::endl;
    }
    else
    {
        std::cout << "No watchpoint at 0x" << std::hex << address << std::dec << std::endl;
    }
}

void CDebugger::list_watchpoints() const
{
    if (m_watchpoints.empty())
    {
        std::cout << "No watchpoints set" << std::endl;
        return;
    }
    std::cout << "Watchpoints:" << std::endl;
    for (const auto &wp : m_watchpoints)
    {
        std::cout << "  0x" << std::hex << wp.address << " (size: " << std::dec << wp.size << " bytes)" << std::endl;
    }
}

bool CDebugger::check_watchpoint_write( uint32_t address, size_t size, uint64_t value )
{
    // Check if this write overlaps with any watchpoint
    for (const auto &wp : m_watchpoints)
    {
        uint32_t wp_end = wp.address + wp.size;
        uint32_t write_end = address + size;

        // Check for overlap: [wp.address, wp_end) overlaps with [address, write_end)
        if (address < wp_end && write_end > wp.address)
        {
            // Calculate PC to show where the write is coming from
            uint32_t pc;
            uc_reg_read( m_uc, UC_PPC_REG_PC, &pc );

            std::cout << "\n=== Watchpoint Hit ===" << std::endl;
            std::cout << "Write to 0x" << std::hex << address << " (size: " << std::dec << size << " bytes)"
                      << std::endl;
            std::cout << "Watchpoint: 0x" << std::hex << wp.address << " (size: " << std::dec << wp.size << " bytes)"
                      << std::endl;
            std::cout << "Value: 0x" << std::hex << value << std::endl;
            std::cout << "PC: 0x" << std::hex << pc << std::dec << get_symbol_name( pc ) << std::endl;

            return true; // Break execution
        }
    }

    return false; // Continue execution
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

    std::cout << "  PC  = 0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << pc << "  ";
    std::cout << "  LR  = 0x" << std::setw( 8 ) << lr << "  ";
    std::cout << "  CTR = 0x" << std::setw( 8 ) << ctr << "  ";
    std::cout << "  CR  = 0x" << std::setw( 8 ) << cr << "  ";
    std::cout << "  XER = 0x" << std::setw( 8 ) << xer << "  " << std::dec << std::endl;

    // General purpose registers
    for (int i = 0; i < 32; i++)
    {
        uint32_t reg;
        uc_reg_read( m_uc, UC_PPC_REG_0 + i, &reg );
        std::cout << "  R" << std::dec << std::setfill( ' ' ) << std::left << std::setw( 2 ) << i << " = 0x"
                  << std::right << std::hex << std::setfill( '0' ) << std::setw( 8 ) << reg;
        if (i % 8 == 7)
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
    bool useLRfirst = ( lr != 0 );

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
        std::cout << "  #" << ( i + 1 ) << "  0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << addresses[i]
                  << std::dec << get_symbol_name( addresses[i] ) << std::endl;
    }

    if (addresses.size() == maxDepth)
        std::cout << "  ... (max depth reached)" << std::endl;
}

bool CDebugger::print_vm_map()
{
    uc_mem_region *regions;
    uint32_t count{};
    if (uc_mem_regions( m_uc, &regions, &count ) != UC_ERR_OK)
        return false;

    std::cout << "     va         size     perm  description" << std::endl;
    for (uint32_t i = 0; i < count; i++)
    {
        const auto &r = regions[i];
        std::cout << " 0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << r.begin << "  0x" << std::setw( 8 )
                  << r.end - r.begin + 1 << "  ";

        // Print permissions (fixed width of 3 characters + space)
        std::string perms;
        if (r.perms & UC_PROT_READ)
            perms += "R";
        if (r.perms & UC_PROT_WRITE)
            perms += "W";
        if (r.perms & UC_PROT_EXEC)
            perms += "X";

        std::cout << std::left << std::setw( 3 ) << perms << " " << std::right;

        if (r.begin == common::Heap_Start)
        {
            std::cout << "(heap)";
        }
        else if (r.begin == common::Stack_Region_Start_Address)
        {
            std::cout << "(stack)";
        }
        else if (r.begin == common::Import_Dispatch_Table_Address)
        {
            std::cout << "(import dispatch table)";
        }
        else
        {
            std::cout << "(image)";
        }
        std::cout << "\n";
    }
    return true;
}

void CDebugger::print_help() const
{
    std::cout << "Debugger commands:" << std::endl;
    std::cout << "  b <addr>         - Set breakpoint at address (hex)" << std::endl;
    std::cout << "  d <addr>         - Delete breakpoint at address (hex)" << std::endl;
    std::cout << "  l                - List all breakpoints" << std::endl;
    std::cout << "  watch <addr> <size> - Set memory watchpoint (break on write)" << std::endl;
    std::cout << "  unwatch <addr>   - Remove memory watchpoint" << std::endl;
    std::cout << "  lw               - List all watchpoints" << std::endl;
    std::cout << "  s / si           - Step in (execute one instruction)" << std::endl;
    std::cout << "  so               - Step out (run until return)" << std::endl;
    std::cout << "  c                - Continue execution" << std::endl;
    std::cout << "  r                - Show registers" << std::endl;
    std::cout << "  wr <reg> <val>   - Write value to register (e.g., wr r3 1234)" << std::endl;
    std::cout << "  bt               - Show call stack (backtrace)" << std::endl;
    std::cout << "  x <addr> <len>   - Hexdump memory (addr and len in hex)" << std::endl;
    std::cout << "  w <addr> <bytes> - Write hex bytes to memory (e.g., w 1000 deadbeef)" << std::endl;
    std::cout << "  vmmap            - Show virtual memory regions" << std::endl;
    std::cout << "  trace            - Toggle tracing API calls" << std::endl;
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
    else if (command == "watch")
    {
        uint32_t addr;
        size_t size;
        if (iss >> std::hex >> addr >> std::dec >> size)
        {
            if (size == 0 || size > 256)
            {
                std::cout << "Invalid size (must be 1-256)" << std::endl;
            }
            else
            {
                add_watchpoint( addr, size );
            }
        }
        else
        {
            std::cout << "Usage: watch <address> <size>" << std::endl;
            std::cout << "Example: watch bffeff40 4" << std::endl;
        }
    }
    else if (command == "unwatch")
    {
        uint32_t addr;
        if (iss >> std::hex >> addr)
            remove_watchpoint( addr );
        else
            std::cout << "Usage: unwatch <address>" << std::endl;
    }
    else if (command == "lw")
    {
        list_watchpoints();
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
    else if (command == "wr")
    {
        std::string reg_name;
        uint32_t value;
        if (iss >> reg_name >> std::hex >> value)
        {
            // Convert register name to uppercase for easier comparison
            std::transform( reg_name.begin(), reg_name.end(), reg_name.begin(), ::toupper );

            int reg_id = -1;

            // Check for special registers
            if (reg_name == "PC")
                reg_id = UC_PPC_REG_PC;
            else if (reg_name == "LR")
                reg_id = UC_PPC_REG_LR;
            else if (reg_name == "CTR")
                reg_id = UC_PPC_REG_CTR;
            else if (reg_name == "CR")
                reg_id = UC_PPC_REG_CR;
            else if (reg_name == "XER")
                reg_id = UC_PPC_REG_XER;
            else if (reg_name == "MSR")
                reg_id = UC_PPC_REG_MSR;
            else if (reg_name[0] == 'R' && reg_name.length() >= 2)
            {
                // Parse register number (R0-R31)
                try
                {
                    int reg_num = std::stoi( reg_name.substr( 1 ) );
                    if (reg_num >= 0 && reg_num <= 31)
                        reg_id = UC_PPC_REG_0 + reg_num;
                }
                catch (...)
                {
                    // Invalid register number
                }
            }

            if (reg_id != -1)
            {
                uc_err err = uc_reg_write( m_uc, reg_id, &value );
                if (err == UC_ERR_OK)
                    std::cout << reg_name << " = 0x" << std::hex << value << std::dec << std::endl;
                else
                    std::cout << "Failed to write register" << std::endl;
            }
            else
            {
                std::cout << "Unknown register: " << reg_name << std::endl;
            }
        }
        else
        {
            std::cout << "Usage: wr <register> <value>" << std::endl;
            std::cout << "Examples: wr r3 1234, wr pc 4c4dc, wr lr 0" << std::endl;
        }
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
    else if (command == "w" || command == "wm")
    {
        uint32_t addr;
        std::string data_str;
        if (iss >> std::hex >> addr && std::getline( iss, data_str ))
        {
            // Remove leading whitespace
            data_str.erase( 0, data_str.find_first_not_of( " \t" ) );

            if (data_str.empty())
            {
                std::cout << "Usage: w <address> <hex_bytes>" << std::endl;
                std::cout << "Example: w bffefaa0 deadbeef 12345678" << std::endl;
                return;
            }

            // Parse hex bytes
            std::vector<uint8_t> bytes;
            std::istringstream data_stream( data_str );
            std::string byte_str;

            while (data_stream >> byte_str)
            {
                // Handle both individual bytes (aa) and 32-bit words (deadbeef)
                try
                {
                    if (byte_str.length() <= 2)
                    {
                        // Single byte
                        uint32_t byte_val = std::stoul( byte_str, nullptr, 16 );
                        bytes.push_back( static_cast<uint8_t>( byte_val ) );
                    }
                    else
                    {
                        // Multi-byte value - write as big-endian
                        uint32_t value = std::stoul( byte_str, nullptr, 16 );
                        size_t num_bytes = ( byte_str.length() + 1 ) / 2;

                        // Extract bytes in big-endian order
                        for (int i = num_bytes - 1; i >= 0; i--)
                        {
                            bytes.push_back( static_cast<uint8_t>( ( value >> ( i * 8 ) ) & 0xFF ) );
                        }
                    }
                }
                catch (...)
                {
                    std::cout << "Invalid hex value: " << byte_str << std::endl;
                    return;
                }
            }

            if (bytes.empty())
            {
                std::cout << "No data to write" << std::endl;
                return;
            }

            // Write to memory
            uc_err err = uc_mem_write( m_uc, addr, bytes.data(), bytes.size() );
            if (err == UC_ERR_OK)
            {
                std::cout << "Wrote " << std::dec << bytes.size() << " bytes to 0x" << std::hex << addr << std::endl;
                // Show what was written
                std::cout << "Data: ";
                for (size_t i = 0; i < bytes.size(); i++)
                {
                    std::cout << std::hex << std::setfill( '0' ) << std::setw( 2 ) << static_cast<int>( bytes[i] );
                    if (i < bytes.size() - 1)
                        std::cout << " ";
                }
                std::cout << std::dec << std::endl;
            }
            else
            {
                std::cout << "Failed to write memory at 0x" << std::hex << addr << std::dec << std::endl;
            }
        }
        else
        {
            std::cout << "Usage: w <address> <hex_bytes>" << std::endl;
            std::cout << "Example: w bffefaa0 deadbeef 12345678" << std::endl;
        }
    }
    else if (command == "vmmap")
    {
        print_vm_map();
    }
    else if (command == "trace")
    {
        m_trace_mode = !m_trace_mode;
        std::cout << "Tracing API calls: " << ( m_trace_mode ? "ON" : "OFF" ) << std::endl;
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
