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
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace debug
{

CDebugger::CDebugger( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader, std::FILE **trace_file )
    : m_uc( uc ), m_mem( mem ), m_loader( loader ), m_stepMode( StepMode::None ), m_stepOutLR( 0 ), m_trace_file( trace_file )
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
    // std::cout << "Breakpoint added at 0x" << std::hex << address << std::dec << std::endl;
}

void CDebugger::add_conditional_breakpoint( uint32_t address, const BreakpointCondition &condition )
{
    m_conditional_breakpoints[address] = condition;
    std::cout << "Conditional breakpoint added at 0x" << std::hex << address << std::dec << std::endl;
}

void CDebugger::remove_breakpoint( uint32_t address )
{
    bool removed = m_breakpoints.erase( address ) || m_conditional_breakpoints.erase( address );
    if (removed)
        std::cout << "Breakpoint removed at 0x" << std::hex << address << std::dec << std::endl;
    else
        std::cout << "No breakpoint at 0x" << std::hex << address << std::dec << std::endl;
}

void CDebugger::list_breakpoints() const
{
    if (m_breakpoints.empty() && m_conditional_breakpoints.empty() && m_log_breakpoints.empty())
    {
        std::cout << "No breakpoints set" << std::endl;
        return;
    }
    std::cout << "Breakpoints:" << std::endl;
    for (uint32_t addr : m_breakpoints)
        std::cout << "  0x" << std::hex << addr << std::dec << std::endl;

    if (!m_conditional_breakpoints.empty())
    {
        std::cout << "Conditional breakpoints:" << std::endl;
        for (const auto &[addr, cond] : m_conditional_breakpoints)
        {
            std::cout << "  0x" << std::hex << addr << std::dec << " if ";

            if (cond.type == ConditionType::StringMatch)
            {
                std::cout << "str(";
                if (cond.str_reg_id != -1)
                {
                    if (cond.str_reg_id >= UC_PPC_REG_0 && cond.str_reg_id <= UC_PPC_REG_0 + 31)
                        std::cout << "r" << ( cond.str_reg_id - UC_PPC_REG_0 );
                    else
                        std::cout << "reg(" << cond.str_reg_id << ")";
                    if (cond.str_offset > 0)
                        std::cout << "+0x" << std::hex << cond.str_offset << std::dec;
                    else if (cond.str_offset < 0)
                        std::cout << "-0x" << std::hex << ( -cond.str_offset ) << std::dec;
                }
                else
                    std::cout << "0x" << std::hex << cond.str_abs_address << std::dec;
                std::cout << ") " << ( cond.op == CompareOp::Equal ? "==" : "!=" ) << " \"" << cond.str_value << "\""
                          << std::endl;
                continue;
            }

            if (cond.type == ConditionType::Register)
            {
                std::cout << "reg(" << cond.reg_id << ")";
            }
            else if (cond.type == ConditionType::Memory)
            {
                std::cout << "mem[0x" << std::hex << cond.mem_address << std::dec << "]";
            }

            switch (cond.op)
            {
            case CompareOp::Equal:
                std::cout << " == ";
                break;
            case CompareOp::NotEqual:
                std::cout << " != ";
                break;
            case CompareOp::Greater:
                std::cout << " > ";
                break;
            case CompareOp::Less:
                std::cout << " < ";
                break;
            case CompareOp::GreaterEqual:
                std::cout << " >= ";
                break;
            case CompareOp::LessEqual:
                std::cout << " <= ";
                break;
            }

            std::cout << "0x" << std::hex << cond.value << std::dec << std::endl;
        }
    }

    if (!m_log_breakpoints.empty())
    {
        size_t total = 0;
        for (const auto &[addr, entries] : m_log_breakpoints)
            total += entries.size();
        std::cout << "Log breakpoints: " << total << " (use 'llog' to list)" << std::endl;
    }
}

// ─── Log breakpoints (non-breaking tracepoints) ──────────────────────────────

void CDebugger::add_log_breakpoint( uint32_t address, const LogBreakpoint &lb )
{
    m_log_breakpoints[address].push_back( lb );
    std::cout << "Log breakpoint added at 0x" << std::hex << address << std::dec << " [" << lb.prefix << "]"
              << std::endl;
}

void CDebugger::remove_log_breakpoints( uint32_t address )
{
    if (m_log_breakpoints.erase( address ))
        std::cout << "Log breakpoints removed at 0x" << std::hex << address << std::dec << std::endl;
    else
        std::cout << "No log breakpoints at 0x" << std::hex << address << std::dec << std::endl;
}

void CDebugger::list_log_breakpoints() const
{
    if (m_log_breakpoints.empty())
    {
        std::cout << "No log breakpoints set" << std::endl;
        return;
    }

    static const char *action_names[] = { "str", "i8", "i16", "i32", "hex", "reg" };

    std::cout << "Log breakpoints:" << std::endl;
    for (const auto &[addr, entries] : m_log_breakpoints)
    {
        for (const auto &lb : entries)
        {
            std::cout << "  0x" << std::hex << addr << std::dec << "  [" << lb.prefix << "]  "
                      << action_names[static_cast<int>( lb.action )] << "  ";

            if (lb.action == LogAction::RegValue)
            {
                // Just show register name
                if (lb.reg_id >= UC_PPC_REG_0 && lb.reg_id <= UC_PPC_REG_0 + 31)
                    std::cout << "r" << ( lb.reg_id - UC_PPC_REG_0 );
                else
                    std::cout << "reg(" << lb.reg_id << ")";
            }
            else if (lb.reg_id != -1)
            {
                if (lb.reg_id >= UC_PPC_REG_0 && lb.reg_id <= UC_PPC_REG_0 + 31)
                    std::cout << "r" << ( lb.reg_id - UC_PPC_REG_0 );
                else
                    std::cout << "reg(" << lb.reg_id << ")";

                if (lb.offset > 0)
                    std::cout << "+0x" << std::hex << lb.offset << std::dec;
                else if (lb.offset < 0)
                    std::cout << "-0x" << std::hex << ( -lb.offset ) << std::dec;
            }
            else
            {
                std::cout << "0x" << std::hex << lb.abs_address << std::dec;
            }

            if (lb.action == LogAction::Hex)
                std::cout << " len=" << lb.hex_len;

            std::cout << std::endl;
        }
    }
}

uint32_t CDebugger::resolve_log_address( const LogBreakpoint &lb ) const
{
    if (lb.reg_id == -1)
        return lb.abs_address;

    uint32_t reg_val = 0;
    uc_reg_read( m_uc, lb.reg_id, &reg_val );
    return static_cast<uint32_t>( static_cast<int64_t>( reg_val ) + lb.offset );
}

bool CDebugger::parse_log_expression( const std::string &expr, int &reg_id, int32_t &offset,
                                      uint32_t &abs_addr ) const
{
    reg_id = -1;
    offset = 0;
    abs_addr = 0;

    // Find '+' or '-' that separates register from offset (skip leading chars)
    std::string::size_type sep = std::string::npos;
    for (std::string::size_type i = 1; i < expr.size(); ++i)
    {
        if (expr[i] == '+' || expr[i] == '-')
        {
            sep = i;
            break;
        }
    }

    if (sep != std::string::npos)
    {
        // Register + offset  (e.g. r3+0xb  or  lr-4)
        std::string reg_part = expr.substr( 0, sep );
        std::string off_part = expr.substr( sep ); // includes the sign

        reg_id = parse_register_name( reg_part );
        if (reg_id == -1)
            return false;

        // Parse offset (may start with + or -)
        char *end = nullptr;
        long off_val = std::strtol( off_part.c_str(), &end, 0 ); // handles 0x prefix
        if (end == off_part.c_str())
            return false;
        offset = static_cast<int32_t>( off_val );
        return true;
    }

    // Try as register name alone (e.g. r3)
    reg_id = parse_register_name( expr );
    if (reg_id != -1)
    {
        offset = 0;
        return true;
    }

    // Try as absolute hex address (e.g. 0x1234 or 1234)
    char *end = nullptr;
    unsigned long addr = std::strtoul( expr.c_str(), &end, 16 );
    if (end != expr.c_str() && *end == '\0')
    {
        abs_addr = static_cast<uint32_t>( addr );
        return true;
    }

    return false;
}

void CDebugger::check_log_breakpoints( uint32_t address )
{
    auto it = m_log_breakpoints.find( address );
    if (it == m_log_breakpoints.end())
        return;

    for (const auto &lb : it->second)
    {
        // Print prefix
        std::cout << "\033[33m[" << lb.prefix << "]\033[0m ";

        // Handle RegValue action separately (no memory read)
        if (lb.action == LogAction::RegValue)
        {
            uint32_t reg_val = 0;
            uc_reg_read( m_uc, lb.reg_id, &reg_val );
            std::cout << "0x" << std::hex << reg_val << " (" << std::dec << reg_val << ")" << std::endl;
            continue;
        }

        uint32_t addr = resolve_log_address( lb );

        switch (lb.action)
        {
        case LogAction::String: {
            auto str = common::read_string_at_va( m_uc, addr );
            if (str.has_value())
                std::cout << "\"" << *str << "\"" << std::endl;
            else
                std::cout << "(failed to read string at 0x" << std::hex << addr << ")" << std::dec << std::endl;
            break;
        }
        case LogAction::Int8: {
            uint8_t val = 0;
            if (uc_mem_read( m_uc, addr, &val, sizeof( val ) ) == UC_ERR_OK)
                std::cout << "0x" << std::hex << static_cast<uint32_t>( val ) << " (" << std::dec
                          << static_cast<uint32_t>( val ) << ")" << std::endl;
            else
                std::cout << "(failed to read at 0x" << std::hex << addr << ")" << std::dec << std::endl;
            break;
        }
        case LogAction::Int16: {
            uint16_t val = 0;
            if (uc_mem_read( m_uc, addr, &val, sizeof( val ) ) == UC_ERR_OK)
            {
                val = common::ensure_endianness( val, std::endian::big );
                std::cout << "0x" << std::hex << val << " (" << std::dec << val << ")" << std::endl;
            }
            else
                std::cout << "(failed to read at 0x" << std::hex << addr << ")" << std::dec << std::endl;
            break;
        }
        case LogAction::Int32: {
            uint32_t val = 0;
            if (uc_mem_read( m_uc, addr, &val, sizeof( val ) ) == UC_ERR_OK)
            {
                val = common::ensure_endianness( val, std::endian::big );
                std::cout << "0x" << std::hex << val << " (" << std::dec << val << ")" << std::endl;
            }
            else
                std::cout << "(failed to read at 0x" << std::hex << addr << ")" << std::dec << std::endl;
            break;
        }
        case LogAction::Hex: {
            std::vector<uint8_t> buf( lb.hex_len );
            if (uc_mem_read( m_uc, addr, buf.data(), lb.hex_len ) == UC_ERR_OK)
            {
                std::cout << "hexdump at 0x" << std::hex << addr << ":" << std::dec << std::endl;
                for (size_t i = 0; i < lb.hex_len; i += 16)
                {
                    std::cout << "  " << std::hex << std::setfill( '0' ) << std::setw( 8 ) << ( addr + i ) << "  ";
                    for (size_t j = 0; j < 16; ++j)
                    {
                        if (i + j < lb.hex_len)
                            std::cout << std::setw( 2 ) << static_cast<int>( buf[i + j] ) << " ";
                        else
                            std::cout << "   ";
                        if (j == 7)
                            std::cout << " ";
                    }
                    std::cout << " |";
                    for (size_t j = 0; j < 16 && i + j < lb.hex_len; ++j)
                    {
                        uint8_t b = buf[i + j];
                        std::cout << ( ( b >= 0x20 && b <= 0x7E ) ? static_cast<char>( b ) : '.' );
                    }
                    std::cout << "|" << std::dec << std::endl;
                }
            }
            else
                std::cout << "(failed to read at 0x" << std::hex << addr << ")" << std::dec << std::endl;
            break;
        }
        default:
            break;
        }
    }
}

bool CDebugger::is_breakpoint( uint32_t address ) const
{
    // Check conditional breakpoints first — they take priority over unconditional ones.
    // This allows IDA to set a Z0 breakpoint at the same address (so it recognises the
    // stop) while the server-side condition still gates whether we actually break.
    auto it = m_conditional_breakpoints.find( address );
    if (it != m_conditional_breakpoints.end())
    {
        return check_condition( it->second );
    }

    if (m_breakpoints.contains( address ))
        return true;

    return false;
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
    return m_stepMode != StepMode::None || !m_breakpoints.empty() || !m_conditional_breakpoints.empty() ||
           !m_log_breakpoints.empty();
}

bool CDebugger::should_break( uint32_t address )
{
    // Always process log breakpoints (non-breaking)
    check_log_breakpoints( address );

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
        std::cout << std::hex << std::setfill( '0' ) << std::setw( 8 ) << ( address + i ) << "  ";
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
            returnAddr = lr;
            useLRfirst = false;
        }
        else
        {
            uint32_t savedLR;
            if (uc_mem_read( m_uc, currentSP + 8, &savedLR, sizeof( savedLR ) ) != UC_ERR_OK)
                break;

            savedLR = common::ensure_endianness( savedLR, std::endian::big );
            if (savedLR == 0)
                break;
            returnAddr = savedLR;
        }

        addresses.push_back( returnAddr );
        uint32_t savedSP;
        if (uc_mem_read( m_uc, currentSP, &savedSP, sizeof( savedSP ) ) != UC_ERR_OK)
            break;

        savedSP = common::ensure_endianness( savedSP, std::endian::big );

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

    std::cout << "  #0  0x" << std::hex << std::setfill( '0' ) << std::setw( 8 ) << pc << std::dec
              << get_symbol_name( pc ) << std::endl;

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
    std::cout << "  <enter>          - Step in (same as 's')" << std::endl;
    std::cout << "  b <addr>         - Set breakpoint at address (hex)" << std::endl;
    std::cout << "  bc <addr> <type> <op> <value> - Conditional breakpoint" << std::endl;
    std::cout << "       type: reg <reg_name> | mem <addr> [size] | str <expr>" << std::endl;
    std::cout << "       op: == != > < >= <= (str only supports == !=)" << std::endl;
    std::cout << "       Example: bc 4c4dc reg r3 == 0" << std::endl;
    std::cout << "       Example: bc 4c4dc mem bffeff40 4 != 0" << std::endl;
    std::cout << "       Example: bc 803e0 str r9+0xa == GetMenuItemHierarchicalID" << std::endl;
    std::cout << "  d <addr>         - Delete breakpoint at address (hex)" << std::endl;
    std::cout << "  l                - List all breakpoints" << std::endl;
    std::cout << "  watch <addr> <size> - Set memory watchpoint (break on write)" << std::endl;
    std::cout << "  unwatch <addr>   - Remove memory watchpoint" << std::endl;
    std::cout << "  lw               - List all watchpoints" << std::endl;
    std::cout << "  log <addr> <action> <expr> [len]" << std::endl;
    std::cout << "       Non-breaking breakpoint that reads state and prints it." << std::endl;
    std::cout << "       action: str | i8 | i16 | i32 | hex | reg" << std::endl;
    std::cout << "       expr:   r3 | r3+0xb | r3-4 | lr | 0x1234" << std::endl;
    std::cout << "       Examples: log 82c04 str r3+0xb" << std::endl;
    std::cout << "                 log 82c04 i32 r3" << std::endl;
    std::cout << "                 log 82c04 reg r3" << std::endl;
    std::cout << "                 log 82c04 hex r5+0x10 40" << std::endl;
    std::cout << "  dlog <addr>      - Delete all log breakpoints at address" << std::endl;
    std::cout << "  llog             - List all log breakpoints" << std::endl;
    std::cout << "  s / si           - Step in (execute one instruction)" << std::endl;
    std::cout << "  so               - Step out (run until return)" << std::endl;
    std::cout << "  c                - Continue execution" << std::endl;
    std::cout << "  r                - Show registers" << std::endl;
    std::cout << "  wr <reg> <val>   - Write value to register (e.g., wr r3 1234)" << std::endl;
    std::cout << "  bt               - Show call stack (backtrace)" << std::endl;
    std::cout << "  x <addr> <len>   - Hexdump memory (addr and len in hex)" << std::endl;
    std::cout << "  w/wm <addr> <bytes> - Write hex bytes to memory (e.g., w 1000 deadbeef)" << std::endl;
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
    else if (command == "bc")
    {
        std::uint32_t addr{};
        std::string type_str{};

        if (!( iss >> std::hex >> addr >> type_str ))
        {
            std::cout << "Usage: bc <addr> reg <reg_name> <op> <value>" << std::endl;
            std::cout << "       bc <addr> mem <addr> <size> <op> <value>" << std::endl;
            std::cout << "       bc <addr> str <expr> == <string>" << std::endl;
            return;
        }

        BreakpointCondition condition;

        if (type_str == "str")
        {
            // bc <addr> str <expr> ==/!= <string>
            std::string expr_str;
            std::string op_str;
            std::string str_val;

            if (!( iss >> expr_str >> op_str ))
            {
                std::cout << "Usage: bc <addr> str <expr> == <string>" << std::endl;
                std::cout << "  expr: r9+0xa | r3 | 0x1234" << std::endl;
                return;
            }

            // Read the rest of the line as the string value (supports spaces)
            std::getline( iss >> std::ws, str_val );
            if (str_val.empty())
            {
                std::cout << "Missing string value" << std::endl;
                return;
            }

            if (op_str != "==" && op_str != "!=")
            {
                std::cout << "String conditions only support == and != operators" << std::endl;
                return;
            }

            condition.type = ConditionType::StringMatch;
            condition.op = ( op_str == "==" ) ? CompareOp::Equal : CompareOp::NotEqual;
            condition.str_value = str_val;

            if (!parse_log_expression( expr_str, condition.str_reg_id, condition.str_offset,
                                       condition.str_abs_address ))
            {
                std::cout << "Invalid expression: " << expr_str << std::endl;
                return;
            }

            add_conditional_breakpoint( addr, condition );
            return;
        }
        else if (type_str == "reg")
        {
            std::string reg_name;
            if (!( iss >> reg_name ))
            {
                std::cout << "Missing register name" << std::endl;
                return;
            }

            int reg_id = parse_register_name( reg_name );
            if (reg_id == -1)
            {
                std::cout << "Unknown register: " << reg_name << std::endl;
                return;
            }

            condition.type = ConditionType::Register;
            condition.reg_id = reg_id;
        }
        else if (type_str == "mem")
        {
            uint32_t mem_addr;
            if (!( iss >> std::hex >> mem_addr ))
            {
                std::cout << "Missing memory address" << std::endl;
                return;
            }

            condition.type = ConditionType::Memory;
            condition.mem_address = mem_addr;
            condition.mem_size = 4; // Default to 4 bytes

            // Try to read optional size
            std::streampos pos = iss.tellg();
            uint32_t size;
            if (iss >> std::dec >> size)
            {
                if (size == 1 || size == 2 || size == 4)
                {
                    condition.mem_size = size;
                }
                else
                {
                    std::cout << "Invalid size (must be 1, 2, or 4)" << std::endl;
                    return;
                }
            }
            else
            {
                // Restore position if size wasn't provided
                iss.clear();
                iss.seekg( pos );
            }
        }
        else
        {
            std::cout << "Unknown type: " << type_str << " (use 'reg', 'mem', or 'str')" << std::endl;
            return;
        }

        std::string op_str;
        if (!( iss >> op_str ))
        {
            std::cout << "Missing comparison operator" << std::endl;
            return;
        }

        if (op_str == "==")
            condition.op = CompareOp::Equal;
        else if (op_str == "!=")
            condition.op = CompareOp::NotEqual;
        else if (op_str == ">")
            condition.op = CompareOp::Greater;
        else if (op_str == "<")
            condition.op = CompareOp::Less;
        else if (op_str == ">=")
            condition.op = CompareOp::GreaterEqual;
        else if (op_str == "<=")
            condition.op = CompareOp::LessEqual;
        else
        {
            std::cout << "Unknown operator: " << op_str << std::endl;
            return;
        }

        if (!( iss >> std::hex >> condition.value ))
        {
            std::cout << "Missing comparison value" << std::endl;
            return;
        }

        add_conditional_breakpoint( addr, condition );
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
    else if (command == "log")
    {
        // log <addr> <action> <expr> [len]
        uint32_t addr{};
        std::string action_str{};
        std::string expr_str{};

        if (!( iss >> std::hex >> addr >> action_str >> expr_str ))
        {
            std::cout << "Usage: log <addr> <action> <expr> [len]" << std::endl;
            std::cout << "  action: str | i8 | i16 | i32 | hex | reg" << std::endl;
            std::cout << "  expr:   r3 | r3+0xb | r3-4 | 0x1234" << std::endl;
            return;
        }

        LogBreakpoint lb{};

        // Parse action
        if (action_str == "str")
            lb.action = LogAction::String;
        else if (action_str == "i8")
            lb.action = LogAction::Int8;
        else if (action_str == "i16")
            lb.action = LogAction::Int16;
        else if (action_str == "i32")
            lb.action = LogAction::Int32;
        else if (action_str == "hex")
            lb.action = LogAction::Hex;
        else if (action_str == "reg")
            lb.action = LogAction::RegValue;
        else
        {
            std::cout << "Unknown action: " << action_str << " (use str/i8/i16/i32/hex/reg)" << std::endl;
            return;
        }

        // Parse expression
        if (!parse_log_expression( expr_str, lb.reg_id, lb.offset, lb.abs_address ))
        {
            std::cout << "Invalid expression: " << expr_str << std::endl;
            std::cout << "  Expected: r3 | r3+0xb | r3-4 | lr | 0x1234" << std::endl;
            return;
        }

        // For RegValue action, we need a register
        if (lb.action == LogAction::RegValue && lb.reg_id == -1)
        {
            std::cout << "reg action requires a register expression (e.g. r3, lr)" << std::endl;
            return;
        }

        // Optional length for hex action
        if (lb.action == LogAction::Hex)
        {
            size_t len = 16;
            if (iss >> std::hex >> len)
                lb.hex_len = len;
        }

        // Auto-generate prefix: hex address e.g. "82C04"
        {
            std::ostringstream pfx;
            pfx << std::hex << std::uppercase << addr;
            lb.prefix = pfx.str();
        }

        add_log_breakpoint( addr, lb );
    }
    else if (command == "dlog")
    {
        uint32_t addr{};
        if (iss >> std::hex >> addr)
            remove_log_breakpoints( addr );
        else
            std::cout << "Usage: dlog <address>" << std::endl;
    }
    else if (command == "llog")
    {
        list_log_breakpoints();
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
        if (m_trace_mode && m_trace_file)
        {
            // Close previous file if open, then open fresh (truncate)
            if (*m_trace_file)
                std::fclose( *m_trace_file );
            *m_trace_file = std::fopen( "trace.txt", "w" );
            if (*m_trace_file)
                std::setvbuf( *m_trace_file, nullptr, _IOFBF, 256 * 1024 );
        }
        else if (!m_trace_mode && m_trace_file && *m_trace_file)
        {
            std::fclose( *m_trace_file );
            *m_trace_file = nullptr;
        }
        std::cout << "Tracing API calls: " << ( m_trace_mode ? "ON" : "OFF" );
        if (m_trace_mode)
            std::cout << " -> " << std::filesystem::absolute( "trace.txt" ).string();
        std::cout << std::endl;
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

bool CDebugger::check_condition( const BreakpointCondition &condition ) const
{
    // Handle string match separately
    if (condition.type == ConditionType::StringMatch)
    {
        uint32_t addr = condition.str_abs_address;
        if (condition.str_reg_id != -1)
        {
            uint32_t reg_val = 0;
            uc_reg_read( m_uc, condition.str_reg_id, &reg_val );
            addr = static_cast<uint32_t>( static_cast<int64_t>( reg_val ) + condition.str_offset );
        }

        auto str = common::read_string_at_va( m_uc, addr );
        if (!str.has_value())
            return false;

        if (condition.op == CompareOp::Equal)
            return *str == condition.str_value;
        if (condition.op == CompareOp::NotEqual)
            return *str != condition.str_value;
        return false;
    }

    uint32_t current_value = 0;

    if (condition.type == ConditionType::Register)
    {
        uint64_t reg_val = 0;
        if (uc_reg_read( m_uc, condition.reg_id, &reg_val ) != UC_ERR_OK)
            return false;
        current_value = static_cast<uint32_t>( reg_val );
    }
    else if (condition.type == ConditionType::Memory)
    {
        void *mem_ptr = m_mem->get( condition.mem_address );
        if (!mem_ptr)
            return false;

        switch (condition.mem_size)
        {
        case 1:
            current_value = *static_cast<uint8_t *>( mem_ptr );
            break;
        case 2:
            current_value = common::ensure_endianness( *static_cast<uint16_t *>( mem_ptr ), std::endian::big );
            break;
        case 4:
            current_value = common::ensure_endianness( *static_cast<uint32_t *>( mem_ptr ), std::endian::big );
            break;
        default:
            return false;
        }
    }
    else
    {
        return false;
    }

    switch (condition.op)
    {
    case CompareOp::Equal:
        return current_value == condition.value;
    case CompareOp::NotEqual:
        return current_value != condition.value;
    case CompareOp::Greater:
        return current_value > condition.value;
    case CompareOp::Less:
        return current_value < condition.value;
    case CompareOp::GreaterEqual:
        return current_value >= condition.value;
    case CompareOp::LessEqual:
        return current_value <= condition.value;
    }
    return false;
}

int CDebugger::parse_register_name( const std::string &reg_name ) const
{
    std::string upper_name = reg_name;
    std::transform( upper_name.begin(), upper_name.end(), upper_name.begin(), ::toupper );

    if (upper_name == "PC")
        return UC_PPC_REG_PC;
    if (upper_name == "LR")
        return UC_PPC_REG_LR;
    if (upper_name == "CTR")
        return UC_PPC_REG_CTR;
    if (upper_name == "CR")
        return UC_PPC_REG_CR;
    if (upper_name == "XER")
        return UC_PPC_REG_XER;
    if (upper_name == "MSR")
        return UC_PPC_REG_MSR;

    if (upper_name[0] == 'R' && upper_name.length() >= 2)
    {
        int reg_num = std::stoi( upper_name.substr( 1 ) );
        if (reg_num >= 0 && reg_num <= 31)
            return UC_PPC_REG_0 + reg_num;
    }
    return -1;
}

} // namespace debug

#endif // DEBUG
