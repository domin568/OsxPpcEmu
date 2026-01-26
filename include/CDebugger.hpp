/**
 * Author:    domin568
 * Created:   17.01.2026
 * Brief:     Interactive debugger for PPC emulator (DEBUG builds only)
 **/
#pragma once

#ifdef DEBUG

#include "CMemory.hpp"
#include <cstdint>
#include <set>
#include <unicorn/unicorn.h>
#include <vector>

// Forward declaration
namespace loader
{
class CMachoLoader;
}

namespace debug
{

enum class StepMode
{
    None,
    StepIn,  // Execute next instruction
    StepOut, // Run until return (lr is loaded into pc)
    Continue // Run until next breakpoint
};

class CDebugger
{
  public:
    CDebugger( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader );

    // Breakpoint management
    void add_breakpoint( uint32_t address );
    void remove_breakpoint( uint32_t address );
    void list_breakpoints() const;
    bool is_breakpoint( uint32_t address ) const;

    // Watchpoint management
    void add_watchpoint( uint32_t address, size_t size );
    void remove_watchpoint( uint32_t address );
    void list_watchpoints() const;
    bool check_watchpoint_write( uint32_t address, size_t size, uint64_t value );
    uc_hook get_watchpoint_hook() const
    {
        return m_watchpoint_hook;
    }

    // Stepping control
    void step_in();
    void step_out();
    void continue_execution();
    bool should_break( uint32_t address );
    bool is_active() const; // Returns true if debugger should be checking instructions
    bool is_trace_mode() const
    {
        return m_trace_mode;
    }

    // Memory inspection
    void hexdump( uint32_t address, size_t length ) const;
    void show_registers() const;
    void show_callstack( size_t maxDepth = 10 ) const;
    bool print_vm_map();

    // Callstack utility (returns vector of addresses: [LR, saved_LR1, saved_LR2, ...])
    std::vector<uint32_t> get_callstack_addresses( size_t maxDepth = 10 ) const;

    // Interactive prompt
    void interactive_prompt();

  private:
    struct Watchpoint
    {
        uint32_t address;
        size_t size;
        bool operator<( const Watchpoint &other ) const
        {
            return address < other.address;
        }
    };

    uc_engine *m_uc;
    memory::CMemory *m_mem;
    loader::CMachoLoader *m_loader;
    std::set<uint32_t> m_breakpoints{};
    std::set<Watchpoint> m_watchpoints{};
    uc_hook m_watchpoint_hook{};
    StepMode m_stepMode;
    uint32_t m_stepOutLR{};
    bool m_trace_mode{ false };

    void print_help() const;
    void handle_command( const std::string &cmd );
    std::string get_symbol_name( uint32_t address ) const;
};

} // namespace debug

#endif // DEBUG
