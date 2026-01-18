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
#include <vector>
#include <unicorn/unicorn.h>

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

    // Stepping control
    void step_in();
    void step_out();
    void continue_execution();
    bool should_break( uint32_t address );
    bool is_active() const; // Returns true if debugger should be checking instructions

    // Memory inspection
    void hexdump( uint32_t address, size_t length ) const;
    void show_registers() const;
    void show_callstack( size_t maxDepth = 10 ) const;

    // Callstack utility (returns vector of addresses: [LR, saved_LR1, saved_LR2, ...])
    std::vector<uint32_t> get_callstack_addresses( size_t maxDepth = 10 ) const;

    // Interactive prompt
    void interactive_prompt();

  private:
    uc_engine *m_uc;
    memory::CMemory *m_mem;
    loader::CMachoLoader *m_loader;
    std::set<uint32_t> m_breakpoints;
    StepMode m_stepMode;
    uint32_t m_stepOutLR; // LR value to wait for when stepping out

    void print_help() const;
    void handle_command( const std::string &cmd );
    std::string get_symbol_name( uint32_t address ) const;
};

} // namespace debug

#endif // DEBUG
