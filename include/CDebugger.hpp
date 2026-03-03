/**
 * Author:    domin568
 * Created:   17.01.2026
 * Brief:     Interactive debugger for PPC emulator (DEBUG builds only)
 **/
#pragma once

#ifdef DEBUG

#include "CMemory.hpp"
#include <cstdint>
#include <map>
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

enum class ConditionType
{
    None,
    Register,
    Memory
};

enum class CompareOp
{
    Equal,
    NotEqual,
    Greater,
    Less,
    GreaterEqual,
    LessEqual
};

struct BreakpointCondition
{
    ConditionType type{ ConditionType::None };
    CompareOp op{ CompareOp::Equal };
    int reg_id{ -1 };
    uint32_t mem_address{ 0 };
    size_t mem_size{ 4 }; // 1, 2, or 4 bytes
    uint32_t value{ 0 };
};

class CDebugger
{
  public:
    CDebugger( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader );

    // Breakpoint management
    void add_breakpoint( uint32_t address );
    void add_conditional_breakpoint( uint32_t address, const BreakpointCondition &condition );
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

    void step_in();
    void step_out();
    void continue_execution();
    bool should_break( uint32_t address );
    bool is_active() const; // Returns true if debugger should be checking instructions
    bool is_trace_mode() const
    {
        return m_trace_mode;
    }

    void hexdump( uint32_t address, size_t length ) const;
    void show_registers() const;
    void show_callstack( size_t maxDepth = 10 ) const;
    bool print_vm_map();

    std::vector<uint32_t> get_callstack_addresses( size_t maxDepth = 10 ) const;

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
    std::map<uint32_t, BreakpointCondition> m_conditional_breakpoints{};
    std::set<Watchpoint> m_watchpoints{};
    uc_hook m_watchpoint_hook{};
    StepMode m_stepMode;
    uint32_t m_stepOutLR{};
    bool m_trace_mode{ false };

    void print_help() const;
    void handle_command( const std::string &cmd );
    std::string get_symbol_name( uint32_t address ) const;
    bool check_condition( const BreakpointCondition &condition ) const;
    int parse_register_name( const std::string &reg_name ) const;
};

} // namespace debug

#endif
