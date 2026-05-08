/**
 * Author:    domin568
 * Created:   17.01.2026
 * Brief:     Interactive debugger for PPC emulator (DEBUG builds only)
 **/
#pragma once

#ifdef DEBUG

#include "CMemory.hpp"
#include <cstdint>
#include <cstdio>
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
    Memory,
    StringMatch // Compare string at reg+offset with a target string
};

enum class LogAction
{
    String,   // Read null-terminated string from computed address
    Int8,     // Read 8-bit value from computed address
    Int16,    // Read 16-bit big-endian value from computed address
    Int32,    // Read 32-bit big-endian value from computed address
    Hex,      // Hexdump N bytes from computed address
    RegValue  // Just print the register value (no memory dereference)
};

struct LogBreakpoint
{
    std::string prefix;          // Prefix printed when hit
    LogAction action;            // What to read
    int reg_id{ -1 };            // Source register (-1 means absolute address)
    int32_t offset{ 0 };         // Offset added to register value
    uint32_t abs_address{ 0 };   // Used when reg_id == -1
    size_t hex_len{ 16 };        // Byte count for Hex action
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

    // StringMatch fields: read string at str_reg + str_offset and compare with str_value
    int str_reg_id{ -1 };          // register for address (-1 = absolute)
    int32_t str_offset{ 0 };       // offset from register
    uint32_t str_abs_address{ 0 }; // absolute address (when str_reg_id == -1)
    std::string str_value{};       // target string to compare against
};

class CDebugger
{
  public:
    CDebugger( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader, std::FILE **trace_file );

    // Breakpoint management
    void add_breakpoint( uint32_t address );
    void add_conditional_breakpoint( uint32_t address, const BreakpointCondition &condition );
    void remove_breakpoint( uint32_t address );
    void list_breakpoints() const;
    bool is_breakpoint( uint32_t address ) const;

    // Log breakpoint management (non-breaking, reads state and prints)
    void add_log_breakpoint( uint32_t address, const LogBreakpoint &lb );
    void remove_log_breakpoints( uint32_t address );
    void list_log_breakpoints() const;
    void check_log_breakpoints( uint32_t address );

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
    std::map<uint32_t, std::vector<LogBreakpoint>> m_log_breakpoints{};
    std::set<Watchpoint> m_watchpoints{};
    uc_hook m_watchpoint_hook{};
    StepMode m_stepMode;
    uint32_t m_stepOutLR{};
    bool m_trace_mode{ false };
    std::FILE **m_trace_file{};

    void print_help() const;
    void handle_command( const std::string &cmd );
    std::string get_symbol_name( uint32_t address ) const;
    bool check_condition( const BreakpointCondition &condition ) const;
    int parse_register_name( const std::string &reg_name ) const;
    uint32_t resolve_log_address( const LogBreakpoint &lb ) const;
    bool parse_log_expression( const std::string &expr, int &reg_id, int32_t &offset, uint32_t &abs_addr ) const;
};

} // namespace debug

#endif
