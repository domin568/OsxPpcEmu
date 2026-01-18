/**
 * Author:    domin568
 * Created:   18.01.2026
 * Brief:     GDB Remote Serial Protocol server for IDA Pro integration
 **/
#pragma once

#ifdef DEBUG

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <unicorn/unicorn.h>
#include <vector>

// Forward declarations
namespace debug
{
class CDebugger;
}

namespace memory
{
class CMemory;
}

namespace loader
{
class CMachoLoader;
}

namespace gdb
{

enum class DebugState
{
    Running,
    Stopped,
    Detached
};

enum class StopReason
{
    Breakpoint,
    SingleStep,
    Interrupt,
    Trap
};

class CGdbServer
{
  public:
    CGdbServer( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader, debug::CDebugger *debugger,
                uint16_t port = 23946 );
    ~CGdbServer();

    // Server control
    bool start();
    void stop();
    bool is_running() const;

    // Debugger integration - called by emulator hooks
    void notify_breakpoint( uint32_t address );
    void notify_step_complete( uint32_t address );
    void notify_exception( uint32_t address );

    // State control - called by GDB client
    void continue_execution();
    void single_step();
    bool is_execution_stopped() const;
    void wait_for_continue();

  private:
    uc_engine *m_uc;
    memory::CMemory *m_mem;
    loader::CMachoLoader *m_loader;
    debug::CDebugger *m_debugger;

    uint16_t m_port;
    int m_server_socket;
    int m_client_socket;
    std::atomic<bool> m_running;
    std::unique_ptr<std::thread> m_server_thread;

    std::atomic<DebugState> m_state;
    std::atomic<StopReason> m_stop_reason;
    std::atomic<uint32_t> m_stop_address;
    std::atomic<bool> m_step_mode;

    // Server thread
    void server_loop();
    bool accept_connection();
    void handle_client();

    // Packet handling
    std::string receive_packet();
    void send_packet( const std::string &data );
    void send_ack();
    void send_nak();
    std::string handle_packet( const std::string &packet );

    // GDB command handlers
    std::string handle_query( const std::string &query );
    std::string handle_read_registers();
    std::string handle_write_registers( const std::string &data );
    std::string handle_read_memory( uint32_t address, uint32_t length );
    std::string handle_write_memory( uint32_t address, const std::string &data );
    std::string handle_continue( const std::string &addr_str );
    std::string handle_step( const std::string &addr_str );
    std::string handle_insert_breakpoint( uint32_t address );
    std::string handle_remove_breakpoint( uint32_t address );
    std::string handle_stop_reason();

    // Utility functions
    static uint8_t calculate_checksum( const std::string &data );
    static std::string encode_hex( const uint8_t *data, size_t length );
    static std::string encode_hex_u32( uint32_t value );
    static std::vector<uint8_t> decode_hex( const std::string &hex );
    static uint32_t decode_hex_u32( const std::string &hex );
};

} // namespace gdb

#endif // DEBUG
