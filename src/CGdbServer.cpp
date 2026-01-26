/**
 * Author:    domin568
 * Created:   18.01.2026
 * Brief:     GDB Remote Serial Protocol server implementation
 **/

#include "../include/CGdbServer.hpp"
#include "../include/CDebugger.hpp"
#include "../include/CMemory.hpp"
#include "../include/Common.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#ifdef DEBUG

namespace gdb
{

CGdbServer::CGdbServer( uc_engine *uc, memory::CMemory *mem, loader::CMachoLoader *loader, debug::CDebugger *debugger,
                        uint16_t port )
    : m_uc( uc ), m_mem( mem ), m_loader( loader ), m_debugger( debugger ), m_port( port ), m_server_socket( -1 ),
      m_client_socket( -1 ), m_running( false ), m_state( DebugState::Stopped ), m_stop_reason( StopReason::Trap ),
      m_stop_address( 0 ), m_step_mode( false )
{
}

CGdbServer::~CGdbServer()
{
    stop();
}

bool CGdbServer::start()
{
    if (m_running.load())
        return true;

    // Create socket
    m_server_socket = socket( AF_INET, SOCK_STREAM, 0 );
    if (m_server_socket < 0)
    {
        std::cerr << "GDB server: Failed to create socket" << std::endl;
        return false;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt( m_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof( opt ) ) < 0)
    {
        std::cerr << "GDB server: Failed to set socket options" << std::endl;
        close( m_server_socket );
        return false;
    }

    // Bind socket
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons( m_port );

    if (bind( m_server_socket, reinterpret_cast<sockaddr *>( &server_addr ), sizeof( server_addr ) ) < 0)
    {
        std::cerr << "GDB server: Failed to bind to port " << m_port << std::endl;
        close( m_server_socket );
        return false;
    }

    // Listen
    if (listen( m_server_socket, 1 ) < 0)
    {
        std::cerr << "GDB server: Failed to listen" << std::endl;
        close( m_server_socket );
        return false;
    }

    m_running.store( true );
    m_server_thread = std::make_unique<std::thread>( &CGdbServer::server_loop, this );

    std::cout << "GDB server listening on port " << m_port << std::endl;
    std::cout << "In IDA Pro: Debugger -> Attach -> Remote GDB debugger -> localhost:" << m_port << std::endl;

    return true;
}

void CGdbServer::stop()
{
    if (!m_running.load())
        return;

    m_running.store( false );

    if (m_client_socket >= 0)
    {
        close( m_client_socket );
        m_client_socket = -1;
    }

    if (m_server_socket >= 0)
    {
        close( m_server_socket );
        m_server_socket = -1;
    }

    if (m_server_thread && m_server_thread->joinable())
    {
        m_server_thread->join();
    }

    std::cout << "GDB server stopped" << std::endl;
}

bool CGdbServer::is_running() const
{
    return m_running.load();
}

void CGdbServer::notify_breakpoint( uint32_t address )
{
    m_stop_reason.store( StopReason::Breakpoint );
    m_stop_address.store( address );
    m_state.store( DebugState::Stopped );
}

void CGdbServer::notify_step_complete( uint32_t address )
{
    m_stop_reason.store( StopReason::SingleStep );
    m_stop_address.store( address );
    m_state.store( DebugState::Stopped );
}

void CGdbServer::notify_exception( uint32_t address )
{
    m_stop_reason.store( StopReason::Trap );
    m_stop_address.store( address );
    m_state.store( DebugState::Stopped );
}

void CGdbServer::continue_execution()
{
    m_step_mode.store( false );
    m_state.store( DebugState::Running );
}

void CGdbServer::single_step()
{
    m_step_mode.store( true );
    m_state.store( DebugState::Running );
}

bool CGdbServer::is_execution_stopped() const
{
    return m_state.load() == DebugState::Stopped;
}

void CGdbServer::wait_for_continue()
{
    while (m_state.load() == DebugState::Stopped && m_running.load())
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
    }
}

void CGdbServer::server_loop()
{
    while (m_running.load())
    {
        if (!accept_connection())
        {
            std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
            continue;
        }

        std::cout << "GDB client connected" << std::endl;
        handle_client();
        std::cout << "GDB client disconnected" << std::endl;

        if (m_client_socket >= 0)
        {
            close( m_client_socket );
            m_client_socket = -1;
        }
    }
}

bool CGdbServer::accept_connection()
{
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof( client_addr );

    // Set socket to non-blocking for accept
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100ms timeout
    fd_set readfds;
    FD_ZERO( &readfds );
    FD_SET( m_server_socket, &readfds );

    int ret = select( m_server_socket + 1, &readfds, nullptr, nullptr, &tv );
    if (ret <= 0)
        return false;

    m_client_socket = accept( m_server_socket, reinterpret_cast<sockaddr *>( &client_addr ), &client_len );
    if (m_client_socket >= 0)
    {
        // Set client socket to non-blocking mode
        int flags = fcntl( m_client_socket, F_GETFL, 0 );
        fcntl( m_client_socket, F_SETFL, flags | O_NONBLOCK );

        // Set read timeout
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 50000; // 50ms timeout
        setsockopt( m_client_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof( tv ) );
    }
    return m_client_socket >= 0;
}

void CGdbServer::handle_client()
{
    bool waiting_for_stop = false;
    std::vector<std::string> queued_packets;

    while (m_running.load() && m_client_socket >= 0)
    {
        // Check if execution stopped while we were waiting
        if (waiting_for_stop && m_state.load() == DebugState::Stopped)
        {
            send_packet( handle_stop_reason() );
            waiting_for_stop = false;

            // Process any queued packets that arrived while waiting
            for (const auto &queued : queued_packets)
            {
                // std::cout << "[GDB] Processing queued RX: " << queued << std::endl;
                std::string response = handle_packet( queued );
                if (!response.empty())
                {
                    // std::cout << "[GDB] TX: " << response << std::endl;
                    send_packet( response );
                }
            }
            queued_packets.clear();
        }

        std::string packet = receive_packet();
        if (packet.empty())
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
                continue;
            }
            break; // Client disconnected
        }

        // If we're waiting for execution to stop, queue non-interrupt packets
        if (waiting_for_stop)
        {
            // Allow interrupt command (Ctrl-C)
            if (packet.length() > 0 && packet[0] == 0x03)
            {
                m_state.store( DebugState::Stopped );
                m_stop_reason.store( StopReason::Interrupt );
                continue;
            }

            // Queue this packet to process after stop
            // std::cout << "[GDB] Queuing packet while waiting for stop" << std::endl;
            queued_packets.push_back( packet );
            continue;
        }

        std::string response = handle_packet( packet );
        if (!response.empty())
        {
            send_packet( response );
        }
        else
        {
            // Check if this was a continue/step command
            bool is_async_cmd = ( packet[0] == 'c' || packet[0] == 's' ||
                                  ( packet.find( "vCont;" ) == 0 && ( packet[6] == 'c' || packet[6] == 's' ) ) );

            if (is_async_cmd)
            {
                waiting_for_stop = true;
            }
        }
    }
}

std::string CGdbServer::receive_packet()
{
    std::string packet;
    char ch;

    // Wait for '$' start marker
    while (true)
    {
        ssize_t n = recv( m_client_socket, &ch, 1, 0 );
        if (n <= 0)
            return "";

        if (ch == '$')
            break;
        if (ch == 0x03) // Ctrl-C interrupt
        {
            m_state.store( DebugState::Stopped );
            m_stop_reason.store( StopReason::Interrupt );
            send_packet( "S02" ); // SIGINT
            return "";
        }
    }

    // Read packet data until '#'
    while (true)
    {
        ssize_t n = recv( m_client_socket, &ch, 1, 0 );
        if (n <= 0)
            return "";

        if (ch == '#')
            break;

        packet += ch;
    }

    // Read 2-character checksum
    char checksum[3] = { 0 };
    if (recv( m_client_socket, checksum, 2, 0 ) != 2)
        return "";

    // Verify checksum
    uint8_t expected = calculate_checksum( packet );
    uint8_t received = static_cast<uint8_t>( strtol( checksum, nullptr, 16 ) );

    if (expected == received)
    {
        send_ack();
        return packet;
    }
    else
    {
        send_nak();
        return "";
    }
}

void CGdbServer::send_packet( const std::string &data )
{
    std::ostringstream oss;
    oss << '$' << data << '#';

    uint8_t checksum = calculate_checksum( data );
    char checksum_str[3];
    snprintf( checksum_str, sizeof( checksum_str ), "%02x", checksum );
    oss << checksum_str;

    std::string packet = oss.str();
    send( m_client_socket, packet.c_str(), packet.length(), 0 );

    // Wait for ack
    char ack;
    recv( m_client_socket, &ack, 1, 0 );
}

void CGdbServer::send_ack()
{
    char ack = '+';
    send( m_client_socket, &ack, 1, 0 );
}

void CGdbServer::send_nak()
{
    char nak = '-';
    send( m_client_socket, &nak, 1, 0 );
}

std::string CGdbServer::handle_packet( const std::string &packet )
{
    if (packet.empty())
        return "";

    char cmd = packet[0];

    switch (cmd)
    {
    case '?': // Stop reason
        return handle_stop_reason();

    case 'g': // Read registers
        return handle_read_registers();

    case 'G': // Write registers
        return handle_write_registers( packet.substr( 1 ) );

    case 'p': // Read single register
    {
        if (packet.length() < 2)
            return "E01";
        uint32_t regnum = decode_hex_u32( packet.substr( 1 ) );

        if (regnum < 32) // r0-r31
        {
            uint32_t value = 0;
            uc_reg_read( m_uc, UC_PPC_REG_0 + regnum, &value );
            return encode_hex_u32( value );
        }
        if (regnum >= 32 && regnum <= 63) // f0-f31
        {
            uint64_t value = 0;
            uc_reg_read( m_uc, UC_PPC_REG_FPR0 + ( regnum - 32 ), &value );
            return encode_hex_u64( value );
        }
        if (regnum == 64) // PC
        {
            uint32_t value = 0;
            uc_reg_read( m_uc, UC_PPC_REG_PC, &value );
            return encode_hex_u32( value );
        }
        if (regnum == 65) // MSR
        {
            uint32_t value = 0;
            uc_reg_read( m_uc, UC_PPC_REG_MSR, &value );
            return encode_hex_u32( value );
        }
        if (regnum == 66) // CR
        {
            uint32_t value = 0;
            uc_reg_read( m_uc, UC_PPC_REG_CR, &value );
            return encode_hex_u32( value );
        }
        if (regnum == 67) // LR
        {
            uint32_t value = 0;
            uc_reg_read( m_uc, UC_PPC_REG_LR, &value );
            return encode_hex_u32( value );
        }
        if (regnum == 68) // CTR
        {
            uint32_t value = 0;
            uc_reg_read( m_uc, UC_PPC_REG_CTR, &value );
            return encode_hex_u32( value );
        }
        if (regnum == 69) // XER
        {
            uint32_t value = 0;
            uc_reg_read( m_uc, UC_PPC_REG_XER, &value );
            return encode_hex_u32( value );
        }
        if (regnum == 70) // FPSCR
        {
            uint32_t value = 0;
            uc_reg_read( m_uc, UC_PPC_REG_FPSCR, &value );
            return encode_hex_u32( value );
        }
        return "E01"; // Invalid register
    }

    case 'P': // Write single register
    {
        size_t eq = packet.find( '=' );
        if (eq == std::string::npos || packet.length() < 3)
            return "E01";

        uint32_t regnum = decode_hex_u32( packet.substr( 1, eq - 1 ) );
        std::string payload = packet.substr( eq + 1 );

        if (regnum < 32) // r0-r31
        {
            uint32_t value = decode_hex_u32( payload );
            uc_reg_write( m_uc, UC_PPC_REG_0 + regnum, &value );
            return "OK";
        }
        if (regnum >= 32 && regnum <= 63) // f0-f31
        {
            uint64_t value = decode_hex_u64( payload );
            uc_reg_write( m_uc, UC_PPC_REG_FPR0 + ( regnum - 32 ), &value );
            return "OK";
        }
        if (regnum == 64) // PC
        {
            uint32_t value = decode_hex_u32( payload );
            uc_reg_write( m_uc, UC_PPC_REG_PC, &value );
            return "OK";
        }
        if (regnum == 65) // MSR
        {
            uint32_t value = decode_hex_u32( payload );
            uc_reg_write( m_uc, UC_PPC_REG_MSR, &value );
            return "OK";
        }
        if (regnum == 66) // CR
        {
            uint32_t value = decode_hex_u32( payload );
            uc_reg_write( m_uc, UC_PPC_REG_CR, &value );
            return "OK";
        }
        if (regnum == 67) // LR
        {
            uint32_t value = decode_hex_u32( payload );
            uc_reg_write( m_uc, UC_PPC_REG_LR, &value );
            return "OK";
        }
        if (regnum == 68) // CTR
        {
            uint32_t value = decode_hex_u32( payload );
            uc_reg_write( m_uc, UC_PPC_REG_CTR, &value );
            return "OK";
        }
        if (regnum == 69) // XER
        {
            uint32_t value = decode_hex_u32( payload );
            uc_reg_write( m_uc, UC_PPC_REG_XER, &value );
            return "OK";
        }
        if (regnum == 70) // FPSCR
        {
            uint32_t value = decode_hex_u32( payload );
            uc_reg_write( m_uc, UC_PPC_REG_FPSCR, &value );
            return "OK";
        }
        return "E01"; // Invalid register
    }

    case 'm': // Read memory
    {
        size_t comma = packet.find( ',' );
        if (comma == std::string::npos)
            return "E01";
        uint32_t addr = decode_hex_u32( packet.substr( 1, comma - 1 ) );
        uint32_t len = decode_hex_u32( packet.substr( comma + 1 ) );
        return handle_read_memory( addr, len );
    }

    case 'M': // Write memory
    {
        size_t comma = packet.find( ',' );
        size_t colon = packet.find( ':' );
        if (comma == std::string::npos || colon == std::string::npos)
            return "E01";
        uint32_t addr = decode_hex_u32( packet.substr( 1, comma - 1 ) );
        return handle_write_memory( addr, packet.substr( colon + 1 ) );
    }

    case 'c': // Continue
        return handle_continue( packet.length() > 1 ? packet.substr( 1 ) : "" );

    case 's': // Step
        return handle_step( packet.length() > 1 ? packet.substr( 1 ) : "" );

    case 'Z': // Insert breakpoint
    {
        if (packet.length() < 3 || packet[1] != '0')
            return ""; // Only support software breakpoints
        size_t comma = packet.find( ',' );
        if (comma == std::string::npos)
            return "E01";
        uint32_t addr = decode_hex_u32( packet.substr( 3, comma - 3 ) );
        return handle_insert_breakpoint( addr );
    }

    case 'z': // Remove breakpoint
    {
        if (packet.length() < 3 || packet[1] != '0')
            return ""; // Only support software breakpoints
        size_t comma = packet.find( ',' );
        if (comma == std::string::npos)
            return "E01";
        uint32_t addr = decode_hex_u32( packet.substr( 3, comma - 3 ) );
        return handle_remove_breakpoint( addr );
    }

    case 'q': // Query
        return handle_query( packet.substr( 1 ) );

    case 'v': // vCont and other v packets
    {
        if (packet.find( "vCont?" ) == 0)
        {
            // Report supported vCont actions
            return "vCont;c;s;t"; // continue, step, stop
        }
        else if (packet.find( "vCont;" ) == 0)
        {
            // Parse vCont command
            std::string action = packet.substr( 6 ); // Skip "vCont;"

            if (action[0] == 'c') // Continue
            {
                return handle_continue( "" );
            }
            else if (action[0] == 's') // Step
            {
                return handle_step( "" );
            }
            else if (action[0] == 't') // Stop
            {
                m_state.store( DebugState::Stopped );
                m_stop_reason.store( StopReason::Interrupt );
                return "S02"; // SIGINT
            }
        }
        return ""; // Not supported
    }

    case 'H': // Set thread (ignore, we're single-threaded)
        return "OK";

    case 'k': // Kill
        m_state.store( DebugState::Detached );
        return "";

    case 'D': // Detach
        m_state.store( DebugState::Detached );
        return "OK";

    default:
        return ""; // Empty response = not supported
    }
}

std::string CGdbServer::handle_query( const std::string &query )
{
    if (query.find( "Supported" ) == 0)
    {
        return "PacketSize=4000;qXfer:features:read+;qXfer:threads:read+;QStartNoAckMode+;swbreak+;hwbreak+";
    }
    else if (query.find( "Attached" ) == 0)
    {
        return "1"; // Attached to existing process
    }
    else if (query.find( "C" ) == 0)
    {
        return "QC1"; // Current thread ID = 1
    }
    else if (query.find( "fThreadInfo" ) == 0)
    {
        return "m1"; // Thread list: only thread 1
    }
    else if (query.find( "sThreadInfo" ) == 0)
    {
        return "l"; // End of thread list
    }
    else if (query.find( "Offsets" ) == 0)
    {
        return "Text=0;Data=0;Bss=0"; // No relocation
    }
    else if (query.find( "Symbol" ) == 0)
    {
        return ""; // No symbol lookup support
    }
    else if (query.find( "Rcmd," ) == 0)
    {
        return ""; // No monitor commands
    }
    else if (query.find( "ThreadExtraInfo," ) == 0)
    {
        // Return thread description (IDA uses this)
        return encode_hex( reinterpret_cast<const uint8_t *>( "Emulated PPC32" ), 14 );
    }
    else if (query.find( "TStatus" ) == 0)
    {
        // Trace status - not running a trace experiment
        return "T0;tnotrun:0";
    }
    else if (query.find( "L" ) == 0 && query.length() == 1)
    {
        // Thread list - deprecated, use qfThreadInfo instead
        return ""; // Not supported
    }
    else if (query.find( "RegisterInfo" ) == 0)
    {
        // Per-register information (used by LLDB/IDA)
        // Extract register number from query like "qRegisterInfo0"
        std::string num_str = query.substr( 12 ); // Skip "RegisterInfo"
        if (num_str.empty())
            return "";

        uint32_t regnum = decode_hex_u32( num_str );

        if (regnum == 1) // r1 (SP)
            return "name:r1;bitsize:32;offset:4;encoding:uint;format:hex;set:General Purpose Registers;gcc:1;dwarf:1;generic:sp;";
        else if (regnum == 67) // LR
            return "name:lr;bitsize:32;offset:268;encoding:uint;format:hex;set:Special Purpose Registers;gcc:67;dwarf:67;generic:ra;";
        else if (regnum == 64) // PC
            return "name:pc;bitsize:32;offset:256;encoding:uint;format:hex;set:Special Purpose Registers;gcc:64;dwarf:64;generic:pc;alt-name:srr0;";
        else if (regnum < 32) // r0-r31
        {
            std::ostringstream oss;
            oss << "name:r" << regnum << ";bitsize:32;offset:" << (regnum * 4)
                << ";encoding:uint;format:hex;set:General Purpose Registers;gcc:" << regnum << ";dwarf:" << regnum
                << ";";
            return oss.str();
        }

        return ""; // Register not found
    }
    else if (query.find( "Xfer:threads:read" ) == 0)
    {
        // IDA Pro uses this to enumerate threads with full info
        std::string threads_xml = "<?xml version=\"1.0\"?>"
                                   "<threads>"
                                   "<thread id=\"1\" core=\"0\" name=\"main\"/>"
                                   "</threads>";

        size_t offset = 0;
        size_t length = threads_xml.size();
        size_t colon = query.rfind( ':' );
        if (colon != std::string::npos)
        {
            std::string range = query.substr( colon + 1 );
            size_t comma = range.find( ',' );
            if (comma != std::string::npos)
            {
                offset = decode_hex_u32( range.substr( 0, comma ) );
                length = decode_hex_u32( range.substr( comma + 1 ) );
            }
        }

        if (offset >= threads_xml.size())
            return "l";

        size_t remaining = threads_xml.size() - offset;
        size_t chunk = std::min( remaining, length );
        char prefix = ( chunk == remaining ) ? 'l' : 'm';
        return std::string( 1, prefix ) + threads_xml.substr( offset, chunk );
    }
    else if (query.find( "Xfer:features:read:target.xml" ) == 0)
    {
        // PowerPC target description with standard register layout.
        std::string xml = "<?xml version=\"1.0\"?>"
                          "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
                          "<target version=\"1.0\">"
                          "<architecture>powerpc:common</architecture>"
                          "<osabi>none</osabi>"
                          "<feature name=\"org.gnu.gdb.power.core\">"
                          "<reg name=\"r0\" bitsize=\"32\" type=\"uint32\" regnum=\"0\"/>"
                          "<reg name=\"r1\" bitsize=\"32\" type=\"data_ptr\" regnum=\"1\" generic=\"sp\"/>"
                          "<reg name=\"r2\" bitsize=\"32\" type=\"uint32\" regnum=\"2\"/>"
                          "<reg name=\"r3\" bitsize=\"32\" type=\"uint32\" regnum=\"3\"/>"
                          "<reg name=\"r4\" bitsize=\"32\" type=\"uint32\" regnum=\"4\"/>"
                          "<reg name=\"r5\" bitsize=\"32\" type=\"uint32\" regnum=\"5\"/>"
                          "<reg name=\"r6\" bitsize=\"32\" type=\"uint32\" regnum=\"6\"/>"
                          "<reg name=\"r7\" bitsize=\"32\" type=\"uint32\" regnum=\"7\"/>"
                          "<reg name=\"r8\" bitsize=\"32\" type=\"uint32\" regnum=\"8\"/>"
                          "<reg name=\"r9\" bitsize=\"32\" type=\"uint32\" regnum=\"9\"/>"
                          "<reg name=\"r10\" bitsize=\"32\" type=\"uint32\" regnum=\"10\"/>"
                          "<reg name=\"r11\" bitsize=\"32\" type=\"uint32\" regnum=\"11\"/>"
                          "<reg name=\"r12\" bitsize=\"32\" type=\"uint32\" regnum=\"12\"/>"
                          "<reg name=\"r13\" bitsize=\"32\" type=\"uint32\" regnum=\"13\"/>"
                          "<reg name=\"r14\" bitsize=\"32\" type=\"uint32\" regnum=\"14\"/>"
                          "<reg name=\"r15\" bitsize=\"32\" type=\"uint32\" regnum=\"15\"/>"
                          "<reg name=\"r16\" bitsize=\"32\" type=\"uint32\" regnum=\"16\"/>"
                          "<reg name=\"r17\" bitsize=\"32\" type=\"uint32\" regnum=\"17\"/>"
                          "<reg name=\"r18\" bitsize=\"32\" type=\"uint32\" regnum=\"18\"/>"
                          "<reg name=\"r19\" bitsize=\"32\" type=\"uint32\" regnum=\"19\"/>"
                          "<reg name=\"r20\" bitsize=\"32\" type=\"uint32\" regnum=\"20\"/>"
                          "<reg name=\"r21\" bitsize=\"32\" type=\"uint32\" regnum=\"21\"/>"
                          "<reg name=\"r22\" bitsize=\"32\" type=\"uint32\" regnum=\"22\"/>"
                          "<reg name=\"r23\" bitsize=\"32\" type=\"uint32\" regnum=\"23\"/>"
                          "<reg name=\"r24\" bitsize=\"32\" type=\"uint32\" regnum=\"24\"/>"
                          "<reg name=\"r25\" bitsize=\"32\" type=\"uint32\" regnum=\"25\"/>"
                          "<reg name=\"r26\" bitsize=\"32\" type=\"uint32\" regnum=\"26\"/>"
                          "<reg name=\"r27\" bitsize=\"32\" type=\"uint32\" regnum=\"27\"/>"
                          "<reg name=\"r28\" bitsize=\"32\" type=\"uint32\" regnum=\"28\"/>"
                          "<reg name=\"r29\" bitsize=\"32\" type=\"uint32\" regnum=\"29\"/>"
                          "<reg name=\"r30\" bitsize=\"32\" type=\"uint32\" regnum=\"30\"/>"
                          "<reg name=\"r31\" bitsize=\"32\" type=\"uint32\" regnum=\"31\"/>"
                          "<reg name=\"pc\" bitsize=\"32\" type=\"code_ptr\" regnum=\"64\" generic=\"pc\"/>"
                          "<reg name=\"msr\" bitsize=\"32\" type=\"uint32\" regnum=\"65\"/>"
                          "<reg name=\"cr\" bitsize=\"32\" type=\"uint32\" regnum=\"66\"/>"
                          "<reg name=\"lr\" bitsize=\"32\" type=\"code_ptr\" regnum=\"67\" generic=\"ra\"/>"
                          "<reg name=\"ctr\" bitsize=\"32\" type=\"uint32\" regnum=\"68\"/>"
                          "<reg name=\"xer\" bitsize=\"32\" type=\"uint32\" regnum=\"69\"/>"
                          "<reg name=\"fpscr\" bitsize=\"32\" type=\"uint32\" regnum=\"70\"/>"
                          "<reg name=\"f0\" bitsize=\"64\" type=\"ieee_double\" regnum=\"32\"/>"
                          "<reg name=\"f1\" bitsize=\"64\" type=\"ieee_double\" regnum=\"33\"/>"
                          "<reg name=\"f2\" bitsize=\"64\" type=\"ieee_double\" regnum=\"34\"/>"
                          "<reg name=\"f3\" bitsize=\"64\" type=\"ieee_double\" regnum=\"35\"/>"
                          "<reg name=\"f4\" bitsize=\"64\" type=\"ieee_double\" regnum=\"36\"/>"
                          "<reg name=\"f5\" bitsize=\"64\" type=\"ieee_double\" regnum=\"37\"/>"
                          "<reg name=\"f6\" bitsize=\"64\" type=\"ieee_double\" regnum=\"38\"/>"
                          "<reg name=\"f7\" bitsize=\"64\" type=\"ieee_double\" regnum=\"39\"/>"
                          "<reg name=\"f8\" bitsize=\"64\" type=\"ieee_double\" regnum=\"40\"/>"
                          "<reg name=\"f9\" bitsize=\"64\" type=\"ieee_double\" regnum=\"41\"/>"
                          "<reg name=\"f10\" bitsize=\"64\" type=\"ieee_double\" regnum=\"42\"/>"
                          "<reg name=\"f11\" bitsize=\"64\" type=\"ieee_double\" regnum=\"43\"/>"
                          "<reg name=\"f12\" bitsize=\"64\" type=\"ieee_double\" regnum=\"44\"/>"
                          "<reg name=\"f13\" bitsize=\"64\" type=\"ieee_double\" regnum=\"45\"/>"
                          "<reg name=\"f14\" bitsize=\"64\" type=\"ieee_double\" regnum=\"46\"/>"
                          "<reg name=\"f15\" bitsize=\"64\" type=\"ieee_double\" regnum=\"47\"/>"
                          "<reg name=\"f16\" bitsize=\"64\" type=\"ieee_double\" regnum=\"48\"/>"
                          "<reg name=\"f17\" bitsize=\"64\" type=\"ieee_double\" regnum=\"49\"/>"
                          "<reg name=\"f18\" bitsize=\"64\" type=\"ieee_double\" regnum=\"50\"/>"
                          "<reg name=\"f19\" bitsize=\"64\" type=\"ieee_double\" regnum=\"51\"/>"
                          "<reg name=\"f20\" bitsize=\"64\" type=\"ieee_double\" regnum=\"52\"/>"
                          "<reg name=\"f21\" bitsize=\"64\" type=\"ieee_double\" regnum=\"53\"/>"
                          "<reg name=\"f22\" bitsize=\"64\" type=\"ieee_double\" regnum=\"54\"/>"
                          "<reg name=\"f23\" bitsize=\"64\" type=\"ieee_double\" regnum=\"55\"/>"
                          "<reg name=\"f24\" bitsize=\"64\" type=\"ieee_double\" regnum=\"56\"/>"
                          "<reg name=\"f25\" bitsize=\"64\" type=\"ieee_double\" regnum=\"57\"/>"
                          "<reg name=\"f26\" bitsize=\"64\" type=\"ieee_double\" regnum=\"58\"/>"
                          "<reg name=\"f27\" bitsize=\"64\" type=\"ieee_double\" regnum=\"59\"/>"
                          "<reg name=\"f28\" bitsize=\"64\" type=\"ieee_double\" regnum=\"60\"/>"
                          "<reg name=\"f29\" bitsize=\"64\" type=\"ieee_double\" regnum=\"61\"/>"
                          "<reg name=\"f30\" bitsize=\"64\" type=\"ieee_double\" regnum=\"62\"/>"
                          "<reg name=\"f31\" bitsize=\"64\" type=\"ieee_double\" regnum=\"63\"/>"
                          "</feature>"
                          "</target>";
        size_t offset = 0;
        size_t length = xml.size();
        size_t colon = query.rfind( ':' );
        if (colon != std::string::npos)
        {
            std::string range = query.substr( colon + 1 );
            size_t comma = range.find( ',' );
            if (comma != std::string::npos)
            {
                offset = decode_hex_u32( range.substr( 0, comma ) );
                length = decode_hex_u32( range.substr( comma + 1 ) );
            }
        }

        if (offset >= xml.size())
            return "l";

        size_t remaining = xml.size() - offset;
        size_t chunk = std::min( remaining, length );
        char prefix = ( chunk == remaining ) ? 'l' : 'm';
        return std::string( 1, prefix ) + xml.substr( offset, chunk );
    }

    return ""; // Not supported
}

std::string CGdbServer::handle_read_registers()
{
    std::ostringstream oss;

    // Read GPRs (r0-r31) - 32 registers x 4 bytes
    for (int i = 0; i < 32; i++)
    {
        uint32_t reg;
        if (uc_reg_read( m_uc, UC_PPC_REG_0 + i, &reg ) == UC_ERR_OK)
        {
            oss << encode_hex_u32( reg );
        }
        else
        {
            oss << "00000000";
        }
    }

    // Read FPRs (f0-f31) - 32 registers x 8 bytes
    for (int i = 0; i < 32; i++)
    {
        uint64_t reg = 0;
        if (uc_reg_read( m_uc, UC_PPC_REG_FPR0 + i, &reg ) == UC_ERR_OK)
        {
            oss << encode_hex_u64( reg );
        }
        else
        {
            oss << "0000000000000000";
        }
    }

    // Read special registers
    uint32_t pc, msr, cr, lr, ctr, xer, fpscr;
    uc_reg_read( m_uc, UC_PPC_REG_PC, &pc );
    uc_reg_read( m_uc, UC_PPC_REG_MSR, &msr );
    uc_reg_read( m_uc, UC_PPC_REG_CR, &cr );
    uc_reg_read( m_uc, UC_PPC_REG_LR, &lr );
    uc_reg_read( m_uc, UC_PPC_REG_CTR, &ctr );
    uc_reg_read( m_uc, UC_PPC_REG_XER, &xer );
    uc_reg_read( m_uc, UC_PPC_REG_FPSCR, &fpscr );

    oss << encode_hex_u32( pc );    // PC
    oss << encode_hex_u32( msr );   // MSR
    oss << encode_hex_u32( cr );    // CR
    oss << encode_hex_u32( lr );    // LR
    oss << encode_hex_u32( ctr );   // CTR
    oss << encode_hex_u32( xer );   // XER
    oss << encode_hex_u32( fpscr ); // FPSCR

    return oss.str();
}

std::string CGdbServer::handle_write_registers( const std::string &data )
{
    // Parse register data (hex string, GPRs 4 bytes, FPRs 8 bytes)
    size_t offset = 0;

    // Write GPRs (r0-r31)
    for (int i = 0; i < 32 && offset + 8 <= data.length(); i++)
    {
        uint32_t reg = decode_hex_u32( data.substr( offset, 8 ) );
        uc_reg_write( m_uc, UC_PPC_REG_0 + i, &reg );
        offset += 8;
    }

    // Write FPRs (f0-f31)
    for (int i = 0; i < 32 && offset + 16 <= data.length(); i++)
    {
        uint64_t reg = decode_hex_u64( data.substr( offset, 16 ) );
        uc_reg_write( m_uc, UC_PPC_REG_FPR0 + i, &reg );
        offset += 16;
    }

    // Write special registers
    if (offset + 8 <= data.length())
    {
        uint32_t pc = decode_hex_u32( data.substr( offset, 8 ) );
        uc_reg_write( m_uc, UC_PPC_REG_PC, &pc );
        offset += 8;
    }

    if (offset + 8 <= data.length())
    {
        uint32_t msr = decode_hex_u32( data.substr( offset, 8 ) );
        uc_reg_write( m_uc, UC_PPC_REG_MSR, &msr );
        offset += 8;
    }

    if (offset + 8 <= data.length())
    {
        uint32_t cr = decode_hex_u32( data.substr( offset, 8 ) );
        uc_reg_write( m_uc, UC_PPC_REG_CR, &cr );
        offset += 8;
    }

    if (offset + 8 <= data.length())
    {
        uint32_t lr = decode_hex_u32( data.substr( offset, 8 ) );
        uc_reg_write( m_uc, UC_PPC_REG_LR, &lr );
        offset += 8;
    }

    if (offset + 8 <= data.length())
    {
        uint32_t ctr = decode_hex_u32( data.substr( offset, 8 ) );
        uc_reg_write( m_uc, UC_PPC_REG_CTR, &ctr );
        offset += 8;
    }

    if (offset + 8 <= data.length())
    {
        uint32_t xer = decode_hex_u32( data.substr( offset, 8 ) );
        uc_reg_write( m_uc, UC_PPC_REG_XER, &xer );
        offset += 8;
    }

    if (offset + 8 <= data.length())
    {
        uint32_t fpscr = decode_hex_u32( data.substr( offset, 8 ) );
        uc_reg_write( m_uc, UC_PPC_REG_FPSCR, &fpscr );
        offset += 8;
    }

    return "OK";
}

std::string CGdbServer::handle_read_memory( uint32_t address, uint32_t length )
{
    std::vector<uint8_t> buffer( length );

    if (uc_mem_read( m_uc, address, buffer.data(), length ) != UC_ERR_OK)
    {
        return "E01"; // Error
    }

    return encode_hex( buffer.data(), length );
}

std::string CGdbServer::handle_write_memory( uint32_t address, const std::string &data )
{
    std::vector<uint8_t> buffer = decode_hex( data );

    if (uc_mem_write( m_uc, address, buffer.data(), buffer.size() ) != UC_ERR_OK)
    {
        return "E01"; // Error
    }

    return "OK";
}

std::string CGdbServer::handle_continue( const std::string &addr_str )
{
    if (!addr_str.empty())
    {
        uint32_t addr = decode_hex_u32( addr_str );
        uc_reg_write( m_uc, UC_PPC_REG_PC, &addr );
    }

    // Tell debugger to continue
    if (m_debugger)
    {
        m_debugger->continue_execution();
    }

    continue_execution();
    return ""; // No immediate response, will send stop reply later when breakpoint is hit
}

std::string CGdbServer::handle_step( const std::string &addr_str )
{
    if (!addr_str.empty())
    {
        uint32_t addr = decode_hex_u32( addr_str );
        uc_reg_write( m_uc, UC_PPC_REG_PC, &addr );
    }

    // Tell debugger to step once
    if (m_debugger)
    {
        m_debugger->step_in();
    }

    single_step();
    return ""; // No immediate response, will send stop reply after step completes
}

std::string CGdbServer::handle_insert_breakpoint( uint32_t address )
{
    if (m_debugger)
    {
        m_debugger->add_breakpoint( address );
        return "OK";
    }
    return "E01";
}

std::string CGdbServer::handle_remove_breakpoint( uint32_t address )
{
    if (m_debugger)
    {
        m_debugger->remove_breakpoint( address );
        return "OK";
    }
    return "E01";
}

std::string CGdbServer::handle_stop_reason()
{
    // Return signal/stop reason
    StopReason reason = m_stop_reason.load();
    uint32_t addr = m_stop_address.load();

    std::ostringstream oss;
    switch (reason)
    {
    case StopReason::Breakpoint:
        oss << "T05"; // SIGTRAP
        break;
    case StopReason::SingleStep:
        oss << "T05"; // SIGTRAP
        break;
    case StopReason::Interrupt:
        oss << "T02"; // SIGINT
        break;
    case StopReason::Trap:
    default:
        oss << "T05"; // SIGTRAP
        break;
    }

    // Add register values needed for call stack unwinding
    // r1 (sp - regnum 1) and lr (regnum 67) are critical for IDA Pro
    uint32_t sp = 0, lr = 0, pc = 0;
    uc_reg_read( m_uc, UC_PPC_REG_1, &sp );  // r1 (stack pointer)
    uc_reg_read( m_uc, UC_PPC_REG_LR, &lr ); // link register
    uc_reg_read( m_uc, UC_PPC_REG_PC, &pc ); // program counter

    // Format: regnum:value; (regnum in hex, values in target byte order - big endian for PPC)
    oss << "1:" << encode_hex_u32( sp ) << ";";   // r1 (sp)
    oss << "40:" << encode_hex_u32( pc ) << ";";  // pc (regnum 64 = 0x40)
    oss << "43:" << encode_hex_u32( lr ) << ";";  // lr (regnum 67 = 0x43)
    oss << "thread:1;";

    return oss.str();
}

uint8_t CGdbServer::calculate_checksum( const std::string &data )
{
    uint8_t sum = 0;
    for (char c : data)
    {
        sum += static_cast<uint8_t>( c );
    }
    return sum;
}

std::string CGdbServer::encode_hex( const uint8_t *data, size_t length )
{
    std::ostringstream oss;
    for (size_t i = 0; i < length; i++)
    {
        char buf[3];
        snprintf( buf, sizeof( buf ), "%02x", data[i] );
        oss << buf;
    }
    return oss.str();
}

std::string CGdbServer::encode_hex_u32( uint32_t value )
{
    // Encode as target-endian hex string.
    uint8_t bytes[4];
    bytes[0] = ( value >> 24 ) & 0xFF; // MSB first (big-endian)
    bytes[1] = ( value >> 16 ) & 0xFF;
    bytes[2] = ( value >> 8 ) & 0xFF;
    bytes[3] = value & 0xFF; // LSB last
    return encode_hex( bytes, 4 );
}

std::string CGdbServer::encode_hex_u64( uint64_t value )
{
    uint8_t bytes[8];
    bytes[0] = ( value >> 56 ) & 0xFF;
    bytes[1] = ( value >> 48 ) & 0xFF;
    bytes[2] = ( value >> 40 ) & 0xFF;
    bytes[3] = ( value >> 32 ) & 0xFF;
    bytes[4] = ( value >> 24 ) & 0xFF;
    bytes[5] = ( value >> 16 ) & 0xFF;
    bytes[6] = ( value >> 8 ) & 0xFF;
    bytes[7] = value & 0xFF;
    return encode_hex( bytes, 8 );
}

std::vector<uint8_t> CGdbServer::decode_hex( const std::string &hex )
{
    std::vector<uint8_t> data;
    for (size_t i = 0; i + 1 < hex.length(); i += 2)
    {
        std::string byte_str = hex.substr( i, 2 );
        uint8_t byte = static_cast<uint8_t>( strtol( byte_str.c_str(), nullptr, 16 ) );
        data.push_back( byte );
    }
    return data;
}

uint32_t CGdbServer::decode_hex_u32( const std::string &hex )
{
    return static_cast<uint32_t>( strtoul( hex.c_str(), nullptr, 16 ) );
}

uint64_t CGdbServer::decode_hex_u64( const std::string &hex )
{
    return static_cast<uint64_t>( strtoull( hex.c_str(), nullptr, 16 ) );
}

} // namespace gdb

#endif // DEBUG
