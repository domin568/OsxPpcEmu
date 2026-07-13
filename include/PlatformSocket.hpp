/**
 * Author:    domin568
 * Brief:     Minimal cross-platform (POSIX / Winsock) TCP socket helpers used by CGdbServer.
 **/
#pragma once

#include <cstdint>
#include <string>

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment( lib, "ws2_32.lib" )
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace platform
{

#ifdef _WIN32
using socket_t = SOCKET;
inline constexpr socket_t Invalid_Socket{ INVALID_SOCKET };
#else
using socket_t = int;
inline constexpr socket_t Invalid_Socket{ -1 };
#endif

// Must be called once before any socket use, and matched by socket_cleanup() on shutdown.
// No-op on POSIX.
inline bool socket_stack_init()
{
#ifdef _WIN32
    WSADATA wsaData{};
    return WSAStartup( MAKEWORD( 2, 2 ), &wsaData ) == 0;
#else
    return true;
#endif
}

inline void socket_stack_cleanup()
{
#ifdef _WIN32
    WSACleanup();
#endif
}

inline void close_socket( socket_t s )
{
    if (s == Invalid_Socket)
        return;
#ifdef _WIN32
    ::closesocket( s );
#else
    ::close( s );
#endif
}

inline bool set_non_blocking( socket_t s, bool nonBlocking )
{
#ifdef _WIN32
    u_long mode{ nonBlocking ? 1u : 0u };
    return ::ioctlsocket( s, FIONBIO, &mode ) == 0;
#else
    int flags{ ::fcntl( s, F_GETFL, 0 ) };
    if (flags == -1)
        return false;
    flags = nonBlocking ? ( flags | O_NONBLOCK ) : ( flags & ~O_NONBLOCK );
    return ::fcntl( s, F_SETFL, flags ) == 0;
#endif
}

// timeoutMs == 0 disables the timeout (blocking recv).
inline bool set_recv_timeout( socket_t s, int timeoutMs )
{
#ifdef _WIN32
    DWORD timeout{ static_cast<DWORD>( timeoutMs ) };
    return ::setsockopt( s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>( &timeout ), sizeof( timeout ) ) ==
           0;
#else
    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = ( timeoutMs % 1000 ) * 1000;
    return ::setsockopt( s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>( &tv ), sizeof( tv ) ) == 0;
#endif
}

inline bool set_reuse_addr( socket_t s )
{
    int opt{ 1 };
    return ::setsockopt( s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>( &opt ), sizeof( opt ) ) == 0;
}

// True if the last recv()/send() failure was just "would block" (i.e. not a real error).
inline bool last_error_would_block()
{
#ifdef _WIN32
    const int err{ WSAGetLastError() };
    return err == WSAEWOULDBLOCK || err == WSAETIMEDOUT;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

// select()-based readability wait, used to poll the listening socket without blocking the server thread forever.
inline int wait_readable( socket_t s, int timeoutMs )
{
    fd_set readfds;
    FD_ZERO( &readfds );
    FD_SET( s, &readfds );

    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = ( timeoutMs % 1000 ) * 1000;

#ifdef _WIN32
    return ::select( 0, &readfds, nullptr, nullptr, &tv );
#else
    return ::select( s + 1, &readfds, nullptr, nullptr, &tv );
#endif
}

inline int send_bytes( socket_t s, const char *data, std::size_t len )
{
    return static_cast<int>( ::send( s, data, static_cast<int>( len ), 0 ) );
}

inline int recv_bytes( socket_t s, char *buf, std::size_t len )
{
    return static_cast<int>( ::recv( s, buf, static_cast<int>( len ), 0 ) );
}

} // namespace platform
