/**
 * Author:    domin568
 * Created:   06.10.2025
 * Brief:     memory manager for emu
 **/
#include "../include/CMemory.hpp"
#include <cstddef>
#include <expected>
#include <iostream>
#include <ostream>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace memory
{
std::expected<CMemory, Error> CMemory::init( size_t size )
{
#ifdef _WIN32
    void *ptr = VirtualAlloc( nullptr, size, MEM_RESERVE, PAGE_NOACCESS );
    if (!ptr)
        return std::unexpected{
            Error{ Error::Type::Map_Error, "Could not reserve virtual memory for 32 bit guest process (WIN32)" } };
#else
    void *ptr{ mmap( nullptr, size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0 ) };
    if (ptr == MAP_FAILED)
        return std::unexpected{
            Error{ Error::Type::Map_Error, "Could not reserve virtual memory for 32 bit guest process (POSIX)" } };
#endif
    return CMemory{ ptr, size };
}

CMemory::CMemory( void *memPtr, size_t size ) : m_memPtr{ memPtr }, m_memSize{ size }
{
}
CMemory::~CMemory()
{
#ifdef _WIN32
    if (!m_memPtr)
        return;
    if (!VirtualFree( m_memPtr, 0, MEM_RELEASE )
        std::cerr << "Could not release emu memory (WIN32)" << std::endl;
#else
    if (!m_memPtr)
        return;
    int ret{ munmap( m_memPtr, m_memSize ) };
    if (ret != 0)
        std::cerr << "Could not unmap emu memory (POSIX)" << std::endl;
#endif
}

bool CMemory::commit( uintptr_t guestAddress, size_t size )
{
    if (( guestAddress & 0xfff ) != 0 || ( size & 0xfff ) != 0)
        return false;

#ifdef _WIN32
    auto base = reinterpret_cast<unsigned char *>( m_memPtr ) + static_cast<size_t>( guestAddress );
    void *res = VirtualAlloc( base, size, MEM_COMMIT, PAGE_READWRITE );
    return res != nullptr;
#else
    uintptr_t hostAddress{ m_address + guestAddress };
    int ret{ mprotect( reinterpret_cast<void *>( hostAddress ), size, PROT_READ | PROT_WRITE ) };
    return ret == 0;
#endif
}

} // namespace memory