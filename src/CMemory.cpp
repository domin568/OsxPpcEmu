/**
 * Author:    domin568
 * Created:   06.10.2025
 * Brief:     memory manager for emu
 **/
#include "../include/CMemory.hpp"
#include <cstddef>
#include <cstring>
#include <expected>
#include <iostream>
#include <mutex>
#include <ostream>
#include <unicorn/unicorn.h>
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
    std::size_t pageSize{ get_system_page_size() };
    return { std::move( CMemory{ ptr, size, pageSize } ) };
}

CMemory::CMemory( void *memPtr, size_t size, std::size_t pageSize )
    : m_memPtr{ memPtr }, m_memSize{ size }, m_pageSize{ pageSize }
{
}

std::size_t CMemory::get_system_page_size()
{
    static std::size_t page_size{ 0 };
    static std::once_flag once;
    std::call_once( once, [] {
#ifdef _WIN32
        SYSTEM_INFO si;
        GetSystemInfo( &si );
        page_size = static_cast<std::size_t>( si.dwPageSize );
#else
        long p{ sysconf(_SC_PAGESIZE) };
        if (p <= 0)
            page_size = Default_Page_Size;
        else
            page_size = static_cast<std::size_t>(p);
#endif
    } );
    return page_size;
}

CMemory::~CMemory()
{
#ifdef _WIN32
    if (!m_memPtr)
        return;
    if (!VirtualFree( m_memPtr, 0, MEM_RELEASE ))
        std::cerr << "Could not release emu memory (WIN32)" << std::endl;
#else
    if (!m_memPtr)
        return;
    int ret{ munmap( m_memPtr, m_memSize ) };
    if (ret != 0)
        std::cerr << "Could not unmap emu memory (POSIX)" << std::endl;
#endif
}

CMemory::CMemory( CMemory &&o ) noexcept : m_memPtr( o.m_memPtr ), m_memSize( o.m_memSize )
{
    o.m_memPtr = nullptr;
    o.m_memSize = 0;
}

CMemory &CMemory::operator=( CMemory &&o ) noexcept
{
    if (this != &o)
    {
        // free current resource if any
        if (m_memPtr)
        {
#ifndef _WIN32
            munmap( m_memPtr, m_memSize );
#else
            VirtualFree( m_memPtr, 0, MEM_RELEASE );
#endif
        }
        m_memPtr = o.m_memPtr;
        m_memSize = o.m_memSize;
        o.m_memPtr = nullptr;
        o.m_memSize = 0;
    }
    return *this;
}

bool CMemory::commit( uc_engine *uc, uintptr_t guestAddress, size_t size, int prot )
{
    if (( guestAddress & 0xfff ) != 0 || ( size & 0xfff ) != 0) // check for unicorn memory manager
        return false;

#ifdef _WIN32
    // TODO
    auto base = reinterpret_cast<unsigned char *>( m_memPtr ) + static_cast<size_t>( guestAddress );
    void *res = VirtualAlloc( base, size, MEM_COMMIT, PAGE_READWRITE );
    return res != nullptr;
#else
    size_t pageSize = sysconf( _SC_PAGE_SIZE );
    if (pageSize == -1)
        return false;

    uintptr_t hostPtrVal{ m_address + guestAddress };
    uintptr_t hostPtrValAlignedDown{ hostPtrVal & ~( pageSize - 1 ) };
    uintptr_t hostPtrDiff{ hostPtrVal - hostPtrValAlignedDown };
    size_t alignedUpSize{ ( size + hostPtrDiff + pageSize - 1 ) & ~( pageSize - 1 ) };
    if (mprotect( reinterpret_cast<void *>( hostPtrValAlignedDown ), alignedUpSize, PROT_READ | PROT_WRITE ) != 0)
    {
        std::cout << errno << std::endl;
        return false;
    }

    if (!check( guestAddress, size ))
        return false;

    if (uc_mem_map_ptr( uc, guestAddress, size, prot, reinterpret_cast<void *>( hostPtrVal ) ) != UC_ERR_OK)
        return false;
#endif
    // TODO add memory range
    return true;
}

bool CMemory::check( size_t offset, size_t size )
{
    // TODO
    return true;
}

void CMemory::write( size_t guestAddress, const void *srcPtr, size_t byteCount )
{
    std::memcpy( reinterpret_cast<void *>( m_address + guestAddress ), srcPtr, byteCount );
}

void *CMemory::get( size_t offset )
{
    return reinterpret_cast<void *>( m_address + offset );
}

uint32_t CMemory::to_guest( void *ptr )
{
    return reinterpret_cast<size_t>( ptr ) - m_address;
}

} // namespace memory