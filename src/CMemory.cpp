/**
 * Author:    domin568
 * Created:   06.10.2025
 * Brief:     memory manager for emu
 **/
#include "../include/CMemory.hpp"
#include "../include/Common.hpp"
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
std::expected<CMemory, Error> CMemory::init( uc_engine *uc, size_t size )
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
    return { std::move( CMemory{ uc, ptr, size, pageSize } ) };
}

CMemory::CMemory( uc_engine *uc, void *memPtr, size_t size, std::size_t pageSize )
    : m_uc{ uc }, m_memPtr{ memPtr }, m_memSize{ size }, m_pageSize{ pageSize }
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
            page_size = common::Default_Page_Size;
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

CMemory::CMemory( CMemory &&o ) noexcept : m_uc{ o.m_uc }, m_memPtr( o.m_memPtr ), m_memSize( o.m_memSize )
{
    o.m_memPtr = nullptr;
    o.m_memSize = 0;
    o.m_uc = nullptr;
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
        m_uc = o.m_uc;
        o.m_memPtr = nullptr;
        o.m_memSize = 0;
        o.m_uc = nullptr;
    }
    return *this;
}

bool CMemory::commit( uintptr_t guestAddress, size_t size, int prot )
{
    if (( guestAddress & 0xfff ) != 0 || ( size & 0xfff ) != 0) // check for unicorn memory manager
        return false;

    std::size_t pageSize{ get_system_page_size() };
    if (pageSize == 0)
        return false;

    uintptr_t hostPtrVal{ m_address + guestAddress };
    uintptr_t hostPtrValAlignedDown{ hostPtrVal & ~( pageSize - 1 ) };
    uintptr_t hostPtrDiff{ hostPtrVal - hostPtrValAlignedDown };
    size_t alignedUpSize{ ( size + hostPtrDiff + pageSize - 1 ) & ~( pageSize - 1 ) };

#ifdef _WIN32
    auto base{ reinterpret_cast<unsigned char *>( m_memPtr ) + static_cast<size_t>( guestAddress ) };
    void *res{ VirtualAlloc( reinterpret_cast<void *>( hostPtrValAlignedDown ), alignedUpSize, MEM_COMMIT,
                             PAGE_READWRITE ) }; // TODO prot
    if (res == nullptr)
        return false;
#else // UNIX
    if (mprotect( reinterpret_cast<void *>( hostPtrValAlignedDown ), alignedUpSize, PROT_READ | PROT_WRITE ) != 0)
    {
        std::cout << errno << std::endl;
        return false;
    }
#endif
    if (!check( guestAddress, size ))
        return false;

    if (uc_mem_map_ptr( m_uc, guestAddress, size, prot, reinterpret_cast<void *>( hostPtrVal ) ) != UC_ERR_OK)
        return false;

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
    assert( reinterpret_cast<std::size_t>( ptr ) >= m_address );
    return reinterpret_cast<size_t>( ptr ) - m_address;
}

uint64_t CMemory::to_host( uint32_t ptr )
{
    return ptr + m_address;
}
// ultra simple, just to move emulation further
void CMemory::initialize_heap()
{
    commit( common::Heap_Start, common::Heap_Size, 3 );
}

uint32_t CMemory::heap_alloc( std::size_t size )
{
    static std::size_t ptr{ common::Heap_Start };
    const uint32_t tmp{ static_cast<uint32_t>( ptr ) };
    // Round up to 16-byte alignment for PowerPC (required for proper alignment of all data types)
    std::size_t alignedSize{ ( size + 15 ) & ~15 };
    ptr += alignedSize;

    // Track allocation size
    m_allocSizes[tmp] = size;

    return tmp;
}

std::size_t CMemory::get_alloc_size( uint32_t ptr )
{
    auto it{ m_allocSizes.find( ptr ) };
    if (it != m_allocSizes.end())
        return it->second;
    return 0;
}

} // namespace memory