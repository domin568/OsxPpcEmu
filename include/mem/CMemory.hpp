/**
 * Author:    domin568
 * Created:   06.10.2025
 * Brief:     memory manager for emu
 **/
#pragma once
#include "CHeap.hpp"
#include "Common.hpp"
#include "Expected.hpp"
#include <string>
#include <unicorn/unicorn.h>

namespace memory
{
struct Error
{
    enum Type
    {
        Map_Error,
    };
    Type type;
    std::string message{};
};

class CMemory
{
    using MemoryRange = std::pair<size_t, size_t>;

  public:
    static compat::expected<CMemory, Error> init( uc_engine *uc, size_t size );
    ~CMemory();
    CMemory( const CMemory & ) = delete;
    CMemory &operator=( const CMemory & ) = delete;
    CMemory( CMemory &&o ) noexcept;
    CMemory &operator=( CMemory &&o ) noexcept;

    bool commit( size_t guestAddress, size_t size, int prot );
    void write( size_t guestAddress, const void *srcPtr, size_t byteCount );
    bool check( size_t offset, size_t size );
    void *get( size_t offset );
    uint32_t to_guest( const void *ptr );
    uint64_t to_host( uint32_t ptr );

    [[nodiscard]] bool initialize_heap( common::HeapMode mode = common::Heap_Default_Mode );
    uint32_t heap_alloc( std::size_t size );
    uint32_t heap_realloc( uint32_t ptr, std::size_t size );
    bool heap_free( uint32_t ptr );
    bool heap_owns( uint32_t ptr ) const;
    std::size_t get_alloc_size( uint32_t ptr );
    const CHeap::Stats &heap_stats() const;
    [[nodiscard]] const CHeap &heap() const
    {
        return m_heap;
    }

  private:
    CMemory( uc_engine *uc, void *memPtr, size_t size, std::size_t pageSize );
    uc_engine *m_uc{ nullptr };
    union {
        void *m_memPtr{ nullptr };
        uintptr_t m_address;
    };
    std::size_t m_memSize{ 0 };
    CHeap m_heap{ this, static_cast<std::uint32_t>( common::Heap_Start ), common::Heap_Size };
    static std::size_t get_system_page_size();

    std::size_t m_pageSize{};
};
} // namespace memory
