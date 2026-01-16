/**
 * Author:    domin568
 * Created:   06.10.2025
 * Brief:     memory manager for emu
 **/
#pragma once
#include <expected>
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
    static std::expected<CMemory, Error> init( uc_engine *uc, size_t size );
    ~CMemory();
    CMemory( const CMemory & ) = delete;
    CMemory &operator=( const CMemory & ) = delete;
    CMemory( CMemory &&o ) noexcept;
    CMemory &operator=( CMemory &&o ) noexcept;

    bool commit( size_t guestAddress, size_t size, int prot );
    void write( size_t guestAddress, const void *srcPtr, size_t byteCount );
    bool check( size_t offset, size_t size );
    void *get( size_t offset );
    uint32_t to_guest( void *ptr );
    uint64_t to_host( uint32_t ptr );

    void initialize_heap();
    uint32_t heap_alloc( std::size_t size );

  private:
    CMemory( uc_engine *uc, void *memPtr, size_t size, std::size_t pageSize );

    static constexpr std::size_t Default_Page_Size{ 0x1000 };
    static constexpr std::size_t Heap_Start{ 0x10'00'00'00 };
    static constexpr std::size_t Heap_Size{ 0x10'00'00'00 };

    uc_engine *m_uc{ nullptr };
    union {
        void *m_memPtr{ nullptr };
        uintptr_t m_address;
    };
    std::size_t m_memSize{ 0 };

    static std::size_t get_system_page_size();

    std::size_t m_pageSize{};
};
} // namespace memory
