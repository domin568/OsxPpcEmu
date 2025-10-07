/**
 * Author:    domin568
 * Created:   06.10.2025
 * Brief:     memory manager for emu
 **/
#pragma once
#include <cstdint>
#include <expected>
#include <string>

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
  public:
    static std::expected<CMemory, Error> init( size_t size );
    ~CMemory();
    bool commit( size_t guestAddress, size_t size );

  private:
    CMemory( void *memPtr, size_t size );

    union {
        void *m_memPtr{ nullptr };
        uintptr_t m_address;
    };
    size_t m_memSize{ 0 };
};
} // namespace memory
