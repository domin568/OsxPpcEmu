/**
 * Author:    domin568
 * Created:   03.12.2025
 * Brief:     heap manager for emu
 **/

#pragma once
#include <cstddef>

namespace memory
{

class CMemory;
class CHeap
{
  public:
    CHeap( CMemory *owner, void *virtualAddressSpace, std::size_t size );

    void *alloc( std::size_t size );

  private:
    void *m_ptr{};
    std::size_t m_size{};
    CMemory *m_owner{ nullptr };
};
} // namespace memory
