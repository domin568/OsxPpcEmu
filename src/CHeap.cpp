/**
 * Author:    domin568
 * Created:   03.12.2025
 * Brief:     heap manager for emu
 **/
#include "../include/CHeap.hpp"

namespace memory
{
CHeap::CHeap( CMemory *owner, void *virtualAddressSpace, std::size_t size )
    : m_owner{ owner }, m_ptr{ virtualAddressSpace }, m_size{ size }
{
}

void *CHeap::alloc( const std::size_t size )
{
    return nullptr;
}
} // namespace memory