/**
 * Author:    domin568
 * Created:   03.12.2025
 * Brief:     heap manager for emu
 **/
#include "../../include/mem/CHeap.hpp"
#include "../../include/Common.hpp"
#include "../../include/mem/CMemory.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <unicorn/unicorn.h>

namespace memory
{

CHeap::CHeap( CMemory *owner, std::uint32_t baseVa, std::size_t maxSize )
    : m_owner{ owner }, m_baseVa{ baseVa }, m_maxSize{ maxSize }
{
}

void CHeap::rebind( CMemory *owner )
{
    m_owner = owner;
}

void *CHeap::host( std::uint32_t guestVa ) const
{
    return m_owner->get( guestVa );
}

CHeap::ChunkHeader CHeap::read_header( std::uint32_t chunkVa ) const
{
    std::uint32_t raw[4]{};
    std::memcpy( raw, host( chunkVa ), sizeof( raw ) );
    return ChunkHeader{
        common::ensure_endianness( raw[0], std::endian::big ),
        common::ensure_endianness( raw[1], std::endian::big ),
        common::ensure_endianness( raw[2], std::endian::big ),
        common::ensure_endianness( raw[3], std::endian::big ),
    };
}

void CHeap::write_header( std::uint32_t chunkVa, const ChunkHeader &h ) const
{
    const std::uint32_t raw[4]{
        common::ensure_endianness( h.size, std::endian::big ),
        common::ensure_endianness( h.prevSize, std::endian::big ),
        common::ensure_endianness( h.flags, std::endian::big ),
        common::ensure_endianness( h.magic, std::endian::big ),
    };
    std::memcpy( host( chunkVa ), raw, sizeof( raw ) );
}

std::uint32_t CHeap::read_free_link( std::uint32_t chunkVa, std::size_t fieldOffset ) const
{
    auto *p{ static_cast<std::uint8_t *>( host( chunkVa ) ) + common::Heap_Header_Size + fieldOffset };
    std::uint32_t raw{};
    std::memcpy( &raw, p, sizeof( raw ) );
    return common::ensure_endianness( raw, std::endian::big );
}

void CHeap::write_free_link( std::uint32_t chunkVa, std::size_t fieldOffset, std::uint32_t value ) const
{
    auto *p{ static_cast<std::uint8_t *>( host( chunkVa ) ) + common::Heap_Header_Size + fieldOffset };
    const std::uint32_t raw{ common::ensure_endianness( value, std::endian::big ) };
    std::memcpy( p, &raw, sizeof( raw ) );
}

void CHeap::poison( std::uint32_t payloadVa, std::size_t len ) const
{
    static constexpr std::array<std::uint8_t, 4> Pattern{ 0xDE, 0xAD, 0xBE, 0xEF };
    auto *p{ static_cast<std::uint8_t *>( host( payloadVa ) ) };
    for (std::size_t i{ 0 }; i < len; ++i)
        p[i] = Pattern[i % Pattern.size()];
}

std::size_t CHeap::small_bin_index( std::size_t chunkSize )
{
    return ( chunkSize / common::Heap_Alignment ) - 2;
}

std::size_t CHeap::chunk_size_for_payload( std::size_t payloadSize )
{
    const std::size_t aligned{ common::align_up( payloadSize, common::Heap_Alignment ) };
    return std::max( aligned + common::Heap_Header_Size, common::Heap_Min_Chunk_Size );
}

void CHeap::bin_insert( std::uint32_t chunkVa, std::size_t chunkSize )
{
    std::uint32_t &head{ chunkSize <= common::Heap_Small_Bin_Max_Size ? m_smallBins[small_bin_index( chunkSize )]
                                                                       : m_largeBinHead };
    const std::uint32_t oldHead{ head };
    write_free_link( chunkVa, 0, oldHead );
    write_free_link( chunkVa, 4, 0 );
    if (oldHead != 0)
        write_free_link( oldHead, 4, chunkVa );
    head = chunkVa;
}

void CHeap::bin_remove( std::uint32_t chunkVa, std::size_t chunkSize )
{
    const std::uint32_t nextFree{ read_free_link( chunkVa, 0 ) };
    const std::uint32_t prevFree{ read_free_link( chunkVa, 4 ) };
    std::uint32_t &head{ chunkSize <= common::Heap_Small_Bin_Max_Size ? m_smallBins[small_bin_index( chunkSize )]
                                                                       : m_largeBinHead };
    if (prevFree != 0)
        write_free_link( prevFree, 0, nextFree );
    else
        head = nextFree;
    if (nextFree != 0)
        write_free_link( nextFree, 4, prevFree );
}

std::uint32_t CHeap::bin_take_small( std::size_t chunkSize )
{
    const std::uint32_t va{ m_smallBins[small_bin_index( chunkSize )] };
    if (va == 0)
        return 0;
    bin_remove( va, chunkSize );
    return va;
}

std::uint32_t CHeap::bin_take_large_fit( std::size_t chunkSize )
{
    std::uint32_t best{ 0 };
    std::size_t bestSize{ 0 };
    std::uint32_t cur{ m_largeBinHead };
    for (std::size_t scanned{ 0 }; cur != 0 && scanned < common::Heap_Large_Bin_Scan_Cap; ++scanned)
    {
        const ChunkHeader h{ read_header( cur ) };
        if (h.size >= chunkSize && ( best == 0 || h.size < bestSize ))
        {
            best = cur;
            bestSize = h.size;
        }
        cur = read_free_link( cur, 0 );
    }
    if (best != 0)
        bin_remove( best, bestSize );
    return best;
}

bool CHeap::grow( std::size_t additionalNeeded )
{
    if (m_committedSize >= m_maxSize)
        return false;
    std::size_t delta{ common::align_up( additionalNeeded, common::Heap_Commit_Granularity ) };
    if (delta == 0)
        delta = common::Heap_Commit_Granularity;
    const std::size_t remaining{ m_maxSize - m_committedSize };
    delta = std::min( delta, remaining );
    if (delta == 0)
        return false;
    if (!m_owner->commit( m_baseVa + m_committedSize, delta, UC_PROT_ALL ))
        return false;
    m_committedSize += delta;
    m_topSize += delta;
    ++m_stats.growCount;
    m_stats.bytesCommitted = m_committedSize;
    return true;
}

bool CHeap::initialize( common::HeapMode mode )
{
    m_mode = mode;
    m_committedSize = 0;
    m_topVa = m_baseVa;
    m_topSize = 0;
    m_topPrevChunkSize = 0;
    return grow( common::Heap_Initial_Commit );
}

std::uint32_t CHeap::carve_from_top( std::size_t chunkSize )
{
    if (chunkSize > m_topSize)
    {
        if (!grow( chunkSize - m_topSize ) || chunkSize > m_topSize)
            return 0;
    }
    const ChunkHeader h{ static_cast<std::uint32_t>( chunkSize ), m_topPrevChunkSize, Flag_In_Use, Chunk_Magic_Used };
    write_header( m_topVa, h );
    const std::uint32_t va{ m_topVa };
    m_topVa += static_cast<std::uint32_t>( chunkSize );
    m_topSize -= chunkSize;
    m_topPrevChunkSize = static_cast<std::uint32_t>( chunkSize );
    return va;
}

void CHeap::fix_prev_size_after( std::uint32_t chunkVa, std::size_t chunkSize )
{
    const std::uint32_t nextVa{ chunkVa + static_cast<std::uint32_t>( chunkSize ) };
    if (nextVa == m_topVa)
    {
        m_topPrevChunkSize = static_cast<std::uint32_t>( chunkSize );
        return;
    }
    if (nextVa >= m_baseVa + m_committedSize)
        return;
    ChunkHeader nh{ read_header( nextVa ) };
    nh.prevSize = static_cast<std::uint32_t>( chunkSize );
    write_header( nextVa, nh );
}

void CHeap::release_free_chunk( std::uint32_t va, std::size_t size, std::uint32_t prevSize )
{
    // Always write the free header, even when the chunk is about to be folded into the top
    // (wilderness) region below: this overwrites the stale "in-use" header that used to occupy
    // this address, which is what lets owns()/free() correctly recognise a stale pointer into
    // now-unallocated top territory as no-longer-live instead of accidentally-still-plausible.
    const ChunkHeader h{ static_cast<std::uint32_t>( size ), prevSize, 0, Chunk_Magic_Free };
    write_header( va, h );

    const std::uint32_t nextVa{ va + static_cast<std::uint32_t>( size ) };
    if (nextVa == m_topVa)
    {
        m_topVa = va;
        m_topSize += size;
        m_topPrevChunkSize = prevSize;
        return;
    }
    bin_insert( va, size );
    fix_prev_size_after( va, size );
}

void CHeap::retire_chunk( std::uint32_t va, std::size_t size, std::uint32_t prevSize )
{
    const ChunkHeader h{ static_cast<std::uint32_t>( size ), prevSize, 0, Chunk_Magic_Retired };
    write_header( va, h );
    fix_prev_size_after( va, size );
}

std::uint32_t CHeap::alloc( std::size_t size )
{
    ++m_stats.allocCalls;
    m_stats.bytesRequested += size;

    const std::size_t chunkSize{ chunk_size_for_payload( size == 0 ? 1 : size ) };
    std::uint32_t va{ 0 };
    if (chunkSize <= common::Heap_Small_Bin_Max_Size)
        va = bin_take_small( chunkSize );
    if (va == 0)
        va = bin_take_large_fit( chunkSize );

    if (va != 0)
    {
        ChunkHeader h{ read_header( va ) };
        const std::size_t actualSize{ h.size };
        if (actualSize - chunkSize >= common::Heap_Min_Chunk_Size)
        {
            const std::uint32_t remainderVa{ va + static_cast<std::uint32_t>( chunkSize ) };
            const std::size_t remainderSize{ actualSize - chunkSize };
            const ChunkHeader used{ static_cast<std::uint32_t>( chunkSize ), h.prevSize, Flag_In_Use,
                                     Chunk_Magic_Used };
            write_header( va, used );
            release_free_chunk( remainderVa, remainderSize, static_cast<std::uint32_t>( chunkSize ) );
        }
        else
        {
            h.flags = Flag_In_Use;
            h.magic = Chunk_Magic_Used;
            write_header( va, h );
        }
    }
    else
    {
        va = carve_from_top( chunkSize );
        if (va == 0)
            return 0;
    }

    const ChunkHeader finalHeader{ read_header( va ) };
    m_stats.bytesInUse += finalHeader.size - common::Heap_Header_Size;
    m_stats.peakBytesInUse = std::max( m_stats.peakBytesInUse, m_stats.bytesInUse );
    return va + static_cast<std::uint32_t>( common::Heap_Header_Size );
}

std::uint32_t CHeap::alloc_aligned( std::size_t size, std::size_t alignment )
{
    if (alignment <= common::Heap_Alignment)
        return alloc( size );
    // Over-alignment beyond the natural 16-byte guarantee is not supported by this allocator.
    return 0;
}

bool CHeap::owns( std::uint32_t guestPtr ) const
{
    if (guestPtr < m_baseVa + common::Heap_Header_Size)
        return false;
    const std::uint32_t chunkVa{ guestPtr - static_cast<std::uint32_t>( common::Heap_Header_Size ) };
    if (chunkVa < m_baseVa || chunkVa >= m_baseVa + m_committedSize)
        return false;
    if (( chunkVa - m_baseVa ) % common::Heap_Alignment != 0)
        return false;
    const ChunkHeader h{ read_header( chunkVa ) };
    return h.magic == Chunk_Magic_Used && h.size >= common::Heap_Min_Chunk_Size &&
           h.size % common::Heap_Alignment == 0 && chunkVa + h.size <= m_baseVa + m_committedSize;
}

std::size_t CHeap::usable_size( std::uint32_t guestPtr ) const
{
    if (!owns( guestPtr ))
        return 0;
    const std::uint32_t chunkVa{ guestPtr - static_cast<std::uint32_t>( common::Heap_Header_Size ) };
    return read_header( chunkVa ).size - common::Heap_Header_Size;
}

CHeap::MergeResult CHeap::coalesce_with_free_neighbors( std::uint32_t va, std::size_t size, std::uint32_t prevSize )
{
    std::uint32_t curVa{ va };
    std::size_t curSize{ size };
    std::uint32_t curPrevSize{ prevSize };

    const std::uint32_t nextVa{ curVa + static_cast<std::uint32_t>( curSize ) };
    if (nextVa != m_topVa && nextVa < m_baseVa + m_committedSize)
    {
        const ChunkHeader nh{ read_header( nextVa ) };
        if (nh.magic == Chunk_Magic_Free)
        {
            bin_remove( nextVa, nh.size );
            curSize += nh.size;
        }
    }

    if (curPrevSize != 0)
    {
        const std::uint32_t prevVa{ curVa - curPrevSize };
        const ChunkHeader ph{ read_header( prevVa ) };
        if (ph.magic == Chunk_Magic_Free)
        {
            bin_remove( prevVa, ph.size );
            curVa = prevVa;
            curSize += ph.size;
            curPrevSize = ph.prevSize;
        }
    }

    return { curVa, curSize, curPrevSize };
}

bool CHeap::free( std::uint32_t guestPtr )
{
    ++m_stats.freeCalls;
    if (guestPtr == 0)
        return true;

    if (guestPtr < m_baseVa + common::Heap_Header_Size)
    {
        ++m_stats.invalidFrees;
        return false;
    }
    const std::uint32_t chunkVa{ guestPtr - static_cast<std::uint32_t>( common::Heap_Header_Size ) };
    if (chunkVa < m_baseVa || chunkVa >= m_baseVa + m_committedSize ||
        ( chunkVa - m_baseVa ) % common::Heap_Alignment != 0)
    {
        ++m_stats.invalidFrees;
        return false;
    }

    const ChunkHeader h{ read_header( chunkVa ) };
    if (h.magic == Chunk_Magic_Free || h.magic == Chunk_Magic_Quarantined || h.magic == Chunk_Magic_Retired)
    {
        ++m_stats.doubleFrees;
        return false;
    }
    if (h.magic != Chunk_Magic_Used || h.size < common::Heap_Min_Chunk_Size ||
        h.size % common::Heap_Alignment != 0 || chunkVa + h.size > m_baseVa + m_committedSize)
    {
        ++m_stats.corruptHeaders;
        return false;
    }

    m_stats.bytesInUse -= ( h.size - common::Heap_Header_Size );

    if (m_mode == common::HeapMode::Bump)
    {
        poison( chunkVa + static_cast<std::uint32_t>( common::Heap_Header_Size ), h.size - common::Heap_Header_Size );
        retire_chunk( chunkVa, h.size, h.prevSize );
        m_stats.retiredBytes += h.size;
        return true;
    }

    const MergeResult merged{ coalesce_with_free_neighbors( chunkVa, h.size, h.prevSize ) };

    if (m_mode == common::HeapMode::Real)
    {
        release_free_chunk( merged.va, merged.size, merged.prevSize );
        return true;
    }

    // HeapMode::Quarantine (default): poison, mark as quarantined, hold in a FIFO before the
    // chunk is allowed to be admitted back into the free bins.
    poison( merged.va + static_cast<std::uint32_t>( common::Heap_Header_Size ),
            merged.size - common::Heap_Header_Size );

    const ChunkHeader quarantined{ static_cast<std::uint32_t>( merged.size ), merged.prevSize, 0,
                                    Chunk_Magic_Quarantined };
    write_header( merged.va, quarantined );
    // The chunk being quarantined may have grown via coalesce_with_free_neighbors() above (it
    // absorbed a free forward neighbour); whatever now follows it physically must have its
    // prevSize boundary tag updated to match, exactly as release_free_chunk() does for the
    // Real-mode path. Missing this call is what let two adjacent free/quarantined chunks drift
    // out of sync with the following chunk's prevSize field.
    fix_prev_size_after( merged.va, merged.size );
    m_quarantine.emplace_back( merged.va, static_cast<std::uint32_t>( merged.size ) );
    m_quarantineBytes += merged.size;
    m_stats.quarantineBytes = m_quarantineBytes;

    while (m_quarantineBytes > common::Heap_Quarantine_Bytes && !m_quarantine.empty())
    {
        const auto [qva, qsize]{ m_quarantine.front() };
        m_quarantine.pop_front();
        m_quarantineBytes -= qsize;
        m_stats.quarantineBytes = m_quarantineBytes;
        admit_from_quarantine( qva );
    }
    return true;
}

void CHeap::admit_from_quarantine( std::uint32_t va )
{
    const ChunkHeader h{ read_header( va ) };
    const MergeResult merged{ coalesce_with_free_neighbors( va, h.size, h.prevSize ) };
    release_free_chunk( merged.va, merged.size, merged.prevSize );
}

std::uint32_t CHeap::realloc( std::uint32_t guestPtr, std::size_t size )
{
    ++m_stats.reallocCalls;
    if (guestPtr == 0)
        return alloc( size );
    if (size == 0)
    {
        free( guestPtr );
        return 0;
    }
    if (!owns( guestPtr ))
        return 0;

    const std::uint32_t chunkVa{ guestPtr - static_cast<std::uint32_t>( common::Heap_Header_Size ) };
    const ChunkHeader h{ read_header( chunkVa ) };
    const std::size_t neededChunkSize{ chunk_size_for_payload( size ) };

    if (neededChunkSize <= h.size)
    {
        if (h.size - neededChunkSize >= common::Heap_Min_Chunk_Size)
        {
            const std::uint32_t remainderVa{ chunkVa + static_cast<std::uint32_t>( neededChunkSize ) };
            const std::size_t remainderSize{ h.size - neededChunkSize };
            const ChunkHeader used{ static_cast<std::uint32_t>( neededChunkSize ), h.prevSize, Flag_In_Use,
                                     Chunk_Magic_Used };
            write_header( chunkVa, used );
            // The chunk being shrunk was in-use, so its physical neighbour's freeness was never
            // constrained by the "no two adjacent free chunks" invariant - it may already be a
            // free chunk sitting in a bin. Coalesce with it before releasing the remainder,
            // otherwise this would create exactly that forbidden adjacency.
            const MergeResult merged{ coalesce_with_free_neighbors(
                remainderVa, remainderSize, static_cast<std::uint32_t>( neededChunkSize ) ) };
            release_free_chunk( merged.va, merged.size, merged.prevSize );
        }
        return guestPtr;
    }

    const std::uint32_t nextVa{ chunkVa + static_cast<std::uint32_t>( h.size ) };
    if (nextVa == m_topVa)
    {
        const std::size_t need{ neededChunkSize - h.size };
        if (need > m_topSize)
            grow( need - m_topSize );
        if (neededChunkSize <= h.size + m_topSize)
        {
            const std::size_t extra{ neededChunkSize - h.size };
            m_topVa += static_cast<std::uint32_t>( extra );
            m_topSize -= extra;
            const ChunkHeader grown{ static_cast<std::uint32_t>( neededChunkSize ), h.prevSize, Flag_In_Use,
                                      Chunk_Magic_Used };
            write_header( chunkVa, grown );
            m_topPrevChunkSize = static_cast<std::uint32_t>( neededChunkSize );
            return guestPtr;
        }
    }
    else if (nextVa < m_baseVa + m_committedSize)
    {
        const ChunkHeader nh{ read_header( nextVa ) };
        if (nh.magic == Chunk_Magic_Free && h.size + nh.size >= neededChunkSize)
        {
            bin_remove( nextVa, nh.size );
            const std::size_t combined{ h.size + nh.size };
            if (combined - neededChunkSize >= common::Heap_Min_Chunk_Size)
            {
                const std::uint32_t remainderVa{ chunkVa + static_cast<std::uint32_t>( neededChunkSize ) };
                const std::size_t remainderSize{ combined - neededChunkSize };
                const ChunkHeader used{ static_cast<std::uint32_t>( neededChunkSize ), h.prevSize, Flag_In_Use,
                                         Chunk_Magic_Used };
                write_header( chunkVa, used );
                release_free_chunk( remainderVa, remainderSize, static_cast<std::uint32_t>( neededChunkSize ) );
            }
            else
            {
                const ChunkHeader used{ static_cast<std::uint32_t>( combined ), h.prevSize, Flag_In_Use,
                                         Chunk_Magic_Used };
                write_header( chunkVa, used );
                fix_prev_size_after( chunkVa, combined );
            }
            return guestPtr;
        }
    }

    const std::uint32_t newPtr{ alloc( size ) };
    if (newPtr == 0)
        return 0;
    const std::size_t oldPayload{ h.size - common::Heap_Header_Size };
    const std::size_t copySize{ std::min( oldPayload, size ) };
    std::memcpy( host( newPtr ), host( guestPtr ), copySize );
    free( guestPtr );
    return newPtr;
}

bool CHeap::walk( std::vector<ChunkInfo> *out, std::string *report, std::size_t limit ) const
{
    std::uint32_t va{ m_baseVa };
    std::uint32_t prevSize{ 0 };
    bool prevWasFree{ false };
    std::size_t emitted{ 0 };
    while (va != m_topVa)
    {
        if (limit != 0 && emitted >= limit)
            return true;
        if (va < m_baseVa || va >= m_baseVa + m_committedSize)
        {
            if (report)
                *report = "chunk walk left the committed region";
            if (out)
                out->push_back( ChunkInfo{ va, 0, 0, 0, prevSize, ChunkState::Corrupt } );
            return false;
        }
        const ChunkHeader h{ read_header( va ) };
        if (h.magic != Chunk_Magic_Used && h.magic != Chunk_Magic_Free && h.magic != Chunk_Magic_Quarantined &&
            h.magic != Chunk_Magic_Retired)
        {
            if (report)
                *report = "bad chunk magic";
            if (out)
                out->push_back( ChunkInfo{ va, va + static_cast<std::uint32_t>( common::Heap_Header_Size ), h.size,
                                            0, prevSize, ChunkState::Corrupt } );
            return false;
        }
        if (h.size < common::Heap_Min_Chunk_Size || h.size % common::Heap_Alignment != 0)
        {
            if (report)
                *report = "bad chunk size";
            if (out)
                out->push_back( ChunkInfo{ va, va + static_cast<std::uint32_t>( common::Heap_Header_Size ), h.size,
                                            0, prevSize, ChunkState::Corrupt } );
            return false;
        }
        if (h.prevSize != prevSize)
        {
            if (report)
                *report = "prevSize boundary-tag mismatch";
            if (out)
                out->push_back( ChunkInfo{
                    va, va + static_cast<std::uint32_t>( common::Heap_Header_Size ), h.size,
                    h.size - static_cast<std::uint32_t>( common::Heap_Header_Size ), h.prevSize,
                    ChunkState::Corrupt } );
            return false;
        }
        // Chunk_Magic_Retired is deliberately excluded from the adjacency check below: Bump mode
        // never coalesces, so two physically-adjacent retired chunks are the normal steady state,
        // not a missed-coalesce corruption.
        const bool isFree{ h.magic == Chunk_Magic_Free };
        if (isFree && prevWasFree)
        {
            if (report)
                *report = "two physically-adjacent free chunks (missed coalesce)";
            if (out)
                out->push_back( ChunkInfo{
                    va, va + static_cast<std::uint32_t>( common::Heap_Header_Size ), h.size,
                    h.size - static_cast<std::uint32_t>( common::Heap_Header_Size ), h.prevSize,
                    ChunkState::Corrupt } );
            return false;
        }
        if (out)
        {
            const ChunkState state{ h.magic == Chunk_Magic_Used       ? ChunkState::InUse
                                     : h.magic == Chunk_Magic_Free     ? ChunkState::Free
                                     : h.magic == Chunk_Magic_Retired  ? ChunkState::Retired
                                                                       : ChunkState::Quarantined };
            out->push_back( ChunkInfo{
                va, va + static_cast<std::uint32_t>( common::Heap_Header_Size ), h.size,
                h.size - static_cast<std::uint32_t>( common::Heap_Header_Size ), h.prevSize, state } );
        }
        ++emitted;
        prevWasFree = isFree;
        prevSize = h.size;
        va += h.size;
    }
    if (m_topPrevChunkSize != prevSize)
    {
        if (report)
            *report = "top chunk prevSize mismatch";
        if (out)
            out->push_back(
                ChunkInfo{ m_topVa, m_topVa + static_cast<std::uint32_t>( common::Heap_Header_Size ),
                           static_cast<std::uint32_t>( m_topSize ), 0, m_topPrevChunkSize, ChunkState::Corrupt } );
        return false;
    }
    if (out && ( limit == 0 || emitted < limit ))
        out->push_back( ChunkInfo{ m_topVa, m_topVa + static_cast<std::uint32_t>( common::Heap_Header_Size ),
                                    static_cast<std::uint32_t>( m_topSize ), static_cast<std::uint32_t>( m_topSize ),
                                    m_topPrevChunkSize, ChunkState::Top } );
    return true;
}

bool CHeap::validate( std::string *report ) const
{
    return walk( nullptr, report, 0 );
}

std::vector<ChunkInfo> CHeap::walk_chunks( std::size_t limit ) const
{
    std::vector<ChunkInfo> out{};
    if (!m_owner || !is_initialized())
        return out;
    walk( &out, nullptr, limit );
    return out;
}

std::optional<ChunkInfo> CHeap::find_chunk( std::uint32_t guestVa ) const
{
    if (!m_owner || !is_initialized())
        return std::nullopt;
    if (guestVa < m_baseVa || guestVa >= m_baseVa + m_committedSize + common::Heap_Header_Size)
        return std::nullopt;

    const std::vector<ChunkInfo> chunks{ walk_chunks() };
    for (const ChunkInfo &c : chunks)
    {
        if (guestVa >= c.chunkVa && guestVa < c.chunkVa + c.size)
            return c;
    }
    return std::nullopt;
}

std::vector<BinInfo> CHeap::bin_snapshot() const
{
    std::vector<BinInfo> out{};
    if (!m_owner || !is_initialized())
        return out;

    const std::size_t cap{ std::max<std::size_t>( 1, m_committedSize / common::Heap_Min_Chunk_Size ) };

    for (std::size_t i{ 0 }; i < m_smallBins.size(); ++i)
    {
        std::uint32_t cur{ m_smallBins[i] };
        if (cur == 0)
            continue;
        std::size_t count{ 0 };
        std::uint64_t bytes{ 0 };
        const std::uint32_t chunkSize{ static_cast<std::uint32_t>( ( i + 2 ) * common::Heap_Alignment ) };
        while (cur != 0 && count < cap)
        {
            if (cur < m_baseVa || cur >= m_baseVa + m_committedSize || ( cur - m_baseVa ) % common::Heap_Alignment != 0)
                break;
            ++count;
            bytes += chunkSize;
            cur = read_free_link( cur, 0 );
        }
        out.push_back( BinInfo{ i, chunkSize, count, bytes } );
    }

    if (m_largeBinHead != 0)
    {
        std::uint32_t cur{ m_largeBinHead };
        std::size_t count{ 0 };
        std::uint64_t bytes{ 0 };
        while (cur != 0 && count < cap)
        {
            if (cur < m_baseVa || cur >= m_baseVa + m_committedSize || ( cur - m_baseVa ) % common::Heap_Alignment != 0)
                break;
            const ChunkHeader h{ read_header( cur ) };
            ++count;
            bytes += h.size;
            cur = read_free_link( cur, 0 );
        }
        out.push_back( BinInfo{ m_smallBins.size(), 0, count, bytes } );
    }

    return out;
}

std::vector<ChunkInfo> CHeap::quarantine_snapshot() const
{
    std::vector<ChunkInfo> out{};
    out.reserve( m_quarantine.size() );
    for (const auto &[va, size] : m_quarantine)
    {
        out.push_back( ChunkInfo{ va, va + static_cast<std::uint32_t>( common::Heap_Header_Size ), size,
                                   size - static_cast<std::uint32_t>( common::Heap_Header_Size ), 0,
                                   ChunkState::Quarantined } );
    }
    return out;
}

} // namespace memory

