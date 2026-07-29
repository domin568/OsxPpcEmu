/**
 * Author:    domin568
 * Created:   03.12.2025
 * Brief:     heap manager for emu
 **/

#pragma once
#include "../Common.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace memory
{

class CMemory;

enum class ChunkState
{
    InUse,
    Free,
    Quarantined,
    Retired,
    Top,
    Corrupt,
};

struct ChunkInfo
{
    std::uint32_t chunkVa{};
    std::uint32_t payloadVa{};
    std::uint32_t size{};
    std::uint32_t payloadSize{};
    std::uint32_t prevSize{};
    ChunkState state{};
};

struct BinInfo
{
    std::size_t index{};
    std::uint32_t chunkSize{};
    std::size_t count{};
    std::uint64_t totalBytes{};
};

class CHeap
{
  public:
    struct Stats
    {
        std::uint64_t allocCalls{};
        std::uint64_t freeCalls{};
        std::uint64_t reallocCalls{};
        std::uint64_t bytesRequested{};
        std::uint64_t bytesInUse{};
        std::uint64_t bytesCommitted{};
        std::uint64_t peakBytesInUse{};
        std::uint64_t growCount{};
        std::uint64_t doubleFrees{};
        std::uint64_t invalidFrees{};
        std::uint64_t corruptHeaders{};
        std::uint64_t quarantineBytes{};
        std::uint64_t retiredBytes{};
    };

    CHeap( CMemory *owner, std::uint32_t baseVa, std::size_t maxSize );

    CHeap( const CHeap & ) = delete;
    CHeap &operator=( const CHeap & ) = delete;
    CHeap( CHeap && ) noexcept = default;
    CHeap &operator=( CHeap && ) noexcept = default;

    // Commits the initial region and prepares the top (wilderness) chunk. Must be called once
    // before any alloc()/free()/realloc(). `mode` fixes the free() policy for the lifetime of
    // this heap instance; there is deliberately no public setter to change it afterwards - a
    // heap that already has quarantined/retired chunks under one policy is not a state we want
    // a policy switch to have to reason about. Re-initialize() to change it.
    [[nodiscard]] bool initialize( common::HeapMode mode = common::Heap_Default_Mode );

    [[nodiscard]] common::HeapMode mode() const
    {
        return m_mode;
    }

    // CMemory may move (e.g. std::expected's converting constructor); CHeap keeps a back
    // pointer to it and must be re-pointed at the new owner after such a move.
    void rebind( CMemory *owner );

    // All addresses below are GUEST virtual addresses. 0 means failure / guest NULL.
    [[nodiscard]] std::uint32_t alloc( std::size_t size );
    [[nodiscard]] std::uint32_t alloc_aligned( std::size_t size, std::size_t alignment );
    [[nodiscard]] std::uint32_t realloc( std::uint32_t guestPtr, std::size_t size );
    bool free( std::uint32_t guestPtr );

    [[nodiscard]] std::size_t usable_size( std::uint32_t guestPtr ) const;
    [[nodiscard]] bool owns( std::uint32_t guestPtr ) const;

    [[nodiscard]] const Stats &stats() const
    {
        return m_stats;
    }

    [[nodiscard]] bool validate( std::string *report = nullptr ) const;

    [[nodiscard]] std::uint32_t base_va() const
    {
        return m_baseVa;
    }
    [[nodiscard]] std::uint32_t top_va() const
    {
        return m_topVa;
    }
    [[nodiscard]] std::size_t top_size() const
    {
        return m_topSize;
    }
    [[nodiscard]] std::size_t committed_size() const
    {
        return m_committedSize;
    }
    [[nodiscard]] std::size_t max_size() const
    {
        return m_maxSize;
    }
    [[nodiscard]] bool is_initialized() const
    {
        return m_committedSize != 0;
    }

    [[nodiscard]] std::vector<ChunkInfo> walk_chunks( std::size_t limit = 0 ) const;
    [[nodiscard]] std::optional<ChunkInfo> find_chunk( std::uint32_t guestVa ) const;
    [[nodiscard]] std::vector<BinInfo> bin_snapshot() const;
    [[nodiscard]] std::vector<ChunkInfo> quarantine_snapshot() const;

  private:
    struct ChunkHeader
    {
        std::uint32_t size{};
        std::uint32_t prevSize{};
        std::uint32_t flags{};
        std::uint32_t magic{};
    };

    static constexpr std::uint32_t Flag_In_Use{ 0x1 };
    static constexpr std::uint32_t Chunk_Magic_Used{ 0xC0FFEE01 };
    static constexpr std::uint32_t Chunk_Magic_Free{ 0xC0FFEE02 };
    // A freed-but-not-yet-reusable chunk, executable error proof
    static constexpr std::uint32_t Chunk_Magic_Quarantined{ 0xC0FFEE03 };
    // A chunk retired permanently under HeapMode::Bump: never coalesced, never reused
    static constexpr std::uint32_t Chunk_Magic_Retired{ 0xC0FFEE04 };

    struct MergeResult
    {
        std::uint32_t va;
        std::size_t size;
        std::uint32_t prevSize;
    };

    CMemory *m_owner{ nullptr };
    std::uint32_t m_baseVa{ 0 };
    std::size_t m_maxSize{ 0 };
    std::size_t m_committedSize{ 0 };
    common::HeapMode m_mode{ common::Heap_Default_Mode };

    std::uint32_t m_topVa{ 0 };
    std::size_t m_topSize{ 0 };
    std::uint32_t m_topPrevChunkSize{ 0 };

    std::array<std::uint32_t, 31> m_smallBins{}; // exact-size bins, guest VA of bin head (0 == empty)
    std::uint32_t m_largeBinHead{ 0 };

    std::deque<std::pair<std::uint32_t, std::uint32_t>> m_quarantine{}; // FIFO of (chunkVa, chunkSize)
    std::size_t m_quarantineBytes{ 0 };

    Stats m_stats{};

    void *host( std::uint32_t guestVa ) const;

    ChunkHeader read_header( std::uint32_t chunkVa ) const;
    void write_header( std::uint32_t chunkVa, const ChunkHeader &h ) const;
    std::uint32_t read_free_link( std::uint32_t chunkVa, std::size_t fieldOffset ) const;
    void write_free_link( std::uint32_t chunkVa, std::size_t fieldOffset, std::uint32_t value ) const;
    void poison( std::uint32_t payloadVa, std::size_t len ) const;

    static std::size_t small_bin_index( std::size_t chunkSize );
    static std::size_t chunk_size_for_payload( std::size_t payloadSize );

    void bin_insert( std::uint32_t chunkVa, std::size_t chunkSize );
    void bin_remove( std::uint32_t chunkVa, std::size_t chunkSize );
    std::uint32_t bin_take_small( std::size_t chunkSize );
    std::uint32_t bin_take_large_fit( std::size_t chunkSize );

    bool grow( std::size_t additionalNeeded );
    std::uint32_t carve_from_top( std::size_t chunkSize );
    void fix_prev_size_after( std::uint32_t chunkVa, std::size_t chunkSize );
    // Writes a free chunk header at [va, va+size) (or merges it into the top chunk if adjacent)
    // and links it into the appropriate free bin. Does not touch anything before `va`.
    void release_free_chunk( std::uint32_t va, std::size_t size, std::uint32_t prevSize );
    // Absorbs any physically-adjacent chunk that is genuinely free (bin-linked). Removes the
    // absorbed neighbour(s) from their bin.
    MergeResult coalesce_with_free_neighbors( std::uint32_t va, std::size_t size, std::uint32_t prevSize );
    // Moves one quarantined chunk back into circulation: re-checks its neighbours (one may have
    // been freed while this chunk was quarantined) and releases it for reuse.
    void admit_from_quarantine( std::uint32_t va );
    // HeapMode::Bump's free() disposition: writes a poisoned, permanently-retired header at
    // [va, va+size). Never coalesces, never enters a bin - the chunk is simply gone.
    void retire_chunk( std::uint32_t va, std::size_t size, std::uint32_t prevSize );

    // Shared boundary-tag walk used by both validate() and walk_chunks(). Appends every chunk
    // visited to *out (if non-null), stopping after appending a Corrupt entry on invariant
    // failure. limit == 0 means unlimited. Returns false (and sets *report, if non-null) on
    // any invariant violation, matching validate()'s prior contract.
    bool walk( std::vector<ChunkInfo> *out, std::string *report, std::size_t limit = 0 ) const;
};

} // namespace memory
