/**
 * Author:    domin568
 * Brief:     Byte-level file comparison utility for E2E golden-file tests.
 **/
#pragma once

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace testutil
{

struct DiffRegion
{
    std::size_t offset{};
    std::size_t len{};
};

struct DiffResult
{
    bool equal{ true };
    std::size_t expectedSize{};
    std::size_t actualSize{};
    std::size_t diffByteCount{};
    std::vector<DiffRegion> regions{}; // coalesced mismatching byte ranges (capped)
};

inline std::vector<uint8_t> read_file_bytes( const std::filesystem::path &path )
{
    std::ifstream f( path, std::ios::binary );
    return std::vector<uint8_t>( std::istreambuf_iterator<char>( f ), std::istreambuf_iterator<char>() );
}

// Compares `actual` against `expected`. Byte ranges listed in `ignore` are skipped
// entirely (never counted as a diff). Reports at most `maxRegions` coalesced
// mismatching regions.
inline DiffResult compare_files( const std::filesystem::path &expected, const std::filesystem::path &actual,
                                 const std::vector<DiffRegion> &ignore = {}, std::size_t maxRegions = 32 )
{
    DiffResult result{};
    const std::vector<uint8_t> expectedBytes{ read_file_bytes( expected ) };
    const std::vector<uint8_t> actualBytes{ read_file_bytes( actual ) };
    result.expectedSize = expectedBytes.size();
    result.actualSize = actualBytes.size();

    const auto isIgnored{ [&]( std::size_t offset ) {
        for (const DiffRegion &r : ignore)
            if (offset >= r.offset && offset < r.offset + r.len)
                return true;
        return false;
    } };

    const std::size_t commonSize{ std::min( result.expectedSize, result.actualSize ) };
    bool inRegion{ false };
    std::size_t regionStart{ 0 };
    std::size_t regionLen{ 0 };

    const auto flushRegion{ [&]() {
        if (inRegion && result.regions.size() < maxRegions)
            result.regions.push_back( { regionStart, regionLen } );
        inRegion = false;
        regionLen = 0;
    } };

    for (std::size_t i{ 0 }; i < commonSize; ++i)
    {
        const bool mismatch{ expectedBytes[i] != actualBytes[i] && !isIgnored( i ) };
        if (mismatch)
        {
            ++result.diffByteCount;
            if (!inRegion)
            {
                inRegion = true;
                regionStart = i;
                regionLen = 0;
            }
            ++regionLen;
        }
        else
        {
            flushRegion();
        }
    }
    flushRegion();

    if (result.expectedSize != result.actualSize)
        result.diffByteCount += ( result.expectedSize > result.actualSize ? result.expectedSize - result.actualSize
                                                                          : result.actualSize - result.expectedSize );

    result.equal = ( result.expectedSize == result.actualSize ) && ( result.diffByteCount == 0 );
    return result;
}

inline std::string format_diff_report( const DiffResult &diff, const std::filesystem::path &expected,
                                       const std::filesystem::path &actual )
{
    const std::vector<uint8_t> expectedBytes{ read_file_bytes( expected ) };
    const std::vector<uint8_t> actualBytes{ read_file_bytes( actual ) };

    std::ostringstream oss;
    oss << "Binary mismatch:\n"
        << "  expected: " << expected.string() << " (" << diff.expectedSize << " bytes)\n"
        << "  actual:   " << actual.string() << " (" << diff.actualSize << " bytes)\n"
        << "  total mismatching bytes (incl. size delta): " << diff.diffByteCount << "\n";

    for (const DiffRegion &r : diff.regions)
    {
        oss << "  @0x" << std::hex << r.offset << " len=0x" << r.len << std::dec << "  expected=";
        for (std::size_t i{ 0 }; i < std::min<std::size_t>( r.len, 16 ) && r.offset + i < expectedBytes.size(); ++i)
            oss << std::hex << static_cast<int>( expectedBytes[r.offset + i] ) << ' ' << std::dec;
        oss << " actual=";
        for (std::size_t i{ 0 }; i < std::min<std::size_t>( r.len, 16 ) && r.offset + i < actualBytes.size(); ++i)
            oss << std::hex << static_cast<int>( actualBytes[r.offset + i] ) << ' ' << std::dec;
        if (r.len > 16)
            oss << "...";
        oss << '\n';
    }
    return oss.str();
}

} // namespace testutil
