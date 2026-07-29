/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     Semantic (structure-by-structure) comparison of two parsed MWOBPPC objects
 **/
#pragma once

#include "MwObjParser.hpp"

#include <format>
#include <sstream>
#include <string>
#include <vector>

namespace mwobj
{

struct DiffOptions
{
    std::size_t maxDiffs{ 64 };
};

namespace detail
{

inline std::string hex( std::uint64_t v )
{
    std::ostringstream oss;
    oss << "0x" << std::hex << v;
    return oss.str();
}

inline std::string reloc_name( RelocationType t )
{
    switch (t)
    {
    case RelocationType::TocD16:
        return "TOC_D16";
    case RelocationType::TocD16Il:
        return "TOC_D16_IL";
    case RelocationType::Branch24:
        return "BRANCH_24";
    case RelocationType::Abs32:
        return "ABS_32";
    case RelocationType::Rl32:
        return "RL_32";
    case RelocationType::Rel16:
        return "REL_16";
    case RelocationType::Ha16:
        return "HA_16";
    case RelocationType::Lo16:
        return "LO_16";
    case RelocationType::Ha16Il:
        return "HA_16_IL";
    case RelocationType::Lo16Il:
        return "LO_16_IL";
    }
    return "?";
}

class Collector
{
  public:
    explicit Collector( std::size_t maxDiffs ) : m_max{ maxDiffs }
    {
    }

    template <typename T> void check( std::string_view field, const T &expected, const T &actual )
    {
        if (expected != actual)
        {
            if constexpr (std::is_same_v<T, std::string>)
                add( std::string( field ) + ": expected='" + expected + "' actual='" + actual + "'" );
            else if constexpr (std::is_integral_v<T> || std::is_enum_v<T>)
                add( std::string( field ) + ": expected=" + hex( static_cast<std::uint64_t>( expected ) ) +
                     " actual=" + hex( static_cast<std::uint64_t>( actual ) ) );
            else
                add( std::string( field ) + ": mismatch" );
        }
    }

    void add( std::string msg )
    {
        if (m_diffs.size() < m_max)
            m_diffs.push_back( std::move( msg ) );
        ++m_total;
    }

    [[nodiscard]] bool truncated() const
    {
        return m_total > m_diffs.size();
    }
    [[nodiscard]] std::size_t total() const
    {
        return m_total;
    }
    [[nodiscard]] std::vector<std::string> &&take()
    {
        return std::move( m_diffs );
    }

  private:
    std::size_t m_max;
    std::size_t m_total{ 0 };
    std::vector<std::string> m_diffs;
};

inline void compare_relocs( Collector &c, std::string_view ctx, const std::vector<Relocation> &e,
                            const std::vector<Relocation> &a )
{
    if (e.size() != a.size())
    {
        c.add( std::string( ctx ) + ": reloc count expected=" + std::to_string( e.size() ) +
               " actual=" + std::to_string( a.size() ) );
        return;
    }
    for (std::size_t i{ 0 }; i < e.size(); ++i)
    {
        const std::string rctx{ std::string( ctx ) + " reloc[" + std::to_string( i ) + "]" };
        c.check( rctx + ".name", e[i].name, a[i].name );
        c.check( rctx + ".offset", e[i].offset, a[i].offset );
        if (e[i].type != a[i].type)
            c.add( rctx + ".type: expected=" + reloc_name( e[i].type ) + " actual=" + reloc_name( a[i].type ) );
        c.check( rctx + ".sectionClass", e[i].sectionClass, a[i].sectionClass );
    }
}

} // namespace detail

// Returns a list of human-readable mismatches; empty means the two object files are
// semantically equal (modulo embedded path & path-length-derived offsets).
inline std::vector<std::string> compare_objects( const ObjectFile &expected, const ObjectFile &actual,
                                                 const DiffOptions &opts = {} )
{
    detail::Collector c{ opts.maxDiffs };

    // FileHeader — ignore filePathOffset/objOffset (path-length dependent)
    // and embeddedPath itself.
    c.check( "fileHeader.magic", std::string( expected.fileHdr.magic.begin(), expected.fileHdr.magic.end() ),
             std::string( actual.fileHdr.magic.begin(), actual.fileHdr.magic.end() ) );
    c.check( "fileHeader.version", expected.fileHdr.version, actual.fileHdr.version );
    c.check( "fileHeader.flags", expected.fileHdr.flags, actual.fileHdr.flags );
    c.check( "fileHeader.codeSize", expected.fileHdr.codeSize, actual.fileHdr.codeSize );
    c.check( "fileHeader.dataSize", expected.fileHdr.dataSize, actual.fileHdr.dataSize );
    c.check( "fileHeader.unkContainer", expected.fileHdr.unkContainer, actual.fileHdr.unkContainer );
    c.check( "fileHeader.unk2", expected.fileHdr.unk2, actual.fileHdr.unk2 );
    c.check( "fileHeader.headerSize", expected.fileHdr.headerSize, actual.fileHdr.headerSize );
    c.check( "fileHeader.objFileSize", expected.fileHdr.objFileSize, actual.fileHdr.objFileSize );

    // ObjectHeader — every field is deterministic.
    c.check( "objectHeader.magic", std::string( expected.objHdr.magic.begin(), expected.objHdr.magic.end() ),
             std::string( actual.objHdr.magic.begin(), actual.objHdr.magic.end() ) );
    c.check( "objectHeader.unk", expected.objHdr.unk, actual.objHdr.unk );
    c.check( "objectHeader.objSize", expected.objHdr.objSize, actual.objHdr.objSize );
    c.check( "objectHeader.objSizeWithHeader", expected.objHdr.objSizeWithHeader, actual.objHdr.objSizeWithHeader );
    c.check( "objectHeader.symbolCount", expected.objHdr.symbolCount, actual.objHdr.symbolCount );
    c.check( "objectHeader.unk6", expected.objHdr.unk6, actual.objHdr.unk6 );
    c.check( "objectHeader.unk7", expected.objHdr.unk7, actual.objHdr.unk7 );
    c.check( "objectHeader.codeSize", expected.objHdr.codeSize, actual.objHdr.codeSize );
    c.check( "objectHeader.udataSize", expected.objHdr.udataSize, actual.objHdr.udataSize );
    c.check( "objectHeader.idataSize", expected.objHdr.idataSize, actual.objHdr.idataSize );
    c.check( "objectHeader.tocSize", expected.objHdr.tocSize, actual.objHdr.tocSize );

    // Name table
    if (expected.names.size() != actual.names.size())
    {
        c.add( "names: count expected=" + std::to_string( expected.names.size() ) +
               " actual=" + std::to_string( actual.names.size() ) );
    }
    else
    {
        for (std::size_t i{ 0 }; i < expected.names.size(); ++i)
        {
            const std::string ctx{ "names[" + std::to_string( i ) + "]" };
            c.check( ctx + ".hash", expected.names[i].hash, actual.names[i].hash );
            c.check( ctx + ".name", expected.names[i].name, actual.names[i].name );
        }
    }

    // Hunk order (structure sequence)
    if (expected.hunkOrder.size() != actual.hunkOrder.size())
    {
        c.add( "hunkOrder: count expected=" + std::to_string( expected.hunkOrder.size() ) +
               " actual=" + std::to_string( actual.hunkOrder.size() ) );
    }
    else
    {
        for (std::size_t i{ 0 }; i < expected.hunkOrder.size(); ++i)
            c.check( "hunkOrder[" + std::to_string( i ) + "]", expected.hunkOrder[i], actual.hunkOrder[i] );
    }

    // Code entries
    if (expected.code.size() != actual.code.size())
    {
        c.add( "code: count expected=" + std::to_string( expected.code.size() ) +
               " actual=" + std::to_string( actual.code.size() ) );
    }
    else
    {
        for (std::size_t i{ 0 }; i < expected.code.size(); ++i)
        {
            const auto &e{ expected.code[i] };
            const auto &a{ actual.code[i] };
            const std::string ctx{ "code[" + std::to_string( i ) + "] (" + e.name + ")" };
            c.check( ctx + ".name", e.name, a.name );
            c.check( ctx + ".scope", e.scope, a.scope );
            c.check( ctx + ".sectionClass", e.sectionClass, a.sectionClass );
            c.check( ctx + ".align", e.align, a.align );
            c.check( ctx + ".size", e.size, a.size );
            c.check( ctx + ".unk1", e.unk1, a.unk1 );
            c.check( ctx + ".unk2", e.unk2, a.unk2 );
            if (e.bytes != a.bytes)
                c.add( ctx + ".bytes: mismatch (size expected=" + std::to_string( e.bytes.size() ) +
                       " actual=" + std::to_string( a.bytes.size() ) + ")" );
            detail::compare_relocs( c, ctx, e.relocs, a.relocs );
        }
    }

    // Data entries
    if (expected.data.size() != actual.data.size())
    {
        c.add( "data: count expected=" + std::to_string( expected.data.size() ) +
               " actual=" + std::to_string( actual.data.size() ) );
    }
    else
    {
        for (std::size_t i{ 0 }; i < expected.data.size(); ++i)
        {
            const auto &e{ expected.data[i] };
            const auto &a{ actual.data[i] };
            const std::string ctx{ "data[" + std::to_string( i ) + "] (" + e.name + ")" };
            c.check( ctx + ".name", e.name, a.name );
            c.check( ctx + ".scope", e.scope, a.scope );
            c.check( ctx + ".kind", e.kind, a.kind );
            c.check( ctx + ".sectionClass", e.sectionClass, a.sectionClass );
            c.check( ctx + ".align", e.align, a.align );
            c.check( ctx + ".size", e.size, a.size );
            c.check( ctx + ".unk2", e.unk2, a.unk2 );
            c.check( ctx + ".unk3", e.unk3, a.unk3 );
            if (e.kind == DataKind::Initialized && e.bytes != a.bytes)
                c.add( ctx + ".bytes: mismatch (size expected=" + std::to_string( e.bytes.size() ) +
                       " actual=" + std::to_string( a.bytes.size() ) + ")" );
            detail::compare_relocs( c, ctx, e.relocs, a.relocs );
        }
    }

    // Imports
    if (expected.imports.size() != actual.imports.size())
    {
        c.add( "imports: count expected=" + std::to_string( expected.imports.size() ) +
               " actual=" + std::to_string( actual.imports.size() ) );
    }
    else
    {
        for (std::size_t i{ 0 }; i < expected.imports.size(); ++i)
        {
            const std::string ctx{ "imports[" + std::to_string( i ) + "]" };
            c.check( ctx + ".name", expected.imports[i].name, actual.imports[i].name );
            c.check( ctx + ".sectionClass", expected.imports[i].sectionClass, actual.imports[i].sectionClass );
        }
    }

    // Method refs
    if (expected.methodRefs.size() != actual.methodRefs.size())
    {
        c.add( "methodRefs: count expected=" + std::to_string( expected.methodRefs.size() ) +
               " actual=" + std::to_string( actual.methodRefs.size() ) );
    }
    else
    {
        for (std::size_t i{ 0 }; i < expected.methodRefs.size(); ++i)
        {
            const auto &e{ expected.methodRefs[i] };
            const auto &a{ actual.methodRefs[i] };
            const std::string ctx{ "methodRefs[" + std::to_string( i ) + "]" };
            c.check( ctx + ".name", e.name, a.name );
            c.check( ctx + ".count", e.count, a.count );
            c.check( ctx + ".unk", e.unk, a.unk );
            if (e.refs != a.refs)
                c.add( ctx + ".refs: mismatch" );
        }
    }

    // Class defs
    if (expected.classDefs.size() != actual.classDefs.size())
    {
        c.add( "classDefs: count expected=" + std::to_string( expected.classDefs.size() ) +
               " actual=" + std::to_string( actual.classDefs.size() ) );
    }
    else
    {
        for (std::size_t i{ 0 }; i < expected.classDefs.size(); ++i)
        {
            const auto &e{ expected.classDefs[i] };
            const auto &a{ actual.classDefs[i] };
            const std::string ctx{ "classDefs[" + std::to_string( i ) + "]" };
            c.check( ctx + ".name", e.name, a.name );
            c.check( ctx + ".unk", e.unk, a.unk );
            c.check( ctx + ".baseCount", e.baseCount, a.baseCount );
            if (e.bases != a.bases)
                c.add( ctx + ".bases: mismatch" );
        }
    }

    // Raw (opaque) hunks — compare type sequence + payload bytes.
    if (expected.rawHunks.size() != actual.rawHunks.size())
    {
        c.add( "rawHunks: count expected=" + std::to_string( expected.rawHunks.size() ) +
               " actual=" + std::to_string( actual.rawHunks.size() ) );
    }
    else
    {
        for (std::size_t i{ 0 }; i < expected.rawHunks.size(); ++i)
        {
            const auto &e{ expected.rawHunks[i] };
            const auto &a{ actual.rawHunks[i] };
            const std::string ctx{ "rawHunks[" + std::to_string( i ) + "]" };
            c.check( ctx + ".type", e.type, a.type );
            if (e.payload != a.payload)
                c.add( ctx + ".payload: mismatch" );
        }
    }

    if (c.truncated())
        c.add( "... (" + std::to_string( c.total() - opts.maxDiffs ) + " more mismatches suppressed)" );

    return c.take();
}

} // namespace mwobj
