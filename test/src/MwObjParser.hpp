/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     Parser for Metrowerks PowerPC (MWOBPPC) object files, used to compare
 *            golden vs emulator-produced object files structure-by-structure instead
 *            of raw byte comparison (which is unreliable due to uninitialized memory
 *            the compiler leaves in the file and due to embedded-path-length-dependent
 *            offsets).
 **/
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include "Expected.hpp"
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

namespace mwobj
{

// ─── Constants ─────────────────────────────────────────────────────────

inline constexpr std::array<char, 8> Magic{ 'M', 'W', 'O', 'B', 'P', 'P', 'C', ' ' };
inline constexpr std::array<char, 4> ObjectMagic{ 'P', 'O', 'W', 'R' };
inline constexpr int OpcodeBase{ 'g' };

inline constexpr std::array<const char *, 25> SectionClasses{
    "PR", "RO",  "DB",  "TC", "UA", "RW", "GL", "XO",  "SV", "BS", "DS", "UC",   "TI",
    "TB", "???", "TC0", "TD", "NL", "LZ", "ST", "PST", "XC", "TT", "TX", "CSTR",
};

inline std::string section_class_name( std::uint8_t idx )
{
    if (idx < SectionClasses.size())
        return SectionClasses[idx];
    return "UNK_" + std::to_string( idx );
}

enum class SymbolScope : std::uint8_t
{
    Local = 0,
    Global = 1,
};

enum class RelocationType : std::uint8_t
{
    TocD16 = 0,
    TocD16Il = 1,
    Branch24 = 2,
    Abs32 = 3,
    Rl32 = 4,
    Rel16 = 5,
    Ha16 = 6,
    Lo16 = 7,
    Ha16Il = 8,
    Lo16Il = 9,
};

enum class DataKind : std::uint8_t
{
    Uninitialized = 0,
    Initialized = 1,
};

enum class HunkType : std::uint8_t
{
    Start = 0,
    End = 1,
    Segment = 2,
    LocalCode = 3,
    GlobalCode = 4,
    LocalUdata = 5,
    GlobalUdata = 6,
    LocalIdata = 7,
    GlobalIdata = 8,
    GlobalEntry = 9,
    LocalEntry = 10,
    Import = 11,
    Xref16Bit = 12,
    Xref16BitIl = 13,
    Xref24Bit = 14,
    Xref32Bit = 15,
    Xref32BitRl = 16,
    DeinitCode = 17,
    LibraryBreak = 18,
    ImportContainer = 19,
    SourceBreak = 20,
    Xref16BitRel = 21,
    MethodRef = 22,
    ClassDef = 23,
    ForceActive = 24,
    XrefHa16Bit = 25,
    XrefLo16Bit = 26,
    XrefHa16BitIl = 27,
    XrefLo16BitIl = 28,
};

inline bool is_load_hunk( HunkType t )
{
    switch (t)
    {
    case HunkType::LocalCode:
    case HunkType::GlobalCode:
    case HunkType::LocalUdata:
    case HunkType::GlobalUdata:
    case HunkType::LocalIdata:
    case HunkType::GlobalIdata:
        return true;
    default:
        return false;
    }
}

inline bool is_code_hunk( HunkType t )
{
    return t == HunkType::LocalCode || t == HunkType::GlobalCode;
}

inline bool is_data_hunk( HunkType t )
{
    switch (t)
    {
    case HunkType::LocalUdata:
    case HunkType::GlobalUdata:
    case HunkType::LocalIdata:
    case HunkType::GlobalIdata:
        return true;
    default:
        return false;
    }
}

inline compat::expected<RelocationType, std::string> xref_reloc_type( HunkType t )
{
    switch (t)
    {
    case HunkType::Xref16Bit:
        return RelocationType::TocD16;
    case HunkType::Xref16BitIl:
        return RelocationType::TocD16Il;
    case HunkType::Xref24Bit:
        return RelocationType::Branch24;
    case HunkType::Xref32Bit:
        return RelocationType::Abs32;
    case HunkType::Xref32BitRl:
        return RelocationType::Rl32;
    case HunkType::Xref16BitRel:
        return RelocationType::Rel16;
    case HunkType::XrefHa16Bit:
        return RelocationType::Ha16;
    case HunkType::XrefLo16Bit:
        return RelocationType::Lo16;
    case HunkType::XrefHa16BitIl:
        return RelocationType::Ha16Il;
    case HunkType::XrefLo16BitIl:
        return RelocationType::Lo16Il;
    default:
        return compat::unexpected( "not an xref hunk type" );
    }
}

// ─── Data model ────────────────────────────────────────────────────────

struct FileHeader
{
    std::array<char, 8> magic{};
    std::uint32_t version{};
    std::uint32_t flags{};
    std::uint32_t codeSize{};
    std::uint32_t dataSize{};
    std::uint32_t unkContainer{};
    std::uint32_t unk2{};
    std::uint32_t headerSize{};
    std::uint32_t filePathOffset{};
    std::uint32_t objOffset{};
    std::uint32_t objFileSize{};
};

struct ObjectHeader
{
    std::array<char, 4> magic{};
    std::uint32_t unk{};
    std::uint32_t objSize{};
    std::uint32_t objSizeWithHeader{};
    std::uint32_t symbolCount{};
    std::uint32_t unk6{};
    std::uint32_t unk7{};
    std::uint32_t codeSize{};
    std::uint32_t udataSize{};
    std::uint32_t idataSize{};
    std::uint32_t tocSize{};
};

struct NameEntry
{
    std::uint16_t hash{};
    std::string name{};
};

struct Relocation
{
    std::string name{};
    std::uint32_t offset{};
    RelocationType type{};
    std::uint8_t sectionClass{};
};

struct CodeEntry
{
    std::string name{};
    SymbolScope scope{};
    std::uint8_t sectionClass{};
    std::uint8_t align{};
    std::uint32_t size{};
    std::uint32_t unk1{};
    std::uint32_t unk2{};
    std::uint64_t fileOffset{};
    std::vector<std::uint8_t> bytes{};
    std::vector<Relocation> relocs{};
};

struct DataEntry
{
    std::string name{};
    SymbolScope scope{};
    DataKind kind{};
    std::uint8_t sectionClass{};
    std::uint8_t align{};
    std::uint32_t size{};
    std::uint32_t unk2{};
    std::uint32_t unk3{};
    std::uint64_t fileOffset{};
    std::vector<std::uint8_t> bytes{};
    std::vector<Relocation> relocs{};
};

struct ImportEntry
{
    std::string name{};
    std::uint8_t sectionClass{};
};

struct MethodRef
{
    std::string name{};
    std::uint16_t count{};
    std::uint16_t unk{};
    std::vector<std::string> refs{};
};

struct ClassDef
{
    std::string name{};
    std::uint16_t unk{};
    std::int16_t baseCount{};
    std::vector<std::pair<std::string, std::int32_t>> bases{};
};

struct RawHunk
{
    HunkType type{};
    std::vector<std::uint8_t> payload{};
};

struct ObjectFile
{
    FileHeader fileHdr{};
    ObjectHeader objHdr{};
    std::string embeddedPath{};
    std::vector<NameEntry> names{};
    std::vector<CodeEntry> code{};
    std::vector<DataEntry> data{};
    std::vector<ImportEntry> imports{};
    std::vector<MethodRef> methodRefs{};
    std::vector<ClassDef> classDefs{};
    std::vector<RawHunk> rawHunks{};
    std::vector<HunkType> hunkOrder{};
};

// ─── Byte reader ───────────────────────────────────────────────────────

class ByteReader
{
  public:
    explicit ByteReader( std::vector<std::uint8_t> data ) : m_data{ std::move( data ) }
    {
    }

    [[nodiscard]] std::size_t tell() const
    {
        return m_pos;
    }
    [[nodiscard]] std::size_t size() const
    {
        return m_data.size();
    }

    compat::expected<void, std::string> seek( std::size_t pos )
    {
        if (pos > m_data.size())
            return compat::unexpected( "seek out of range" );
        m_pos = pos;
        return {};
    }

    compat::expected<std::uint8_t, std::string> u8()
    {
        if (m_pos + 1 > m_data.size())
            return compat::unexpected( "u8: out of range at " + std::to_string( m_pos ) );
        return m_data[m_pos++];
    }

    compat::expected<std::uint16_t, std::string> u16()
    {
        if (m_pos + 2 > m_data.size())
            return compat::unexpected( "u16: out of range at " + std::to_string( m_pos ) );
        std::uint16_t v{};
        std::memcpy( &v, &m_data[m_pos], 2 );
        m_pos += 2;
        if constexpr (std::endian::native == std::endian::little)
            v = std::byteswap( v );
        return v;
    }

    compat::expected<std::uint32_t, std::string> u32()
    {
        if (m_pos + 4 > m_data.size())
            return compat::unexpected( "u32: out of range at " + std::to_string( m_pos ) );
        std::uint32_t v{};
        std::memcpy( &v, &m_data[m_pos], 4 );
        m_pos += 4;
        if constexpr (std::endian::native == std::endian::little)
            v = std::byteswap( v );
        return v;
    }

    compat::expected<std::int32_t, std::string> i32()
    {
        auto v{ u32() };
        if (!v)
            return compat::unexpected( v.error() );
        return static_cast<std::int32_t>( *v );
    }

    compat::expected<std::vector<std::uint8_t>, std::string> bytes( std::size_t n )
    {
        if (m_pos + n > m_data.size())
            return compat::unexpected( "bytes(" + std::to_string( n ) + "): out of range at " + std::to_string( m_pos ) );
        std::vector<std::uint8_t> out( m_data.begin() + static_cast<long>( m_pos ),
                                       m_data.begin() + static_cast<long>( m_pos + n ) );
        m_pos += n;
        return out;
    }

    compat::expected<std::string, std::string> cstring()
    {
        std::string out;
        while (true)
        {
            if (m_pos >= m_data.size())
                return compat::unexpected( "cstring: unterminated at end of file" );
            const char c{ static_cast<char>( m_data[m_pos++] ) };
            if (c == '\0')
                break;
            out.push_back( c );
        }
        return out;
    }

    compat::expected<void, std::string> skip_align( std::size_t sizeJustRead )
    {
        const std::size_t padding{ ( 4 - ( sizeJustRead % 4 ) ) % 4 };
        if (padding == 0)
            return {};
        if (m_pos + padding > m_data.size())
            return compat::unexpected( "skip_align: out of range" );
        m_pos += padding;
        return {};
    }

  private:
    std::vector<std::uint8_t> m_data;
    std::size_t m_pos{ 0 };
};

// ─── Parsing ───────────────────────────────────────────────────────────

namespace detail
{

#define MWOBJ_TRY( var, expr )                                                                                         \
    auto var##_res{ ( expr ) };                                                                                        \
    if (!var##_res)                                                                                                    \
        return compat::unexpected( var##_res.error() );                                                                   \
    auto &var                                                                                                          \
    {                                                                                                                  \
        *var##_res                                                                                                     \
    }

inline compat::expected<FileHeader, std::string> parse_file_header( ByteReader &r )
{
    FileHeader h{};
    MWOBJ_TRY( magicBytes, r.bytes( 8 ) );
    std::copy( magicBytes.begin(), magicBytes.end(), h.magic.begin() );
    MWOBJ_TRY( version, r.u32() );
    h.version = version;
    MWOBJ_TRY( flags, r.u32() );
    h.flags = flags;
    MWOBJ_TRY( codeSize, r.u32() );
    h.codeSize = codeSize;
    MWOBJ_TRY( dataSize, r.u32() );
    h.dataSize = dataSize;
    MWOBJ_TRY( unkContainer, r.u32() );
    h.unkContainer = unkContainer;
    MWOBJ_TRY( unk2, r.u32() );
    h.unk2 = unk2;
    MWOBJ_TRY( headerSize, r.u32() );
    h.headerSize = headerSize;
    MWOBJ_TRY( filePathOffset, r.u32() );
    h.filePathOffset = filePathOffset;
    MWOBJ_TRY( objOffset, r.u32() );
    h.objOffset = objOffset;
    MWOBJ_TRY( objFileSize, r.u32() );
    h.objFileSize = objFileSize;
    return h;
}

inline compat::expected<ObjectHeader, std::string> parse_object_header( ByteReader &r )
{
    ObjectHeader h{};
    MWOBJ_TRY( magicBytes, r.bytes( 4 ) );
    std::copy( magicBytes.begin(), magicBytes.end(), h.magic.begin() );
    MWOBJ_TRY( unk, r.u32() );
    h.unk = unk;
    MWOBJ_TRY( objSize, r.u32() );
    h.objSize = objSize;
    MWOBJ_TRY( objSizeWithHeader, r.u32() );
    h.objSizeWithHeader = objSizeWithHeader;
    MWOBJ_TRY( symbolCount, r.u32() );
    h.symbolCount = symbolCount;
    MWOBJ_TRY( unk6, r.u32() );
    h.unk6 = unk6;
    MWOBJ_TRY( unk7, r.u32() );
    h.unk7 = unk7;
    MWOBJ_TRY( codeSize, r.u32() );
    h.codeSize = codeSize;
    MWOBJ_TRY( udataSize, r.u32() );
    h.udataSize = udataSize;
    MWOBJ_TRY( idataSize, r.u32() );
    h.idataSize = idataSize;
    MWOBJ_TRY( tocSize, r.u32() );
    h.tocSize = tocSize;
    return h;
}

inline compat::expected<std::vector<NameEntry>, std::string> parse_name_table( ByteReader &r, std::size_t offset,
                                                                            std::size_t endOffset )
{
    if (auto s{ r.seek( offset ) }; !s)
        return compat::unexpected( s.error() );
    std::vector<NameEntry> names;
    while (r.tell() < endOffset)
    {
        auto hashRes{ r.u16() };
        if (!hashRes)
            break; // no more full entries fit
        NameEntry entry{};
        entry.hash = *hashRes;
        MWOBJ_TRY( name, r.cstring() );
        entry.name = name;
        names.push_back( std::move( entry ) );
    }
    return names;
}

inline compat::expected<std::string, std::string> resolve_name( const std::vector<NameEntry> &names,
                                                             std::uint32_t oneBasedIdx )
{
    if (oneBasedIdx == 0 || oneBasedIdx > names.size())
        return compat::unexpected( "name index " + std::to_string( oneBasedIdx ) + " out of range (" +
                                std::to_string( names.size() ) + " names)" );
    return names[oneBasedIdx - 1].name;
}

class HunkParser
{
  public:
    HunkParser( ByteReader &r, const std::vector<NameEntry> &names ) : m_r{ r }, m_names{ names }
    {
    }

    compat::expected<void, std::string> parse( std::size_t endOffset, ObjectFile &out )
    {
        while (m_r.tell() < endOffset)
        {
            MWOBJ_TRY( opcodeBytes, m_r.bytes( 2 ) );
            const int typeVal{ static_cast<int>( opcodeBytes[1] ) - OpcodeBase };
            if (typeVal < 0 || typeVal > static_cast<int>( HunkType::XrefLo16BitIl ))
                return compat::unexpected( "unknown hunk opcode 0x" + to_hex( opcodeBytes[0] ) + to_hex( opcodeBytes[1] ) +
                                        " at offset " + std::to_string( m_r.tell() - 2 ) );
            const auto hunkType{ static_cast<HunkType>( typeVal ) };
            out.hunkOrder.push_back( hunkType );
            if (is_load_hunk( hunkType ))
                m_lastLoadHunk = hunkType;

            compat::expected<void, std::string> res;
            switch (hunkType)
            {
            case HunkType::Start:
            case HunkType::End:
            case HunkType::LibraryBreak:
                res = skip( 2 );
                break;
            case HunkType::Segment:
                res = raw_hunk( hunkType, 6, out );
                break;
            case HunkType::LocalCode:
                res = parse_code( SymbolScope::Local, out );
                break;
            case HunkType::GlobalCode:
                res = parse_code( SymbolScope::Global, out );
                break;
            case HunkType::LocalUdata:
                res = parse_udata( SymbolScope::Local, out );
                break;
            case HunkType::GlobalUdata:
                res = parse_udata( SymbolScope::Global, out );
                break;
            case HunkType::LocalIdata:
                res = parse_idata( SymbolScope::Local, out );
                break;
            case HunkType::GlobalIdata:
                res = parse_idata( SymbolScope::Global, out );
                break;
            case HunkType::GlobalEntry:
            case HunkType::LocalEntry:
                res = raw_hunk( hunkType, 18, out );
                break;
            case HunkType::Import:
                res = parse_import( out );
                break;
            case HunkType::DeinitCode:
                res = {};
                break;
            case HunkType::ImportContainer:
                res = raw_hunk( hunkType, 18, out );
                break;
            case HunkType::SourceBreak:
                res = raw_hunk( hunkType, 10, out );
                break;
            case HunkType::MethodRef:
                res = parse_method_ref( out );
                break;
            case HunkType::ClassDef:
                res = parse_class_def( out );
                break;
            case HunkType::ForceActive:
                res = raw_hunk( hunkType, 2, out );
                break;
            case HunkType::Xref16Bit:
            case HunkType::Xref16BitIl:
            case HunkType::Xref24Bit:
            case HunkType::Xref32Bit:
            case HunkType::Xref32BitRl:
            case HunkType::Xref16BitRel:
            case HunkType::XrefHa16Bit:
            case HunkType::XrefLo16Bit:
            case HunkType::XrefHa16BitIl:
            case HunkType::XrefLo16BitIl:
                if (auto relocType{ xref_reloc_type( hunkType ) }; relocType)
                    res = parse_xref( *relocType, out );
                else
                    return compat::unexpected( "unhandled hunk type at offset " + std::to_string( m_r.tell() - 2 ) );
                break;
            default:
                return compat::unexpected( "unknown hunk type at offset " + std::to_string( m_r.tell() - 2 ) );
            }
            if (!res)
                return compat::unexpected( res.error() );
        }
        return {};
    }

  private:
    static std::string to_hex( std::uint8_t b )
    {
        static constexpr char digits[]{ "0123456789abcdef" };
        return { digits[b >> 4], digits[b & 0xF] };
    }

    compat::expected<void, std::string> skip( std::size_t n )
    {
        auto res{ m_r.bytes( n ) };
        if (!res)
            return compat::unexpected( res.error() );
        return {};
    }

    compat::expected<void, std::string> raw_hunk( HunkType type, std::size_t payloadSize, ObjectFile &out )
    {
        MWOBJ_TRY( payload, m_r.bytes( payloadSize ) );
        out.rawHunks.push_back( RawHunk{ type, std::move( payload ) } );
        return {};
    }

    compat::expected<void, std::string> parse_code( SymbolScope scope, ObjectFile &out )
    {
        MWOBJ_TRY( classIdx, m_r.u8() );
        MWOBJ_TRY( align, m_r.u8() );
        MWOBJ_TRY( nameIdx, m_r.u32() );
        MWOBJ_TRY( codeSize, m_r.u32() );
        MWOBJ_TRY( unk1, m_r.u32() );
        MWOBJ_TRY( unk2, m_r.u32() );
        MWOBJ_TRY( name, resolve_name( m_names, nameIdx ) );
        const std::uint64_t offsetInFile{ m_r.tell() };
        MWOBJ_TRY( raw, m_r.bytes( codeSize ) );
        if (auto s{ m_r.skip_align( codeSize ) }; !s)
            return compat::unexpected( s.error() );

        CodeEntry entry{};
        entry.name = name;
        entry.scope = scope;
        entry.sectionClass = classIdx;
        entry.align = align;
        entry.size = codeSize;
        entry.unk1 = unk1;
        entry.unk2 = unk2;
        entry.fileOffset = offsetInFile;
        entry.bytes = std::move( raw );
        out.code.push_back( std::move( entry ) );
        return {};
    }

    compat::expected<void, std::string> parse_idata( SymbolScope scope, ObjectFile &out )
    {
        MWOBJ_TRY( classIdx, m_r.u8() );
        MWOBJ_TRY( align, m_r.u8() );
        MWOBJ_TRY( nameIdx, m_r.u32() );
        MWOBJ_TRY( dataSize, m_r.u32() );
        MWOBJ_TRY( unk2, m_r.u32() );
        MWOBJ_TRY( unk3, m_r.u32() );
        MWOBJ_TRY( name, resolve_name( m_names, nameIdx ) );
        const std::uint64_t offsetInFile{ m_r.tell() };
        MWOBJ_TRY( raw, m_r.bytes( dataSize ) );
        if (auto s{ m_r.skip_align( dataSize ) }; !s)
            return compat::unexpected( s.error() );

        DataEntry entry{};
        entry.name = name;
        entry.scope = scope;
        entry.kind = DataKind::Initialized;
        entry.sectionClass = classIdx;
        entry.align = align;
        entry.size = dataSize;
        entry.unk2 = unk2;
        entry.unk3 = unk3;
        entry.fileOffset = offsetInFile;
        entry.bytes = std::move( raw );
        out.data.push_back( std::move( entry ) );
        return {};
    }

    compat::expected<void, std::string> parse_udata( SymbolScope scope, ObjectFile &out )
    {
        MWOBJ_TRY( classIdx, m_r.u8() );
        MWOBJ_TRY( align, m_r.u8() );
        MWOBJ_TRY( nameIdx, m_r.u32() );
        MWOBJ_TRY( dataSize, m_r.u32() );
        MWOBJ_TRY( unk2, m_r.u32() );
        MWOBJ_TRY( unk3, m_r.u32() );
        MWOBJ_TRY( name, resolve_name( m_names, nameIdx ) );

        DataEntry entry{};
        entry.name = name;
        entry.scope = scope;
        entry.kind = DataKind::Uninitialized;
        entry.sectionClass = classIdx;
        entry.align = align;
        entry.size = dataSize;
        entry.unk2 = unk2;
        entry.unk3 = unk3;
        entry.fileOffset = 0;
        out.data.push_back( std::move( entry ) );
        return {};
    }

    compat::expected<void, std::string> parse_xref( RelocationType relocType, ObjectFile &out )
    {
        MWOBJ_TRY( classIdx, m_r.u8() );
        MWOBJ_TRY( unk, m_r.u8() );
        (void)unk;
        MWOBJ_TRY( nameIdx, m_r.u32() );
        MWOBJ_TRY( offset, m_r.u32() );
        MWOBJ_TRY( name, resolve_name( m_names, nameIdx ) );

        Relocation reloc{};
        reloc.name = name;
        reloc.offset = offset;
        reloc.type = relocType;
        reloc.sectionClass = classIdx;

        if (is_code_hunk( m_lastLoadHunk ))
        {
            if (out.code.empty())
                return compat::unexpected( "xref with no preceding code entry" );
            out.code.back().relocs.push_back( std::move( reloc ) );
        }
        else if (is_data_hunk( m_lastLoadHunk ))
        {
            if (out.data.empty())
                return compat::unexpected( "xref with no preceding data entry" );
            out.data.back().relocs.push_back( std::move( reloc ) );
        }
        return {};
    }

    compat::expected<void, std::string> parse_import( ObjectFile &out )
    {
        MWOBJ_TRY( classIdx, m_r.u8() );
        MWOBJ_TRY( unk, m_r.u8() );
        (void)unk;
        MWOBJ_TRY( nameIdx, m_r.u32() );
        MWOBJ_TRY( name, resolve_name( m_names, nameIdx ) );
        out.imports.push_back( ImportEntry{ name, classIdx } );
        return {};
    }

    compat::expected<void, std::string> parse_method_ref( ObjectFile &out )
    {
        MWOBJ_TRY( nameIdx, m_r.u32() );
        MWOBJ_TRY( count, m_r.u16() );
        MWOBJ_TRY( unk, m_r.u16() );
        std::vector<std::string> refs;
        refs.reserve( count );
        for (std::uint16_t i{ 0 }; i < count; ++i)
        {
            MWOBJ_TRY( idx, m_r.u16() );
            MWOBJ_TRY( refName, resolve_name( m_names, idx ) );
            refs.push_back( refName );
        }
        MWOBJ_TRY( name, resolve_name( m_names, nameIdx ) );
        out.methodRefs.push_back( MethodRef{ name, count, unk, std::move( refs ) } );
        return {};
    }

    compat::expected<void, std::string> parse_class_def( ObjectFile &out )
    {
        MWOBJ_TRY( nameIdx, m_r.u32() );
        MWOBJ_TRY( unk, m_r.u16() );
        MWOBJ_TRY( countU32, m_r.u32() );
        const auto count{ static_cast<std::int16_t>( countU32 & 0xFFFF ) };
        std::vector<std::pair<std::string, std::int32_t>> bases;
        for (std::int32_t i{ 0 }; i < std::max<std::int32_t>( 0, count ); ++i)
        {
            MWOBJ_TRY( baseIdx, m_r.u32() );
            MWOBJ_TRY( bias, m_r.i32() );
            MWOBJ_TRY( baseName, resolve_name( m_names, baseIdx ) );
            bases.emplace_back( baseName, bias );
        }
        MWOBJ_TRY( name, resolve_name( m_names, nameIdx ) );
        out.classDefs.push_back( ClassDef{ name, unk, count, std::move( bases ) } );
        return {};
    }

    ByteReader &m_r;
    const std::vector<NameEntry> &m_names;
    HunkType m_lastLoadHunk{ HunkType::Start };
};

#undef MWOBJ_TRY

} // namespace detail

inline compat::expected<std::vector<std::uint8_t>, std::string> read_whole_file( const std::filesystem::path &path )
{
    std::ifstream f( path, std::ios::binary );
    if (!f)
        return compat::unexpected( "cannot open file: " + path.string() );
    return std::vector<std::uint8_t>( std::istreambuf_iterator<char>( f ), std::istreambuf_iterator<char>() );
}

inline compat::expected<ObjectFile, std::string> parse( const std::filesystem::path &path )
{
    auto bytesRes{ read_whole_file( path ) };
    if (!bytesRes)
        return compat::unexpected( bytesRes.error() );

    ByteReader r{ std::move( *bytesRes ) };

    if (r.size() < Magic.size())
        return compat::unexpected( "file too small to contain MWOBPPC magic: " + path.string() );
    {
        auto magicPeek{ r.bytes( Magic.size() ) };
        if (!magicPeek)
            return compat::unexpected( magicPeek.error() );
        if (!std::equal( magicPeek->begin(), magicPeek->end(), Magic.begin() ))
            return compat::unexpected( "not an MWOBPPC file: " + path.string() );
    }
    if (auto s{ r.seek( 0 ) }; !s)
        return compat::unexpected( s.error() );

    ObjectFile out{};

    auto fileHdrRes{ detail::parse_file_header( r ) };
    if (!fileHdrRes)
        return compat::unexpected( fileHdrRes.error() );
    out.fileHdr = *fileHdrRes;

    if (out.fileHdr.filePathOffset > 0)
    {
        if (auto s{ r.seek( out.fileHdr.filePathOffset ) }; !s)
            return compat::unexpected( s.error() );
        auto pathRes{ r.cstring() };
        if (!pathRes)
            return compat::unexpected( pathRes.error() );
        out.embeddedPath = *pathRes;
    }

    if (auto s{ r.seek( out.fileHdr.objOffset ) }; !s)
        return compat::unexpected( s.error() );
    auto objHdrRes{ detail::parse_object_header( r ) };
    if (!objHdrRes)
        return compat::unexpected( objHdrRes.error() );
    out.objHdr = *objHdrRes;

    const std::size_t objEnd{ out.fileHdr.objOffset + out.objHdr.objSizeWithHeader };
    const std::size_t hunksStart{ objEnd - out.objHdr.objSize };

    auto namesRes{ detail::parse_name_table( r, objEnd, r.size() ) };
    if (!namesRes)
        return compat::unexpected( namesRes.error() );
    out.names = std::move( *namesRes );

    if (auto s{ r.seek( hunksStart ) }; !s)
        return compat::unexpected( s.error() );
    detail::HunkParser hunkParser{ r, out.names };
    if (auto s{ hunkParser.parse( objEnd, out ) }; !s)
        return compat::unexpected( s.error() );

    return out;
}

} // namespace mwobj
