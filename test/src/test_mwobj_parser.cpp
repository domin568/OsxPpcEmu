/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     Unit tests for the MWOBPPC object file parser and the
 *            semantic diff (MwObjDiff.hpp), using test/test_files/e2e/expected/test.cpp.o.
 **/
#include "MwObjDiff.hpp"
#include "MwObjParser.hpp"

#include <filesystem>
#include <gtest/gtest.h>

namespace fs = std::filesystem;

namespace
{
fs::path fixture_path()
{
    return fs::path( TEST_FOLDER ) / "test_files" / "e2e" / "expected" / "test.cpp.o";
}
} // namespace

TEST( MwObjParser, ParsesGoldenFileHeader )
{
    const auto obj{ mwobj::parse( fixture_path() ) };
    ASSERT_TRUE( obj.has_value() ) << obj.error();

    EXPECT_EQ( ( std::string( obj->fileHdr.magic.begin(), obj->fileHdr.magic.end() ) ), "MWOBPPC " );
    EXPECT_EQ( obj->fileHdr.version, 0u );
    EXPECT_EQ( obj->fileHdr.flags, 0x1u );
    EXPECT_EQ( obj->fileHdr.codeSize, 0x30u );
    EXPECT_EQ( obj->fileHdr.dataSize, 0x1Cu );
    EXPECT_EQ( obj->fileHdr.headerSize, 0x30u );
    EXPECT_EQ( obj->fileHdr.objOffset, 0x6Cu );
    EXPECT_EQ( obj->fileHdr.objFileSize, 0x1B2u );
    EXPECT_EQ( obj->embeddedPath, "/Users/domin568/Desktop/mwpefcc_compiled/test.cpp" );
}

TEST( MwObjParser, ParsesGoldenObjectHeader )
{
    const auto obj{ mwobj::parse( fixture_path() ) };
    ASSERT_TRUE( obj.has_value() ) << obj.error();

    EXPECT_EQ( ( std::string( obj->objHdr.magic.begin(), obj->objHdr.magic.end() ) ), "POWR" );
    EXPECT_EQ( obj->objHdr.objSize, 0x114u );
    EXPECT_EQ( obj->objHdr.objSizeWithHeader, 0x180u );
    EXPECT_EQ( obj->objHdr.symbolCount, 7u );
    EXPECT_EQ( obj->objHdr.codeSize, 0x30u );
    EXPECT_EQ( obj->objHdr.udataSize, 0u );
    EXPECT_EQ( obj->objHdr.idataSize, 0x1Cu );
    EXPECT_EQ( obj->objHdr.tocSize, 0u );
}

TEST( MwObjParser, ParsesNameTable )
{
    const auto obj{ mwobj::parse( fixture_path() ) };
    ASSERT_TRUE( obj.has_value() ) << obj.error();

    ASSERT_EQ( obj->names.size(), 6u );
    EXPECT_EQ( obj->names[0].hash, 0x0162 );
    EXPECT_EQ( obj->names[0].name, ".foo__Fii" );
    EXPECT_EQ( obj->names[1].hash, 0x0519 );
    EXPECT_EQ( obj->names[1].name, ".main" );
    EXPECT_EQ( obj->names[2].hash, 0x0358 );
    EXPECT_EQ( obj->names[2].name, "@11" );
    EXPECT_EQ( obj->names[3].hash, 0x04b3 );
    EXPECT_EQ( obj->names[3].name, "main" );
    EXPECT_EQ( obj->names[4].hash, 0x037e );
    EXPECT_EQ( obj->names[4].name, "TOC" );
    EXPECT_EQ( obj->names[5].hash, 0x00ce );
    EXPECT_EQ( obj->names[5].name, "foo__Fii" );
}

TEST( MwObjParser, ParsesCodeEntries )
{
    const auto obj{ mwobj::parse( fixture_path() ) };
    ASSERT_TRUE( obj.has_value() ) << obj.error();

    ASSERT_EQ( obj->code.size(), 2u );

    const auto &foo{ obj->code[0] };
    EXPECT_EQ( foo.name, ".foo__Fii" );
    EXPECT_EQ( foo.scope, mwobj::SymbolScope::Global );
    EXPECT_EQ( mwobj::section_class_name( foo.sectionClass ), "PR" );
    EXPECT_EQ( foo.align, 4u );
    EXPECT_EQ( foo.size, 0x8u );
    EXPECT_TRUE( foo.relocs.empty() );

    const auto &main{ obj->code[1] };
    EXPECT_EQ( main.name, ".main" );
    EXPECT_EQ( main.size, 0x28u );
    ASSERT_EQ( main.relocs.size(), 1u );
    EXPECT_EQ( main.relocs[0].offset, 0x14u );
    EXPECT_EQ( main.relocs[0].type, mwobj::RelocationType::Branch24 );
    EXPECT_EQ( main.relocs[0].name, ".foo__Fii" );
}

TEST( MwObjParser, ParsesDataEntries )
{
    const auto obj{ mwobj::parse( fixture_path() ) };
    ASSERT_TRUE( obj.has_value() ) << obj.error();

    ASSERT_EQ( obj->data.size(), 4u );

    const auto &at11{ obj->data[0] };
    EXPECT_EQ( at11.name, "@11" );
    EXPECT_EQ( at11.scope, mwobj::SymbolScope::Local );
    EXPECT_EQ( mwobj::section_class_name( at11.sectionClass ), "TI" );
    EXPECT_EQ( at11.size, 0xCu );
    ASSERT_EQ( at11.relocs.size(), 1u );
    EXPECT_EQ( at11.relocs[0].type, mwobj::RelocationType::Rl32 );
    EXPECT_EQ( at11.relocs[0].name, ".main" );

    const auto &mainData{ obj->data[1] };
    EXPECT_EQ( mainData.name, "main" );
    EXPECT_EQ( mainData.scope, mwobj::SymbolScope::Global );
    EXPECT_EQ( mwobj::section_class_name( mainData.sectionClass ), "DS" );
    EXPECT_EQ( mainData.size, 0x8u );
    ASSERT_EQ( mainData.relocs.size(), 2u );
    EXPECT_EQ( mainData.relocs[0].offset, 0x0u );
    EXPECT_EQ( mainData.relocs[0].type, mwobj::RelocationType::Abs32 );
    EXPECT_EQ( mainData.relocs[0].name, ".main" );
    EXPECT_EQ( mainData.relocs[1].offset, 0x4u );
    EXPECT_EQ( mainData.relocs[1].type, mwobj::RelocationType::Abs32 );
    EXPECT_EQ( mainData.relocs[1].name, "TOC" );

    const auto &fooData{ obj->data[2] };
    EXPECT_EQ( fooData.name, "foo__Fii" );
    ASSERT_EQ( fooData.relocs.size(), 2u );

    const auto &toc{ obj->data[3] };
    EXPECT_EQ( toc.name, "TOC" );
    EXPECT_EQ( mwobj::section_class_name( toc.sectionClass ), "TC0" );
    EXPECT_EQ( toc.size, 0x0u );
}

TEST( MwObjParser, NoImportsMethodRefsOrClassDefs )
{
    const auto obj{ mwobj::parse( fixture_path() ) };
    ASSERT_TRUE( obj.has_value() ) << obj.error();

    EXPECT_TRUE( obj->imports.empty() );
    EXPECT_TRUE( obj->methodRefs.empty() );
    EXPECT_TRUE( obj->classDefs.empty() );
}

TEST( MwObjParser, RejectsNonMwobjFile )
{
    const auto obj{ mwobj::parse( fixture_path().parent_path() / "does_not_exist.o" ) };
    EXPECT_FALSE( obj.has_value() );
}

TEST( MwObjDiff, SelfComparisonHasNoDiffs )
{
    const auto obj{ mwobj::parse( fixture_path() ) };
    ASSERT_TRUE( obj.has_value() ) << obj.error();

    const std::vector<std::string> diffs{ mwobj::compare_objects( *obj, *obj ) };
    EXPECT_TRUE( diffs.empty() ) << [&] {
        std::string s;
        for (const auto &d : diffs)
            s += d + "\n";
        return s;
    }();
}

TEST( MwObjDiff, DetectsCodeByteMutation )
{
    const auto objRes{ mwobj::parse( fixture_path() ) };
    ASSERT_TRUE( objRes.has_value() ) << objRes.error();

    mwobj::ObjectFile mutated{ *objRes };
    ASSERT_FALSE( mutated.code.empty() );
    ASSERT_FALSE( mutated.code[0].bytes.empty() );
    mutated.code[0].bytes[0] ^= 0xFF;

    const std::vector<std::string> diffs{ mwobj::compare_objects( *objRes, mutated ) };
    EXPECT_FALSE( diffs.empty() );
}

TEST( MwObjDiff, DetectsRelocationMismatch )
{
    const auto objRes{ mwobj::parse( fixture_path() ) };
    ASSERT_TRUE( objRes.has_value() ) << objRes.error();

    mwobj::ObjectFile mutated{ *objRes };
    ASSERT_FALSE( mutated.code[1].relocs.empty() );
    mutated.code[1].relocs[0].offset += 4;

    const std::vector<std::string> diffs{ mwobj::compare_objects( *objRes, mutated ) };
    EXPECT_FALSE( diffs.empty() );
}

TEST( MwObjDiff, IgnoresEmbeddedPathAndDerivedOffsets )
{
    const auto objRes{ mwobj::parse( fixture_path() ) };
    ASSERT_TRUE( objRes.has_value() ) << objRes.error();

    static constexpr unsigned int Sentinel_Value{ 0x40 };

    mwobj::ObjectFile mutated{ *objRes };
    mutated.embeddedPath = "/some/totally/different/sandbox/path/test.cpp";
    mutated.fileHdr.filePathOffset += Sentinel_Value;
    mutated.fileHdr.objOffset += Sentinel_Value;
    for (auto &entry : mutated.code)
        entry.fileOffset += Sentinel_Value;
    for (auto &entry : mutated.data)
        entry.fileOffset += Sentinel_Value;

    const std::vector<std::string> diffs{ mwobj::compare_objects( *objRes, mutated ) };
    EXPECT_TRUE( diffs.empty() ) << [&] {
        std::string s;
        for (const auto &d : diffs)
            s += d + "\n";
        return s;
    }();
}
