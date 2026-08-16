/**
 * Author:    domin568
 * Created:   16.08.2026
 * Brief:     Unit tests for fs_translate (guest <-> host / MSYS path translation)
 **/
#include "platform/FsTranslate.hpp"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace
{
long getpid_wrapper()
{
#ifdef _WIN32
    return static_cast<long>( ::_getpid() );
#else
    return static_cast<long>( ::getpid() );
#endif
}
} // namespace

#ifdef _WIN32

// ── msys_to_host_path ────────────────────────────────────────────────────

TEST( FsTranslateMsysToHost, ConvertsDriveRootedPath )
{
    const auto host{ fs_translate::msys_to_host_path( "/c/Projects/OsxPpcEmu" ) };
    ASSERT_TRUE( host.has_value() );
    EXPECT_EQ( *host, "c:\\Projects\\OsxPpcEmu" );
}

TEST( FsTranslateMsysToHost, ConvertsBareDriveRoot )
{
    const auto host{ fs_translate::msys_to_host_path( "/c" ) };
    ASSERT_TRUE( host.has_value() );
    EXPECT_EQ( *host, "c:\\" );
}

TEST( FsTranslateMsysToHost, PreservesUppercaseDriveLetterAsIs )
{
    // The function does not itself normalise case; it only builds "<letter>:\..."
    const auto host{ fs_translate::msys_to_host_path( "/C/Windows" ) };
    ASSERT_TRUE( host.has_value() );
    EXPECT_EQ( *host, "C:\\Windows" );
}

TEST( FsTranslateMsysToHost, RejectsNonAbsolutePath )
{
    EXPECT_FALSE( fs_translate::msys_to_host_path( "relative/path" ).has_value() );
    EXPECT_FALSE( fs_translate::msys_to_host_path( "c/Projects" ).has_value() );
}

TEST( FsTranslateMsysToHost, RejectsMissingDriveLetter )
{
    // "/1" - second char is not alphabetic
    EXPECT_FALSE( fs_translate::msys_to_host_path( "/1/Projects" ).has_value() );
}

TEST( FsTranslateMsysToHost, RejectsNonMsysMultiCharSegment )
{
    // "/cw/Projects" looks like a normal absolute unix path with a multi-letter first
    // segment ("cw"), not a single-letter drive - third char must be '/' when present.
    EXPECT_FALSE( fs_translate::msys_to_host_path( "/cw/Projects" ).has_value() );
}

TEST( FsTranslateMsysToHost, RejectsTooShortInput )
{
    EXPECT_FALSE( fs_translate::msys_to_host_path( "" ).has_value() );
    EXPECT_FALSE( fs_translate::msys_to_host_path( "/" ).has_value() );
}

// ── host_to_msys_path ────────────────────────────────────────────────────

TEST( FsTranslateHostToMsys, ConvertsDriveRootedPath )
{
    const auto msys{ fs_translate::host_to_msys_path( "C:\\Projects\\OsxPpcEmu" ) };
    ASSERT_TRUE( msys.has_value() );
    EXPECT_EQ( *msys, "/c/Projects/OsxPpcEmu" );
}

TEST( FsTranslateHostToMsys, LowercasesDriveLetter )
{
    const auto msys{ fs_translate::host_to_msys_path( "D:\\Games" ) };
    ASSERT_TRUE( msys.has_value() );
    EXPECT_EQ( *msys, "/d/Games" );
}

TEST( FsTranslateHostToMsys, ConvertsBareDriveRoot )
{
    const auto msys{ fs_translate::host_to_msys_path( "C:\\" ) };
    ASSERT_TRUE( msys.has_value() );
    EXPECT_EQ( *msys, "/c" );
}

TEST( FsTranslateHostToMsys, RejectsMissingColon )
{
    EXPECT_FALSE( fs_translate::host_to_msys_path( "C\\Projects" ).has_value() );
}

TEST( FsTranslateHostToMsys, RejectsMissingBackslashAfterColon )
{
    EXPECT_FALSE( fs_translate::host_to_msys_path( "C:Projects" ).has_value() );
}

TEST( FsTranslateHostToMsys, RejectsRelativePath )
{
    EXPECT_FALSE( fs_translate::host_to_msys_path( "Projects\\OsxPpcEmu" ).has_value() );
}

TEST( FsTranslateHostToMsys, RejectsTooShortInput )
{
    EXPECT_FALSE( fs_translate::host_to_msys_path( "" ).has_value() );
    EXPECT_FALSE( fs_translate::host_to_msys_path( "C:" ).has_value() );
}

TEST( FsTranslateHostToMsys, RoundTripsThroughMsysToHost )
{
    // host_to_msys_path lowercases the drive letter, so round-tripping back through
    // msys_to_host_path preserves everything except the drive letter's case.
    const std::string original{ "c:\\Projects\\OsxPpcEmu\\test" };
    const auto msys{ fs_translate::host_to_msys_path( original ) };
    ASSERT_TRUE( msys.has_value() );
    const auto backToHost{ fs_translate::msys_to_host_path( *msys ) };
    ASSERT_TRUE( backToHost.has_value() );
    EXPECT_EQ( *backToHost, original );
}

// ── host_path_list_to_msys ───────────────────────────────────────────────

TEST( FsTranslatePathList, ConvertsSingleEmbeddedPath )
{
    const std::string value{ "C:\\cw" };
    EXPECT_EQ( fs_translate::host_path_list_to_msys( value ), "/c/cw" );
}

TEST( FsTranslatePathList, ConvertsSingleEmbeddedPathWithKeyPrefix )
{
    const std::string value{ "CWINSTALL=C:\\cw" };
    EXPECT_EQ( fs_translate::host_path_list_to_msys( value ), "CWINSTALL=/c/cw" );
}

TEST( FsTranslatePathList, ConvertsColonDelimitedListWithoutAmbiguity )
{
    // Drive-letter colons never get confused with the ':' list separator, because a
    // Windows path can never itself contain ':' or ';'.
    const std::string value{ "C:\\Projects\\a:D:\\Projects\\b" };
    EXPECT_EQ( fs_translate::host_path_list_to_msys( value ), "/c/Projects/a:/d/Projects/b" );
}

TEST( FsTranslatePathList, ConvertsSemicolonDelimitedList )
{
    const std::string value{ "C:\\Windows;C:\\Windows\\System32" };
    EXPECT_EQ( fs_translate::host_path_list_to_msys( value ), "/c/Windows;/c/Windows/System32" );
}

TEST( FsTranslatePathList, ConvertsManyPathsInMixedList )
{
    const std::string value{ "C:\\a:C:\\b:C:\\c" };
    EXPECT_EQ( fs_translate::host_path_list_to_msys( value ), "/c/a:/c/b:/c/c" );
}

TEST( FsTranslatePathList, LeavesTextWithoutDrivePathsUntouched )
{
    const std::string value{ "just some plain text, no windows paths here" };
    EXPECT_EQ( fs_translate::host_path_list_to_msys( value ), value );
}

TEST( FsTranslatePathList, LeavesEmptyStringUntouched )
{
    EXPECT_EQ( fs_translate::host_path_list_to_msys( "" ), "" );
}

TEST( FsTranslatePathList, LeavesBareDriveLetterWithoutBackslashUnconverted )
{
    // "C:" alone (no trailing backslash) is matched by the drive-letter marker, but
    // host_to_msys_path() rejects it (it requires "<letter>:\"), so it is left as-is.
    const std::string value{ "C:;D:\\Games" };
    EXPECT_EQ( fs_translate::host_path_list_to_msys( value ), "C:;/d/Games" );
}

#endif // _WIN32

struct TranslatePathFixture : ::testing::Test
{
    fs::path sandbox{};

    void SetUp() override
    {
        sandbox = fs::temp_directory_path() / ( "fstranslate_test_" + std::to_string( getpid_wrapper() ) );
        fs::remove_all( sandbox );
        fs::create_directories( sandbox );
        std::ofstream{ sandbox / "file.txt" } << "content";
    }

    void TearDown() override
    {
        std::error_code ec{};
        fs::remove_all( sandbox, ec );
    }
};

TEST_F( TranslatePathFixture, LeavesAlreadyHostPathUntouchedWhenItExists )
{
    const fs::path hostFile{ sandbox / "file.txt" };
    const fs::path translated{ fs_translate::translate_path( hostFile ) };
    EXPECT_TRUE( fs::exists( translated ) );
    EXPECT_TRUE( fs::equivalent( translated, hostFile ) );
}

TEST_F( TranslatePathFixture, ReturnsOriginalPathWhenNothingMatches )
{
    const fs::path missing{ sandbox / "does_not_exist.txt" };
    const fs::path translated{ fs_translate::translate_path( missing ) };
    EXPECT_EQ( translated, missing );
}

#ifdef _WIN32
TEST_F( TranslatePathFixture, ConvertsMsysPathToExistingHostFile )
{
    const auto msys{ fs_translate::host_to_msys_path( sandbox.string() ) };
    ASSERT_TRUE( msys.has_value() );
    const fs::path msysFile{ fs::path( *msys ) / "file.txt" };

    const fs::path translated{ fs_translate::translate_path( msysFile ) };
    EXPECT_TRUE( fs::exists( translated ) );
    EXPECT_TRUE( fs::equivalent( translated, sandbox / "file.txt" ) );
}
#endif // _WIN32

TEST_F( TranslatePathFixture, ResolvesCaseMismatchOnCaseSensitiveFilesystem )
{
    if (!fs_translate::is_filesystem_case_sensitive())
        GTEST_SKIP() << "Host filesystem is case-insensitive, skipping test";

    const fs::path actual{ sandbox / "CaseTest.TXT" };
    std::ofstream{ actual } << "content";

    const fs::path queried{ sandbox / "casetest.txt" };
    ASSERT_FALSE( fs::exists( queried ) ); // sanity check: case really does matter here

    const fs::path translated{ fs_translate::translate_path( queried ) };
    EXPECT_TRUE( fs::exists( translated ) );
    EXPECT_TRUE( fs::equivalent( translated, actual ) );
}

TEST_F( TranslatePathFixture, ResolvesCaseMismatchAcrossNestedDirectoriesOnCaseSensitiveFilesystem )
{
    if (!fs_translate::is_filesystem_case_sensitive())
        GTEST_SKIP() << "Host filesystem is case-insensitive, skipping test";

    const fs::path actualDir{ sandbox / "SubDir" };
    fs::create_directories( actualDir );
    const fs::path actualFile{ actualDir / "Nested.txt" };
    std::ofstream{ actualFile } << "content";

    const fs::path queried{ sandbox / "subdir" / "nested.txt" };
    ASSERT_FALSE( fs::exists( queried ) );

    const fs::path translated{ fs_translate::translate_path( queried ) };
    EXPECT_TRUE( fs::exists( translated ) );
    EXPECT_TRUE( fs::equivalent( translated, actualFile ) );
}

TEST_F( TranslatePathFixture, ReturnsOriginalPathWhenNoCaseInsensitiveMatchExistsOnCaseSensitiveFilesystem )
{
    if (!fs_translate::is_filesystem_case_sensitive())
        GTEST_SKIP() << "Host filesystem is case-insensitive, skipping test";

    // No entry named "nomatch.txt" exists under any casing.
    const fs::path missing{ sandbox / "nomatch.txt" };
    const fs::path translated{ fs_translate::translate_path( missing ) };
    EXPECT_EQ( translated, missing );
}

TEST_F( TranslatePathFixture, ExactCaseMatchShortCircuitsOnCaseInsensitiveFilesystem )
{
    if (fs_translate::is_filesystem_case_sensitive())
        GTEST_SKIP() << "Host filesystem is case-sensitive, skipping test";

    // On a case-insensitive filesystem, fs::exists() alone already matches regardless of
    // case, so translate_path() should hand the (differently-cased) path straight back.
    const fs::path differentCase{ sandbox / "FILE.TXT" };
    const fs::path translated{ fs_translate::translate_path( differentCase ) };
    EXPECT_TRUE( fs::exists( translated ) );
    EXPECT_TRUE( fs::equivalent( translated, sandbox / "file.txt" ) );
}
