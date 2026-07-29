/**
 * Author:    domin568
 * Created:   13.07.2026
 * Brief:     End-to-end test: run OsxPpcEmu emulating mwpefld to link a PPC object file,
 *            compare the produced Mach-O against a golden file.
 **/
#include "BinaryDiff.hpp"
#include "ProcessRunner.hpp"
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <vector>
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace
{

fs::path fixture_root()
{
    return fs::path( TEST_FOLDER ) / "test_files" / "e2e";
}

long getpid_wrapper()
{
#ifdef _WIN32
    return static_cast<long>( GetCurrentProcessId() );
#else
    return static_cast<long>( ::getpid() );
#endif
}

fs::path make_unique_sandbox_dir( const std::string &prefix )
{
    const auto pid{ static_cast<unsigned long>( getpid_wrapper() ) };
    static std::atomic<unsigned long> counter{ 0 };
    for (int attempt = 0; attempt < 100; ++attempt)
    {
        const auto nowNs{
            static_cast<unsigned long long>( std::chrono::high_resolution_clock::now().time_since_epoch().count() ) };
        const fs::path candidate{ fs::temp_directory_path() /
                                  ( prefix + "_" + std::to_string( pid ) + "_" + std::to_string( ++counter ) + "_" +
                                    std::to_string( nowNs ) ) };
        std::error_code ec;
        if (fs::create_directory( candidate, ec ) && !ec)
            return candidate;
    }
    ADD_FAILURE() << "Could not create a unique sandbox directory after 100 attempts";
    return {};
}

// Files that must exist for the test to run (see MANIFEST.txt). Library files are checked by
// directory-non-empty rather than exact name, since the exact runtime lib set can vary.
std::vector<fs::path> required_paths()
{
    const fs::path root{ fixture_root() };
    return {
        root / "cw" / "tools" / "mwpefld",       root / "expected" / "cw_stress_test",
        root / "input" / "cw_stress_test.cpp.o", root / "expected" / "emu_test",
        root / "input" / "emu_test.cpp.o",
    };
}

std::vector<fs::path> required_lib_dirs()
{
    const fs::path root{ fixture_root() };
    return {
        root / "cw" / "libs" / "MSL" / "MSL_C" / "MSL_Common" / "Include",
        root / "cw" / "libs" / "MSL" / "MSL_C" / "MSL_MacOS" / "Include",
        root / "cw" / "libs" / "MSL" / "MSL_C" / "MSL_MacOS" / "Lib" / "PPC",
        root / "cw" / "libs" / "MSL" / "MSL_C++" / "MSL_Common" / "Include",
        root / "cw" / "libs" / "MSL" / "MSL_C++" / "MSL_MacOS" / "Lib" / "PPC",
        root / "cw" / "libs" / "MSL" / "MSL_Extras" / "MSL_Common" / "Include",
        root / "cw" / "libs" / "MSL" / "MSL_Extras" / "MSL_MacOS" / "Lib" / "PPC",
        root / "cw" / "libs" / "MacOS Support" / "Libraries" / "Runtime" / "Libs",
        root / "cw" / "libs" / "MacOS Support" / "Universal" / "Interfaces" / "CIncludes",
        root / "cw" / "libs" / "MacOS Support" / "Universal" / "Libraries" / "StubLibraries",
    };
}

bool dir_has_files( const fs::path &dir )
{
    if (!fs::exists( dir ) || !fs::is_directory( dir ))
        return false;
    for (const auto &entry : fs::directory_iterator( dir ))
        if (entry.is_regular_file() && entry.path().filename() != ".gitkeep")
            return true;
    return false;
}

// Returns a human-readable reason the fixtures are incomplete, or empty string if all present.
std::string missing_fixtures_reason()
{
    for (const fs::path &p : required_paths())
        if (!fs::exists( p ))
            return "missing required file: " + p.string();
    for (const fs::path &d : required_lib_dirs())
        if (!dir_has_files( d ))
            return "missing library files under: " + d.string();
    return {};
}

} // namespace

class MwpefldE2E : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        const std::string reason{ missing_fixtures_reason() };
        if (!reason.empty())
            GTEST_FAIL() << "E2E fixtures incomplete (" << reason
                         << "). See test/test_files/e2e/MANIFEST.txt for what's required.";

#ifdef DEBUGGER_ENABLED
        GTEST_SKIP() << "E2E test requires a release build with ENABLE_DEBUGGER=OFF "
                        "(debug build blocks on the interactive debugger prompt).";
#endif
        m_sandbox = make_unique_sandbox_dir( "osxppcemu_e2e" );
        ASSERT_FALSE( m_sandbox.empty() ) << "Failed to create a unique sandbox directory";

        const fs::path root{ fixture_root() };
        fs::copy( root / "cw", m_sandbox / "cw", fs::copy_options::recursive );
        fs::create_directories( m_sandbox / "src" );
        fs::copy_file( root / "input" / "cw_stress_test.cpp.o", m_sandbox / "src" / "cw_stress_test.cpp.o" );
        fs::copy_file( root / "input" / "emu_test.cpp.o", m_sandbox / "src" / "emu_test.cpp.o" );
        fs::create_directories( m_sandbox / "output" );

#ifndef _WIN32
        fs::permissions( m_sandbox / "cw" / "tools" / "mwpefld",
                         fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read |
                             fs::perms::others_exec,
                         fs::perm_options::add );
#endif
    }

    void TearDown() override
    {
        if (m_sandbox.empty())
            return;
        const bool keep{ HasFailure() || std::getenv( "OSXPPCEMU_E2E_KEEP" ) != nullptr };
        if (keep)
        {
            std::cerr << "[E2E] sandbox kept at: " << m_sandbox.string() << std::endl;
        }
        else
        {
            std::error_code ec;
            fs::remove_all( m_sandbox, ec );
        }
    }

    std::vector<std::string> get_env_vars( const fs::path &libs )
    {
        const std::string mwCIncludes{ ( libs / "MSL" / "MSL_C" / "MSL_Common" / "Include" ).string() + ":" +
                                       ( libs / "MSL" / "MSL_C" / "MSL_MacOS" / "Include" ).string() + ":" +
                                       ( libs / "MSL" / "MSL_C++" / "MSL_Common" / "Include" ).string() + ":" +
                                       ( libs / "MSL" / "MSL_Extras" / "MSL_Common" / "Include" ).string() + ":" +
                                       ( libs / "MSL" / "MSL_Extras" / "MSL_MacOS" / "Include" ).string() + ":" +
                                       ( libs / "MacOS Support" / "Universal" / "Interfaces" / "CIncludes" ).string() };

        const std::string mwPefLibraries{
            ( libs / "MacOS Support" / "Universal" / "Libraries" / "StubLibraries" ).string() + ":" +
            ( libs / "MSL" / "MSL_C" / "MSL_MacOS" / "Lib" / "PPC" ).string() + ":" +
            ( libs / "MSL" / "MSL_C++" / "MSL_MacOS" / "Lib" / "PPC" ).string() + ":" +
            ( libs / "MacOS Support" / "Libraries" / "Runtime" / "Libs" ).string() };

        return {
            "CWINSTALL=" + ( m_sandbox / "cw" ).string(),
            "MWFrameworkVersions=System",
            "MWCIncludes=" + mwCIncludes,
            "MWPEFLibraries=" + mwPefLibraries,
            "MWPEFLibraryFiles=MSL_All_Carbon.Lib:CarbonLib",
        };
    }

    // Runs mwpefld (emulated) linking `objectFileName` (already copied into sandbox/src by SetUp)
    // into `outputName`, then compares the produced Mach-O against the golden file with the same
    // name under test_files/e2e/expected/.
    void link_and_compare( const std::string &objectFileName, const std::string &outputName )
    {
        const fs::path mwpefld{ m_sandbox / "cw" / "tools" / "mwpefld" };
        const fs::path libs{ m_sandbox / "cw" / "libs" };

        const std::vector<std::string> argv{
            EMU_BINARY, mwpefld.string(), "-v", "-v", "-v", "src/" + objectFileName, "-o", "output/" + outputName,
        };

        const std::vector<std::string> env{ get_env_vars( libs ) };
        const testutil::ProcessResult result{ testutil::run_process( argv, m_sandbox, env ) };

        ASSERT_TRUE( result.launched ) << "Failed to launch emulator binary: " << EMU_BINARY;
        EXPECT_EQ( result.exitCode, 0 ) << "stdout:\n" << result.stdoutText << "\nstderr:\n" << result.stderrText;

        const fs::path outputFile{ m_sandbox / "output" / outputName };
        ASSERT_TRUE( fs::exists( outputFile ) ) << "Linker did not produce an output file.\nstdout:\n"
                                                << result.stdoutText << "\nstderr:\n"
                                                << result.stderrText;
        EXPECT_GT( fs::file_size( outputFile ), 0u );

        const fs::path expected{ fixture_root() / "expected" / outputName };

        static constexpr std::size_t pefTimestampOffset{ 0x10 };
        // known-noisy regions (paths, uninitialized compiler memory)
        testutil::DiffSetup setup{ .expected{ expected },
                                   .actual{ outputFile },
                                   .expectedStartOff{ 0 },
                                   .actualStartOff{ 0 },
                                   .ignore{ { pefTimestampOffset, sizeof( std::uint32_t ) } },
                                   .maxRegions{ 32 } };

        const testutil::DiffResult diff{ testutil::compare_files( setup ) };
        if (!diff.equal)
        {
            const fs::path actualCopy{ expected.string() + ".actual" };
            std::error_code ec;
            fs::copy_file( outputFile, actualCopy, fs::copy_options::overwrite_existing, ec );
            ADD_FAILURE() << testutil::format_diff_report( diff, expected, outputFile )
                          << "\nActual output copied to: " << actualCopy.string();
        }
    }

    fs::path m_sandbox{};
};

TEST_F( MwpefldE2E, CodeWarriorLinkFile1 )
{
    link_and_compare( "cw_stress_test.cpp.o", "cw_stress_test" );
}

TEST_F( MwpefldE2E, CodeWarriorLinkFile2 )
{
    link_and_compare( "emu_test.cpp.o", "emu_test" );
}
