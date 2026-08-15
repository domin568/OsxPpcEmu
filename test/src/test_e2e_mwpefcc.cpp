/**
 * Author:    domin568
 * Created:   13.07.2026
 * Brief:     End-to-end test: run OsxPpcEmu emulating mwpefcc to compile a C/C++ source file,
 *            compare the produced object file against a golden file.
 **/
#include "BinaryDiff.hpp"
#include "MwObjDiff.hpp"
#include "MwObjParser.hpp"
#include "ProcessRunner.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <sstream>
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

// Files that must exist for the test to run (see MANIFEST.txt).
std::vector<fs::path> required_paths()
{
    const fs::path root{ fixture_root() };
    return {
        root / "cw" / "tools" / "mwpefcc",    root / "expected" / "test.cpp.o",       root / "input" / "test.cpp",
        root / "expected" / "emu_test.cpp.o", root / "input" / "emu_test.cpp",        root / "expected" / "sin.cpp.o",
        root / "input" / "sin.cpp",           root / "expected" / "thunk_test.cpp.o", root / "input" / "thunk_test.cpp",
    };
}

// Returns a human-readable reason the fixtures are incomplete, or empty string if all present.
std::string missing_fixtures_reason()
{
    for (const fs::path &p : required_paths())
        if (!fs::exists( p ))
            return "missing required file: " + p.string();
    return {};
}

} // namespace

class MwpefccE2E : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        const std::string reason{ missing_fixtures_reason() };
        if (!reason.empty())
            GTEST_FAIL() << "E2E fixtures incomplete (" << reason
                         << "). See test/test_files/e2e/MANIFEST.txt for what's required.";

#ifdef DEBUGGER_ENABLED
        GTEST_SKIP() << "E2E test requires a release build with DEBUGGER_ENABLED=OFF "
                        "(debug build blocks on the interactive debugger prompt).";
#endif

        m_sandbox = make_unique_sandbox_dir( "osxppcemu_e2e" );
        ASSERT_FALSE( m_sandbox.empty() ) << "Failed to create a unique sandbox directory";

        const fs::path root{ fixture_root() };
        fs::copy( root / "cw", m_sandbox / "cw", fs::copy_options::recursive );
        fs::create_directories( m_sandbox / "src" );
        fs::copy( root / "input", m_sandbox / "src", fs::copy_options::recursive );
        fs::create_directories( m_sandbox / "output" );

#ifndef _WIN32
        fs::permissions( m_sandbox / "cw" / "tools" / "mwpefcc",
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
            std::error_code ec{};
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

        return {
            "CWINSTALL=" + ( m_sandbox / "cw" ).string(),
            "MWCIncludes=" + mwCIncludes,
        };
    }

    void compile_and_compare( const std::string &sourceFileName, const std::string &outputName,
                              std::vector<std::string> additionalSwitches = {} )
    {
        const fs::path mwpefcc{ m_sandbox / "cw" / "tools" / "mwpefcc" };
        const fs::path libs{ m_sandbox / "cw" / "libs" };

        std::vector<std::string> argv{
            EMU_BINARY, mwpefcc.string(), "-c", "-v", "-v", "-v", "src/" + sourceFileName, "-o", "output/" + outputName,
        };
        std::ranges::copy( additionalSwitches, std::back_inserter( argv ) );
        const std::vector<std::string> env{ get_env_vars( libs ) };

        const testutil::ProcessResult result{ testutil::run_process( argv, m_sandbox, env ) };

        ASSERT_TRUE( result.launched ) << "Failed to launch emulator binary: " << EMU_BINARY;
        EXPECT_EQ( result.exitCode, 0 ) << "stdout:\n" << result.stdoutText << "\nstderr:\n" << result.stderrText;

        const fs::path outputFile{ m_sandbox / "output" / outputName };
        ASSERT_TRUE( fs::exists( outputFile ) ) << "Compiler did not produce an output file.\nstdout:\n"
                                                << result.stdoutText << "\nstderr:\n"
                                                << result.stderrText;
        EXPECT_GT( fs::file_size( outputFile ), 0u ) << "Compiler produced empty file";

        const fs::path expected{ fixture_root() / "expected" / outputName };

        // Parse both object files structure-by-structure and compare semantically instead of
        // byte-by-byte: the embedded source path (and everything whose offset/size depends on
        // its length) legitimately differs between the golden fixture and this sandbox build,
        // and the compiler is known to leave uninitialized memory in padding/reserved bytes.
        const auto expectedObj{ mwobj::parse( expected ) };
        const auto actualObj{ mwobj::parse( outputFile ) };
        ASSERT_TRUE( expectedObj.has_value() )
            << "Failed to parse golden object file " << expected.string() << ": " << expectedObj.error();
        ASSERT_TRUE( actualObj.has_value() )
            << "Failed to parse emulator-produced object file " << outputFile.string() << ": " << actualObj.error();

        const std::vector<std::string> diffs{ mwobj::compare_objects( *expectedObj, *actualObj ) };
        if (!diffs.empty())
        {
            const fs::path actualCopy{ expected.string() + ".actual" };
            std::error_code ec;
            fs::copy_file( outputFile, actualCopy, fs::copy_options::overwrite_existing, ec );

            std::ostringstream oss;
            oss << "MWOBPPC object files differ semantically:\n"
                << "  expected: " << expected.string() << "\n"
                << "  actual:   " << outputFile.string() << "\n";
            for (const std::string &d : diffs)
                oss << "  - " << d << "\n";
            ADD_FAILURE() << oss.str() << "Actual output copied to: " << actualCopy.string();
        }
    }

    fs::path m_sandbox{};
};

TEST_F( MwpefccE2E, CodeWarriorCompileSimple )
{
    compile_and_compare( "test.cpp", "test.cpp.o" );
}

TEST_F( MwpefccE2E, CodeWarriorCompileCMathIOStream )
{
    compile_and_compare( "emu_test.cpp", "emu_test.cpp.o" );
}

TEST_F( MwpefccE2E, CodeWarriorCompileSimpleMath )
{
    compile_and_compare( "sin.cpp", "sin.cpp.o" );
}

TEST_F( MwpefccE2E, CodeWarriorCompilePolymorphic )
{
    compile_and_compare( "thunk_test.cpp", "thunk_test.cpp.o" );
}

TEST_F( MwpefccE2E, CodeWarriorCompileCMathIOStreamO2 )
{
    compile_and_compare( "emu_test.cpp", "emu_test_O2.cpp.o", { "-O2" } );
}

TEST_F( MwpefccE2E, CodeWarriorCompileCMathIOStreamO3 )
{
    compile_and_compare( "emu_test.cpp", "emu_test_O3.cpp.o", { "-O3" } );
}

TEST_F( MwpefccE2E, CodeWarriorCompileCMathIOStreamO4 )
{
    compile_and_compare( "emu_test.cpp", "emu_test_O4.cpp.o", { "-O4" } );
}

TEST_F( MwpefccE2E, CodeWarriorCompileInterfaceLib )
{
    compile_and_compare( "simple_alert.cpp", "simple_alert.cpp.o" );
}