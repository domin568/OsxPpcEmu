/**
 * Author:    domin568
 * Brief:     End-to-end test: run OsxPpcEmu emulating mwpefcc to compile a C/C++ source file,
 *            compare the produced object file against a golden file.
 *
 * Self-contained: builds an isolated sandbox directory per run under the system temp dir and
 * populates it from test/test_files/e2e/. Requires fixtures listed in test/test_files/e2e/MANIFEST.txt;
 * if any are missing the test is skipped (not failed) so the rest of the suite stays green without a
 * real CodeWarrior install.
 **/
#include "BinaryDiff.hpp"
#include "ProcessRunner.hpp"

#include <algorithm>
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
        const auto nowNs{ static_cast<unsigned long long>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count() ) };
        const fs::path candidate{ fs::temp_directory_path() /
                                   ( prefix + "_" + std::to_string( pid ) + "_" + std::to_string( ++counter ) +
                                     "_" + std::to_string( nowNs ) ) };
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
        root / "cw" / "tools" / "mwpefcc",
        root / "expected" / "test.cpp.o",
        root / "input" / "test.cpp",
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
            GTEST_SKIP() << "E2E fixtures incomplete (" << reason
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
        fs::copy_file( root / "input" / "test.cpp", m_sandbox / "src" / "test.cpp" );
        fs::create_directories( m_sandbox / "output" );

#ifndef _WIN32
        fs::permissions( m_sandbox / "cw" / "tools" / "mwpefcc",
                         fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec |
                             fs::perms::others_read | fs::perms::others_exec,
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

    std::optional<std::uint64_t> get_powr_header_offset(const std::filesystem::path &filePath)
    {
        std::ifstream file{ filePath, std::ios::binary };
        if (!file)
            return std::nullopt;

        static constexpr uintmax_t Search_Range{ 0x400 };
        std::array<char, Search_Range> buffer{};
        const auto fsz{ std::filesystem::file_size(filePath) };
        const auto toRead{ std::min(fsz, Search_Range) };
        file.read(reinterpret_cast<char*>(buffer.data()), toRead);
        if (!file)
            return std::nullopt;

        static constexpr std::array<char, 4> magic{ 'P', 'O', 'W', 'R' };

        const auto result{ std::ranges::search(buffer.begin(), buffer.end(), magic.begin(), magic.end()) };
        if (result.empty())
            return std::nullopt;
        return std::distance(buffer.begin(), result.begin());
    }

    void compile_and_compare( const std::string &sourceFileName, const std::string &outputName )
    {
        const fs::path mwpefcc{ m_sandbox / "cw" / "tools" / "mwpefcc" };

        const std::vector<std::string> argv
        {
            EMU_BINARY, mwpefcc.string(), "-c", "-v", "-v", "-v", "src/" + sourceFileName, "-o",
            "output/" + outputName,
        };

        const std::vector<std::string> env
        {
            "CWINSTALL=" + ( m_sandbox / "cw" ).string(),
            "MWFrameworkVersions=System",
            "MWCIncludes=" + ( m_sandbox / "cw" / "tools" ).string(),
        };

        const testutil::ProcessResult result{ testutil::run_process( argv, m_sandbox, env ) };

        ASSERT_TRUE( result.launched ) << "Failed to launch emulator binary: " << EMU_BINARY;
        EXPECT_EQ( result.exitCode, 0 ) << "stdout:\n"
                                        << result.stdoutText << "\nstderr:\n"
                                        << result.stderrText;

        const fs::path outputFile{ m_sandbox / "output" / outputName };
        ASSERT_TRUE( fs::exists( outputFile ) ) << "Compiler did not produce an output file.\nstdout:\n"
                                                << result.stdoutText << "\nstderr:\n"
                                                << result.stderrText;
        EXPECT_GT( fs::file_size( outputFile ), 0u ) << "Compiler produced empty file";

        const fs::path expected{ fixture_root() / "expected" / outputName };

        const auto expectedPowrOff{ get_powr_header_offset(expected) };
        const auto actualPowrOff{ get_powr_header_offset(outputFile) };
        ASSERT_TRUE(expectedPowrOff.has_value()) << "Could not find POWR header in expected file";
        ASSERT_TRUE(actualPowrOff.has_value()) << "Could not find POWR header in actual file";

        const testutil::DiffResult diff{ testutil::compare_files( expected, outputFile, *expectedPowrOff, *actualPowrOff ) };
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

TEST_F( MwpefccE2E, CodeWarriorCompileFile1 )
{
    compile_and_compare( "test.cpp", "test.cpp.o" );
}

