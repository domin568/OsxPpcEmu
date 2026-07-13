/**
 * Author:    domin568
 * Brief:     Minimal child-process launcher for E2E tests (explicit argv/envp/cwd, captured stdout+stderr).
 **/
#pragma once

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#endif

namespace testutil
{

struct ProcessResult
{
    int exitCode{ -1 };
    bool launched{ false };
    std::string stdoutText{};
    std::string stderrText{};
};

// Runs `argv[0]` with the given arguments, working directory and an *explicit*
// environment (the parent's environment is not inherited unless included in `env`).
// `env` entries must be in "KEY=VALUE" form. stdout/stderr are captured to files
// under `cwd` and read back into the result.
inline ProcessResult run_process( const std::vector<std::string> &argv, const std::filesystem::path &cwd,
                                  const std::vector<std::string> &env )
{
    ProcessResult result{};
    const std::filesystem::path stdoutPath{ cwd / "stdout.txt" };
    const std::filesystem::path stderrPath{ cwd / "stderr.txt" };

#ifdef _WIN32
    std::string cmdLine;
    for (const std::string &a : argv)
    {
        if (!cmdLine.empty())
            cmdLine += ' ';
        cmdLine += '"' + a + '"';
    }

    std::string envBlock;
    for (const std::string &e : env)
        envBlock += e + '\0';
    envBlock += '\0';

    SECURITY_ATTRIBUTES sa{ sizeof( SECURITY_ATTRIBUTES ), nullptr, TRUE };
    HANDLE hOut{ CreateFileA( stdoutPath.string().c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr ) };
    HANDLE hErr{ CreateFileA( stderrPath.string().c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr ) };

    STARTUPINFOA si{};
    si.cb = sizeof( si );
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hOut;
    si.hStdError = hErr;
    si.hStdInput = GetStdHandle( STD_INPUT_HANDLE );

    PROCESS_INFORMATION pi{};
    const std::string cwdStr{ cwd.string() };
    const BOOL ok{ CreateProcessA( nullptr, cmdLine.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                                   envBlock.data(), cwdStr.c_str(), &si, &pi ) };
    if (hOut)
        CloseHandle( hOut );
    if (hErr)
        CloseHandle( hErr );

    if (!ok)
    {
        result.launched = false;
        return result;
    }
    result.launched = true;
    WaitForSingleObject( pi.hProcess, INFINITE );
    DWORD code{ 0 };
    GetExitCodeProcess( pi.hProcess, &code );
    result.exitCode = static_cast<int>( code );
    CloseHandle( pi.hProcess );
    CloseHandle( pi.hThread );
#else
    std::vector<char *> cArgv;
    cArgv.reserve( argv.size() + 1 );
    for (const std::string &a : argv)
        cArgv.push_back( const_cast<char *>( a.c_str() ) );
    cArgv.push_back( nullptr );

    std::vector<char *> cEnv;
    cEnv.reserve( env.size() + 1 );
    for (const std::string &e : env)
        cEnv.push_back( const_cast<char *>( e.c_str() ) );
    cEnv.push_back( nullptr );

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init( &actions );
    posix_spawn_file_actions_addopen( &actions, STDOUT_FILENO, stdoutPath.string().c_str(),
                                      O_WRONLY | O_CREAT | O_TRUNC, 0644 );
    posix_spawn_file_actions_addopen( &actions, STDERR_FILENO, stderrPath.string().c_str(),
                                      O_WRONLY | O_CREAT | O_TRUNC, 0644 );
#ifdef __APPLE__
    posix_spawn_file_actions_addchdir_np( &actions, cwd.string().c_str() );
#else
    posix_spawn_file_actions_addchdir( &actions, cwd.string().c_str() );
#endif

    pid_t pid{};
    const int spawnErr{ posix_spawn( &pid, argv[0].c_str(), &actions, nullptr, cArgv.data(), cEnv.data() ) };
    posix_spawn_file_actions_destroy( &actions );

    if (spawnErr != 0)
    {
        result.launched = false;
        return result;
    }
    result.launched = true;

    int status{ 0 };
    waitpid( pid, &status, 0 );
    result.exitCode = WIFEXITED( status ) ? WEXITSTATUS( status ) : -1;
#endif

    const auto slurp{ [&]( const std::filesystem::path &p ) {
        std::ifstream f( p, std::ios::binary );
        std::ostringstream oss;
        oss << f.rdbuf();
        return oss.str();
    } };
    result.stdoutText = slurp( stdoutPath );
    result.stderrText = slurp( stderrPath );
    return result;
}

} // namespace testutil
