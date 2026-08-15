/**
 * Author:    domin568
 * Created:   15.08.2026
 * Brief:     Minimal POSIX compatibility shims for MSVC/Windows
 **/
#pragma once

#ifdef _WIN32

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <crtdbg.h>     
#include <filesystem>
#include <sys/stat.h>
#include <sys/utime.h> 
#include <direct.h>    
#include <io.h>         
#include <process.h>

#ifndef PATH_MAX
#define PATH_MAX _MAX_PATH
#endif

#ifndef S_ISDIR
#define S_ISDIR( m ) ( ( ( m ) & S_IFMT ) == S_IFDIR )
#endif
#ifndef S_ISREG
#define S_ISREG( m ) ( ( ( m ) & S_IFMT ) == S_IFREG )
#endif

#ifndef _MODE_T_DEFINED
#define _MODE_T_DEFINED
typedef unsigned short mode_t;
#endif

// Restore the POSIX contract by installing a no-op handler and routing CRT reports to stderr rather than a modal dialog.
// POSIX file APIs report bad file descriptors by returning -1 and setting errno to EBADF.
// The UCRT instead routes them through the "invalid parameter" path, which under a debug CRT
// raises an assertion dialog
inline void init_crt_posix_error_semantics()
{
    _set_invalid_parameter_handler([]( const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t ) {} );
#ifdef _DEBUG
    for (int report : { _CRT_WARN, _CRT_ERROR, _CRT_ASSERT })
    {
        _CrtSetReportMode( report, _CRTDBG_MODE_FILE );
        _CrtSetReportFile( report, _CRTDBG_FILE_STDERR );
    }
#endif
}

inline ssize_t pread( int fd, void *buf, size_t count, long offset )
{
    const long saved{ ::_tell( fd ) };
    if (saved == -1 || ::_lseek( fd, offset, SEEK_SET ) == -1)
        return -1;
    const int n{ ::_read( fd, buf, static_cast<unsigned int>( count ) ) };
    ::_lseek( fd, saved, SEEK_SET );
    return n;
}

inline ssize_t pwrite( int fd, const void *buf, size_t count, long offset )
{
    const long saved{ ::_tell( fd ) };
    if (saved == -1 || ::_lseek( fd, offset, SEEK_SET ) == -1)
        return -1;
    const int n{ ::_write( fd, buf, static_cast<unsigned int>( count ) ) };
    ::_lseek( fd, saved, SEEK_SET );
    return n;
}

inline char *realpath( const char *path, char *resolved )
{
    if (path == nullptr || resolved == nullptr)
    {
        errno = EINVAL;
        return nullptr;
    }
    if (::_fullpath( resolved, path, PATH_MAX ) == nullptr)
    {
        errno = ENOENT;
        return nullptr;
    }
    struct stat st{};
    if (::stat( resolved, &st ) != 0)
        return nullptr; // errno already set by stat()
    return resolved;
}

inline int lstat( const char *path, struct stat *buf )
{
    return ::stat( path, buf );
}

inline ssize_t readlink( const char *, char *, size_t )
{
    errno = EINVAL;
    return -1;
}

inline int getdtablesize()
{
    return 2048;
}

struct dirent
{
    std::uint32_t d_ino{};
    unsigned short d_reclen{};
    unsigned char d_type{};
    char d_name[260]{};
};

struct DIR
{
    std::filesystem::directory_iterator it;
    std::filesystem::directory_iterator end;
    dirent entry{};
    int synthetic{ 0 }; // 0 -> ".", 1 -> "..", 2 -> real entries (mirrors POSIX readdir())
};

inline DIR *opendir( const char *path )
{
    std::error_code ec;
    if (!std::filesystem::is_directory( path, ec ) || ec)
    {
        errno = ENOENT;
        return nullptr;
    }
    std::filesystem::directory_iterator it{ std::filesystem::path{ path }, ec };
    if (ec)
    {
        errno = ENOENT;
        return nullptr;
    }
    DIR *d{ new DIR{} };
    d->it = it;
    return d;
}

inline struct dirent *readdir( DIR *dirp )
{
    if (dirp == nullptr)
    {
        errno = EBADF;
        return nullptr;
    }

    std::memset( &dirp->entry, 0, sizeof( dirp->entry ) );
    dirp->entry.d_reclen = static_cast<unsigned short>( sizeof( dirent ) );

    if (dirp->synthetic == 0)
    {
        std::strcpy( dirp->entry.d_name, "." );
        dirp->entry.d_type = 4; // DT_DIR
        dirp->synthetic = 1;
        return &dirp->entry;
    }
    if (dirp->synthetic == 1)
    {
        std::strcpy( dirp->entry.d_name, ".." );
        dirp->entry.d_type = 4; // DT_DIR
        dirp->synthetic = 2;
        return &dirp->entry;
    }

    if (dirp->it == dirp->end)
        return nullptr; // end of directory (errno left untouched, matching POSIX)

    std::error_code ec;
    const auto &path{ dirp->it->path() };
    const std::string name{ path.filename().string() };
    std::strncpy( dirp->entry.d_name, name.c_str(), sizeof( dirp->entry.d_name ) - 1 );
    dirp->entry.d_type = dirp->it->is_directory( ec ) ? 4u : 8u; // DT_DIR : DT_REG
    dirp->entry.d_ino = static_cast<std::uint32_t>( std::filesystem::hash_value( path ) );
    ++dirp->it;
    return &dirp->entry;
}

inline int closedir( DIR *dirp )
{
    delete dirp;
    return 0;
}

#endif // _WIN32
