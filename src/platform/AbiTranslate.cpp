/**
 * Author:    domin568
 * Created:   02.08.2026
 * Brief:     Guest (Darwin/Mac OS X 10.4) <-> host ABI constant translation
 **/
#include "platform/AbiTranslate.hpp"
#include <cerrno>
#include <fcntl.h>

namespace abi_translate
{

namespace
{
// Darwin (guest) O_* flag bits, from Mac OS X 10.4 <sys/fcntl.h>.
constexpr std::int32_t Darwin_O_NONBLOCK{ 0x00000004 };
constexpr std::int32_t Darwin_O_APPEND{ 0x00000008 };
constexpr std::int32_t Darwin_O_FSYNC{ 0x00000080 }; // aka O_SYNC on Darwin
constexpr std::int32_t Darwin_O_NOFOLLOW{ 0x00000100 };
constexpr std::int32_t Darwin_O_CREAT{ 0x00000200 };
constexpr std::int32_t Darwin_O_TRUNC{ 0x00000400 };
constexpr std::int32_t Darwin_O_EXCL{ 0x00000800 };
constexpr std::int32_t Darwin_O_DIRECTORY{ 0x00100000 };
} // namespace

int darwin_oflags_to_host( std::int32_t darwinFlags )
{
    // O_RDONLY/O_WRONLY/O_RDWR (0/1/2) are identical on every POSIX host.
    int hostFlags{ darwinFlags & 0x3 };

    const auto map{ [&]( std::int32_t darwinBit, int hostBit ) {
        if (darwinFlags & darwinBit)
            hostFlags |= hostBit;
    } };

    // TODO O_NONBLOCK has no exact host equivalent when the host is Windows, it's simply dropped.
    //map( Darwin_O_NONBLOCK, O_NONBLOCK );
    map( Darwin_O_APPEND, O_APPEND );
    map( Darwin_O_CREAT, O_CREAT );
    map( Darwin_O_TRUNC, O_TRUNC );
    map( Darwin_O_EXCL, O_EXCL );
#ifdef O_NOFOLLOW
    map( Darwin_O_NOFOLLOW, O_NOFOLLOW );
#endif
#ifdef O_DIRECTORY
    map( Darwin_O_DIRECTORY, O_DIRECTORY );
#endif
#ifdef O_SYNC
    map( Darwin_O_FSYNC, O_SYNC );
#endif

    return hostFlags;
}

std::int32_t host_errno_to_darwin( int hostErrno )
{
#if defined( __APPLE__ )
    // Host already IS Darwin: identity.
    return hostErrno;
#else
    // Linux (glibc/musl) -> Darwin numeric renumbering. Values below are the Darwin
    // <sys/errno.h> constants; case labels are host macros so this stays correct even if
    // a given libc renumbers something we didn't expect.
    switch (hostErrno)
    {
    case EPERM:
        return 1;
    case ENOENT:
        return 2;
    case ESRCH:
        return 3;
    case EINTR:
        return 4;
    case EIO:
        return 5;
    case ENXIO:
        return 6;
    case E2BIG:
        return 7;
    case ENOEXEC:
        return 8;
    case EBADF:
        return 9;
    case ECHILD:
        return 10;
    case EAGAIN: // Darwin EAGAIN=35, Linux EAGAIN=11 -- SWAPPED with EDEADLK below
        return 35;
    case ENOMEM:
        return 12;
    case EACCES:
        return 13;
    case EFAULT:
        return 14;
    case EBUSY:
        return 16;
    case EEXIST:
        return 17;
    case EXDEV:
        return 18;
    case ENODEV:
        return 19;
    case ENOTDIR:
        return 20;
    case EISDIR:
        return 21;
    case EINVAL:
        return 22;
    case ENFILE:
        return 23;
    case EMFILE:
        return 24;
    case ENOTTY:
        return 25;
    case ETXTBSY:
        return 26;
    case EFBIG:
        return 27;
    case ENOSPC:
        return 28;
    case ESPIPE:
        return 29;
    case EROFS:
        return 30;
    case EMLINK:
        return 31;
    case EPIPE:
        return 32;
    case EDOM:
        return 33;
    case ERANGE:
        return 34;
    case EDEADLK: // Darwin EDEADLK=11, Linux EDEADLK=35 -- SWAPPED with EAGAIN above
        return 11;
    case ENAMETOOLONG:
        return 63;
    case ENOLCK:
        return 77;
    case ENOSYS:
        return 78;
    case ENOTEMPTY:
        return 66;
    case ELOOP:
        return 62;
    case ENOMSG:
        return 91;
    case EIDRM:
        return 90;
#ifdef ENOSTR
    case ENOSTR:
        return 99;
#endif
#ifdef ENODATA
    case ENODATA:
        return 96;
#endif
#ifdef ETIME
    case ETIME:
        return 101;
#endif
#ifdef ENOSR
    case ENOSR:
        return 98;
#endif
    //case EREMOTE:
    //    return 71;
#ifdef ENOLINK
    case ENOLINK:
        return 97;
#endif
    case EPROTO:
        return 100;
    //case EMULTIHOP:
    //    return 95;
    case EBADMSG:
        return 94;
    case EILSEQ:
        return 92;
    //case EUSERS:
    //    return 68;
    case ENOTSOCK:
        return 38;
    case EDESTADDRREQ:
        return 39;
    case EMSGSIZE:
        return 40;
    case EPROTOTYPE:
        return 41;
    case ENOPROTOOPT:
        return 42;
    case EPROTONOSUPPORT:
        return 43;
#ifdef ESOCKTNOSUPPORT
    case ESOCKTNOSUPPORT:
        return 44;
#endif
    case EOPNOTSUPP: // == ENOTSUP on Linux (same numeric value); Darwin ENOTSUP=45
        return 45;
#ifdef EPFNOSUPPORT
    case EPFNOSUPPORT:
        return 46;
#endif
    case EAFNOSUPPORT:
        return 47;
    case EADDRINUSE:
        return 48;
    case EADDRNOTAVAIL:
        return 49;
    case ENETDOWN:
        return 50;
    case ENETUNREACH:
        return 51;
    case ENETRESET:
        return 52;
    case ECONNABORTED:
        return 53;
    case ECONNRESET:
        return 54;
    case ENOBUFS:
        return 55;
    case EISCONN:
        return 56;
    case ENOTCONN:
        return 57;
    //case ESHUTDOWN:
    //    return 58;
    //case ETOOMANYREFS:
    //    return 59;
    case ETIMEDOUT:
        return 60;
    case ECONNREFUSED:
        return 61;
#ifdef EHOSTDOWN
    case EHOSTDOWN:
        return 64;
#endif
    case EHOSTUNREACH:
        return 65;
    case EALREADY:
        return 37;
    case EINPROGRESS:
        return 36;
    //case ESTALE:
    //    return 70;
    //case EDQUOT:
    //    return 69;
    case ECANCELED:
        return 89;
    case EOVERFLOW:
        return 84;
    case EOWNERDEAD:
        return 105;
    case ENOTRECOVERABLE:
        return 104;
    default:
        return hostErrno;
    }
#endif
}

} // namespace abi_translate
