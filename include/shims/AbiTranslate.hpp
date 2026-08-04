/**
 * Author:    domin568
 * Created:   02.08.2026
 * Brief:     Guest (Darwin/Mac OS X 10.4) <-> host ABI constant translation
 **/
#pragma once
#include <cstdint>

namespace abi_translate
{
// On Linux most bits (O_CREAT, O_TRUNC, O_EXCL, O_APPEND, O_NONBLOCK, ...) sit at
// different numeric positions -- e.g. guest O_CREAT (0x200) equals Linux O_TRUNC (0x200),
int darwin_oflags_to_host( std::int32_t darwinFlags );

// Translates a HOST errno value the numeric value the guest (Mac OS X 10.4 / Darwin) expects in its <sys/errno.h>.
std::int32_t host_errno_to_darwin( int hostErrno );

} // namespace abi_translate
