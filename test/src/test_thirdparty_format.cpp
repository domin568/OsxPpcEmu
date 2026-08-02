/**
 * Author:    domin568
 * Created:   02.08.2026
 * Brief:     Unit tests for third_party printf/scanf
 **/

#include "../../third_party/printf/printf.h"
#include "../../third_party/scanf/scanf.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <gtest/gtest.h>

namespace
{

template <typename... A> std::array<uint64_t, sizeof...( A )> pack( A... a )
{
    return { static_cast<uint64_t>( a )... };
}

} // namespace

// ── printf_ / vsnprintf_ ─────────────────────────────────────────────

TEST( ThirdPartyPrintf, Integers )
{
    char buf[64];
    const auto args{ pack( 42u, static_cast<uint32_t>( -7 ), 8u, 255u, 255u ) };
    vsnprintf_( buf, sizeof( buf ), "%d %d %o %x %X", args.data() );
    EXPECT_STREQ( buf, "42 -7 10 ff FF" );
}

TEST( ThirdPartyPrintf, WidthFlags )
{
    char buf[64];
    const auto args1{ pack( 7u ) };
    vsnprintf_( buf, sizeof( buf ), "%05d", args1.data() );
    EXPECT_STREQ( buf, "00007" );

    const auto args2{ pack( 3u, 5u ) }; // dynamic width '*' then value
    vsnprintf_( buf, sizeof( buf ), "%*d", args2.data() );
    EXPECT_STREQ( buf, "  5" );
}

TEST( ThirdPartyPrintf, StringsAndChar )
{
    char buf[64];
    const auto args{ pack( reinterpret_cast<uint64_t>( "hi" ), 'x' ) };
    vsnprintf_( buf, sizeof( buf ), "%-5s|%c", args.data() );
    EXPECT_STREQ( buf, "hi   |x" );
}

TEST( ThirdPartyPrintf, Pointer )
{
    char buf[64];
    const auto args{ pack( reinterpret_cast<uint64_t>( (void *)0x1234 ) ) };
    vsnprintf_( buf, sizeof( buf ), "%p", args.data() );
    EXPECT_STREQ( buf, "0000000000001234" );
}

TEST( ThirdPartyPrintf, TruncationReturnsFullLength )
{
    char buf[4];
    const auto args{ pack( reinterpret_cast<uint64_t>( "hello world" ) ) };
    const int ret{ vsnprintf_( buf, sizeof( buf ), "%s", args.data() ) };
    EXPECT_EQ( ret, 11 ); // full length, even though buffer only holds 3 chars + NUL
    EXPECT_STREQ( buf, "hel" );
}

// ── vsscanf_ ──────────────────────────────────────────────────────────

TEST( ThirdPartyScanf, Integers )
{
    int a, b, c;
    const auto args{
        pack( reinterpret_cast<uint64_t>( &a ), reinterpret_cast<uint64_t>( &b ), reinterpret_cast<uint64_t>( &c ) ) };
    const int ret{ vsscanf_( "12 -34 0x1f", "%d %d %i", args.data() ) };
    EXPECT_EQ( ret, 3 );
    EXPECT_EQ( a, 12 );
    EXPECT_EQ( b, -34 );
    EXPECT_EQ( c, 0x1f );
}

TEST( ThirdPartyScanf, FloatAndString )
{
    float f;
    char s[16];
    const auto args{ pack( reinterpret_cast<uint64_t>( &f ), reinterpret_cast<uint64_t>( s ) ) };
    const int ret{ vsscanf_( "3.5 abc", "%f %s", args.data() ) };
    EXPECT_EQ( ret, 2 );
    EXPECT_FLOAT_EQ( f, 3.5f );
    EXPECT_STREQ( s, "abc" );
}

TEST( ThirdPartyScanf, Suppression )
{
    int b{ -1 };
    const auto args{ pack( reinterpret_cast<uint64_t>( &b ) ) };
    const int ret{ vsscanf_( "1 2", "%*d %d", args.data() ) };
    EXPECT_EQ( ret, 1 );
    EXPECT_EQ( b, 2 );
}

TEST( ThirdPartyScanf, CharAndScanset )
{
    char c1;
    char set[16];
    int n;
    const auto args{ pack( reinterpret_cast<uint64_t>( &c1 ), reinterpret_cast<uint64_t>( set ),
                           reinterpret_cast<uint64_t>( &n ) ) };
    const int ret{ vsscanf_( "az123", "%c%[a-z]%d", args.data() ) };
    EXPECT_EQ( ret, 3 );
    EXPECT_EQ( c1, 'a' );
    EXPECT_STREQ( set, "z" );
    EXPECT_EQ( n, 123 );
}

TEST( ThirdPartyScanf, Width )
{
    char s[16]{};
    const auto args{ pack( reinterpret_cast<uint64_t>( s ) ) };
    const int ret{ vsscanf_( "abcdef", "%3s", args.data() ) };
    EXPECT_EQ( ret, 1 );
    EXPECT_STREQ( s, "abc" );
}

TEST( ThirdPartyScanf, MatchFailureReturnsAssignedCount )
{
    int a, b;
    const auto args{ pack( reinterpret_cast<uint64_t>( &a ), reinterpret_cast<uint64_t>( &b ) ) };
    const int ret{ vsscanf_( "10 abc", "%d %d", args.data() ) };
    EXPECT_EQ( ret, 1 );
    EXPECT_EQ( a, 10 );
}

TEST( ThirdPartyScanf, EmptyInputReturnsEof )
{
    int a;
    const auto args{ pack( reinterpret_cast<uint64_t>( &a ) ) };
    EXPECT_EQ( vsscanf_( "", "%d", args.data() ), EOF );
}

TEST( ThirdPartyScanf, NConversion )
{
    int a, n;
    const auto args{ pack( reinterpret_cast<uint64_t>( &a ), reinterpret_cast<uint64_t>( &n ) ) };
    const int ret{ vsscanf_( "12ab", "%d%n", args.data() ) };
    EXPECT_EQ( ret, 1 ); // %n does not count towards the assignment total
    EXPECT_EQ( a, 12 );
    EXPECT_EQ( n, 2 );
}
