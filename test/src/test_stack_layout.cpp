/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     Unit tests for emu::detail::build_stack_image (StackLayout.hpp)
 **/
#include "StackLayout.hpp"

#include <cstring>
#include <gtest/gtest.h>

namespace
{

std::uint32_t read_u32_be( const std::vector<std::uint8_t> &buf, std::size_t offset )
{
    std::uint32_t v{};
    std::memcpy( &v, buf.data() + offset, sizeof( v ) );
    return common::ensure_endianness( v, std::endian::big );
}

std::string read_cstr( const std::vector<std::uint8_t> &buf, std::uint32_t stackBase, std::uint32_t address )
{
    const std::size_t offset{ address - stackBase };
    const char *p{ reinterpret_cast<const char *>( buf.data() + offset ) };
    return std::string{ p };
}

constexpr std::uint32_t Test_Stack_Base{ 0xBFFF'0000 };
constexpr std::size_t Test_Max_Size{ 0x1'0000 };

} // namespace

TEST( StackLayout, RejectsEmptyTargetArgs )
{
    const std::vector<std::string> empty{};
    const std::vector<std::string> env{ "FOO=bar" };
    const auto result{ emu::detail::build_stack_image( empty, env, Test_Stack_Base, Test_Max_Size ) };
    EXPECT_FALSE( result.has_value() );
}

TEST( StackLayout, RejectsOversizedImage )
{
    const std::vector<std::string> args{ std::string( 0x2000, 'a' ) };
    const std::vector<std::string> env{};
    const auto result{ emu::detail::build_stack_image( args, env, Test_Stack_Base, /*maxSize=*/0x100 ) };
    EXPECT_FALSE( result.has_value() );
}

TEST( StackLayout, ArgcMatchesTargetArgsCount )
{
    const std::vector<std::string> args{ "/guest/bin/prog", "-x", "foo" };
    const std::vector<std::string> env{ "A=1", "B=2" };
    const auto result{ emu::detail::build_stack_image( args, env, Test_Stack_Base, Test_Max_Size ) };
    ASSERT_TRUE( result.has_value() ) << result.error();

    EXPECT_EQ( read_u32_be( result->bytes, 0 ), args.size() );
}

TEST( StackLayout, ArgvPointersResolveToExpectedStrings )
{
    const std::vector<std::string> args{ "/guest/bin/prog", "-x", "foo" };
    const std::vector<std::string> env{ "A=1" };
    const auto result{ emu::detail::build_stack_image( args, env, Test_Stack_Base, Test_Max_Size ) };
    ASSERT_TRUE( result.has_value() ) << result.error();

    constexpr std::size_t argvOffset{ 4 };
    for (std::size_t i{ 0 }; i < args.size(); ++i)
    {
        const std::uint32_t address{ read_u32_be( result->bytes, argvOffset + i * 4 ) };
        EXPECT_EQ( read_cstr( result->bytes, Test_Stack_Base, address ), args[i] ) << "argv[" << i << "]";
    }
}

TEST( StackLayout, EnvpPointersResolveToExpectedStrings )
{
    const std::vector<std::string> args{ "/guest/bin/prog" };
    const std::vector<std::string> env{ "A=1", "B=2", "C=3" };
    const auto result{ emu::detail::build_stack_image( args, env, Test_Stack_Base, Test_Max_Size ) };
    ASSERT_TRUE( result.has_value() ) << result.error();

    const std::size_t envpOffset{ 4 + args.size() * 4 + 4 };
    for (std::size_t j{ 0 }; j < env.size(); ++j)
    {
        const std::uint32_t address{ read_u32_be( result->bytes, envpOffset + j * 4 ) };
        EXPECT_EQ( read_cstr( result->bytes, Test_Stack_Base, address ), env[j] ) << "envp[" << j << "]";
    }
}

TEST( StackLayout, ArgvEnvpAndAppleAreNullTerminated )
{
    const std::vector<std::string> args{ "/guest/bin/prog", "a", "b" };
    const std::vector<std::string> env{ "X=1", "Y=2" };
    const auto result{ emu::detail::build_stack_image( args, env, Test_Stack_Base, Test_Max_Size ) };
    ASSERT_TRUE( result.has_value() ) << result.error();

    const std::size_t argvOffset{ 4 };
    const std::size_t envpOffset{ argvOffset + args.size() * 4 + 4 };
    const std::size_t execPathOffset{ envpOffset + env.size() * 4 + 4 };
    const std::size_t applePadOffset{ execPathOffset + 4 };

    EXPECT_EQ( read_u32_be( result->bytes, argvOffset + args.size() * 4 ), 0u ) << "argv[] terminator";
    EXPECT_EQ( read_u32_be( result->bytes, envpOffset + env.size() * 4 ), 0u ) << "envp[] terminator";
    EXPECT_EQ( read_u32_be( result->bytes, applePadOffset ), 0u ) << "apple[] terminator";
}

TEST( StackLayout, ExecPathEqualsArgv0 )
{
    const std::vector<std::string> args{ "/guest/bin/prog", "a" };
    const std::vector<std::string> env{ "X=1" };
    const auto result{ emu::detail::build_stack_image( args, env, Test_Stack_Base, Test_Max_Size ) };
    ASSERT_TRUE( result.has_value() ) << result.error();

    const std::size_t argvOffset{ 4 };
    const std::size_t envpOffset{ argvOffset + args.size() * 4 + 4 };
    const std::size_t execPathOffset{ envpOffset + env.size() * 4 + 4 };

    const std::uint32_t argv0{ read_u32_be( result->bytes, argvOffset ) };
    const std::uint32_t execPath{ read_u32_be( result->bytes, execPathOffset ) };
    EXPECT_EQ( execPath, argv0 );
    EXPECT_EQ( read_cstr( result->bytes, Test_Stack_Base, execPath ), args[0] );
}

TEST( StackLayout, StringAreaIs16ByteAligned )
{
    const std::vector<std::string> args{ "/guest/bin/prog" };
    const std::vector<std::string> env{};
    const auto result{ emu::detail::build_stack_image( args, env, Test_Stack_Base, Test_Max_Size ) };
    ASSERT_TRUE( result.has_value() ) << result.error();

    const std::size_t argvOffset{ 4 };
    const std::size_t envpOffset{ argvOffset + args.size() * 4 + 4 };
    const std::size_t execPathOffset{ envpOffset + env.size() * 4 + 4 };
    const std::size_t applePadOffset{ execPathOffset + 4 };
    const std::size_t stringAreaOffset{
        common::align_up( applePadOffset + 4, emu::detail::Stack_String_Area_Alignment ) };

    EXPECT_EQ( stringAreaOffset % emu::detail::Stack_String_Area_Alignment, 0u );

    const std::uint32_t argv0{ read_u32_be( result->bytes, argvOffset ) };
    EXPECT_EQ( argv0, Test_Stack_Base + stringAreaOffset );
}

TEST( StackLayout, EmptyEnvWorks )
{
    const std::vector<std::string> args{ "/guest/bin/prog", "onlyarg" };
    const std::vector<std::string> env{};
    const auto result{ emu::detail::build_stack_image( args, env, Test_Stack_Base, Test_Max_Size ) };
    ASSERT_TRUE( result.has_value() ) << result.error();
    EXPECT_EQ( read_u32_be( result->bytes, 0 ), args.size() );
}

TEST( StackLayout, ValuesAreBigEndian )
{
    // 3 target args -> argc == 3 == 0x00000003. Verify the raw bytes are big-endian,
    // not just that our BE-aware reader round-trips (which would hide a native-endian bug
    // on a little-endian host if the reader used the same byteswap).
    const std::vector<std::string> args{ "/guest/bin/prog", "a", "b" };
    const std::vector<std::string> env{};
    const auto result{ emu::detail::build_stack_image( args, env, Test_Stack_Base, Test_Max_Size ) };
    ASSERT_TRUE( result.has_value() ) << result.error();

    ASSERT_GE( result->bytes.size(), 4u );
    EXPECT_EQ( result->bytes[0], 0x00 );
    EXPECT_EQ( result->bytes[1], 0x00 );
    EXPECT_EQ( result->bytes[2], 0x00 );
    EXPECT_EQ( result->bytes[3], 0x03 );
}
