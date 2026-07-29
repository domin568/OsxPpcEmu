/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     initial guest stack image (argc/argv/envp/apple[] + string area) builder
 **/
#include "StackLayout.hpp"

namespace emu::detail
{

void write_u32_be( std::span<std::uint8_t> buf, std::size_t offset, std::uint32_t value )
{
    const std::uint32_t be{ common::ensure_endianness( value, std::endian::big ) };
    std::memcpy( buf.data() + offset, &be, sizeof( be ) );
}

std::expected<StackImage, std::string> build_stack_image( std::span<const std::string> targetArgs,
                                                          std::span<const std::string> env, std::uint32_t stackBase,
                                                          std::size_t maxSize )
{
    if (targetArgs.empty())
        return std::unexpected( "no guest program arguments (targetArgs is empty; exec_path would be null)" );

    // ── offsets ──────────────────────────────────────────────────────────
    constexpr std::size_t argcOffset{ 0 };
    constexpr std::size_t argvOffset{ argcOffset + sizeof( std::uint32_t ) };
    const std::size_t envpOffset{ argvOffset + targetArgs.size() * sizeof( std::uint32_t ) +
                                  sizeof( std::uint32_t ) }; // + argv NULL terminator
    const std::size_t execPathOffset{ envpOffset + env.size() * sizeof( std::uint32_t ) +
                                      sizeof( std::uint32_t ) }; // + envp NULL terminator
    const std::size_t applePadOffset{ execPathOffset + sizeof( std::uint32_t ) };
    const std::size_t stringAreaOffset{
        common::align_up( applePadOffset + sizeof( std::uint32_t ), Stack_String_Area_Alignment ) };

    std::vector<std::uint8_t> stringArea{};
    std::vector<std::size_t> stringOffsets{};
    stringOffsets.reserve( targetArgs.size() + env.size() );

    const auto appendString{ [&]( const std::string &s ) {
        stringOffsets.push_back( stringArea.size() );
        stringArea.insert( stringArea.end(), s.begin(), s.end() );
        stringArea.push_back( 0 );
    } };
    for (const auto &s : targetArgs)
        appendString( s );
    for (const auto &s : env)
        appendString( s );

    // ── assemble the full image ─────────────────────────────────────────
    StackImage image{};
    image.bytes.assign( stringAreaOffset + stringArea.size(), 0 );
    std::span<std::uint8_t> buf{ image.bytes };

    write_u32_be( buf, argcOffset, static_cast<std::uint32_t>( targetArgs.size() ) );

    for (std::size_t i{ 0 }; i < targetArgs.size(); ++i)
    {
        const auto address{ static_cast<std::uint32_t>( stackBase + stringAreaOffset + stringOffsets[i] ) };
        write_u32_be( buf, argvOffset + i * sizeof( std::uint32_t ), address );
    }
    write_u32_be( buf, argvOffset + targetArgs.size() * sizeof( std::uint32_t ), 0 ); // argv[] NULL terminator

    for (std::size_t j{ 0 }; j < env.size(); ++j)
    {
        const auto address{
            static_cast<std::uint32_t>( stackBase + stringAreaOffset + stringOffsets[targetArgs.size() + j] ) };
        write_u32_be( buf, envpOffset + j * sizeof( std::uint32_t ), address );
    }
    write_u32_be( buf, envpOffset + env.size() * sizeof( std::uint32_t ), 0 ); // envp[] NULL terminator

    // exec_path (apple[0]) == argv[0]'s string address; targetArgs is guaranteed non-empty above.
    const auto execPathAddress{ static_cast<std::uint32_t>( stackBase + stringAreaOffset + stringOffsets[0] ) };
    write_u32_be( buf, execPathOffset, execPathAddress );
    write_u32_be( buf, applePadOffset, 0 ); // apple[] NULL terminator

    std::memcpy( image.bytes.data() + stringAreaOffset, stringArea.data(), stringArea.size() );

    if (image.bytes.size() > maxSize)
        return std::unexpected( "initial stack image (0x" + std::to_string( image.bytes.size() ) +
                                " bytes) does not fit in dyld stack region (0x" + std::to_string( maxSize ) +
                                " bytes)" );

    return image;
}

} // namespace emu::detail
