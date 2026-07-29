/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     initial guest stack image (argc/argv/envp/apple[] + string area) builder
 **/
#pragma once

#include "Common.hpp"

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace emu::detail
{

inline constexpr std::size_t Stack_String_Area_Alignment{ 0x10 };

struct StackImage
{
    // Full image bytes, meant to be written starting at the stack region base address.
    std::vector<std::uint8_t> bytes{};
};

void write_u32_be( std::span<std::uint8_t> buf, std::size_t offset, std::uint32_t value );

/**
 * Builds the initial stack image:
 *
 *  +-------------+
 *  |    argc     |
 *  +-------------+
 *  |   argv[0]   |
 *  +-------------+
 *        :
 *  +-------------+
 *  | argv[argc-1]|
 *  +-------------+
 *  |      0      |
 *  +-------------+
 *  |   envp[0]   |
 *  +-------------+
 *        :
 *  +-------------+
 *  |   envp[n]   |
 *  +-------------+
 *  |      0      |
 *  +-------------+
 *  |  exec_path  |   (apple[0], == argv[0]'s string address)
 *  +-------------+
 *  |      0      |   (apple[] terminator)
 *  +-------------+
 *  | STRING AREA |   (16-byte aligned; argv[] strings then envp[] strings, NUL-separated)
 *        :
 *  +-------------+
 *
 * `targetArgs` must be the guest-visible argv (i.e. NOT including the host emulator's own
 * argv[0]) and must be non-empty — `exec_path` is always argv[0]'s string address.
 *
 */
std::expected<StackImage, std::string> build_stack_image( std::span<const std::string> targetArgs,
                                                          std::span<const std::string> env, std::uint32_t stackBase,
                                                          std::size_t maxSize );

} // namespace emu::detail
