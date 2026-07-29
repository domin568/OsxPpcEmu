/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     diagnostics printed by the Unicorn hooks (interrupt reports, memory violation
 *            reports, DEBUGGER_ENABLED API call/return tracing). Pure I/O, no dispatch logic.
 **/
#pragma once

#include "HookContext.hpp"

#include <cstddef>
#include <cstdint>
#include <unicorn/unicorn.h>

namespace emu::trace
{

void print_interrupt( const emu::hooks::HookContext &ctx, uc_engine *uc, std::uint32_t intno );
void print_mem_violation( const emu::hooks::HookContext &ctx, uc_engine *uc, uc_mem_type type, std::uint64_t address,
                          int size, std::int64_t value );

#ifdef DEBUGGER_ENABLED
void print_api_call_source( const emu::hooks::HookContext &ctx, uc_engine *uc, std::uint64_t address, std::size_t idx );
void print_api_return( const emu::hooks::HookContext &ctx, uc_engine *uc, std::size_t idx );
#endif

} // namespace emu::trace
