/**
 * Author:    domin568
 * Created:   29.07.2026
 * Brief:     everything a Unicorn hook callback is allowed to reach; owned by COsxPpcEmu
 **/
#pragma once

#include "CMachoLoader.hpp"
#include "CMemory.hpp"
#ifdef DEBUGGER_ENABLED
#include "CDebugger.hpp"
#include "CGdbServer.hpp"
#endif

#include <unicorn/unicorn.h>

namespace emu::hooks
{

struct HookContext
{
    uc_engine *uc{};
    memory::CMemory *mem{};
    loader::CMachoLoader *loader{};
#ifdef DEBUGGER_ENABLED
    debug::CDebugger *debugger{};
    gdb::CGdbServer *gdbServer{};
    std::FILE **traceFile{};
    // guest address of the last dispatched API call, used for interrupt diagnostics
    std::uint32_t lastApiAddress{ 0 };
#endif
};

} // namespace emu::hooks
