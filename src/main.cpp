/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     main source file
 **/

#include "../include/COsxPpcEmu.hpp"
#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

namespace
{

// Emulator-level flags are only recognised in the leading position, i.e. before the target
// executable path. Anything from the target path onward is untouched and handed to
// COsxPpcEmu::init() verbatim, which in turn hands everything after its own argv[0] to the
// guest's argv - so a flag consumed here must never leak into that vector, and the target path
// must never be mistaken for a flag.
constexpr std::string_view Heap_Mode_Flag_Prefix{ "--heap-mode=" };

} // namespace

int main( int argc, const char *argv[] )
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " [--heap-mode=bump|quarantine|real] <executable> [args]" << std::endl;
        return -1;
    }

    common::HeapMode heapMode{ common::Heap_Default_Mode };
    bool heapModeExplicit{ false };

    if (const char *envMode{ std::getenv( "OSXPPCEMU_HEAP_MODE" ) })
    {
        const std::optional<common::HeapMode> parsed{ common::heap_mode_from_string( envMode ) };
        if (!parsed.has_value())
        {
            std::cerr << "Invalid OSXPPCEMU_HEAP_MODE '" << envMode << "'. Accepted values: bump, quarantine, real."
                      << std::endl;
            return -1;
        }
        heapMode = *parsed;
        heapModeExplicit = true;
    }

    // Strip leading emulator flags (currently only --heap-mode=...) before the target path.
    std::vector<const char *> filteredArgv{};
    filteredArgv.push_back( argv[0] );
    int firstGuestArgIdx{ 1 };
    for (; firstGuestArgIdx < argc; ++firstGuestArgIdx)
    {
        const std::string_view arg{ argv[firstGuestArgIdx] };
        if (!arg.starts_with( Heap_Mode_Flag_Prefix ))
            break;

        const std::string_view modeStr{ arg.substr( Heap_Mode_Flag_Prefix.size() ) };
        const std::optional<common::HeapMode> parsed{ common::heap_mode_from_string( modeStr ) };
        if (!parsed.has_value())
        {
            std::cerr << "Invalid --heap-mode value '" << modeStr << "'. Accepted values: bump, quarantine, real."
                      << std::endl;
            return -1;
        }
        heapMode = *parsed;
        heapModeExplicit = true;
    }
    for (int i{ firstGuestArgIdx }; i < argc; ++i)
        filteredArgv.push_back( argv[i] );

    if (filteredArgv.size() < 2)
    {
        std::cerr << "Usage: " << argv[0] << " [--heap-mode=bump|quarantine|real] <executable> [args]" << std::endl;
        return -1;
    }

    std::cout << "[OsxPpcEmu] Emulating " << filteredArgv[1] << std::endl;
    if (heapModeExplicit && heapMode != common::Heap_Default_Mode)
        std::cout << "[OsxPpcEmu] Heap mode: " << common::heap_mode_name( heapMode ) << std::endl;
    const std::array<std::string, 1> guestEnv{ "EXAMPLE=1" };

    std::chrono::high_resolution_clock::time_point start{ std::chrono::high_resolution_clock::now() };
    compat::expected<emu::COsxPpcEmu, emu::Error> emu{ emu::COsxPpcEmu::init(
        static_cast<int>( filteredArgv.size() ), filteredArgv.data(), guestEnv, heapMode ) };
    if (!emu)
    {
        std::cerr << emu.error().message << std::endl;
        return emu.error().type;
    }
#ifdef DEBUGGER_ENABLED
    emu->init_debugger();
#endif
    emu->run();

    std::chrono::high_resolution_clock::time_point end{ std::chrono::high_resolution_clock::now() };
    std::chrono::duration<double, std::milli> elapsed{ end - start };
    std::cout << "[OsxPpcEmu] Execution time: " << elapsed.count() << " ms" << std::endl;

    return 0;
}


