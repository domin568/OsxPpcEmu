/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     main source file
 **/

#include "../include/COsxPpcEmu.hpp"
#include <array>
#include <chrono>
#include <iostream>

int main( int argc, const char *argv[] )
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <executable> [args]" << std::endl;
        return -1;
    }
    const std::array<std::string, 1> guestEnv{ "EXAMPLE=1" };

    std::chrono::high_resolution_clock::time_point start{ std::chrono::high_resolution_clock::now() };
    std::expected<emu::COsxPpcEmu, emu::Error> emu{ emu::COsxPpcEmu::init( argc, argv, guestEnv ) };
    if (!emu)
    {
        std::cerr << emu.error().message << std::endl;
        return emu.error().type;
    }
#ifdef DEBUG
    emu->init_debugger();
#endif
    emu->run();

    std::chrono::high_resolution_clock::time_point end{ std::chrono::high_resolution_clock::now() };
    std::chrono::duration<double, std::milli> elapsed{ end - start };
    std::cout << "[OsxPpcEmu] Execution time: " << elapsed.count() << " ms" << std::endl;

    return 0;
}
