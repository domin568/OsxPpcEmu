/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     main source file
 **/

#include "../include/CMachoLoader.hpp"
#include "../include/COsxPpcEmu.hpp"
#include <array>
#include <iostream>
#include <unicorn/unicorn.h>

int main( int argc, const char *argv[] )
{
    if (argc < 2)
        return -1;

    const std::array<std::string, 2> env{
        "MANPATH=/opt/local/share/man:",
        "MWMacOSXPPCLibraryFiles=MSL_All_Mach-O.lib",
    };

    std::expected<emu::COsxPpcEmu, emu::Error> emu{ emu::COsxPpcEmu::init( argc, argv, env ) };
    if (!emu)
    {
        std::cerr << emu.error().message << std::endl;
        return emu.error().type;
    }
    emu->print_vm_map( std::cout );
    emu->run();

    return 0;
}
