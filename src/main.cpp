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

int main( int argc, char *argv[] )
{
    if (argc < 2)
    {
        return -1;
    }

    std::expected<COsxPpcEmu, common::Error> emu{ COsxPpcEmu::init( argv[1] ) };
    if (!emu)
    {
        std::cerr << emu.error().message << std::endl;
        return emu.error().type;
    }
    emu->run();

    return 0;
}
