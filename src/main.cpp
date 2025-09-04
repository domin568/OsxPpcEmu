/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     main source file
 **/

#include "../include/CMachoLoader.hpp"
#include <array>
#include <iostream>
#include <unicorn/unicorn.h>

#define STATUS_OK 0
#define STATUS_UNRECOVERABLE_ERROR 1
#define STATUS_NOT_SUPPORTED 2

int main( int argc, char *argv[] )
{
    if (argc == 2)
    {
        return STATUS_UNRECOVERABLE_ERROR;
    }
    std::expected<CMachoLoader, CMachoLoader::Error> loader{ CMachoLoader::create( argv[1] ) };
    if (!loader)
    {
        std::cerr << loader.error().message << std::endl;
        return loader.error().type;
    }
    /*
      std::unique_ptr<LIEF::MachO::FatBinary> fat{LIEF::MachO::Parser::parse(argv[1])};
      ASSERT_RETURN(fat->size() == 1, STATUS_UNRECOVERABLE_ERROR);
      const std::unique_ptr<LIEF::MachO::Binary> macho{ fat->take(0) };
      ASSERT_RETURN(macho->header, STATUS_NOT_SUPPORTED);
      uint64_t ep{ macho->entrypoint() };
      std::cout << std::hex << ep << std::endl;
      std::cout << macho->is_pie() << std::endl;

    */
    uc_err err;
    uc_engine *uc;
    uc_mode ppcMode{ static_cast<uc_mode>( UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN ) };
    err = uc_open( UC_ARCH_PPC, ppcMode, &uc );
    if (err != UC_ERR_OK)
    {
        return STATUS_UNRECOVERABLE_ERROR;
    }

    return STATUS_OK;
}
