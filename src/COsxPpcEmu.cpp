/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Emulator for Mach-O PowerPC object files
 **/

#include "../include/COsxPpcEmu.hpp"
#include "../include/CMachoLoader.hpp"
#include "../include/Common.hpp"
#include <filesystem>
#include <string_view>

COsxPpcEmu::COsxPpcEmu( uc_engine *uc, CMachoLoader &&loader ) : m_uc( uc ), m_loader( std::move( loader ) )
{
}

std::expected<COsxPpcEmu, common::Error> COsxPpcEmu::init( const std::string &executablePath )
{
    if (!std::filesystem::exists( executablePath ))
        return std::unexpected( common::Error{ common::Error::Type::NotFound, "File not found." } );

    std::expected<CMachoLoader, common::Error> loader{ CMachoLoader::init( executablePath ) };
    if (!loader)
        return std::unexpected{ std::move( loader ).error() };

    uc_err err;
    uc_engine *uc;
    uc_mode ppcMode{ static_cast<uc_mode>( UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN ) };
    err = uc_open( UC_ARCH_PPC, ppcMode, &uc );
    if (err != UC_ERR_OK)
        return std::unexpected(
            common::Error{ common::Error::Type::Unicorn_Open_Error, "Could not create ppc32 unicorn emulator." } );

    if (!loader->mapMemory( uc ))
        return std::unexpected( common::Error{ common::Error::Type::Memory_Map_Error, "Could not map memory." } );

    return COsxPpcEmu{ uc, std::move( loader.value() ) };
}

void COsxPpcEmu::run()
{
}
