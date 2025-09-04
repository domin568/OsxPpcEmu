/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     Loader for Mach-O object files (PPC)
 **/

#include "../include/CMachoLoader.hpp"
#include <LIEF/MachO.hpp>
#include <filesystem>
#include <fstream>

CMachoLoader::CMachoLoader( std::unique_ptr<LIEF::MachO::Binary> executable ) : m_executable( std::move( executable ) )
{
}

std::expected<CMachoLoader, CMachoLoader::Error> CMachoLoader::create( const std::string &path )
{
    if (!std::filesystem::exists( path ))
        return error( Error::Type::NotFound, "File not found." );

    const LIEF::MachO::ParserConfig conf{ LIEF::MachO::ParserConfig::deep() };
    std::unique_ptr<LIEF::MachO::FatBinary> fat{ LIEF::MachO::Parser::parse( path, conf ) };

    if (fat->size() > 1)
        return error( Error::Type::Unsupported, "FAT MachO binaries are not supported" );

    std::unique_ptr<LIEF::MachO::Binary> ppcBinary{ fat->take( LIEF::MachO::Header::CPU_TYPE::POWERPC ) };
    if (!ppcBinary)
        return error( Error::Type::Unsupported, "Only PowerPC binaries are supported." );

    CMachoLoader loader{ std::move( ppcBinary ) };
    return loader;
}

std::expected<CMachoLoader, CMachoLoader::Error> CMachoLoader::error( Error::Type type, const std::string &message )
{
    return std::unexpected( Error{ .type{ type }, .message{ std::move( message ) } } );
}