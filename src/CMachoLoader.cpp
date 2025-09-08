/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     Loader for Mach-O object files (PPC)
 **/

#include "../include/CMachoLoader.hpp"
#include "../include/Common.hpp"
#include <LIEF/MachO.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>

CMachoLoader::CMachoLoader( std::unique_ptr<LIEF::MachO::Binary> executable ) : m_executable( std::move( executable ) )
{
}

std::expected<CMachoLoader, common::Error> CMachoLoader::init( const std::string &path )
{
    if (!std::filesystem::exists( path ))
        return std::unexpected{ common::Error{ common::Error::Type::NotFound, "File not found." } };

    const LIEF::MachO::ParserConfig conf{ LIEF::MachO::ParserConfig::deep() };
    std::unique_ptr<LIEF::MachO::FatBinary> fat{ LIEF::MachO::Parser::parse( path, conf ) };

    if (fat->size() > 1)
        return std::unexpected{
            common::Error{ common::Error::Type::Unsupported, "FAT MachO binaries are not supported" } };

    std::unique_ptr<LIEF::MachO::Binary> ppcBinary{ fat->take( LIEF::MachO::Header::CPU_TYPE::POWERPC ) };
    if (!ppcBinary)
        return std::unexpected{
            common::Error{ common::Error::Type::Unsupported, "Only PowerPC binaries are supported." } };

    CMachoLoader loader{ std::move( ppcBinary ) };
    return loader;
}

bool CMachoLoader::mapMemory( uc_engine *uc )
{
    for (const auto &seg : m_executable->segments())
    {
        uc_err err{ uc_mem_map( uc, seg.virtual_address(), seg.virtual_size(), seg.max_protection() ) };
        if (err != UC_ERR_OK)
        {
            std::cerr << "Error mapping memory from MachO file\n uc error:" << std::hex << "0x" << err << "\n -> "
                      << uc_strerror( err ) << "\n SEGMENT: " << seg.name() << std::endl;
            return false;
        }

        if (seg.file_size() > Max_Segment_File_Size)
        {
            std::cerr << "SEGMENT: " << seg.name() << " filesize is too big to map: " << std::hex << "0x"
                      << seg.file_size() << std::endl;
            return false;
        }

        if (seg.file_size() > 0)
        {
            err = uc_mem_write( uc, seg.virtual_address(), seg.data().data(), seg.data().size_bytes() );
            if (err != UC_ERR_OK)
            {
                std::cerr << "SEGMENT: " << seg.name() << " could not be written to unicorn" << std::endl;
                return false;
            }
        }
    }
    return true;
}