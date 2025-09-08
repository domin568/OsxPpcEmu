/**
 * Author:    domin568
 * Created:   04.09.2025
 * Brief:     Loader for Mach-O object files (PPC)
 **/
#pragma once
#include "../include/Common.hpp"
#include <LIEF/MachO.hpp>
#include <expected>
#include <unicorn/unicorn.h>

class CMachoLoader
{
  public:
    static std::expected<CMachoLoader, common::Error> init( const std::string &path );
    bool mapMemory( uc_engine *eng );

  private:
    explicit CMachoLoader( std::unique_ptr<LIEF::MachO::Binary> executable );

    static constexpr size_t Max_Segment_File_Size{ 0x100'000 };

    std::unique_ptr<LIEF::MachO::Binary> m_executable;
};