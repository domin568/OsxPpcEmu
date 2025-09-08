/**
 * Author:    domin568
 * Created:   08.09.2025
 * Brief:     Emulator for Mach-O PowerPC object files
 **/
#pragma once
#include "../include/CMachoLoader.hpp"
#include "../include/Common.hpp"
#include <expected>
#include <string_view>
#include <unicorn/unicorn.h>

class COsxPpcEmu
{
  public:
    static std::expected<COsxPpcEmu, common::Error> init( const std::string &executablePath );
    void run();

  private:
    COsxPpcEmu( uc_engine *uc, CMachoLoader &&loader );

    CMachoLoader m_loader;
    uc_engine *m_uc;
};