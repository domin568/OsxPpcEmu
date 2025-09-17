/**
 * Author:    domin568
 * Created:   15.09.2025
 * Brief:     redirected API implementations
 **/
#pragma once

#include "CMachoLoader.hpp"
#include <unicorn/unicorn.h>
#include <vector>

namespace api
{

using ApiPtr = bool ( * )( uc_engine * );

/*
enum class Type
{
    Direct,
    Ptr,
    DoublePtr,
};
*/

struct Api_Dispatch_Data
{
    uint32_t apiDispatchTableVa{};
    int apiRedirectEntrySizePow2{};
    const std::vector<api::ApiPtr> apiRedirectEntries{};
};

struct Api_Item
{
    std::span<const uint8_t> ppcCode{};
    ApiPtr hook{};
};

static bool api_unknown( uc_engine *uc )
{
    return true;
}
static bool api_mach_init_routine( uc_engine *uc )
{
    return true;
}

static const std::array<uint8_t, 4> Blr_Opcode{ 0x4E, 0x80, 0x00, 0x20 };
static const api::Api_Item Unknown_Api{
    .ppcCode{ Blr_Opcode },
    .hook{ api::api_unknown },
};

} // namespace api
