/**
 * Author:    domin568
 * Created:   15.09.2025
 * Brief:     redirected API implementations
 **/
#pragma once

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
    std::vector<uint8_t> ppcCode{};
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

} // namespace api
