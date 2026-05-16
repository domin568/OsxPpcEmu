/**
 * Author:    domin568
 * Created:   16.05.2026
 * Brief:     redirected API declarations
 **/

#pragma once

namespace import::callback
{
using CallbackPtr = bool ( * )( ShimContext &ctx );
#define callback( name ) bool name( ShimContext &ctx );

callback( dyld_stub_binding_helper );
callback( dyld_make_delayed_module_initializer_calls );
callback( dyld_func_lookup );
callback( mach_init_routine );
} // namespace import::callback