/**
 * Author:    domin568
 * Created:   16.05.2026
 * Brief:     Carbon shims declarations
 */

#pragma once

namespace import::callback
{
using CallbackPtr = bool ( * )( ShimContext &ctx );
#define callback( name ) bool name( ShimContext &ctx );

callback( BlockMoveData );
callback( CloseResFile );
callback( DetachResource );
callback( DisposeHandle );
callback( FSClose );
callback( FSGetCatalogInfo );
callback( FSpOpenRF );
callback( FSpOpenResFile );
callback( FSpGetFInfo );
callback( FSpSetFInfo );
callback( FSPathMakeRef );
callback( FSWrite );
callback( Get1Resource );
callback( GetHandleSize );
callback( HandAndHand );
callback( HLock );
callback( HLockHi );
callback( HUnlock );
callback( MemError );
callback( NewHandle );
callback( NewHandleClear );
callback( PBGetCatInfoSync );
callback( PtrAndHand );
callback( SetHandleSize );
callback( TempNewHandle );
} // namespace import::callback