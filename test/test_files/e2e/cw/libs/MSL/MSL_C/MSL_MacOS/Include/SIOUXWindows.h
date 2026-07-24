/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:52 $
 * $Revision: 1.13 $
 */

/*****************************************************************************/
/*  Project...: C++ and ANSI-C Compiler Environment                          */
/*  Purpose...: Menu related functions for SIOUX			                 */
/*****************************************************************************/

#ifndef _MSL_SIOUXWINDOWS_H
#define _MSL_SIOUXWINDOWS_H

#if __MWERKS__
	#include <ansi_parms.h>
#else
	#define _MSL_IMP_EXP_SIOUX
#endif

/*	Dialog IDs */
enum {
	GENERICWIND = 32000,
	alrt_cantsave = 32001,
	alrt_yesnocancel = 32002,
	alrt_aboutbox = 32003
};

_MSL_BEGIN_EXTERN_C	/*- cc 010410 -*/

	/* Function prototypes ...*/
	_MSL_IMP_EXP_SIOUX extern Boolean SIOUXIsAppWindow(WindowPtr window) _MSL_CANT_THROW;
	_MSL_IMP_EXP_SIOUX extern void SIOUXUpdateScrollbar(void) _MSL_CANT_THROW;
	_MSL_IMP_EXP_SIOUX extern void SIOUXDoContentClick(WindowPtr window, EventRecord *theEvent) _MSL_CANT_THROW;
	_MSL_IMP_EXP_SIOUX extern void SIOUXDrawGrowBox(WindowPtr theWindow) _MSL_CANT_THROW;
	_MSL_IMP_EXP_SIOUX extern void SIOUXUpdateWindow(WindowPtr theWindow) _MSL_CANT_THROW;
	_MSL_IMP_EXP_SIOUX extern void SIOUXUpdateStatusLine(WindowPtr theWindow) _MSL_CANT_THROW;
	_MSL_IMP_EXP_SIOUX extern void SIOUXMyGrowWindow(WindowPtr theWindow, Point thePoint) _MSL_CANT_THROW;
	_MSL_IMP_EXP_SIOUX extern Boolean SIOUXSetupTextWindow(void) _MSL_CANT_THROW;
	_MSL_IMP_EXP_SIOUX extern void SIOUXDoAboutBox(void) _MSL_CANT_THROW;
	_MSL_IMP_EXP_SIOUX extern void SIOUXCantSaveAlert(StrFileName filename) _MSL_CANT_THROW;
	_MSL_IMP_EXP_SIOUX extern short SIOUXYesNoCancelAlert(StrFileName filename) _MSL_CANT_THROW;
	
	#if SIOUX_USE_WASTE
		#include <WASTE.h>
		_MSL_IMP_EXP_SIOUX extern Boolean SIOUXisinrange(long first, WEReference te) _MSL_CANT_THROW;
		_MSL_IMP_EXP_SIOUX extern void MoveScrollBox( ControlHandle theControl, long scrollDistance ) _MSL_CANT_THROW;
	#else
		_MSL_IMP_EXP_SIOUX extern Boolean SIOUXisinrange(short first, TEHandle te) _MSL_CANT_THROW;
		_MSL_IMP_EXP_SIOUX extern void MoveScrollBox( ControlHandle theControl, short scrollDistance ) _MSL_CANT_THROW;
	#endif	/* SIOUX_USE_WASTE */
	
	_MSL_IMP_EXP_SIOUX extern void AdjustText( void ) _MSL_CANT_THROW;

	WindowRef SIOUXFrontWindow(void) _MSL_CANT_THROW;
_MSL_END_EXTERN_C	/*- cc 010410 -*/

#endif /* _MSL_SIOUXWINDOWS_H */

/* Change record:
 * mm  960930 Changed C++ comments to C comments for ANSI strict
 * ra  980923 Changed use of Str63 for filename to StrFileName type instead.
 * cc  991108 added ra Carbon Changes done 990611
 * cc  010410 updated to new namespace macros
 * JWW 010917 Added floating window mode to SIOUX
 * hh  020603 Added no throw spec to functions
 */