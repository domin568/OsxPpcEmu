/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:52 $
 * $Revision: 1.12 $
 */

/*****************************************************************************/
/*  Project...: C++ and ANSI-C Compiler Environment                          */
/*  Purpose...: Printing functions for SIOUX			            	     */
/*****************************************************************************/

#ifndef _MSL_SIOUXPRINTER_H
#define _MSL_SIOUXPRINTER_H

#if __MWERKS__
	#include <ansi_parms.h>
	#pragma options align=mac68k
#else
	#define _MSL_IMP_EXP_SIOUX
#endif

_MSL_BEGIN_EXTERN_C	/*- cc 010410 -*/

	/* Function prototypes ...*/
	_MSL_IMP_EXP_SIOUX extern void SIOUXDoPageSetup(void) _MSL_CANT_THROW;
	_MSL_IMP_EXP_SIOUX extern void SIOUXDoPrintText(void) _MSL_CANT_THROW;

_MSL_END_EXTERN_C	/*- cc 010410 -*/

#if __MWERKS__
	#pragma options align=reset
#endif

#endif /* _MSL_SIOUXPRINTER_H */

/* Change record:
 * mm  960930 Changed C++ comments to C comments for ANSI strict
 * cc  010410 updated to new namespace macros 		  
 * hh  020603 Added no throw spec to functions
 */
