/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:51 $
 * $Revision: 1.23 $
 */

#ifndef _MSL_FSP_FOPEN_H           /*- mm 970508 -*/
#define _MSL_FSP_FOPEN_H           /*- mm 970508 -*/

#include <ansi_parms.h>            /*- mm 970903 -*/
#include <cstdio>                 /*- mm 970903 -*/

#if __MACH__
	#include <CarbonCore/CarbonCore.h>
#else
	#include <Files.h>
#endif

_MSL_BEGIN_EXTERN_C	/*- cc 010410 -*/

	_MSL_IMP_EXP_C __std(FILE) * FSp_fopen(ConstFSSpecPtr spec, const char *open_mode) _MSL_CANT_THROW;
	
	#if _MSL_USE_NEW_FILE_APIS || !_MSL_CARBON_FILE_APIS
		_MSL_IMP_EXP_C __std(FILE) * FSRef_fopen(const FSRef *theRef, const char *open_mode) _MSL_CANT_THROW;
		
		_MSL_IMP_EXP_C __std(FILE) * FSRefParentAndFilename_fopen(const FSRef *theParentRef,
			ConstHFSUniStr255Param theName, const char *open_mode) _MSL_CANT_THROW;
	#endif /* _MSL_USE_NEW_FILE_APIS */

_MSL_END_EXTERN_C	/*- cc 010410 -*/

#endif /* _MSL_FSP_FOPEN_H */

/* Change record:
 * mm  970508 Corrected heading wrapper
 * mm  970903 Added #include of ansi_parms.h and stdio.h to allow inclusion as first include
 * mm  990316 Replaced now obsoleted __extern_c and __end_extern_c
 * JWW 001029 Added FSRef_fopen()
 * cc  010405 removed pragma options align native and reset
 * cc  010410 updated to new namespace macros
 * JWW 010618 Use cname headers exclusively to prevent namespace pollution in C++
 * JWW 010709 Added FSRefParentAndFilename_fopen()
 * JWW 011015 Changed const FSRefPtr to const FSRef * in order to get the correct const-ness
 * JWW 011126 Added case for Mach-O
 * hh  020603 Added no throw spec to functions
 * JWW 020607 Always prototype FSRef routines if the Carbon APIs are not being used
 */