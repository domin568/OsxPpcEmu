/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:51 $
 * $Revision: 1.21 $
 */

#ifndef _MSL_PATH2FSS_H
#define _MSL_PATH2FSS_H

#include <ansi_parms.h>

#if _MSL_CARBON_FILE_APIS

#if __MACH__
	#include <Carbon/Carbon.h>
#else
	#include <Files.h>
#endif

_MSL_BEGIN_EXTERN_C	/*- cc 010410 -*/

	_MSL_IMP_EXP_C OSErr __path2fss(const char * pathName, FSSpecPtr spec) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C OSErr __msl_path2fsr(const char * pathName, FSRefPtr theRef) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C OSErr __msl_path2splitfsr(const char * pathName, FSRefPtr theParentRef, HFSUniStr255 * theNewName) _MSL_CANT_THROW;
	
	_MSL_IMP_EXP_C TextEncoding __msl_get_system_encoding(void) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C void __msl_text2unicode(const short theLength, const char *theText, HFSUniStr255 *theUnicodeText) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C void __msl_unicode2text(const HFSUniStr255 *theUnicodeText, short *theLength, char *theText) _MSL_CANT_THROW;
	
#if _MSL_USE_NEW_FILE_APIS && _MSL_WFILEIO_AVAILABLE
	#include <wchar_t.h>
	_MSL_IMP_EXP_C OSErr __wpath2fss(const wchar_t * pathName, FSSpecPtr spec) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C OSErr __msl_wpath2fsr(const wchar_t * pathName, FSRefPtr theRef) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C OSErr __msl_wpath2splitfsr(const wchar_t * pathName, FSRefPtr theParentRef, HFSUniStr255 * theNewName) _MSL_CANT_THROW;
#endif

_MSL_END_EXTERN_C	/*- cc 010410 -*/

#endif /* _MSL_CARBON_FILE_APIS */

#endif /* _MSL_PATH2FSS_H */

/* Change record:
 * hh  971207 expanded _extern macro
 * JWW 001030 Added __msl_path2fsr and __msl_path2splitfsr
 * cc  010405 removed pragma options align native and reset
 * cc  010410 updated to new namespace macros 		  
 * JWW 010510 Added __msl_text2unicode as an extern helper instead of static just for path2fss.c
 * JWW 010529 Added __msl_unicode2text
 * JWW 010614 Added __msl_get_system_encoding
 * JWW 010730 Export the routines from the shared library so external modules can use them
 * hh  020603 Added no throw spec to functions
 * JWW 021010 Added wchar_t file I/O routines controlled by _MSL_WFILEIO_AVAILABLE
 */