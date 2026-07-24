/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/06/13 21:31:37 $
 * $Revision: 1.46 $
 */

#ifndef _MSL_ANSI_PREFIX_MAC_H
#define _MSL_ANSI_PREFIX_MAC_H

#include <os_enum.h>
#define __dest_os __mac_os

#ifndef _MSL_FLT_EVAL_METHOD
	#define _MSL_FLT_EVAL_METHOD  0
#endif

#ifndef _MSL_SIGDIGLEN
	#define _MSL_SIGDIGLEN	36		/*- cc 011211 -*/
#endif

/*
	JWW - You can change the define of _MSL_THREADSAFE to control the behavior of how memory is
	allocated at the system level.  When defined to 0, the traditional NewPtr/DisposePtr toolbox
	calls are used to request memory from the system.  When defined to 1, the multiprocessing
	MPAllocateAligned/MPFree toolbox calls are used to request memory.  Note that the OS must
	have MP 2.0 or later in order for MPAllocateAligned to be present.
*/

#ifndef _MSL_THREADSAFE
	#define _MSL_THREADSAFE 0				/*- JWW 010426 -*/
#endif

#ifndef _MSL_IMP_EXP    		/*- cc 000315 -*/  
	#define _MSL_IMP_EXP 
#endif 

#ifndef _MSL_POSIX
	#define _MSL_POSIX 1
#endif

#ifndef _MSL_C99
	#define _MSL_C99 1
#endif

#ifndef _MSL_LONGLONG
	#define _MSL_LONGLONG 1
#endif

#ifndef _MSL_WIDE_CHAR
	#define _MSL_WIDE_CHAR 1
#endif

#ifndef _MSL_WFILEIO_AVAILABLE
	#if defined(__MWERKS__) && __option(wchar_type)
		#define _MSL_WFILEIO_AVAILABLE 1
	#else
		#define _MSL_WFILEIO_AVAILABLE 0
	#endif
#endif

#ifndef _MSL_NEEDS_EXTRAS
	/* to access prototypes of non standard functions via a standard header */
	#define _MSL_NEEDS_EXTRAS 1
#endif

/* JWW - Always leave this one set to 1.  You cannot use non-Carbon-based APIs when */
/* the executable is linked as PEF. */
#ifndef _MSL_CARBON_FILE_APIS
	#define _MSL_CARBON_FILE_APIS 1
#endif

/*
	JWW - You can comment out either of the following two defines to limit the MSL library
	to using only one style of the file system APIs or the other.
	
	When _MSL_USE_OLD_FILE_APIS is 1 (but _MSL_USE_NEW_FILE_APIS is 0), MSL operates exactly
	the same way it always has since MSL first shipped.
	
	When _MSL_USE_NEW_FILE_APIS is 1 (but _MSL_USE_OLD_FILE_APIS is 0), MSL uses the new
	calls introduced in OS 9 to access the file system.  This means you get access to filenames
	longer than 32 characters and files greater than 2GB.  You must be careful to not use this
	configuration on a system which does not support the new APIs since no test is done to
	see if the file system routines are actually present before using them.
	
	When both _MSL_USE_NEW_FILE_APIS and _MSL_USE_OLD_FILE_APIS are 1, MSL tests the system
	to determine if the enhanced file system APIs are available, and if so it uses them.  If not,
	it falls back to the traditional method of accessing files.  This increases the library size
	since twice the amount of file system code is necessary, but you get the safety of knowing
	your code will operate properly on older systems.
	
	It is an error for both _MSL_USE_NEW_FILE_APIS and _MSL_USE_OLD_FILE_APIS to be 0.
*/

#ifndef _MSL_USE_OLD_FILE_APIS
	#define _MSL_USE_OLD_FILE_APIS 1
#endif

#ifndef _MSL_USE_NEW_FILE_APIS
	#define _MSL_USE_NEW_FILE_APIS 1
#endif

#if _MSL_USE_NEW_FILE_APIS && (!defined(__POWERPC__))
	/* JWW - _MSL_USE_NEW_FILE_APIS cannot be used with 68K targets */
	#undef _MSL_USE_NEW_FILE_APIS
	#define _MSL_USE_NEW_FILE_APIS 0
#endif

#if _MSL_USE_OLD_FILE_APIS && _MSL_USE_NEW_FILE_APIS
	#define _MSL_USE_OLD_AND_NEW_FILE_APIS 1
#elif _MSL_USE_OLD_FILE_APIS || _MSL_USE_NEW_FILE_APIS
	#define _MSL_USE_OLD_AND_NEW_FILE_APIS 0
#else
	#error At least one of _MSL_USE_OLD_FILE_APIS or _MSL_USE_NEW_FILE_APIS must be on!
#endif

/* #define _MSL_MALLOC_0_RETURNS_NON_NULL */

/*
	Turn on _MSL_OS_DIRECT_MALLOC for a malloc alternative that simply goes
	straight to the OS with	no pooling.  Recompile the C lib when flipping
	this switch.  This will typically cause poorer performance, but may be of
	help when debugging memory problems. */

/* #define _MSL_OS_DIRECT_MALLOC */
/* #define _MSL_CLASSIC_MALLOC */

/* Turn on and off namespace std here */
#if defined(__cplusplus) && __embedded_cplusplus == 0
    #define _MSL_USING_NAMESPACE
	/* Turn on support for wchar_t as a built in type */
	/* #pragma wchar_type on */   /*  vss  not implemented yet  */
#endif

/*- hh 980217 

	__ANSI_OVERLOAD__ controls whether or not the prototypes in the C++ standard
	section 26.5 get added to <cmath> and <math.h> or not.  If __ANSI_OVERLOAD__
	is defined, and a C++ compiler is used, then these functions are available,
	otherwise not.
	
	There is one exception to the above rule:  double abs(double); is available
	in <cmath> and <math.h> if the C++ compiler is used.  __ANSI_OVERLOAD__ has
	no effect on the availability of this one function.

	There is no need to recompile the C or C++ libs when this switch is flipped.

	If _MSL_INTEGRAL_MATH is defined then in addition to the prototypes added by
	__ANSI_OVERLOAD__, there are also non-standard integral versions of these
	prototypes added as well.  This is to allow client code to put integral arguments
	into math functions, and avoid ambiguous call errors.
*/

#define __ANSI_OVERLOAD__  /*- hh 990201 -*/
#define _MSL_INTEGRAL_MATH

#define __num2dec num2dec
#define __dec2num dec2num

#endif /*	_MSL_ANSI_PREFIX_MAC_H	  */

/*#pragma once on*/
/* Switching this pragma on, can improve compilation speed but you must rebuild
	any precompiled headers when moving them to different machines. */

/* Change record:
 * mm  970110 Changed wrapper for long long support
 * hh  980727 Wrapped OLDROUTINENAMES and OLDROUTINELOCATIONS to prevent changing previously defined values.
 * mf  980811 commented out #define __ANSI_OVERLOAD__ 
 * hh  990201 turned __ANSI_OVERLOAD__ on because we now have foo(int) support
 * hh  990227 Added flag for malloc - ZoneRanger cooperation
 * hh  000302 Moved the namespace flag to here from mslGlobals.h
 * cc  000315 added _MSL_IMP_EXP
 * JWW 001030 Added _MSL_USE_OLD_FILE_APIS and _MSL_USE_NEW_FILE_APIS definitions
 * JWW 010426 Added _MWMT for using Multiprocessing for obtaining memory
 * JWW 010926 Turn on _MSL_POSIX get POSIX functions from ANSI headers
 * cc  011211 Added defines __num2dec, __dec2num, and  _MSL_SIGDIGLEN
 * JWW 020130 Changed _MWMT to _MSL_THREADSAFE for consistency's sake
 * hh  020214 Renamed _MSL_PRO4_MALLOC to _MSL_CLASSIC_MALLOC
 * JWW 020305 Turn on _MSL_NEEDS_EXTRAS to get POSIX functions included from stdio.h, etc.
 * JWW 020605 Removed obsolete _MWMT macro (use _MSL_THREADSAFE instead)
 * JWW 020626 Stripped out section dealing with including MacHeaders
 * JWW 020627 Stripped out broken section for DebugNew, which had bad circular include dependencies
 * JWW 021010 Added wchar_t file I/O routines controlled by _MSL_WFILEIO_AVAILABLE
 * JWW 030224 Changed __MSL_LONGLONG_SUPPORT__ flag into the new more configurable _MSL_LONGLONG
 * JWW 030321 Configure __has_builtin macros for efficient PPC operations
 * ejs 030613 Remove builtin overrides now that compiler supports them
 */