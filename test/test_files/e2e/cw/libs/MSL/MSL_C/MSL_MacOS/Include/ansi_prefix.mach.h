/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/08/20 20:23:01 $
 * $Revision: 1.39.2.2 $
 */

#ifndef _MSL_ANSI_PREFIX_MACH_H
#define _MSL_ANSI_PREFIX_MACH_H

#include <os_enum.h>
#define __dest_os __mac_os_x


#ifndef _MSL_FLT_EVAL_METHOD
	#define _MSL_FLT_EVAL_METHOD  0		/* all long double */
#endif
/*
	JWW - Default to using the BSD C headers.  If MSLCarbonPrefix.h is used, then
	the MSL C header switch _MSL_USING_MW_C_HEADERS is turned on there and overrides
	the following definition.
*/

#ifndef _MSL_USING_MW_C_HEADERS
	#define _MSL_USING_MW_C_HEADERS 0
#endif

#ifndef _MSL_SIGDIGLEN
	#define _MSL_SIGDIGLEN	36		/*- cc 011211 -*/
#endif

#ifndef _MSL_THREADSAFE
	#define _MSL_THREADSAFE 1
#endif

#if _MSL_THREADSAFE && !defined(_MSL_LOCALDATA)
	#define _MSL_LOCALDATA(_a) __msl_GetThreadLocalData()->_a
#endif

#ifndef _MSL_IMP_EXP    		/*- cc 000315 -*/
	#define _MSL_IMP_EXP
#endif

#ifndef _MSL_INLINE
	#define _MSL_INLINE __inline__
#endif

#ifndef _MSL_DO_NOT_INLINE
	#define _MSL_DO_NOT_INLINE
#endif

#ifndef _MSL_POSIX
	/* JWW - Do not include POSIX calls with MSL.  Instead, use the real POSIX calls provided by OS X */
	#define _MSL_POSIX 0
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

#ifndef _MSL_MB_LEN_MAX
	#define _MSL_MB_LEN_MAX 6
#endif

#ifndef _MSL_MB_CUR_MAX
	#define _MSL_MB_CUR_MAX 6
#endif

#ifndef _MSL_WFILEIO_AVAILABLE
	#if defined(__MWERKS__) && __option(wchar_type)
		#define _MSL_WFILEIO_AVAILABLE 1
	#else
		#define _MSL_WFILEIO_AVAILABLE 0
	#endif
#endif

#ifndef _MSL_WCHAR_T_TYPE
	#define _MSL_WCHAR_T_TYPE int
#endif

#ifndef _MSL_WCHAR_MIN
	#define _MSL_WCHAR_MIN 0x80000000U
#endif

#ifndef _MSL_WCHAR_MAX
	#define _MSL_WCHAR_MAX 0x7FFFFFFFU
#endif

#ifndef _MSL_WEOF
	#define _MSL_WEOF (__std(wint_t))(0xffffffffU)	/*- JWW 020130 -*/
#endif

/* JWW - The BSD malloc() returns memory that is already aligned for AltiVec */
#ifndef _MSL_MALLOC_IS_ALTIVEC_ALIGNED
	#define _MSL_MALLOC_IS_ALTIVEC_ALIGNED 1
#endif

/* JWW - Turn this to 1 to use the Carbon file APIs instead of the POSIX APIs for file I/O. */
/* This is useful if you want to keep your pathnames using : as the separator */
#ifndef _MSL_CARBON_FILE_APIS
	#define _MSL_CARBON_FILE_APIS 0
#endif

/*
	JWW - You can comment out either of the following two defines to limit the MSL library
	to using only one style of the file system APIs or the other.  (These defines only make
	sense when _MSL_CARBON_FILE_APIS is 1.)
	
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

#if _MSL_CARBON_FILE_APIS
	#ifndef _MSL_USE_OLD_FILE_APIS
		#define _MSL_USE_OLD_FILE_APIS 1
	#endif

	#ifndef _MSL_USE_NEW_FILE_APIS
		#define _MSL_USE_NEW_FILE_APIS 1
	#endif

	#if _MSL_USE_OLD_FILE_APIS && _MSL_USE_NEW_FILE_APIS
		#define _MSL_USE_OLD_AND_NEW_FILE_APIS 1
	#elif _MSL_USE_OLD_FILE_APIS || _MSL_USE_NEW_FILE_APIS
		#define _MSL_USE_OLD_AND_NEW_FILE_APIS 0
	#else
		#error At least one of _MSL_USE_OLD_FILE_APIS or _MSL_USE_NEW_FILE_APIS must be on!
	#endif
#endif /* _MSL_CARBON_FILE_APIS */

/* Turn on and off namespace std here */
#if defined(__cplusplus) && _MSL_USING_MW_C_HEADERS
	#define _MSL_USING_NAMESPACE
#endif

#if defined(__cplusplus) && defined(__MWERKS__) && !__option(uchar_bool)
	#define _MSL_BOOL_TYPE unsigned int
#endif

/* hh 980217 

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
/*- hh 990201 -*/

#if _MSL_USING_MW_C_HEADERS
	#define __ANSI_OVERLOAD__
	#define _MSL_INTEGRAL_MATH
#endif

#define _MSL_CX_LIMITED_RANGE

#endif /* _MSL_ANSI_PREFIX_MACH_H */

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
 * JWW 001208 Added _MSL_CX_LIMITED_RANGE and cleaned up for Mach-O
 * JWW 010926 Turn off _MSL_POSIX to not get POSIX functions from ANSI headers
 * JWW 011126 Turn on _MSL_MALLOC_IS_ALTIVEC_ALIGNED since Mach-O automatically aligns its memory
 * JWW 011128 Turn on _MWMT since Mach-O is almost always multithread aware
 * cc  011211 Added _MSL_SIGDIGLEN define
 * cc  011217 Added _MSL_WCHAR_T_TYPE & _MSL_WCHAR_MAX
 * JWW 020130 Use _MSL_WEOF for platform independent definition of WEOF
 * JWW 020130 Changed _MWMT to _MSL_THREADSAFE for consistency's sake
 * JWW 020205 Turn on __ANSI_OVERLOAD__ and _MSL_INTEGRAL_MATH when using Mach-O MSL C
 * JWW 020311 Set _MSL_DO_NOT_INLINE to nothing for MSL to override the system framework routines
 * JWW 020605 Removed obsolete _MWMT macro (use _MSL_THREADSAFE instead)
 * JWW 020627 Added _MSL_WCHAR_MIN configuration macro to account for wchar_t being signed in Mach-O
 * JWW 020712 Turn _MSL_INLINE into inline instead of __inline since C99 recognizes the easier keyword
 * JWW 021031 Made thread local data available for Mach-O
 * JWW 030224 Changed __MSL_LONGLONG_SUPPORT__ flag into the new more configurable _MSL_LONGLONG
 * JWW 030321 Configure __has_builtin macros for efficient PPC operations
 * ejs 030613 Remove builtin overrides now that compiler supports them
 */