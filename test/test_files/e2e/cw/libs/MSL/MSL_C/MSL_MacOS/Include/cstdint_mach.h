/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/06/11 21:53:26 $
 * $Revision: 1.7 $
 */

#ifndef _MSL_CSTDINT_MACH
#define _MSL_CSTDINT_MACH

#include <ansi_parms.h>

/* JWW - Get basic types from system headers */
#include <machine/types.h>

#include <climits>

#if _MSL_C99                          /*- mm 030303 -*/
_MSL_BEGIN_NAMESPACE_STD
_MSL_BEGIN_EXTERN_C

/*
 * 7.18 Integer types <stdint.h>
 * 
 * 7.18.1 Integer types
 *
 */
 
#if defined(__cplusplus) && defined(_MSL_USING_NAMESPACE)
using ::int8_t;
using ::int16_t;
using ::int32_t;

#if _MSL_LONGLONG
	using ::int64_t;
#endif
#endif /* defined(__cplusplus) && defined(_MSL_USING_NAMESPACE) */
 
typedef unsigned char		uint8_t;
typedef unsigned short int  uint16_t;
typedef unsigned long int   uint32_t;

#if _MSL_LONGLONG
	typedef unsigned long long  uint64_t;
#endif

/*
 * 7.18.1.2 Minimum-width integer types
 * 
 */

typedef signed char 		int_least8_t;
typedef short int   		int_least16_t;
typedef long int    		int_least32_t;

#if _MSL_LONGLONG
	typedef long long   		int_least64_t;
#endif

typedef unsigned char		uint_least8_t;
typedef unsigned short int  uint_least16_t;
typedef unsigned long int   uint_least32_t;

#if _MSL_LONGLONG
	typedef unsigned long long  uint_least64_t;
#endif

/*
 * 7.18.1.3 Fastest minimum-width integer types
 *
 */

typedef signed char 		int_fast8_t;
typedef short int   		int_fast16_t;
typedef long int    		int_fast32_t;

#if _MSL_LONGLONG
	typedef long long   		int_fast64_t;
#endif

typedef unsigned char		uint_fast8_t;
typedef unsigned short int  uint_fast16_t;
typedef unsigned long int   uint_fast32_t;

#if _MSL_LONGLONG
	typedef unsigned long long  uint_fast64_t;
#endif

/*
 * 7.18.1.4 Integer types capable of holding object pointers
 *
 */

#if defined(__cplusplus) && defined(_MSL_USING_NAMESPACE)
using ::intptr_t;
using ::uintptr_t;
#endif /* defined(__cplusplus) && defined(_MSL_USING_NAMESPACE) */

/*
 * 7.18.1.5 Greatest-width integer types
 * 
 */

#if _MSL_LONGLONG
	typedef int64_t intmax_t;
#else											
	typedef int32_t intmax_t;				
#endif
 
#if _MSL_LONGLONG
	typedef uint64_t uintmax_t;
#else											
	typedef uint32_t uintmax_t;
#endif

/*
 * 7.18.2 Limits of specified-width integer types
 * 
 * 7.18.2.1 Limits of exact-width integer types
 */

#if (!defined(__cplusplus)) || defined(__STDC_LIMIT_MACROS)
#ifndef INT8_MIN

#define INT8_MIN		SCHAR_MIN
#define INT16_MIN		SHRT_MIN
#define INT32_MIN		LONG_MIN
#define INT64_MIN		LLONG_MIN

#define INT8_MAX		SCHAR_MAX
#define INT16_MAX		SHRT_MAX
#define INT32_MAX		LONG_MAX
#define INT64_MAX		LLONG_MAX

#define UINT8_MAX		UCHAR_MAX
#define UINT16_MAX		USHRT_MAX
#define UINT32_MAX		ULONG_MAX
#define UINT64_MAX		ULLONG_MAX

/*
 * 7.18.2.2 Limits of minimum-width integer types
 */

#define INT_LEAST8_MIN		SCHAR_MIN
#define INT_LEAST16_MIN		SHRT_MIN
#define INT_LEAST32_MIN		LONG_MIN
#define INT_LEAST64_MIN		LLONG_MIN

#define INT_LEAST8_MAX		SCHAR_MAX
#define INT_LEAST16_MAX		SHRT_MAX
#define INT_LEAST32_MAX		LONG_MAX
#define INT_LEAST64_MAX		LLONG_MAX

#define UINT_LEAST8_MAX		UCHAR_MAX
#define UINT_LEAST16_MAX	USHRT_MAX
#define UINT_LEAST32_MAX	ULONG_MAX
#define UINT_LEAST64_MAX	ULLONG_MAX

/*
 * 7.18.2.3 Limits of fastest minimum-width integer types
 */

#define INT_FAST8_MIN		SCHAR_MIN
#define INT_FAST16_MIN		SHRT_MIN
#define INT_FAST32_MIN		LONG_MIN
#define INT_FAST64_MIN		LLONG_MIN

#define INT_FAST8_MAX		SCHAR_MAX
#define INT_FAST16_MAX		SHRT_MAX
#define INT_FAST32_MAX		LONG_MAX
#define INT_FAST64_MAX		LLONG_MAX

#define UINT_FAST8_MAX		UCHAR_MAX
#define UINT_FAST16_MAX		USHRT_MAX
#define UINT_FAST32_MAX		ULONG_MAX
#define UINT_FAST64_MAX		ULLONG_MAX

/*
 * 7.18.2.4 Limits of integer types capable of holding object pointers
 */

#define INTPTR_MIN			LONG_MIN
#define INTPTR_MAX			LONG_MAX
#define UINTPTR_MAX			ULONG_MAX

/*
 * 7.18.2.5 Limits of greatest-width integer types
 */

#if _MSL_LONGLONG
	#define INTMAX_MIN			LLONG_MIN
	#define INTMAX_MAX			LLONG_MAX
	#define UINTMAX_MAX			ULLONG_MAX
#endif

/*					
 * 7.18.3 Limits of other integer types
 */

#define PTRDIFF_MIN			LONG_MIN
#define PTRDIFF_MAX			LONG_MAX
#define SIG_ATOMIC_MIN		INT_MIN
#define SIG_ATOMIC_MAX		INT_MAX

#define SIZE_MAX     		ULONG_MAX

#if _MSL_WIDE_CHAR
	#include <wchar_t.h>   /* do define WCHAR_MIN and WCHAR_MAX */		
	#define WINT_MIN			WCHAR_MIN
	#define WINT_MAX			WCHAR_MAX
#endif

#endif  /* INT8_MIN */
#endif /* (!defined(__cplusplus)) || defined(__STDC_LIMIT_MACROS) */

/*
 * 7.18.4 Macros for integer constants
 */

#if (!defined(__cplusplus)) || defined(__STDC_CONSTANT_MACROS)
#ifndef INT8_C

#define INT8_C(value) 	value
#define INT16_C(value) 	value
#define INT32_C(value) 	value ## L
#define INT64_C(value) 	value ## LL
#define UINT8_C(value) 	value ## U
#define UINT16_C(value) value ## U
#define UINT32_C(value) value ## UL
#define UINT64_C(value) value ## ULL

/*
 * 7.18.4.2 Macros for greatest-width integer constants
 */

#if _MSL_LONGLONG
	#define INTMAX_C(value)  value ## LL
	#define UINTMAX_C(value) value ## ULL
#endif	

#endif /*INT8_C	*/
#endif   /*(!defined(__cplusplus)) || defined(__STDC_CONSTANT_MACROS)*/

_MSL_END_EXTERN_C
_MSL_END_NAMESPACE_STD

#endif /* _MSL_C99 */					/*- mm 030303 -*/
#endif /*_MSL_CSTDINT_MACH */

/* Change record:
 * JWW 020712 Added cases for building on top of the BSD C 3.1 library
 * hh  021002 Changed typedefs under C++ to usings to avoid conflict with BSD
 * JWW 030224 Changed __MSL_LONGLONG_SUPPORT__ flag into the new more configurable _MSL_LONGLONG
 * JWW 030224 Changed __NO_WIDE_CHAR flag into the new more configurable _MSL_WIDE_CHAR
 * mm  030303 Added _MSL_C99 wrapper
 */