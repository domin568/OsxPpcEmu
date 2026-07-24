/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/08/20 20:23:47 $
 * $Revision: 1.22.2.3 $
 */

#ifndef _MSL_CMATH_MACH_H
#define _MSL_CMATH_MACH_H

#include <ansi_parms.h>
#include <msl_t.h>

#if _MSL_C99													/*- mm 030702 -*/
#ifndef __MATH__
	#undef MATH_ERRNO
	#undef MATH_ERREXCEPT
	#undef math_errhandling
	
	#include <math.h>		/* JWW - Get the BSD math.h header... do not use cmath here. */
#endif

/* JWW - BSD C v2 (<= 10.1) does not define FP_FAST_FMA, but v3 (>= 10.2) does */
#ifndef FP_FAST_FMA
	#define _MSL_VERSION_OF_BSD 2
#else
	#define _MSL_VERSION_OF_BSD 3
#endif

#if (_MSL_VERSION_OF_BSD <= 2) && !defined(MATH_ERRNO)
	#define MATH_ERRNO 		1
	#define MATH_ERREXCEPT	2
	#define math_errhandling _MSL_MATH_ERRHANDLING
#endif /* _MSL_VERSION_OF_BSD <= 2 */

#define FP_NAN       1  /*   quiet NaN (signaling Nan supported on MAC but nowhere else. */
#define FP_INFINITE  2  /*   + or - infinity      */
#define FP_ZERO      3  /*   + or - zero          */
#define FP_NORMAL    4  /*   all normal numbers   */
#define FP_SUBNORMAL 5  /*   denormal numbers     */

#define DECIMAL_DIG 17
#endif /* _MSL_C99 */									/*- mm 030702 -*/

#if __option(little_endian)
# define __HI(x) ( sizeof(x)==8 ? *(1+(_INT32*)&x) : (*(_INT32*)&x))
# define __LO(x) (*(_INT32*)&x)
# define __UHI(x) ( sizeof(x)==8 ? *(1+(_UINT32*)&x) : (*(_UINT32*)&x))
# define __ULO(x) (*(_UINT32*)&x)
#else
# define __LO(x) ( sizeof(x)==8 ? *(1+(_INT32*)&x) : (*(_INT32*)&x))
# define __HI(x) (*(_INT32*)&x)
# define __ULO(x) ( sizeof(x)==8 ? *(1+(_UINT32*)&x) : (*(_UINT32*)&x))
# define __UHI(x) (*(_UINT32*)&x)
#endif

_MSL_BEGIN_EXTERN_C	/*- cc 010410 -*/

_MSL_IMP_EXP long __double_huge[];
_MSL_IMP_EXP long __float_nan[];
_MSL_IMP_EXP long __float_huge[];

#if !defined(__FP__) || (defined(__cplusplus) && defined(_MSL_USING_NAMESPACE))

/*
 * <CoreServices/fp.h> also defines efficiency types.
 * we recommend NOT using fp.h to do this if you want your code to be portable outside
 * the Mac environment.  The draft standard specifies double_t and float_t be introduced
 * in <math.h>.  The fp.h header is a Mac specific header.
 */

#undef _MSL_FLT_EVAL_METHOD
#define _MSL_FLT_EVAL_METHOD 2

#ifdef FLT_EVAL_METHOD
	#undef FLT_EVAL_METHOD
	#define FLT_EVAL_METHOD _MSL_FLT_EVAL_METHOD
#endif

/*
 * 7.7
 * 
 * Defines
 */	

_MSL_BEGIN_NAMESPACE_STD

#if _MSL_VERSION_OF_BSD <= 2
	#if	(FLT_EVAL_METHOD == 0)
		typedef float float_t;
		typedef double double_t;
	#elif (FLT_EVAL_METHOD == 1)
		typedef double float_t;
		typedef double double_t;
	#elif (FLT_EVAL_METHOD == 2)
		typedef long double float_t;
		typedef long double double_t;
	#endif  /* FLT_EVAL_METHOD */
#endif /* _MSL_VERSION_OF_BSD <= 2 */

_MSL_END_NAMESPACE_STD

#if defined(__cplusplus) && defined(_MSL_USING_NAMESPACE)
	using std::float_t;
	using std::double_t;
#endif

/*  number classification */

#ifndef HUGE_VAL
	#define HUGE_VAL  (*(double*)     __double_huge)
#endif

#if _MSL_C99

#ifndef INFINITY
	#define INFINITY  (*(float*)      __float_huge)
#endif
#ifndef NAN
	#define NAN       (*(float*)      __float_nan)
#endif

#endif /* _MSL_C99 */
#endif	/* __FP__ */

_MSL_END_EXTERN_C	/*- cc 010410 -*/


#if _MSL_VERSION_OF_BSD <= 2
	#define HUGE_VALF (*(float*)      __float_huge)
#endif /* _MSL_VERSION_OF_BSD <= 2 */

#define HUGE_VALL (*(long double*)__double_huge)


/* start out w/ definitions of inlines/macros which are neither extern "C" nor in namespace std */

#if !defined(__FP__) && (_MSL_VERSION_OF_BSD <= 2)
/* fpclassify for floats */
_MSL_INLINE int __fpclassifyf(float x)
{
 switch( (*(_INT32*)&x)&0x7f800000 )
  {
  case 0x7f800000:
   {
    if((*(_INT32*)&x)&0x007fffff) return FP_NAN;
    else return FP_INFINITE;
    break;
   }
  case 0:
   {
    if((*(_INT32*)&x)&0x007fffff) return FP_SUBNORMAL;
    else return FP_ZERO; 
    break; 
   }
  }
  return FP_NORMAL;
}  

/* fpclassify for doubles or integral types */

_MSL_INLINE int __fpclassifyd(double x) 
{
 switch(__HI(x)&0x7ff00000 )
  {
   case 0x7ff00000:
   {
    if((__HI(x)&0x000fffff) || (__LO(x)&0xffffffff)) return FP_NAN;
    else return FP_INFINITE;
    break;
   }
  case 0:
  {
    if((__HI(x)&0x000fffff) || (__LO(x)&0xffffffff)) return FP_SUBNORMAL;
    else return FP_ZERO; 
    break; 
  }
  
  }
  return FP_NORMAL;
} 

#define fpclassify(x)  \
	 ((sizeof(x) == sizeof(float))  ? __fpclassifyf((float)(x)) \
     :  __fpclassifyd((double)(x)) )
 
#define signbit(x)((int)(__HI(x)&0x80000000))
#define isnormal(x) (fpclassify(x) == FP_NORMAL)
#define isnan(x)    (fpclassify(x) == FP_NAN)
#define isinf(x)    (fpclassify(x) == FP_INFINITE)
#define isfinite(x) ((fpclassify(x) > FP_INFINITE))
#endif /* !defined(__FP__) && (_MSL_VERSION_OF_BSD <= 2) */


_MSL_BEGIN_NAMESPACE_STD	/*- cc 010410 -*/

	/*

	 *
	 * long double math functions(fool's), we do not support true long double outside of macos 68K
	 */

	_MSL_INLINE long double acosl(long double x) _MSL_CANT_THROW
		{return acos((double)x);}
	_MSL_INLINE long double asinl(long double x) _MSL_CANT_THROW
		{return asin((double)x);}
	_MSL_INLINE long double atanl(long double x) _MSL_CANT_THROW
		{return atan((double)x);}
	_MSL_INLINE long double atan2l(long double y, long double x) _MSL_CANT_THROW
		{return atan2((double)y, (double)x);}
	_MSL_INLINE long double cosl(long double x) _MSL_CANT_THROW
		{return cos((double)x);}
	_MSL_INLINE long double sinl(long double x) _MSL_CANT_THROW
		{return sin((double)x);}
	_MSL_INLINE long double tanl(long double x) _MSL_CANT_THROW
		{return tan((double)x);}
	_MSL_INLINE long double coshl(long double x) _MSL_CANT_THROW
		{return cosh((double)x);}
	_MSL_INLINE long double sinhl(long double x) _MSL_CANT_THROW
		{return sinh((double)x);}
	_MSL_INLINE long double tanhl(long double x) _MSL_CANT_THROW
		{return tanh((double)x);}
	_MSL_INLINE long double acoshl(long double x) _MSL_CANT_THROW
		{return acosh((double)x);}
	_MSL_INLINE long double asinhl(long double x) _MSL_CANT_THROW
		{return asinh((double)x);}
	_MSL_INLINE long double atanhl(long double x) _MSL_CANT_THROW
		{return atanh((double)x);}
	_MSL_INLINE long double expl(long double x) _MSL_CANT_THROW
		{return exp((double)x);}
	_MSL_INLINE long double frexpl(long double x, int* exp) _MSL_CANT_THROW
		{return frexp((double)x, exp);}
	_MSL_INLINE long double ldexpl(long double x, int exp) _MSL_CANT_THROW
		{return ldexp((double)x, exp);}
	_MSL_INLINE long double logl(long double x) _MSL_CANT_THROW
		{return log((double)x);}
	_MSL_INLINE long double log10l(long double x) _MSL_CANT_THROW
		{return log10((double)x);}
	_MSL_INLINE long double modfl(long double x, long double* iptr) _MSL_CANT_THROW
		{
			double iptrd;
			long double result = modf((double)x, &iptrd);
			*iptr = iptrd;
			return result;
		}

	_MSL_INLINE long double scalbnl(long double x, int n) _MSL_CANT_THROW
		{return ldexpl(x, n);}
	_MSL_INLINE long double scalblnl(long double x, long int n) _MSL_CANT_THROW
		{return ldexp(x, (int)n);}
	_MSL_INLINE long double fabsl(long double x) _MSL_CANT_THROW
		{return fabs((double)x);}

#if _MSL_VERSION_OF_BSD <= 2
	_MSL_INLINE float abs(float x)
		{return (float) fabs(x);}
	_MSL_INLINE double abs(double x)
		{return fabs(x);}
	_MSL_INLINE long double abs(long double x)
		{return fabs((double)x);}
#endif /* _MSL_VERSION_OF_BSD <= 2 */

	_MSL_INLINE long double powl(long double x, long double y) _MSL_CANT_THROW
		{return pow((double)x, (double)y);}
	_MSL_INLINE long double sqrtl(long double x) _MSL_CANT_THROW
		{return sqrt((double)x);}
	_MSL_INLINE long double hypotl(long double x, long double y) _MSL_CANT_THROW
		{return hypot((double)x, (double)y);}
	
	_MSL_INLINE long double ceill(long double x) _MSL_CANT_THROW
		{return ceil((double)x);}
	_MSL_INLINE long double floorl(long double x) _MSL_CANT_THROW
		{return floor((double)x);}

	_MSL_INLINE long double fmodl(long double x, long double y) _MSL_CANT_THROW
		{return fmod((double)x, (double)y);}
	_MSL_INLINE long double remainderl(long double x, long double y) _MSL_CANT_THROW
		{return remainder((double)x, (double)y);}
	_MSL_INLINE long double copysignl(long double x, long double y) _MSL_CANT_THROW
		{return copysign((double)x, (double)y);}

#if _MSL_VERSION_OF_BSD >= 3
	_MSL_INLINE float log2f(float x) _MSL_CANT_THROW
		{return (float)log2((double)x);}
	_MSL_INLINE long double log2l(long double x) _MSL_CANT_THROW
		{return log2((double)x);}
#endif

/* C9X foof's-- only the 22 K&R math functions have actual foof implementations(prototypes), 
   keep the others as inlines returning double until/if they are actually written.
*/ 

_MSL_END_NAMESPACE_STD	/*- cc 010410 -*/

#if _MSL_VERSION_OF_BSD <= 2
	_MSL_INLINE long double modf(long double x, long double* iptr)
	{
		double iptrd;
		long double result = modf((double)x, &iptrd);
		*iptr = iptrd;
		return result;
	}
#endif /* _MSL_VERSION_OF_BSD <= 2 */

#endif /* _MSL_CMATH_MACH_H */

/* Change record:
 * hh  000614 Created
 * JWW 001208 Turned file into cmath.macho.h and added lots more math functions
 * JWW 010122 Added abs() variants
 * JWW 010215 Added definitions for float_t and double_t if <CoreServices/fp.h> was not included
 * cc  010410 updated to new namespace macros
 * hh  020603 Added no throw spec to functions
 * JWW 020712 Added cases for building on top of the BSD C 3.1 library
 * JWW 020830 Build only with BSD C 3.1 library - version 2 is no longer supported
 * JWW 020904 Get BSD version using FP_FAST_FMA and don't assume math.h is not already included
 * mm  030702 Added C99 wrappers
 */