/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/22 20:42:18 $
 * $Revision: 1.22.2.2 $
 */

#ifndef _MSL_MATH_MACH_H
#define _MSL_MATH_MACH_H

_MSL_BEGIN_NAMESPACE_STD
_MSL_BEGIN_EXTERN_C

#if _MSL_C99							/*-	mm 030722 -*/
	_MSL_INLINE long double _MSL_MATH_CDECL
		cbrtl(long double x) _MSL_CANT_THROW { return (long double)(cbrt)((double)(x)); }
#endif /* _MSL_C99 */					/*-	mm 030722 -*/

_MSL_END_EXTERN_C
_MSL_END_NAMESPACE_STD

#ifndef __FP__

	#define _MSL_CMATH_DEFINED_MATH_ITEMS
	
	_MSL_BEGIN_NAMESPACE_STD

		#if	(_MSL_FLT_EVAL_METHOD == 0)
			
			typedef float float_t;
			typedef double double_t;
			
		#elif (_MSL_FLT_EVAL_METHOD == 1)
			
			typedef double float_t;
			typedef double double_t;
			
		#elif (_MSL_FLT_EVAL_METHOD == 2)
			
			typedef long double float_t;
			typedef long double double_t;	
			
		#endif	/* _MSL_FLT_EVAL_METHOD */


	_MSL_END_NAMESPACE_STD

	#if defined(__cplusplus) && defined(_MSL_USING_NAMESPACE)
		using std::float_t;
		using std::double_t;
	#endif

_MSL_BEGIN_NAMESPACE_STD
_MSL_BEGIN_EXTERN_C

	short relation(double_t, double_t);

	#if _MSL_USE_INLINE
	#if _MSL_C99

		_MSL_INLINE float _MSL_MATH_CDECL
			acosf(float x) _MSL_CANT_THROW { return (float)(acos)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			acosl(long double x) _MSL_CANT_THROW { return (long double)(acos)((double)(x)); }			
		_MSL_INLINE float _MSL_MATH_CDECL
			acoshf(float x) _MSL_CANT_THROW { return (float)(acosh)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			acoshl(long double x) _MSL_CANT_THROW { return (long double)(acosh)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			asinf(float x) _MSL_CANT_THROW { return (float)(asin)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			asinl(long double x) _MSL_CANT_THROW { return (long double)(asin)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			asinhf(float x) _MSL_CANT_THROW { return (float)(asinh)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			asinhl(long double x) _MSL_CANT_THROW { return (long double)(asinh)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			atanf(float x) _MSL_CANT_THROW { return (float)(atan)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			atanl(long double x) _MSL_CANT_THROW { return (long double)(atan)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			atanhl(long double x) _MSL_CANT_THROW { return (long double)(atanh)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			atanhf(float x) _MSL_CANT_THROW { return (float)(atanh)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			atan2f(float y, float x) _MSL_CANT_THROW { return (float)(atan2)((double)(y), (double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			atan2l(long double y, long double x) _MSL_CANT_THROW { return (long double)(atan2)((double)(y), (double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			ceilf(float x) _MSL_CANT_THROW { return (float)(ceil)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			ceill(long double x) _MSL_CANT_THROW { return (long double)(ceil)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			copysignf(float x, float y) _MSL_CANT_THROW { return (float)(copysign)((double)(x), (double)(y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			copysignl(long double x, long double y) _MSL_CANT_THROW { return (long double)(copysign)((double)(x), (double)(y)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			cosf(float x) _MSL_CANT_THROW { return (float)(cos)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			cosl(long double x) _MSL_CANT_THROW { return (long double)(cos)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			coshf(float x) _MSL_CANT_THROW { return (float)(cosh)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			coshl(long double x) _MSL_CANT_THROW { return (long double)(cosh)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			expf(float x) _MSL_CANT_THROW { return (float)(exp)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			expl(long double x) _MSL_CANT_THROW { return (long double)(exp)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			expm1f(float x) _MSL_CANT_THROW { return (float)(expm1)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			expm1l(long double x) _MSL_CANT_THROW { return (long double)(expm1)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			fabsf(float x) _MSL_CANT_THROW { return (float)(fabs)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			fabsl(long double x) _MSL_CANT_THROW { return (long double)(fabs)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			fdimf(float x, float y) _MSL_CANT_THROW { return (float)(fdim)((double)(x), (double)(y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			fdiml(long double x, long double y) _MSL_CANT_THROW { return (long double)(fdim)((double)(x), (double)(y)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			floorf(float x) _MSL_CANT_THROW { return (float)(floor)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			floorl(long double x) _MSL_CANT_THROW { return (long double)(floor)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			fmaxf(float x, float y) _MSL_CANT_THROW { return (float)(fmax)((double)(x), (double)(y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			fmaxl(long double x, long double y) _MSL_CANT_THROW { return (long double)(fmax)((double)(x), (double)(y)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			fminf(float x, float y) _MSL_CANT_THROW { return (float)(fmin)((double)(x), (double)(y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			fminl(long double x, long double y) _MSL_CANT_THROW { return (long double)(fmin)((double)(x), (double)(y)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			fmodf(float x, float y) _MSL_CANT_THROW { return (float)(fmod)((double)(x), (double)(y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			fmodl(long double x, long double y) _MSL_CANT_THROW { return (long double)(fmod)((double)(x), (double)(y)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			frexpf(float x, int* y) _MSL_CANT_THROW { return (float)(frexp)((double)(x), (y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			frexpl(long double x, int* y) _MSL_CANT_THROW { return (long double)(frexp)((double)(x), (y)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			hypotf(float x, float y) _MSL_CANT_THROW { return (float)(hypot)((double)(x), (double)(y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			hypotl(long double x, long double y) _MSL_CANT_THROW { return (long double)(hypot)((double)(x), (double)(y)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			ldexpf(float x, int y) _MSL_CANT_THROW { return (float)(ldexp)((double)(x), (y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			ldexpl(long double x, int y) _MSL_CANT_THROW { return (long double)(ldexp)((double)(x), (y)); }
		_MSL_INLINE long long _MSL_MATH_CDECL
			llrint(double x) _MSL_CANT_THROW { return (long long)(rint)(x); }
		_MSL_INLINE long long _MSL_MATH_CDECL
			llrintf(float x) _MSL_CANT_THROW { return (llrint)((double)(x)); }
		_MSL_INLINE long long _MSL_MATH_CDECL
			llrintl(long double x) _MSL_CANT_THROW { return (llrint)((double)(x)); }
		_MSL_INLINE long long _MSL_MATH_CDECL
			llroundf(float x) _MSL_CANT_THROW { return (llround)((double)(x)); }
		_MSL_INLINE long long _MSL_MATH_CDECL
			llroundl(long double x) _MSL_CANT_THROW { return (llround)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			logf(float x) _MSL_CANT_THROW { return (float)(log)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			logl(long double x) _MSL_CANT_THROW { return (long double)(log)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			log1pf(float x) _MSL_CANT_THROW { return (float)(log1p)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			log1pl(long double x) _MSL_CANT_THROW { return (long double)(log1p)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			log10f(float x) _MSL_CANT_THROW { return (float)(log10)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			log10l(long double x) _MSL_CANT_THROW { return (long double)(log10)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			log2f(float x) _MSL_CANT_THROW { return (float)(log2)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			log2l(long double x) _MSL_CANT_THROW { return (long double)(log2)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			logbf(float x) _MSL_CANT_THROW { return (float)(logb)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			logbl(long double x) _MSL_CANT_THROW { return (long double)(logb)((double)(x)); }
		_MSL_INLINE long _MSL_MATH_CDECL
			lrint(double x) _MSL_CANT_THROW { return (long)(rint)(x); }
		_MSL_INLINE long _MSL_MATH_CDECL
			lrintf(float x) _MSL_CANT_THROW { return (lrint)((double)(x)); }
		_MSL_INLINE long _MSL_MATH_CDECL
			lrintl(long double x) _MSL_CANT_THROW { return (lrint)((double)(x)); }
		_MSL_INLINE long _MSL_MATH_CDECL
			lroundf(float x) _MSL_CANT_THROW { return (lround)((double)(x)); }
		_MSL_INLINE long _MSL_MATH_CDECL
			lroundl(long double x) _MSL_CANT_THROW { return (lround)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			modff(float x, float* iptr) _MSL_CANT_THROW {
		  double iptrd;
		  float result = (float)modf((double)x, &iptrd);
		  *iptr = (float)iptrd;
		  return result;
		}
		
		_MSL_INLINE long double _MSL_MATH_CDECL
			modfl(long double x, long double* iptr) _MSL_CANT_THROW {
		  double iptrd;
		  long double result = (long double)modf((double)x, &iptrd);
		  *iptr = (long double)iptrd;
		  return result;
		}
		
		_MSL_INLINE double _MSL_MATH_CDECL
			nan(const char* x) _MSL_CANT_THROW
			{
				#pragma unused(x)
				return NAN;
		}
		
		_MSL_INLINE float _MSL_MATH_CDECL
			nearbyintf(float x) _MSL_CANT_THROW { return (float)(nearbyint)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			nearbyintl(long double x) _MSL_CANT_THROW { return (long double)(nearbyint)((double)(x)); }
			_MSL_INLINE long double _MSL_MATH_CDECL
			nextafterl(long double x, long double y) _MSL_CANT_THROW { return (long double)(nextafter)((double)(x), (double)(y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			nexttowardl(long double x, long double y) _MSL_CANT_THROW { return (long double)(nexttoward)((double)(x), (y)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			powf(float x, float y) _MSL_CANT_THROW { return (float)(pow)((double)(x), (double)(y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			powl(long double x, long double y) _MSL_CANT_THROW { return (long double)(pow)((double)(x), (double)(y)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			remainderf(float x, float y) _MSL_CANT_THROW { return (float)(remainder)((double)(x), (double)(y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			remainderl(long double x, long double y) _MSL_CANT_THROW { return (long double)(remainder)((double)(x), (double)(y)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			remquof(float x, float y, int* z) _MSL_CANT_THROW { return (float)(remquo)((double)(x), (double)(y), (z)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			remquol(long double x, long double y, int* z) _MSL_CANT_THROW { return (long double)(remquo)((double)(x), (double)(y), (z)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			rintf(float x) _MSL_CANT_THROW { return (float)(rint)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			rintl(long double x) _MSL_CANT_THROW { return (long double)(rint)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			roundf(float x) _MSL_CANT_THROW { return (float)(round)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			roundl(long double x) _MSL_CANT_THROW { return (long double)(round)((double)(x)); }
		
		extern double (scalb) (double, int) _MSL_CANT_THROW;
		_MSL_INLINE double _MSL_MATH_CDECL
			scalbln(double x, long n) _MSL_CANT_THROW { return (double)(scalb)(x, n); }
		_MSL_INLINE float _MSL_MATH_CDECL
			scalblnf(float x, long int y) _MSL_CANT_THROW { return (float)(scalbln)((double)(x), (y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			scalblnl(long double x, long int y) _MSL_CANT_THROW { return (long double)(scalbln)((double)(x), (y)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			scalbnf(float x, int y) _MSL_CANT_THROW { return (float)(scalbn)((double)(x), (y)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			scalbnl(long double x, int y) _MSL_CANT_THROW { return (long double)(scalbn)((double)(x), (y)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			sinf(float x) _MSL_CANT_THROW { return (float)(sin)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			sinhf(float x) _MSL_CANT_THROW { return (float)(sinh)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			sinhl(long double x) _MSL_CANT_THROW { return (long double)(sinh)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			sinl(long double x) _MSL_CANT_THROW { return (long double)(sin)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			sqrtf(float x) _MSL_CANT_THROW { return (float)(sqrt)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			sqrtl(long double x) _MSL_CANT_THROW { return (long double)(sqrt)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			tanf(float x) _MSL_CANT_THROW { return (float)(tan)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			tanhf(float x) _MSL_CANT_THROW { return (float)(tanh)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			tanhl(long double x) _MSL_CANT_THROW { return (long double)(tanh)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			tanl(long double x) _MSL_CANT_THROW { return (long double)(tan)((double)(x)); }
		_MSL_INLINE float _MSL_MATH_CDECL
			truncf(float x) _MSL_CANT_THROW { return (float)(trunc)((double)(x)); }
		_MSL_INLINE long double _MSL_MATH_CDECL
			truncl(long double x) _MSL_CANT_THROW { return (long double)(trunc)((double)(x)); }

	#endif /*_MSL_C99*/

	#endif /* _MSL_USE_INLINE */


_MSL_END_EXTERN_C
_MSL_END_NAMESPACE_STD

#else

	#include <msl_t.h>
	
	_MSL_BEGIN_EXTERN_C

		_MSL_IMP_EXP _INT32 __float_huge[];
		_MSL_IMP_EXP _INT32 __extended_huge[];

		/*  special number macros */
#if _MSL_C99											/*- mm 030521 -*/
		#define HUGE_VALF (*(float*)      __float_huge)
		#define HUGE_VALL (*(long double*)__extended_huge)
#endif /* _MSL_C99 */									/*- mm 030521 -*/

	_MSL_END_EXTERN_C

#endif /* __FP__ */


_MSL_BEGIN_EXTERN_C

extern int signgam;

extern double drem(double, double);
extern int finite(double);
extern double gamma(double);
extern double gamma_r(double, int *);
extern double lgamma_r(double, int *);
extern double j0(double);
extern double j1(double);
extern double jn(int, double);
extern long int rinttol(double x);
extern long int roundtol(double x);
extern double scalb(double, int);
extern double significand(double);
extern double y0(double);
extern double y1(double);
extern double yn(int, double);

#if !defined(__cplusplus)
	#pragma options align=native
	struct exception
	{
		int type;
		char *name;
		double arg1;
		double arg2;
		double retval;
	};
	#pragma options align=reset
	
	extern int matherr(struct exception *);
#endif

_MSL_END_EXTERN_C

#endif /* _MSL_MATH_MACH_H */

/* Change record:
 * JWW 020205 New file to define things properly for using Mach-O MSL C
 * JWW 020422 Define _MSL_CMATH_DEFINED_MATH_ITEMS instead of relying solely on __FP__
 * hh  020603 Added no throw spec to functions
 * JWW 020628 Added nan function in order to not need to rely on the Carbon.framework nan
 * mm  021108 Added wrappers for math functions in math.c
 * JWW 021211 Added cases for using extra parts of BSD and POSIX through the MSL headers
 * mm  030521 Added C99 wrappers
 * mm  030722 Added more C99 wrappers
 */