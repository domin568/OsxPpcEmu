/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/08/08 01:53:17 $
 * $Revision: 1.52.2.8 $
 */
 
#ifndef _MSL_CMATH_MACOS_H
#define _MSL_CMATH_MACOS_H

#ifndef _No_Floating_Point

#include <ansi_parms.h>
#include <msl_t.h>

/* 
 *	common macro definitions 
 */

_MSL_BEGIN_EXTERN_C

#if __option(little_endian)
	#define __HI(x) ( sizeof(x)==8 ? *(1+(_INT32*)&x) : (*(_INT32*)&x))
	#define __LO(x) (*(_INT32*)&x)
	#define __UHI(x) ( sizeof(x)==8 ? *(1+(_UINT32*)&x) : (*(_UINT32*)&x))
	#define __ULO(x) (*(_UINT32*)&x)
#else
	#define __LO(x) ( sizeof(x)==8 ? *(1+(_INT32*)&x) : (*(_INT32*)&x))
	#define __HI(x) (*(_INT32*)&x)
	#define __ULO(x) ( sizeof(x)==8 ? *(1+(_UINT32*)&x) : (*(_UINT32*)&x))
	#define __UHI(x) (*(_UINT32*)&x)
#endif /* __option(little_endian) */

_MSL_IMP_EXP_C _INT32 __float_huge[];
_MSL_IMP_EXP_C _INT32 __float_nan[];
_MSL_IMP_EXP_C _INT32 __double_huge[];
_MSL_IMP_EXP_C _INT32 __extended_huge[];

#define __STDC_IEC_559__ 1

/*
 * The Apple Universal Interfaces fp.h file also defines efficiency types.
 * We recommend NOT using fp.h to do this if you want your code to be portable
 * outside the Mac environment.  The draft standard specifies double_t and
 * float_t be introduced in math.h.  The fp.h file is a Mac specific header.
 */
#if !defined(__FP__) || (defined(__cplusplus) && defined(_MSL_USING_NAMESPACE))

	/*
	 * 7.7 Defines
	 */	

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
	
#endif /* _MSL_FLT_EVAL_METHOD */
	
_MSL_END_NAMESPACE_STD

#if defined(__cplusplus) && defined(_MSL_USING_NAMESPACE)
	using std::float_t;
	using std::double_t;
#endif

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

#endif /* !__FP__ */ 

#if _MSL_C99
	#define HUGE_VALF (*(float*)      __float_huge)
	#define HUGE_VALL (*(long double*)__extended_huge)

#define FP_NAN    1  /* Quiet NaN (Signaling NaN supported on Mac but nowhere else.  If you need this support begin this list with FP_SNAN, FP_QNAN instead of FP_NAN) */
#endif /* _MSL_C99 */


#ifndef __FP__

	#define _MSL_CMATH_DEFINED_MATH_ITEMS
	
#if _MSL_C99												/*- mm 030702 -*/
	#define FP_INFINITE  2  /*   + or - infinity      */
	#define FP_ZERO      3  /*   + or - zero          */
	#define FP_NORMAL    4  /*   all normal numbers   */
	#define FP_SUBNORMAL 5  /*   denormal numbers     */
	
	#define DECIMAL_DIG 17
#ifndef FP_ILOGB0								/*- mm 030715 -*/
	 #define FP_ILOGB0   INT_MIN 				/*- mm 030715 -*/
#endif											/*- mm 030715 -*/

#ifndef FP_ILOGBNAN								/*- mm 030715 -*/
	 #define FP_ILOGBNAN INT_MAX 				/*- mm 030715 -*/
#endif 											/*- mm 030715 -*/
	
	/*  7.7.3  Classification macros */
	int __fpclassifyf(float x) _MSL_CANT_THROW;
	int __fpclassifyd(double x) _MSL_CANT_THROW;
	int __fpclassify(long double x) _MSL_CANT_THROW; 
	
	#define fpclassify(x)  \
		 ((sizeof(x) == 4)  ? __fpclassifyf((float)(x)) \
		: (sizeof(x) == 8) ?  __fpclassifyd((double)(x)) \
		:                     __fpclassify(x) )
	
	#define isnormal(x) (fpclassify(x) == FP_NORMAL)
	#define isnan(x) (fpclassify(x) <= FP_NAN)
	
	int __signbitf(float x) _MSL_CANT_THROW;
	int __signbitd(double x) _MSL_CANT_THROW;
	int __signbit(long double x) _MSL_CANT_THROW;
	
	#define signbit(x)  \
		 ((sizeof(x) == 4)  ? __signbitf((float)(x)) \
		: (sizeof(x) == 8) ? __signbitd((double)(x)) \
		:                                 __signbit(x) )
	
	int __isfinitef(float x) _MSL_CANT_THROW;
	int __isfinited(double x) _MSL_CANT_THROW;
	int __isfinite(long double x) _MSL_CANT_THROW;
	
	#define isfinite(x)  \
		 ((sizeof(x) == 4)  ? __isfinitef((float)(x)) \
		: (sizeof(x) == 8) ? __isfinited((double)(x)) \
		:                                 __isfinite(x) )		
#endif /* _MSL_C99 */
#endif /* !__FP__ */

#if _MSL_C99
	#define isinf(x) (fpclassify(x) == FP_INFINITE)
#endif /* _MSL_C99 */

#ifndef __FP__
	short relation(__std(double_t) x, __std(double_t) y) _MSL_CANT_THROW;
#endif /* __FP__ */


#if _MSL_C99
/*  7/7/14  Comparison macros  */
	#define isgreater(x, y) (relation(x, y) == 0)
	#define isgreaterequal(x, y) (relation(x, y) % 2 == 0)
	#define isless(x, y) (relation(x, y) == 1)
	#define islessequal(x, y) ((relation(x, y)+1)/2 == 1)
	#define islessgreater(x, y) (relation(x, y) <= 1)
	#define isunordered(x, y) (relation(x, y) == 3)
#endif /* _MSL_C99 */

_MSL_END_EXTERN_C

_MSL_BEGIN_NAMESPACE_STD
_MSL_BEGIN_EXTERN_C

	/* 
	 *	common function prototype declarations
	 *  (better known as the "foo" functions)
	 *  (foof and fool defined below)
	 */

#ifndef __FP__

	double acos(double x) _MSL_CANT_THROW;
	double asin(double x) _MSL_CANT_THROW;
	double atan(double x) _MSL_CANT_THROW;
	double atan2(double y, double x) _MSL_CANT_THROW;
	double ceil(double x) _MSL_CANT_THROW;
	double cos(double x) _MSL_CANT_THROW;
	double cosh(double x) _MSL_CANT_THROW;
	double exp(double x) _MSL_CANT_THROW;
	double floor(double x) _MSL_CANT_THROW;
	double fmod(double x, double y) _MSL_CANT_THROW;
	double frexp(double x, int *exp) _MSL_CANT_THROW;
	double ldexp(double x, int exp) _MSL_CANT_THROW;
	double log(double x) _MSL_CANT_THROW;
	double log10(double x) _MSL_CANT_THROW;
	double modf(double x, double *iptr) _MSL_CANT_THROW;
	double pow(double x, double y) _MSL_CANT_THROW;	
	double sin(double x) _MSL_CANT_THROW;
	double sinh(double x) _MSL_CANT_THROW;
	double sqrt(double x) _MSL_CANT_THROW;
	double tan(double x) _MSL_CANT_THROW;
	double tanh(double x) _MSL_CANT_THROW;
#if _MSL_C99												/*- mm 030702 -*/
	double acosh(double x) _MSL_CANT_THROW;
	double asinh(double x) _MSL_CANT_THROW;
	double atanh(double x) _MSL_CANT_THROW;
	double copysign(double x, double y) _MSL_CANT_THROW;
	double erf(double x) _MSL_CANT_THROW;
	double erfc(double x) _MSL_CANT_THROW;	
	double exp2(double x) _MSL_CANT_THROW;
	double expm1(double x) _MSL_CANT_THROW;
	double fdim(double x, double y) _MSL_CANT_THROW;
	double fmax(double x, double y) _MSL_CANT_THROW;
	double fmin(double x, double y) _MSL_CANT_THROW;
	double hypot(double x, double y) _MSL_CANT_THROW;
	double lgamma(double) _MSL_CANT_THROW;
	double log1p(double x) _MSL_CANT_THROW;
	double log2(double x) _MSL_CANT_THROW;
	double logb(double x) _MSL_CANT_THROW;	
	#if __MACH__
		_MSL_INLINE double nan(const char*) _MSL_CANT_THROW {return NAN;}
	#else
		double nan(const char *tagp) _MSL_CANT_THROW;
	#endif
	double nearbyint(double x) _MSL_CANT_THROW;
	#if !__MACH__
		double nextafterd(double x, double y) _MSL_CANT_THROW;
	#endif	
	double remainder(double x, double y) _MSL_CANT_THROW;
	double remquo(double x, double y, int *quo) _MSL_CANT_THROW;
	double rint(double x) _MSL_CANT_THROW;
	double round(double x) _MSL_CANT_THROW;
	double_t scalb(double_t x, long n) _MSL_CANT_THROW; 
	double trunc(double x) _MSL_CANT_THROW;

#endif /* _MSL_C99 */												/*- mm 030702 -*/

	long rinttol(double x) _MSL_CANT_THROW;
	long roundtol(double x) _MSL_CANT_THROW;
	double gamma(double x) _MSL_CANT_THROW;

#endif /* !__FP__ */

#if _MSL_C99	

	double cbrt(double x) _MSL_CANT_THROW;
	int ilogb(double x);
	_MSL_INLINE _MSL_IMP_EXP_C  double      _MSL_MATH_CDECL fma(double, double, double) _MSL_CANT_THROW;
	_MSL_INLINE _MSL_IMP_EXP_C  float       _MSL_MATH_CDECL fmaf(float, float, float) _MSL_CANT_THROW;
	_MSL_INLINE _MSL_IMP_EXP_C  long double _MSL_MATH_CDECL fmal(long double, long double, long double) _MSL_CANT_THROW;
	double tgamma(double) _MSL_CANT_THROW;
	float tgammaf(float) _MSL_CANT_THROW;
	long double tgammal(long double) _MSL_CANT_THROW;
	
	#if __has_intrinsic(__builtin_fma)
		#define FAST_FMA 1
		#define FAST_FMAL 1
		
		_MSL_INLINE _MSL_IMP_EXP_C double _MSL_MATH_CDECL fma(double x, double y, double z) _MSL_CANT_THROW
		{
			return __builtin_fma(x, y, z);
		}
	#else
		_MSL_INLINE _MSL_IMP_EXP_C double _MSL_MATH_CDECL fma(double x, double y, double z) _MSL_CANT_THROW
		{
			return __msl_fma(x, y, z);
		}
	#endif /* __has_intrinsic(__builtin_fma) */
	
	#if __has_intrinsic(__builtin_fmaf)
		#define FAST_FMAF 1
		
		_MSL_INLINE _MSL_IMP_EXP_C float _MSL_MATH_CDECL fmaf(float x, float y, float z) _MSL_CANT_THROW
		{
			return (float) __builtin_fmaf(x, y, z);
		}
	#else
		_MSL_INLINE _MSL_IMP_EXP_C float _MSL_MATH_CDECL fmaf(float x, float y, float z) _MSL_CANT_THROW
		{
			return __msl_fmaf(x, y, z);
		}
	#endif /* __has_intrinsic(__builtin_fmaf) */
	
	_MSL_INLINE _MSL_IMP_EXP_C long double _MSL_MATH_CDECL fmal(long double x, long double y, long double z) _MSL_CANT_THROW
	{
		return fma((double) x, (double) y, (double) z);
	}

#endif /* _MSL_C99 */

/* foo redirection */
#ifndef __cplusplus

	#if !defined(__FP__) && !defined(_No_Floating_Point_Regs)
		double fabs(double x) _MSL_CANT_THROW;
		#define fabs(x) __fabs(x)
	#endif
	
#if _MSL_C99

	#if _MSL_LONGLONG
	_MSL_IMP_EXP_C long long llrint(double x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C long long llround(double x) _MSL_CANT_THROW;
	#endif	/* _MSL_LONGLONG */	
	_MSL_IMP_EXP_C long int lrint(double x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C long int lround(double x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C double nextafter(double x, double y) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C double scalbn(double x, int n) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C double scalbln(double x, long n) _MSL_CANT_THROW;

	#if !__MACH__
		#define nextafter(x, y) nextafterd(x, y)
	#endif	
	#if _MSL_LONGLONG	
	#define llrint(x)     ((long long)rint(x))
	#define llround(x)    ((long long)round(x))
	#endif /* _MSL_LONGLONG */
	#define lrint(x)      rinttol(x)
	#define lround(x)     roundtol(x)	
	#define scalbn(x, n)  scalb(x, n)
	#define scalbln(x, n) scalb(x, n)

#endif /* _MSL_C99 */

#else

#if _MSL_C99
	_MSL_IMP_EXP_C double nextafter(double x, double y) _MSL_CANT_THROW;
#endif /* _MSL_C99 */	

_MSL_END_EXTERN_C	

	#if !defined(__FP__) && !defined(_No_Floating_Point_Regs)
		inline double fabs(double x) _MSL_CANT_THROW
			{return __fabs(x);}
	#endif

#if _MSL_C99

	#if _MSL_LONGLONG
	inline long long llround(double x) _MSL_CANT_THROW
		{return (long long)round(x);}	
	inline long long llrint(double x) _MSL_CANT_THROW
		{return (long long)rint(x);}
	#endif /* _MSL_LONGLONG */
	inline long int lrint(double x) _MSL_CANT_THROW
		{return rinttol(x);}
	inline long int lround(double x) _MSL_CANT_THROW
		{return roundtol(x);}		
	inline double scalbn(double x, int n) _MSL_CANT_THROW
		{return (double)scalb(x, n);}
	inline double scalbln(double x, long n) _MSL_CANT_THROW
		{return (double)scalb(x, n);}	

#endif /* _MSL_C99 */	

_MSL_BEGIN_EXTERN_C

#endif /* __cplusplus */ /* end foo support */

#if _MSL_C99

/* foof functions */
float modff(float x, float *iptr) _MSL_CANT_THROW;
float nanf(const char* x);
#ifndef __FP__
long double nanl(const char* x);
#endif /* !__FP__ */
float nextafterf(float x, float y) _MSL_CANT_THROW;
#ifndef __FP__
long double nextafterl(long double x, long double y) _MSL_CANT_THROW;     /*- mm 030716 */
#endif
double nexttoward(double x, long double y) _MSL_CANT_THROW;
float nexttowardf(float x, long double y) _MSL_CANT_THROW;
long double nexttowardl(long double x, long double y) _MSL_CANT_THROW;

#endif /* _MSL_C99 */

#ifndef __cplusplus

/* C foof - redirection support */	
	
#if _MSL_C99

	_MSL_IMP_EXP_C float acosf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float acoshf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float asinf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float asinhf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float atanf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float atanhf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float atan2f(float y, float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float cbrtf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float ceilf(float x) _MSL_CANT_THROW;	
	_MSL_IMP_EXP_C float copysignf(float x, float y) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float cosf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float coshf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float erff(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float erfcf(float x) _MSL_CANT_THROW;	
	_MSL_IMP_EXP_C float expf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float exp2f(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float expm1f(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float fabsf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float fdimf(float x, float y) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float floorf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float fmodf(float x, float y) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float fmaxf(float x, float y) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float fminf(float x, float y) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float frexpf(float x, int *exp) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float gammaf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float hypotf(float x, float y) _MSL_CANT_THROW;		
	_MSL_IMP_EXP_C int ilogbf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float ldexpf(float x, int exp) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float lgammaf(float x) _MSL_CANT_THROW;	
	#if _MSL_LONGLONG
	_MSL_IMP_EXP_C long long llrintf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C long long llroundf(float x) _MSL_CANT_THROW;
	#endif /* _MSL_LONGLONG	*/	
	_MSL_IMP_EXP_C float logf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float log10f(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float log1pf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float log2f(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float logbf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C long int lrintf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C long int lroundf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float nearbyintf(float x) _MSL_CANT_THROW;	
	_MSL_IMP_EXP_C float powf(float x, float y) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float remainderf(float x, float y) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float remquof(float x, float y, int *quo) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float rintf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float roundf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float scalbnf(float x, int n) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float scalblnf(float x, long int n) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float sinf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float sinhf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float sqrtf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float tanf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float tanhf(float x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C float truncf(float x) _MSL_CANT_THROW;	/*  Do some foof optimization  */

	#define acosf(x)           ((float)acos(x))
	#define acoshf(x)          ((float)acosh(x))
	#define asinf(x)           ((float)asin(x))
	#define asinhf(x)          ((float)asinh(x))
	#define atanf(x)           ((float)atan(x))
	#define atan2f(y, x)       ((float)atan2(y, x))
	#define atanhf(x)          ((float)atanh(x))
	#define ceilf(x)           ((float)ceil(x))	
	#define copysignf(x, y)    ((float)copysign(x, y))		
	#define cosf(x)            ((float)cos(x))
	#define coshf(x)           ((float)cosh(x))
	#define expf(x)            ((float)exp(x))
	#define exp2f(x)           ((float)exp2(x))
	#define fabsf(x)           ((float)fabs(x))
	#define fdimf(x, y)        ((float)fdim(x, y))		
	#define floorf(x)          ((float)floor(x))
	#define fmaxf(x, y)        ((float)fmax(x, y))
	#define fminf(x, y)        ((float)fmin(x, y))	
	#define fmodf(x, y)        ((float)fmod(x, y))		
	#define frexpf(x, exp) ((float)frexp(x, exp))	
	#define hypotf(x, y)       ((float)hypot(x, y))	
	#define ldexpf(x, exp)     ((float)ldexp(x, exp))
	#define logf(x)            ((float)log(x))
	#define log10f(x)          ((float)log10(x))
	#define log1pf(x)          ((float)log1p(x))
	#define log2f(x)           ((float)log2(x))
	#define logbf(x)           ((float)logb(x))	
	#if _MSL_LONGLONG
	#define llrintf(x)         llrint(x)
	#define llroundf(x)        llround(x)
	#endif /* _MSL_LONGLONG */
	#define lrintf(x)          lrint(x)	
	#define lroundf(x)         lround(x)
	#define nearbyintf(x)      ((float)nearbyint(x))
	#define remainderf(x, y)   ((float)remainder(x, y))
	#define remquof(x, y, quo) ((float)remquo(x, y, quo))		
	#define rintf(x)           ((float)rint(x))	
	#define roundf(x)          ((float)round(x))		
	#define scalbnf(x, n)      ((float)scalb(x, n))
	#define scalblnf(x, n)     ((float)scalb(x, n))
	#define sqrtf(x)           ((float)sqrt(x))			
	#define sinf(x)            ((float)sin(x))
	#define sinhf(x)           ((float)sinh(x))
	#define tanf(x)            ((float)tan(x))
	#define tanhf(x)           ((float)tanh(x))
	#define truncf(x)          ((float)trunc(x))

#endif /* _MSL_C99 */

#define gammaf(x)          ((float)gamma(x))	

#else

_MSL_END_EXTERN_C

	/* C++ foof - redirection support */
	
	inline float gammaf(float x) _MSL_CANT_THROW
		{return (float)gamma((double_t)x);}

#if _MSL_C99	

	inline float acosf(float x) _MSL_CANT_THROW
		{return (float)acos((double_t)x);}
	inline float acoshf(float x) _MSL_CANT_THROW
		{return (float)acosh((double_t)x);}		
	inline float asinf(float x) _MSL_CANT_THROW
		{return (float)asin((double_t)x);}
	inline float asinhf(float x) _MSL_CANT_THROW
		{return (float)asinh((double_t)x);}	
	inline float atanf(float x) _MSL_CANT_THROW
		{return (float)atan((double_t)x);}
	inline float atanhf(float x) _MSL_CANT_THROW
		{return (float)atanh((double_t)x);}		
	inline float atan2f(float y, float x) _MSL_CANT_THROW
		{return (float)atan2((double_t)y, (double_t)x);}
	inline float cbrtf(float x) _MSL_CANT_THROW
		{return (float)cbrt((double_t)x);}	
	inline float ceilf(float x) _MSL_CANT_THROW
		{return (float)ceil((double_t)x);}				
	inline float cosf(float x) _MSL_CANT_THROW
		{return (float)cos((double_t)x);}
	inline float coshf(float x) _MSL_CANT_THROW
		{return (float)cosh((double_t)x);}
	inline float copysignf(float x, float y) _MSL_CANT_THROW
		{return (float)copysign((double_t)x, (double_t)y);}		
	inline float erff(float x) _MSL_CANT_THROW
		{return (float)erf((double_t)x);}
	inline float erfcf(float x) _MSL_CANT_THROW
		{return (float)erfc((double_t)x);}		
	inline float expf(float x) _MSL_CANT_THROW
		{return (float)exp((double_t)x);}
	inline float exp2f(float x) _MSL_CANT_THROW
		{return (float)exp2((double_t)x);}
	inline float expm1f(float x) _MSL_CANT_THROW
		{return (float)expm1((double_t)x);}
	inline float fabsf(float x) _MSL_CANT_THROW
		{return (float)fabs((double_t)x);}	
	inline float fdimf(float x, float y) _MSL_CANT_THROW
		{return (float)fdim((double_t)x, (double_t)y);}		
	inline float floorf(float x) _MSL_CANT_THROW
		{return (float)floor((double_t)x);}
	inline float fmaxf(float x, float y) _MSL_CANT_THROW
		{return (float)fmax((double_t)x, (double_t)y);}
	inline float fminf(float x, float y) _MSL_CANT_THROW
		{return (float)fmin((double_t)x, (double_t)y);}		
	inline float fmodf(float x, float y) _MSL_CANT_THROW
		{return (float)fmod((double_t)x, (double_t)y);}						
	inline float frexpf(float x, int* exp) _MSL_CANT_THROW
		{return (float)frexp((double_t)x, exp);}
	inline float hypotf(float x, float y) _MSL_CANT_THROW
		{return (float)hypot((double_t)x, (double_t)y);}		
	inline int ilogbf(float x) _MSL_CANT_THROW
		{return ilogb((double_t)x);} 		
	inline float ldexpf(float x, int exp) _MSL_CANT_THROW
		{return (float)ldexp((double_t)x, exp);}
	inline float lgammaf(float x) _MSL_CANT_THROW
		{return (float)lgamma((double_t)x);}
	#if _MSL_LONGLONG	
	inline long long llrintf(float x) _MSL_CANT_THROW
		{return llrint((double)x);}	
	inline long long llroundf(float x) _MSL_CANT_THROW
		{return llround((double)x);}		
	#endif /* _MSL_LONGLONG */
	inline float logf(float x) _MSL_CANT_THROW
		{return (float)log((double_t)x);}
	inline float log1pf(float x) _MSL_CANT_THROW
		{return (float)log1p((double_t)x);}
	inline float log10f(float x) _MSL_CANT_THROW
		{return (float)log10((double_t)x);}		
	inline float log2f(float x) _MSL_CANT_THROW
		{return (float)log2((double_t)x);}
	inline float logbf(float x) _MSL_CANT_THROW
		{return (float)logb((double_t)x);}
	inline long int lrintf(float x) _MSL_CANT_THROW
		{return lrint((double)x);}
	inline long int lroundf(float x) _MSL_CANT_THROW
		{return lround((double)x);}
	inline float nanf(const char* x) _MSL_CANT_THROW
		{ return (float)(nan)((x)); }
	inline float nearbyintf(float x) _MSL_CANT_THROW
		{return (float)nearbyint((double_t)x);}		
	inline float powf(float x, float y) _MSL_CANT_THROW
		{return (float)pow((double_t)x, (double_t)y);}	\
	inline float remainderf(float x, float y) _MSL_CANT_THROW
		{return (float)remainder((double_t)x, (double_t)y);}
	inline float remquof(float x, float y, int *quo) _MSL_CANT_THROW
		{return (float)remquo((double_t)x, (double_t)y, quo);}				
	inline float rintf(float x) _MSL_CANT_THROW
		{return (float)rint((double_t)x);}
	inline float roundf(float x) _MSL_CANT_THROW
		{return (float)round((double_t)x);}						
	inline float scalbnf(float x, int n) _MSL_CANT_THROW
		{return (float)scalb((double_t)x, n);}
	inline float scalblnf(float x, long int n) _MSL_CANT_THROW
		{return (float)scalb((double_t)x, n);}
	inline float sqrtf(float x) _MSL_CANT_THROW
		{return (float)sqrt((double_t)x);}													
	inline float sinf(float x) _MSL_CANT_THROW
		{return (float)sin((double_t)x);}
	inline float sinhf(float x) _MSL_CANT_THROW
		{return (float)sinh((double_t)x);}		
	inline float tanf(float x) _MSL_CANT_THROW
		{return (float)tan((double_t)x);}
	inline float tanhf(float x) _MSL_CANT_THROW
		{return (float)tanh((double_t)x);}
	inline float truncf(float x) _MSL_CANT_THROW
		{return (float)trunc((double_t)x);}

#endif /* _MSL_C99 */		

_MSL_BEGIN_EXTERN_C	

#endif /* __cplusplus */ /* end foof support */

#ifndef __cplusplus /* fool functions */

/* C fool - redirection support */
	_MSL_IMP_EXP_C long double gammal(long double x);
	
#if _MSL_C99	

	_MSL_IMP_EXP_C long double __acosl(long double x);
	_MSL_IMP_EXP_C long double __acoshl(long double x);	
	_MSL_IMP_EXP_C long double __asinl(long double x);
	_MSL_IMP_EXP_C long double __asinhl(long double x);      /*- mm 030520 -*/
	_MSL_IMP_EXP_C long double __atanl(long double x);
	_MSL_IMP_EXP_C long double __atanhl(long double x);
	_MSL_IMP_EXP_C long double __atan2l(long double y, long double x);
	_MSL_IMP_EXP_C long double cbrtl(long double x) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C long double __ceill(long double x);
	_MSL_IMP_EXP_C long double __copysignl(long double x, long double y);			
	_MSL_IMP_EXP_C long double __cosl(long double x);
	_MSL_IMP_EXP_C long double __coshl(long double x);
	_MSL_IMP_EXP_C long double __erfl(long double x);
	_MSL_IMP_EXP_C long double __erfcl(long double x);	
	_MSL_IMP_EXP_C long double __expl(long double x);
	_MSL_IMP_EXP_C long double __expm1l(long double x);
	_MSL_IMP_EXP_C long double __exp2l(long double x);
	_MSL_IMP_EXP_C long double __fabsl(long double x);
	_MSL_IMP_EXP_C long double __fdiml(long double x, long double y);	
	_MSL_IMP_EXP_C long double __floorl(long double x);
	_MSL_IMP_EXP_C long double __fmaxl(long double x, long double y);
	_MSL_IMP_EXP_C long double __fminl(long double x, long double y);
	_MSL_IMP_EXP_C long double __fmodl(long double x, long double y);	
	_MSL_IMP_EXP_C long double __frexpl(long double x, int *exp);	
	_MSL_IMP_EXP_C long double __hypotl(long double x, long double y);
	_MSL_IMP_EXP_C long double __lgammal(long double x);	
	long double lgammal(long double) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C int ilogbl(long double x);	
	_MSL_IMP_EXP_C long double __ldexpl(long double x, int exp);
	#if _MSL_LONGLONG	
	_MSL_IMP_EXP_C long long llrintl(long double x);
	_MSL_IMP_EXP_C long long llroundl(long double x);
	#endif /* _MSL_LONGLONG */	
	_MSL_IMP_EXP_C long double __logl(long double x);
	_MSL_IMP_EXP_C long double __logbl(long double x);	
	_MSL_IMP_EXP_C long double __log1pl(long double x);	
	_MSL_IMP_EXP_C long double __log10l(long double x);
	_MSL_IMP_EXP_C long double __log2l(long double x);	
	_MSL_IMP_EXP_C long int lrintl(long double x);
	_MSL_IMP_EXP_C long int lroundl(long double x);	
	_MSL_IMP_EXP_C long double __modfl(long double x, long double *iptr);
	_MSL_IMP_EXP_C long double __nanl(const char* x);
	_MSL_IMP_EXP_C float __nanf(const char* x);
	_MSL_IMP_EXP_C long double __nearbyintl(long double x);			
	_MSL_IMP_EXP_C long double __powl(long double x, long double y);
	_MSL_IMP_EXP_C long double __remainderl(long double x, long double y);
	_MSL_IMP_EXP_C long double __remquol(long double x, long double y, int *quo);	
	_MSL_IMP_EXP_C long double __rintl(long double x);
	_MSL_IMP_EXP_C long double __roundl(long double x);
	_MSL_IMP_EXP_C long double scalbnl(long double x, int n);
	_MSL_IMP_EXP_C long double scalblnl(long double x, long n);	
	_MSL_IMP_EXP_C long double __sqrtl(long double x);
	_MSL_IMP_EXP_C long double __sinl(long double x);
	_MSL_IMP_EXP_C long double __sinhl(long double x);
	_MSL_IMP_EXP_C long double __tanhl(long double x);
	_MSL_IMP_EXP_C long double __tanl(long double x);
	_MSL_IMP_EXP_C long double __truncl(long double x);

	/*  Do some fool optimization  */

	#define acosl           __acosl
	#define acoshl          __acoshl	
	#define asinl           __asinl
	#define asinhl          __asinhl	
	#define atanl           __atanl
	#define atan2l          __atan2l
	#define atanhl          __atanhl
	#define cbrtl(x)        cbrt((double)(x))		
	#define ceill           __ceill
	#define copysignl       __copysignl	
	#define cosl            __cosl
	#define coshl           __coshl
    #define erfl            __erfl
  	#define erfcl           __erfcl	
	#define expl            __expl
	#define exp2l           __exp2l
	#define expm1l          __expm1l
	#define fabsl           __fabsl
	#define fdiml           __fdiml
	#define floorl          __floorl
	#define fmaxl           __fmaxl
	#define fminl           __fminl		
	#define fmodl           __fmodl	
	#define frexpl          __frexpl
	#define hypotl          __hypotl	
	#define ldexpl          __ldexpl
	#if _MSL_LONGLONG	
	#define llrintl(x)      llrint((double)(x))
	#define llroundl(x)     llround((double)(x))
	#endif /* _MSL_LONGLONG */
	#define logbl           __logbl
	#define logl            __logl	
	#define log10l          __log10l
	#define log1pl          __log1pl
	#define log2l           __log2l
	#define lrintl(x)       lrint((double)(x))
	#define lroundl(x)      lround((double)(x))
	#define modfl           __modfl
	#define nearbyintl      __nearbyintl	
	#define powl            __powl	
	#define rintl           __rintl
	#define roundl          __roundl
	#define remainderl      __remainderl
	#define remquol         __remquol	
	#define scalbnl(x, n)   scalb((double)(x), n)
	#define scalblnl(x, n)  scalb((double)(x), n)	
	#define sqrtl           __sqrtl	
	#define sinl            __sinl
	#define sinhl           __sinhl	
	#define tanl            __tanl
	#define tanhl           __tanhl
	#define truncl          __truncl

#endif /* _MSL_C99 */		

#else

/* C++ fool - redirection support */

_MSL_END_EXTERN_C

	inline long double gammal(long double x) _MSL_CANT_THROW
		{return gamma((double_t)x);}
		
#if _MSL_C99		

	inline long double acosl(long double x) _MSL_CANT_THROW
		{return acos((double_t)x);}
	inline long double acoshl(long double x) _MSL_CANT_THROW
		{return acosh((double_t)x);}		
	inline long double asinl(long double x) _MSL_CANT_THROW
		{return asin((double_t)x);}
	inline long double asinhl(long double x) _MSL_CANT_THROW
		{return asinh((double_t)x);}		
	inline long double atanl(long double x) _MSL_CANT_THROW
		{return atan((double_t)x);}
	inline long double atanhl(long double x) _MSL_CANT_THROW
		{return atanh((double_t)x);}		
	inline long double atan2l(long double y, long double x) _MSL_CANT_THROW
		{return atan2((double_t)y, (double_t)x);}
	inline long double cbrtl(long double x) _MSL_CANT_THROW
		{return cbrt((double)x);}
	inline long double ceill(long double x) _MSL_CANT_THROW
		{return ceil((double_t)x);}
	inline long double copysignl(long double x, long double y) _MSL_CANT_THROW
		{return copysign((double_t)x, (double_t)y);}					
	inline long double cosl(long double x) _MSL_CANT_THROW
		{return cos((double_t)x);}
	inline long double coshl(long double x) _MSL_CANT_THROW
		{return cosh((double_t)x);}	
	inline long double erfl(long double x) _MSL_CANT_THROW
		{return erf((double_t)x);}
	inline long double erfcl(long double x) _MSL_CANT_THROW
		{return erfc((double_t)x);}		
	inline long double expl(long double x) _MSL_CANT_THROW
		{return exp((double_t)x);}
	inline long double exp2l(long double x) _MSL_CANT_THROW
		{return exp2((double_t)x);}
	inline long double expm1l(long double x) _MSL_CANT_THROW
		{return expm1((double_t)x);}
	inline long double fabsl(long double x) _MSL_CANT_THROW
		{return fabs((double_t)x);}
	inline long double fdiml(long double x, long double y) _MSL_CANT_THROW
		{return fdim((double_t)x, (double_t)y);}	
	inline long double floorl(long double x) _MSL_CANT_THROW
		{return floor((double_t)x);}
	inline long double fmaxl(long double x, long double y) _MSL_CANT_THROW
		{return fmax((double_t)x, (double_t)y);}
	inline long double fminl(long double x, long double y) _MSL_CANT_THROW
		{return fmin((double_t)x, (double_t)y);}
	inline long double fmodl(long double x, long double y) _MSL_CANT_THROW
		{return fmod((double_t)x, (double_t)y);}				
	inline long double frexpl(long double x, int* exp) _MSL_CANT_THROW
		{return frexp((double_t)x, exp);}
	inline long double hypotl(long double x, long double y) _MSL_CANT_THROW
		{return hypot((double_t)x, (double_t)y);}		
	inline int ilogbl(long double x) _MSL_CANT_THROW
		{return ilogb((double)x);}	
	inline long double ldexpl(long double x, int exp) _MSL_CANT_THROW
		{return ldexp((double_t)x, exp);}
	inline long double lgammal(long double x) _MSL_CANT_THROW
		{return lgamma((double_t)x);}
	#if _MSL_LONGLONG	
	inline long long llrintl(long double x) _MSL_CANT_THROW
		{return llrint((double)x);}	
	inline long long llroundl(long double x) _MSL_CANT_THROW
		{return llround((double)x);}
	#endif /* _MSL_LONGLONG */
	inline long double logl(long double x) _MSL_CANT_THROW
		{return log((double_t)x);}
	inline long double logbl(long double x) _MSL_CANT_THROW
		{return logb((double_t)x);}			
	inline long double log10l(long double x) _MSL_CANT_THROW
		{return log10((double_t)x);}
	inline long double log1pl(long double x) _MSL_CANT_THROW
		{return log1p((double_t)x);}
	inline long double log2l(long double x) _MSL_CANT_THROW
		{return log2((double_t)x);}	
	inline long double modfl(long double x, long double* iptr) _MSL_CANT_THROW
	{
		double iptrd;
		long double result = modf((double)x, &iptrd);
		*iptr = iptrd;
		return result;
	}
	inline long int lrintl(long double x) _MSL_CANT_THROW
		{return lrint((double)x);}
	inline long int lroundl(long double x) _MSL_CANT_THROW
		{return lround((double)x);}				
	inline long double nanl(const char* x) _MSL_CANT_THROW
		{return (long double)(nan)(x); }
	inline long double nearbyintl(long double x) _MSL_CANT_THROW
		{return nearbyint((double_t)x);}	
	inline long double powl(long double x, long double y) _MSL_CANT_THROW
		{return pow((double_t)x, (double_t)y);}
	inline long double remainderl(long double x, long double y) _MSL_CANT_THROW
		{return remainder((double_t)x, (double_t)y);}		
	inline long double remquol(long double x, long double y, int *quo) _MSL_CANT_THROW
		{return remquo((double_t)x, (double_t)y, quo);}	
	inline long double rintl(long double x) _MSL_CANT_THROW
		{return rint((double_t)x);}
	inline long double roundl(long double x) _MSL_CANT_THROW
		{return round((double_t)x);}	
	inline long double scalbnl(long double x, int n) _MSL_CANT_THROW
		{return scalb((double_t)x, n);}
	inline long double scalblnl(long double x, long int n) _MSL_CANT_THROW
		{return scalb((double_t)x, n);}	
	inline long double sqrtl(long double x) _MSL_CANT_THROW
		{return sqrt((double_t)x);}		
	inline long double sinl(long double x) _MSL_CANT_THROW
		{return sin((double_t)x);}
	inline long double sinhl(long double x) _MSL_CANT_THROW
		{return sinh((double_t)x);}					
	inline long double tanl(long double x) _MSL_CANT_THROW
		{return tan((double_t)x);}
	inline long double tanhl(long double x) _MSL_CANT_THROW
		{return tanh((double_t)x);}		
	inline long double truncl(long double x) _MSL_CANT_THROW
		{return trunc((double_t)x);}
		
#endif /*_MSL_C99 */
				
_MSL_BEGIN_EXTERN_C

#endif /* __cplusplus */ /* end fool support */

#ifdef __cplusplus

_MSL_END_EXTERN_C
	
	inline float abs(float x) _MSL_CANT_THROW
		{return fabsf(x);}
	inline double abs(double x) _MSL_CANT_THROW
		{return fabs(x);}
	inline long double abs(long double x) _MSL_CANT_THROW
		{return fabsl(x);}
	
_MSL_BEGIN_EXTERN_C	

#endif /* __cplusplus */

#if defined(__cplusplus) && defined(__ANSI_OVERLOAD__) && !defined(__FP__)

_MSL_END_EXTERN_C

	inline double pow(double x, int y) _MSL_CANT_THROW
		{return pow(x, (double)y);}
	inline float gamma(float x) _MSL_CANT_THROW
		{return gammaf(x);}		
		
#if _MSL_C99 	/*  foo(float) support  */

	inline float acos(float x) _MSL_CANT_THROW
		{return acosf(x);}
	inline float acosh(float x) _MSL_CANT_THROW
		{return acoshf(x);}		
	inline float asin(float x) _MSL_CANT_THROW
		{return asinf(x);}
	inline float asinh(float x) _MSL_CANT_THROW
		{return asinhf(x);}		
	inline float atan(float x) _MSL_CANT_THROW
		{return atanf(x);}
	inline float atanh(float x) _MSL_CANT_THROW
		{return atanhf(x);}			
	inline float atan2(float y, float x) _MSL_CANT_THROW
		{return atan2f(y, x);}
	inline float ceil(float x) _MSL_CANT_THROW
		{return ceilf(x);}		
	inline float cbrt(float x) _MSL_CANT_THROW 
		{return cbrtf(x);}
	inline float copysign(float x, float y) _MSL_CANT_THROW
		{return copysignf(x, y);}		 			
	inline float cos(float x) _MSL_CANT_THROW
		{return cosf(x);}
	inline float cosh(float x) _MSL_CANT_THROW
		{return coshf(x);}
	inline float erf(float x) _MSL_CANT_THROW
		{return erff(x);}
	inline float erfc(float x) _MSL_CANT_THROW
		{return erfcf(x);}		
	inline float exp(float x) _MSL_CANT_THROW
		{return expf(x);}
	inline float expm1(float x) _MSL_CANT_THROW
		{return expm1f(x);}		
	inline float exp2(float x) _MSL_CANT_THROW
		{return exp2f(x);}	
	inline float fabs(float x) _MSL_CANT_THROW
		{return fabsf(x);}
	inline float fdim(float x, float y) _MSL_CANT_THROW
		{return fdimf(x, y);}		
	inline float floor(float x) _MSL_CANT_THROW
		{return floorf(x);}
	inline float nearbyint(float x) _MSL_CANT_THROW
		{return nearbyintf(x);}
	inline float fma(float x, float y, float z) _MSL_CANT_THROW
		{return fmaf(x, y, z);}		
	inline float fmax(float x, float y) _MSL_CANT_THROW
		{return fmaxf(x, y);}
	inline float fmin(float x, float y) _MSL_CANT_THROW
		{return fminf(x, y);}		
	inline float fmod(float x, float y) _MSL_CANT_THROW
		{return fmodf(x, y);}				
	inline float frexp(float x, int* exp) _MSL_CANT_THROW
		{return frexpf(x, exp);}
	inline float hypot(float x, float y) _MSL_CANT_THROW
		{return hypotf(x, y);}		
	inline int ilogb(float x) _MSL_CANT_THROW
		{return ilogbf(x);}			
	inline float ldexp(float x, int exp) _MSL_CANT_THROW
		{return ldexpf(x, exp);}
	#if _MSL_LONGLONG	
	inline long long llrint(float x) _MSL_CANT_THROW
		{return llrintf(x);}
	inline long long llround(float x) _MSL_CANT_THROW
		{return llroundf(x);}
	#endif /* _MSL_LONGLONG */
	inline float lgamma(float x) _MSL_CANT_THROW
		{return lgammaf(x);}
	inline long int lrint(float x) _MSL_CANT_THROW
		{return lrintf(x);}
	inline long int lround(float x) _MSL_CANT_THROW
		{return lroundf(x);}				
	inline float log(float x) _MSL_CANT_THROW
		{return logf(x);}
	inline float logb(float x) _MSL_CANT_THROW
		{return logbf(x);}		
	inline float log1p(float x) _MSL_CANT_THROW
		{return log1pf(x);}		
	inline float log10(float x) _MSL_CANT_THROW
		{return log10f(x);}
	inline float log2(float x) _MSL_CANT_THROW
		{return log2f(x);}		
	inline float modf(float x, float* y) _MSL_CANT_THROW
		{return modff(x, y);}
	inline float nextafter(float x, float y) _MSL_CANT_THROW
		{return nextafterf(x, y);}		
	inline float pow(float x, float y) _MSL_CANT_THROW
		{return powf(x, y);}
	inline float pow(float x, int y) _MSL_CANT_THROW
		{return powf(x, y);}		
	inline float remainder(float x, float y) _MSL_CANT_THROW
		{return remainderf(x, y);}		
	inline float remquo(float x, float y, int *quo) _MSL_CANT_THROW
		{return remquof(x, y, quo);}		
	inline float rint(float x) _MSL_CANT_THROW
		{return rintf(x);}
	inline float round(float x) _MSL_CANT_THROW
		{return roundf(x);}				
	inline float scalbn(float x, int n) _MSL_CANT_THROW
		{return scalbnf(x, n);}
	inline float scalbln(float x, long int n) _MSL_CANT_THROW
		{return scalblnf(x, n);}
	inline float sqrt(float x) _MSL_CANT_THROW
		{return sqrtf(x);}												
	inline float sin(float x) _MSL_CANT_THROW
		{return sinf(x);}
	inline float sinh(float x) _MSL_CANT_THROW
		{return sinhf(x);}		
	inline float tan(float x) _MSL_CANT_THROW
		{return tanf(x);}
	inline float tanh(float x) _MSL_CANT_THROW
		{return tanhf(x);}
	inline float trunc(float x) _MSL_CANT_THROW
		{return truncf(x);}

	inline long double acos(long double x) _MSL_CANT_THROW
		{return acosl(x);}
	inline long double acosh(long double x) _MSL_CANT_THROW
		{return acoshl(x);}
	inline long double asin(long double x) _MSL_CANT_THROW
		{return asinl(x);}		
	inline long double asinh(long double x) _MSL_CANT_THROW
		{return asinhl(x);}
	inline long double atan(long double x) _MSL_CANT_THROW
		{return atanl(x);}		
	inline long double atanh(long double x) _MSL_CANT_THROW
		{return atanhl(x);}
	inline long double atan2(long double y, long double x) _MSL_CANT_THROW
		{return atan2l(y, x);}
	inline long double ceil(long double x) _MSL_CANT_THROW
		{return ceill(x);}
	inline long double cbrt(long double x) _MSL_CANT_THROW
		{return cbrtl(x);}		
	inline long double copysign(long double x, long double y) _MSL_CANT_THROW
		{return copysignl(x, y);}			
	inline long double cos(long double x) _MSL_CANT_THROW
		{return cosl(x);}
	inline long double cosh(long double x) _MSL_CANT_THROW
		{return coshl(x);}
	inline long double erf(long double x) _MSL_CANT_THROW
		{return erfl(x);}
	inline long double erfc(long double x) _MSL_CANT_THROW
		{return erfcl(x);}				
	inline long double exp(long double x) _MSL_CANT_THROW
		{return expl(x);}
	inline long double expm1(long double x) _MSL_CANT_THROW
		{return expm1l(x);}		
	inline long double exp2(long double x) _MSL_CANT_THROW
		{return exp2l(x);}
	inline long double fabs(long double x) _MSL_CANT_THROW
		{return fabsl(x);}		
	inline long double fdim(long double x, long double y) _MSL_CANT_THROW
		{return fdiml(x, y);}					
	inline long double fma(long double x, long double y, long double z) _MSL_CANT_THROW
		{return fmal(x, y, z);}
	inline long double fmax(long double x, long double y) _MSL_CANT_THROW
		{return fmaxl(x, y);}
	inline long double fmin(long double x, long double y) _MSL_CANT_THROW
		{return fminl(x, y);}
	inline long double fmod(long double x, long double y) _MSL_CANT_THROW
		{return fmodl(x, y);}	
	inline long double floor(long double x) _MSL_CANT_THROW
		{return floorl(x);}						
	inline long double frexp(long double x, int* exp) _MSL_CANT_THROW
		{return frexpl(x, exp);}
	inline long double hypot(long double x, long double y) _MSL_CANT_THROW
		{return hypotl(x, y);}	
	inline int ilogb(long double x) _MSL_CANT_THROW
		{return ilogbl(x);}			
	inline long double ldexp(long double x, int exp) _MSL_CANT_THROW
		{return ldexpl(x, exp);}
	inline long double lgamma(long double x) _MSL_CANT_THROW
		{return lgammal(x);}		
	inline long double log(long double x) _MSL_CANT_THROW
		{return logl(x);}
	inline long double logb(long double x) _MSL_CANT_THROW
		{return logbl(x);}		
	inline long double log10(long double x) _MSL_CANT_THROW
		{return log10l(x);}
	inline long double log1p(long double x) _MSL_CANT_THROW
		{return log1pl(x);}
	inline long double log2(long double x) _MSL_CANT_THROW
		{return log2l(x);}							
	inline long int lrint(long double x) _MSL_CANT_THROW
		{return lrintl(x);}
	inline long int lround(long double x) _MSL_CANT_THROW
		{return lroundl(x);}		
	#if _MSL_LONGLONG	
	inline long long llrint(long double x) _MSL_CANT_THROW
		{return llrintl(x);}
	inline long long llround(long double x) _MSL_CANT_THROW
		{return llroundl(x);}		
	#endif /* _MSL_LONGLONG */
	inline long double modf(long double x, long double* y) _MSL_CANT_THROW
		{return modfl(x, y);}
	inline long double nearbyint(long double x) _MSL_CANT_THROW
		{return nearbyintl(x);}			
	inline long double nextafter(long double x, long double y) _MSL_CANT_THROW
		{return nextafterl(x, y);}
	inline long double pow(long double x, long double y) _MSL_CANT_THROW
		{return powl(x, y);}
	inline long double pow(long double x, int y) _MSL_CANT_THROW
		{return powl(x, y);}		
	inline long double remainder(long double x, long double y) _MSL_CANT_THROW
		{return remainderl(x, y);}		
	inline long double remquo(long double x, long double y, int *quo) _MSL_CANT_THROW
		{return remquol(x, y, quo);}
	inline long double rint(long double x) _MSL_CANT_THROW
		{return rintl(x);}
	inline long double round(long double x) _MSL_CANT_THROW
		{return roundl(x);}				
	inline long double scalbn(long double x, int n) _MSL_CANT_THROW
		{return scalbnl(x, n);}
	inline long double scalbln(long double x, long int n) _MSL_CANT_THROW
		{return scalblnl(x, n);}
	inline long double sqrt(long double x) _MSL_CANT_THROW
		{return sqrtl(x);}		
	inline long double sin(long double x) _MSL_CANT_THROW
		{return sinl(x);}
	inline long double sinh(long double x) _MSL_CANT_THROW
		{return sinhl(x);}		
	inline long double tan(long double x) _MSL_CANT_THROW
		{return tanl(x);}
	inline long double tanh(long double x) _MSL_CANT_THROW
		{return tanhl(x);}
	inline long double trunc(long double x) _MSL_CANT_THROW
		{return truncl(x);}
				
#endif /* _MSL_C99 */	
	
	inline long double gamma(long double x) _MSL_CANT_THROW
		{return gammal(x);}

_MSL_BEGIN_EXTERN_C

#endif /* defined(__cplusplus) && defined(__ANSI_OVERLOAD__) && !defined(__FP__) */

_MSL_END_EXTERN_C
_MSL_END_NAMESPACE_STD

#include <math_integral.h>

#endif /* No_Floating_Point */

#endif /* _MSL_CMATH_MACOS_H */

/* Change record:
 * mm  960722 Inserted declaration for pi
 * mm  960722 Added declaration for pi for Infinity Marathon.
 * mm  961008 Removed declaration for pi since it does not conform to the ANSI C Standard
 * bk  961221 line 121 wrapped fabs intrinsic (mmoss)
 * bk  961223 line 24 wrapped HUGE_VAL define
 * bk  970318 restructured for 68K, PPC, x86 to reduce confusion
 * bk  970410 restructured more to reduce 68K mess, started to add C9X support
 * bk  970411 added long double support for PPC cplus plus, 68K cplus plus and c
 * bk  970415 68K changes
 * bk  970423 c++ long double overrides replaced with casts to double versions
 * sm  970723 Wrapped entire file in #ifndef _No_Floating_Point.
 * mf  970902 took out all c++ inlines for math functions on all platforms. They don't do 
 *            anything!  Still have fpu inlines on 68k with either C or C++ .
 * mf  970915 corrected a bug that defines regular math functions to the "d" suffixed 
 *            macros on 68K.  They should only be defined for 8 byte doubles
 * mf  970916 moved __extern_c to surround long __double_huge[]                
 * mf  970928 define efficiency types double_t, float_t by default(used to require
 *            __MSL_C9X__ to be defined).
 * mf  971005 updated math.h to be compatible with 3.0.1 universal headers. Removed
 *            __MSL_C9X__ altogether.   
 * mf  971202 completed X86 classification macros/functions isnormal/fpclassify/signbit and
 *            enumerated types FP_NAN etc....
 * mf  971202 put parenthesis around classification macros(currently used on the MAC only)                                           
 * hh  971206 many many changes for namespace support.  Including file name change.
 * hh  971217 "extern C" must appear inside of namespace {}
 * hh  971230 added RC_INVOKED wrapper
 * hh  980122 ppc does not have fmodl, #defined it to fmod
 * hh  980122 Added C++ inlines
 * hh  980217 Put most of the inlines added 980122 under #ifdef __ANSI_OVERLOAD__.  The
 *            customer is free to turn this switch on and off to access or hide these
 *            functions.  Please see <ansi_parms.h> for more details.
 * mf  980305 fixed some problems with C++ inlines. added standard prototype for nextafter                
 * rjk 980316 turned off k63d_calls for intel compiler
 * hh  980628 rewrote
 * vss 980809 __double_huge, et al, need to be in extern C clause too
 * mf  980811 wrap everyting in fp.h  __FP__, changed dest_os!=__win32_os to __INTEL__, nan prototype for intel enabled
 * mf  980813 added comparison macros for intel fpu
 * mm  981023 added wrappers round long long support
 * mm  981023 Added wrappers to avoid redefinition of HUGE_VAL
 * mm  981029 changed __DSP568 to __mc56800__
 * mf  981019 cmath for embedded
 * hh  990210 added guard for fp.h on __ANSI_OVERLOAD__ stuff.
 * hh  990210 added pow(double, int)
 * hh  990224 added foo(integral) support 
 * hh  990324 Modified nextafter on 68K to check for __option(IEEEdoubles)
 * hh  990504 Wrapped templates up in #if __embedded_cplusplus == 0
 * hh  990804 Changed templates to ordinary functions taking integrals
 * hh  990928 Added	_MAKE_FOO2(func, integral, float ... long double)
 * hh  000324 Moved integral math overloads into <math_integral.h>
 * cc  010405 removed pragma options align native and reset
 * cc  010410 updated to new namespace macros
 * JWW 010419 Conditionalized out nextafterl when Apple's <fp.h> comes before MSL's <math.h>
 * hh  010719 Fixed isnan to recognize signalling nans
 * JWW 010730 Scrubbed out dead code sections and exported float_math_glue.PPC.c glue routines
 * JWW 011009 Conditionalize out fabs() if fp.h has already been included
 * JWW 020422 Define _MSL_CMATH_DEFINED_MATH_ITEMS instead of relying solely on __FP__
 * hh  020603 Added no throw spec to functions
 * mm  021108 Added wrappers for math functions added in math.c
 * JWW 030224 Changed __MSL_LONGLONG_SUPPORT__ flag into the new more configurable _MSL_LONGLONG
 * JWW 030321 Added fma(), fmaf(), and fmal() prototypes
 * mm  030520 Added prototype for asinhl()
 * mm  030702 Added some C99 wrappers
 * mm  030715 Added defines of FP_ILOGB0 and  FP_ILOGBNAN
 * mm  030716 Added prototype of nextafterl
 */