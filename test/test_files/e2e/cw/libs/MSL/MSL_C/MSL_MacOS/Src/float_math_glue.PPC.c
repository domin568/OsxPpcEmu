/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/08/06 02:01:54 $
 * $Revision: 1.15.2.2 $
 */

/*
 *	math.h glue functions for PowerPC (float precision math) ...
 *  this is only to provide support for those wanting to use the address of
 *  the f suffixed functions.  These are significantly slower than the macros
 *  in math.h as the incur the overhead of an additional functions call
 */

#ifndef __FP__
	#include <fp.h>
#endif

#include <ansi_parms.h>


#if _MSL_C99											/*- mm 030522 -*/
_MSL_IMP_EXP_C double cbrt(double) _MSL_CANT_THROW;
_MSL_IMP_EXP_C int ilogb(double) _MSL_CANT_THROW;

_MSL_IMP_EXP_C double scalbn(double x, int n);
_MSL_IMP_EXP_C double scalbln(double x, long n);
_MSL_IMP_EXP_C long int lrint(double x);
_MSL_IMP_EXP_C long long llrint(double x);
_MSL_IMP_EXP_C long int lround(double x);
_MSL_IMP_EXP_C long long llround(double x);
_MSL_IMP_EXP_C double nextafter(double x, double y);
/*double fma(double x, double y, double z);*/
_MSL_IMP_EXP_C float acosf(float x);
_MSL_IMP_EXP_C float asinf(float x);
_MSL_IMP_EXP_C float atanf(float x);
_MSL_IMP_EXP_C float atan2f(float y, float x);
_MSL_IMP_EXP_C float cosf(float x);
_MSL_IMP_EXP_C float sinf(float x);
_MSL_IMP_EXP_C float tanf(float x);
_MSL_IMP_EXP_C float coshf(float x);
_MSL_IMP_EXP_C float sinhf(float x);
_MSL_IMP_EXP_C float tanhf(float x);
_MSL_IMP_EXP_C float acoshf(float x);
_MSL_IMP_EXP_C float asinhf(float x);
_MSL_IMP_EXP_C float atanhf(float x);
_MSL_IMP_EXP_C float expf(float x);
_MSL_IMP_EXP_C float frexpf(float value, int *exp);
_MSL_IMP_EXP_C float ldexpf(float x, int exp);
_MSL_IMP_EXP_C float logf(float x);
_MSL_IMP_EXP_C float log10f(float x);
_MSL_IMP_EXP_C float exp2f(float x);
_MSL_IMP_EXP_C float expm1f(float x);
_MSL_IMP_EXP_C float log1pf(float x);
_MSL_IMP_EXP_C float log2f(float x);
_MSL_IMP_EXP_C float logbf(float x);
_MSL_IMP_EXP_C float scalbnf(float x, int n);
_MSL_IMP_EXP_C float scalblnf(float x, long int n);
_MSL_IMP_EXP_C int ilogbf(float x); 
_MSL_IMP_EXP_C float fabsf(float x);
_MSL_IMP_EXP_C float powf(float x, float y);
_MSL_IMP_EXP_C float sqrtf(float x);
/*	float cbrtf(float x); */
_MSL_IMP_EXP_C float hypotf(float x, float y);
_MSL_IMP_EXP_C float erff(float x);
_MSL_IMP_EXP_C float erfcf(float x);
_MSL_IMP_EXP_C float gammaf(float x);
_MSL_IMP_EXP_C float lgammaf(float x);
_MSL_IMP_EXP_C float ceilf(float x);
_MSL_IMP_EXP_C float floorf(float x);
_MSL_IMP_EXP_C float nearbyintf(float x);
_MSL_IMP_EXP_C float rintf(float x);
_MSL_IMP_EXP_C long int lrintf(float x);
_MSL_IMP_EXP_C long long llrintf(float x);
_MSL_IMP_EXP_C float roundf(float x);
_MSL_IMP_EXP_C long int lroundf(float x);
_MSL_IMP_EXP_C long long llroundf(float x);
_MSL_IMP_EXP_C float truncf(float x);
_MSL_IMP_EXP_C float fmodf(float x, float y);
_MSL_IMP_EXP_C float remainderf(float x, float y);
_MSL_IMP_EXP_C float copysignf(float x, float y);
_MSL_IMP_EXP_C float remquof(float x, float y, int *quo);
_MSL_IMP_EXP_C float nextafterf(float x, float y);
/*	float nextafterxf(float x, long double y); */
_MSL_IMP_EXP_C float fdimf(float x, float y);
_MSL_IMP_EXP_C float fmaxf(float x, float y);
_MSL_IMP_EXP_C float fminf(float x, float y);
#endif /* _MSL_C99 */									/*- mm 030522 -*/
/*	float fmaf(float x, float y, float z); */
_MSL_IMP_EXP_C long double __acosl(long double x);
_MSL_IMP_EXP_C long double __asinl(long double x);
_MSL_IMP_EXP_C long double __atanl(long double x);
_MSL_IMP_EXP_C long double __atan2l(long double y, long double x);
_MSL_IMP_EXP_C long double __cosl(long double x);
_MSL_IMP_EXP_C long double __sinl(long double x);
_MSL_IMP_EXP_C long double __tanl(long double x);
_MSL_IMP_EXP_C long double __coshl(long double x);
_MSL_IMP_EXP_C long double __sinhl(long double x);
_MSL_IMP_EXP_C long double __tanhl(long double x);
_MSL_IMP_EXP_C long double __acoshl(long double x);
_MSL_IMP_EXP_C long double __asinhl(long double x);
_MSL_IMP_EXP_C long double __atanhl(long double x);
_MSL_IMP_EXP_C long double __expl(long double x);
_MSL_IMP_EXP_C long double __frexpl(long double value, int *exp);
_MSL_IMP_EXP_C long double __ldexpl(long double x, int exp);
_MSL_IMP_EXP_C long double __logl(long double x);
_MSL_IMP_EXP_C long double __log10l(long double x);
_MSL_IMP_EXP_C long double __modfl(long double value, long double *iptr);
_MSL_IMP_EXP_C long double __exp2l(long double x);
_MSL_IMP_EXP_C long double __expm1l(long double x);
_MSL_IMP_EXP_C long double __log1pl(long double x);
_MSL_IMP_EXP_C long double __log2l(long double x);
_MSL_IMP_EXP_C long double __logbl(long double x);
_MSL_IMP_EXP_C long double scalbnl(long double x, int n);
_MSL_IMP_EXP_C long double scalblnl(long double x, long n);
_MSL_IMP_EXP_C int ilogbl(long double x);
_MSL_IMP_EXP_C long double __fabsl(long double x);
_MSL_IMP_EXP_C long double __powl(long double x, long double y);
_MSL_IMP_EXP_C long double __sqrtl(long double x);
_MSL_IMP_EXP_C long double cbrtl(long double x); 
_MSL_IMP_EXP_C long double __hypotl(long double x, long double y);
_MSL_IMP_EXP_C long double __erfl(long double x);
_MSL_IMP_EXP_C long double __erfcl(long double x);
_MSL_IMP_EXP_C long double __gammal(long double x);
_MSL_IMP_EXP_C long double __lgammal(long double x);
_MSL_IMP_EXP_C long double __nanl(const char* x);
_MSL_IMP_EXP_C long double __ceill(long double x);
_MSL_IMP_EXP_C long double __floorl(long double x);
_MSL_IMP_EXP_C long double __nearbyintl(long double x);
_MSL_IMP_EXP_C long double __rintl(long double x);
_MSL_IMP_EXP_C long int lrintl(long double x);
_MSL_IMP_EXP_C long long llrintl(long double x);
_MSL_IMP_EXP_C long double __roundl(long double x);
_MSL_IMP_EXP_C long int lroundl(long double x);
_MSL_IMP_EXP_C long long llroundl(long double x);
_MSL_IMP_EXP_C long double __truncl(long double x);
_MSL_IMP_EXP_C long double __modfl(long double value, long double* iptr);
_MSL_IMP_EXP_C long double __fmodl(long double x, long double y);
_MSL_IMP_EXP_C long double __remainderl(long double x, long double y);
_MSL_IMP_EXP_C long double __copysignl(long double x, long double y);
_MSL_IMP_EXP_C long double __remquol(long double x, long double y, int *quo);
_MSL_IMP_EXP_C long double __nextafterl(long double x, long double y);
/*	long double nextafterxl(long double x, long double y); */

#if _MSL_C99											/*- mm 030522 -*/
_MSL_IMP_EXP_C long double __fdiml(long double x, long double y);
_MSL_IMP_EXP_C long double __fmaxl(long double x, long double y);
_MSL_IMP_EXP_C long double __fminl(long double x, long double y);
#endif /* _MSL_C99 */									/*- mm 030522 -*/
/* long double fmal(long double x, long double y, long double z); */

/*******************************************************************************
*                            double glue                                       *
*******************************************************************************/


#if _MSL_C99											/*- mm 030522 -*/

double scalbn(double x, int n)
{
	return scalb(x, n);
}

double scalbln(double x, long n)
{
	return scalb(x, n);
}

long lrint(double x)
{
	return rinttol(x);
}

long long llrint(double x)
{
	return (long long)rint(x);
}

long lround(double x)
{
	return roundtol(x);
}

long long llround(double x)
{
	return (long long)round(x);
}

double nextafter(double x, double y)
{
	return nextafterd(x, y);
}
#endif /* _MSL_C99 */									/*- mm 030522 -*/

/*
double fma(double x, double y, double z)
{
	return (double)((long double)x*y + z);
}
*/
/*******************************************************************************
*                            float glue                                       *
*******************************************************************************/

/*******************************************************************************
*                            Trigonometric functions                           *
*******************************************************************************/

#if _MSL_C99											/*- mm 030522 -*/

float acosf(float x)
{
	return (float)acos(x);
}

float asinf(float x)
{
	return (float)asin(x);
}

float atanf(float x)
{
	return (float)atan(x);
}

float atan2f(float y, float x)
{
	return (float)atan2(y, x);
}

float cosf(float x)
{
	return (float)cos(x);
}

float sinf(float x)
{
	return (float)sin(x);
}

float tanf(float x)
{
	return (float)tan(x);
}
#endif /* _MSL_C99 */									/*- mm 030522 -*/

/*******************************************************************************
*                              Hyperbolic functions                            *
*******************************************************************************/

#if _MSL_C99											/*- mm 030522 -*/

float coshf(float x)
{
	return (float)cosh(x);
}

float sinhf(float x)
{
	return (float)sinh(x);
}

float tanhf(float x)
{
	return (float)tanh(x);
}

float acoshf(float x)
{
	return (float)acosh(x);
}

float asinhf(float x)
{
	return (float)asinh(x);
}

float atanhf(float x)
{
	return (float)atanh(x);
}

/*******************************************************************************
*                              Exponential functions                           *
*******************************************************************************/

float expf(float x)
{
	return (float)exp(x);
}

float frexpf(float x, int *exp)
{
	return (float)frexp(x, exp);
}

float ldexpf(float x, int n)
{
	return (float)ldexp(x, n);
}

float logf(float x)
{
	return (float)log(x);
}

float log10f(float x)
{
	return (float)log10(x);
}

float exp2f(float x)
{
	return (float)exp2(x);
}

float expm1f(float x)
{
	return (float)expm1(x);
}

float log1pf(float x)
{
	return (float)log1p(x);
}

float log2f(float x)
{
	return (float)log2(x);
}

float logbf(float x)
{
	return (float)logb(x);
}

float scalbnf(float x, int n)
{
	return (float)scalb(x, n);
}

float scalblnf(float x, long n)
{
	return (float)scalb(x, n);
}

/*  ilogb not implemented yet
int ilogbf(float x)
{
	return ilogb(x);
}
*/

/*******************************************************************************
*                     Power and absolute value functions                       *
*******************************************************************************/

float fabsf(float x)
{
	return (float)__fabs(x);
}

float powf(float x, float y)
{
	return (float)pow(x, y);
}

float sqrtf(float x)
{
	return (float)sqrt(x);
}

/*  cbrt not implemented yet
float cbrtf(float x)
{
	return (float)cbrt(x);
}
*/

float hypotf(float x, float y)
{
	return (float)hypot(x, y);
}


float erff(float x)
{
	return (float)erf(x);
}

float erfcf(float x)
{
	return (float)erfc(x);
}

float gammaf(float x)
{
	return (float)gamma(x);
}

float lgammaf(float x)
{
	return (float)lgamma(x);
}

/*******************************************************************************
*                        Nearest integer functions                             *
*******************************************************************************/

float ceilf(float x)
{
	return (float)ceil(x);
}

float floorf(float x)
{
	return (float)floor(x);
}

float nearbyintf(float x)
{
	return (float)nearbyint(x);
}

float rintf(float x)
{
	return (float)rint(x);
}

long lrintf(float x)
{
	return rinttol(x);
}

long long llrintf(float x)
{
	return (long long)rint(x);
}

float roundf(float x)
{
	return (float)round(x);
}

long lroundf(float x)
{
	return roundtol(x);
}

long long llroundf(float x)
{
	return (long long)round(x);
}

float truncf(float x)
{
	return (float)trunc(x);
}

/*******************************************************************************
*                            Remainder functions                               *
*******************************************************************************/

float fmodf(float x, float y)
{
	return (float)fmod(x, y);
}

float remainderf(float x, float y)
{
	return (float)remainder(x, y);
}

float copysignf(float x, float y)
{
	return (float)copysign(x, y);
}

float remquof(float x, float y, int* quo)
{
	return (float)remquo(x, y, quo);
}


float fdimf(float x, float y)
{
	return (float)fdim(x, y);
}

float fmaxf(float x, float y)
{
	return (float)fmax(x, y);
}

float fminf(float x, float y)
{
	return (float)fmin(x, y);
}
#endif /* _MSL_C99 */									/*- mm 030522 -*/

/*
float fmaf(float x, float y, float z)
{
	return (float)((long double)x*y + z);
}
*/

/*******************************************************************************
*                           long double glue                                   *
*******************************************************************************/

/*******************************************************************************
*                            Trigonometric functions                           *
*******************************************************************************/

long double __acosl(long double x)
{
	return acos((double)x);
}

long double __asinl(long double x)
{
	return asin((double)x);
}

long double __atanl(long double x)
{
	return atan((double)x);
}

long double __atan2l(long double y, long double x)
{
	return atan2((double)y, (double)x);
}

long double __cosl(long double x)
{
	return cos((double)x);
}

long double __sinl(long double x)
{
	return sin((double)x);
}

long double __tanl(long double x)
{
	return tan((double)x);
}

/*******************************************************************************
*                              Hyperbolic functions                            *
*******************************************************************************/

long double __coshl(long double x)
{
	return cosh((double)x);
}

long double __sinhl(long double x)
{
	return sinh((double)x);
}

long double __tanhl(long double x)
{
	return tanh((double)x);
}

long double __acoshl(long double x)
{
	return acosh((double)x);
}

long double __asinhl(long double x)
{
	return asinh((double)x);
}

long double __atanhl(long double x)
{
	return atanh((double)x);
}

/*******************************************************************************
*                              Exponential functions                           *
*******************************************************************************/

long double __expl(long double x)
{
	return exp((double)x);
}

long double __frexpl(long double x, int *exp)
{
	return frexp((double)x, exp);
}

long double __ldexpl(long double x, int n)
{
	return ldexp((double)x, n);
}

long double __logl(long double x)
{
	return log((double)x);
}

long double __log10l(long double x)
{
	return log10((double)x);
}

long double __exp2l(long double x)
{
	return exp2((double)x);
}

long double __expm1l(long double x)
{
	return expm1((double)x);
}

long double __log1pl(long double x)
{
	return log1p((double)x);
}

long double __log2l(long double x)
{
	return log2((double)x);
}

long double __logbl(long double x)
{
	return logb((double)x);
}

long double scalbnl(long double x, int n)
{
	return scalb((double)x, n);
}

long double scalblnl(long double x, long n)
{
	return scalb((double)x, n);
}

int ilogbf(float x)
{
	return ilogb((double)x);
}


/*******************************************************************************
*                     Power and absolute value functions                       *
*******************************************************************************/

long double __fabsl(long double x)
{
	return fabs((double)x);
}

long double __powl(long double x, long double y)
{
	return pow((double)x, (double)y);
}

long double __sqrtl(long double x)
{
	return sqrt((double)x);
}

#if _MSL_C99											/*- mm 030522 -*/

long double cbrtl(long double x)
{
	return cbrt((double)x);
}

long double __hypotl(long double x, long double y)
{
	return hypot((double)x, (double)y);
}

long double __erfl(long double x)
{
	return erf((double)x);
}

long double __erfcl(long double x)
{
	return erfc((double)x);
}

long double __gammal(long double x)
{
	return gamma((double)x);
}

long double __lgammal(long double x)
{
	return lgamma((double)x);
}
#endif /* _MSL_C99 */									/*- mm 030522 -*/

/*******************************************************************************
*                        Nearest integer functions                             *
*******************************************************************************/

long double __nanl(const char* x)
{
	return nan(x);
}

long double __ceill(long double x)
{
	return ceil((double)x);
}

long double __floorl(long double x)
{
	return floor((double)x);
}

long double __nearbyintl(long double x)
{
	return nearbyint((double)x);
}

long double __rintl(long double x)
{
	return rint((double)x);
}

long lrintl(long double x)
{
	return rinttol((double)x);
}

long long llrintl(long double x)
{
	return (long long)rint((double)x);
}

long double __roundl(long double x)
{
	return round((double)x);
}

long lroundl(long double x)
{
	return roundtol((double)x);
}

long long llroundl(long double x)
{
	return (long long)round((double)x);
}

long double __truncl(long double x)
{
	return trunc((double)x);
}

/*******************************************************************************
*                            Remainder functions                               *
*******************************************************************************/

long double __modfl(long double value, long double* iptr)
{
	double iptrd;
	long double result = modf((double)value, &iptrd);

	*iptr = iptrd;

	return result;
}

long double __fmodl(long double x, long double y)
{
	return fmod((double)x, (double)y);
}

long double __remainderl(long double x, long double y)
{
	return remainder((double)x, (double)y);
}

long double __copysignl(long double x, long double y)
{
	return copysign((double)x, (double)y);
}

long double __remquol(long double x, long double y, int* quo)
{
	return remquo((double)x, (double)y, quo);
}

long double __nextafterl(long double x, long double y)
{
	return nextafterd((double)x, (double)y);
}

#if _MSL_C99											/*- mm 030522 -*/

long double __fdiml(long double x, long double y)
{
	return fdim((double)x, (double)y);
}

long double __fmaxl(long double x, long double y)
{
	return fmax((double)x, (double)y);
}

long double __fminl(long double x, long double y)
{
	return fmin((double)x, (double)y);
}
#endif /* _MSL_C99 */									/*- mm 030522 -*/

/*
long double fmal(long double x, long double y, long double z)
{
	return x*y + z;
}
*/

/* Change record:
 *  mf 052898 These functions are superseded by macros in math.h. 
 *            This file exists only to provide support to those 
 *            wishing to use function pointers to the "f" suffixed
 *            functions in the absence of real "f" functions.
 * JWW 010730 Export all the math glue functions from the shared library
 * mm  030521 Added C99 wrappers.
 * mm  030625 Removed a few C99 wrappers
 */