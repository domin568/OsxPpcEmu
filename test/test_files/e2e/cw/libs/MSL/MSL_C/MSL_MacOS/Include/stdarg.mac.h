/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/14 15:26:01 $
 * $Revision: 1.3.2.1 $
 */

#ifndef _MSL_STDARG_MAC_H
#define _MSL_STDARG_MAC_H

_MSL_BEGIN_EXTERN_C

	#define va_start(ap, parm) ap = __va_start(parm)
	#define va_end(ap) ((void) 0)						/*- mm 011006 -*/
#if _MSL_C99											/*- mm 030703 -*/
	#define va_copy(dest, src) dest = src				/*- mm 980824 -*/
#endif /* _MSL_C99 */									/*- mm 030703 -*/
   	#define __va_start(parm)	(__std(va_list)) (&parm + 1)	/*- mm 9708027 -*/
   	
	#if __VEC__
		#define va_arg(ap, type) (*(((type *) (ap = (char *)((((unsigned long) ap + __builtin_align(type) - 1) & ~(__builtin_align(type) - 1) ) + sizeof(type)))) - 1))
	#else
		/*#define va_arg(ap, type) (*(((type *) (ap += (((sizeof(type) + 3) / 4) * 4))) - 1))*/
		#define va_arg(ap, type) (*(type *) ((ap += sizeof(type) + 3U & ~3U) - (sizeof(type) + 3U & ~3U)))   /*- mm 991207 -*/
	#endif

_MSL_END_EXTERN_C

#endif /* _MSL_STDARG_MAC_H */

/* Change record:
 * JWW 011101 New file to make stdarg information platform independent
 * mm  030703 Added C99 wrappers
 */