/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:53 $
 * $Revision: 1.18 $
 */
 
/*
 *
 *		Notes
 *		-----
 *  There are two distinct epochs in use: the Macintosh 1904 Jan 1 and the MSL Mac Epoch, 
 *  1970 Jan 1.  This header defines the number of seconds between the two epochs for
 *  use where a conversion is required.    mm 990203 mm 000127
 */
 
#ifndef _MSL_TIME_MAC_H
#define _MSL_TIME_MAC_H

#include <ansi_parms.h>

#if __dest_os == __mac_os

	#include <timesize.mac.h>
	
  	#if defined(__TIMESIZE_DOUBLE__) 
    	#define _MSL_CLOCKS_PER_SEC 1000000  /*- jz 971222 -*/
      	#define _MSL_CLOCK_T double
  	#else
      	#define _MSL_CLOCKS_PER_SEC 60
      	#define _MSL_CLOCK_T unsigned long
  	#endif
	
#elif __dest_os == __mac_os_x

	#include <ppc/ansi.h>
	
	#define _MSL_CLOCKS_PER_SEC 100
	#define _MSL_CLOCK_T _BSD_CLOCK_T_
	
	#if !defined(__cplusplus) || !defined(_MSL_USING_NAMESPACE)
		#ifndef	_BSD_CLOCK_T_DEFINED_
			#define	_BSD_CLOCK_T_DEFINED_
		#else
			#ifndef _MSL_CLOCK_T_DEFINED
				#define _MSL_CLOCK_T_DEFINED
			#endif
		#endif
	#endif
	
	#if !defined(__cplusplus) || !defined(_MSL_USING_NAMESPACE)
		#ifndef	_BSD_TIME_T_DEFINED_
			#define	_BSD_TIME_T_DEFINED_
		#else
			#ifndef _MSL_TIME_T_DEFINED
				#define _MSL_TIME_T_DEFINED
				
				/* The following macro is old and will disappear in a future version of MSL */
				/* Switch to using _MSL_TIME_T_DEFINED instead */
				#define _TIME_T_DEFINED
			#endif
		#endif
	#endif

#endif


#define _mac_msl_epoch_offset_ (-((365L * 66L) + 17) * 24L * 60L * 60L)		/*- mm 000127 -*/ /*- mm 001023 -*/

#endif /* _MSL_TIME_MAC_H */

/* Change record:
 * mm  970521 Header created
 * mm  970905 added include of ansi_parms.h to avoid need for prefix file
 * mm  990203 Corrected comment and name of epoch conversion comment.
 * mm  000127 Changed MSL Mac epoch to 1970 Jan 1 to accord with POSIX and MSL on Windows. MW07637
 * mm  001013 Corrected sign of _mac_msl_epoch_offset_  WB1-17713
 * JWW 011101 Make time information platform independent
 * JWW 020129 Do not leak time_t or clock_t from the Mach-O C++ std namespace
 * JWW 020130 Changed _TIME_T_DEFINED to _MSL_TIME_T_DEFINED for consistency's sake
 */