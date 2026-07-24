/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:32 $
 * $Revision: 1.15 $
 */

#include <critical_regions.h>

#if __MACH__
	#include <pthread.h>
#else
	#include <Multiprocessing.h>
#endif

#if _MSL_THREADSAFE

	#if __MACH__
		pthread_mutex_t __cs[num_critical_regions];
		pthread_t __cs_id[num_critical_regions];
		int __cs_ref[num_critical_regions];
		
		static void __msl_setup_criticals(void)
		{
			__init_critical_regions();
		}
		#pragma CALL_ON_MODULE_BIND __msl_setup_criticals
		
		#ifdef __mwlinker__
			#pragma INIT_BEFORE_TERM_AFTER on
		#endif
	#else
		MPCriticalRegionID __cs[num_critical_regions];
	#endif /* __MACH__ */

#endif /* _MSL_THREADSAFE */

/* Change record:
 * JFH 951016 First code release.
 * hh  990804 Filled out for #if _MWMT
 * hh  990831 Added undefs for __init_critical_regions, __kill_critical_regions
 * JWW 011027 Added case for Mach-O
 * JWW 020130 Changed _MWMT to _MSL_THREADSAFE for consistency's sake
 * JWW 020331 Initialize Mach-O regions on module bind and keep refcount info for locked threads
 * JWW 020423 Use new INIT_BEFORE_TERM_AFTER to setup critical regions first on Mach-O
 */