/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/06/30 17:21:22 $
 * $Revision: 1.16.2.2 $
 */

/*
 *	Routines
 *	--------
 *		__get_clock
 *		__get_time
 *
 *		__to_gm_time
 *		__isdst
 */

#include <timesize.mac.h>

#include <time.h>
#include <time_api.h>
#include <time.mac.h>                   /*- mm970521 -*/

#if __MACH__

#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifndef CLK_TCK
	#define CLK_TCK 100
#endif

#define TIME2CLOCK(seconds) ((seconds.tv_sec * CLK_TCK) + (seconds.tv_usec / (1000000 / CLK_TCK)))

clock_t __get_clock(void)
{
	struct rusage resources;
	
	if (getrusage(RUSAGE_SELF, &resources) == -1)
		return ((clock_t) -1);
	
	return ((clock_t) ((TIME2CLOCK(resources.ru_utime) + TIME2CLOCK(resources.ru_stime))));
}

time_t __get_time(void)
{
	struct timeval daytime;
	struct timezone zone;
	
	if (gettimeofday(&daytime, &zone) == -1)
		return -1;
	
	return daytime.tv_sec - (zone.tz_minuteswest * 60);
}

int __to_gm_time(time_t * time)
{
	struct timezone zone;
	
	if (gettimeofday(NULL, &zone) == -1)
		return 0;
	
	*time += zone.tz_minuteswest * 60;
	
	return 1;
}

int __isdst(void)
{
	struct timezone zone;
	
	if (gettimeofday(NULL, &zone) == -1)
		return -1;
	
	return (zone.tz_dsttime != DST_NONE);
}

#else

#if defined(__TIMESIZE_DOUBLE__)
	#include <Timer.h> 		/*- jz 971222 -*/
#else
	#include <Events.h>
	#include <OSUtils.h>
#endif  /* __TIMESIZE_DOUBLE__ */

clock_t __get_clock(void)
{

#if  defined(__TIMESIZE_DOUBLE__)
	/*  971222  jz
	    The following implementation contributed by Jay Zipnick to increase
	    the time resolution of the microsecond clock.  Note that the return
	    type of this function has changed (see time.h) from unsigned long to
	    double.
	 */
	 
    /*  Get a high resolution time stamp  */
    UnsignedWide microseconds;
    Microseconds(&microseconds);
    
    /* Convert to appropriate type in the floating point domain */
    return(microseconds.hi * 4294967296.0 + microseconds.lo);
    
#else
    
    return(TickCount());
    
#endif  /*  __TIMESIZE_DOUBLE__ */
   
}

time_t __get_time(void)
{
	unsigned long	time;
	
	GetDateTime(&time);
	
	time += _mac_msl_epoch_offset_;	/* seconds between 1/1/1904 and 1/1/1970 */ /*- mm 970521 -*/ /*- mm 000127 -*/ /*- mm 001023 -*/
	
	return(time);
}

int __to_gm_time(time_t * time)
{
	MachineLocation	loc;
	long						delta;

	ReadLocation(&loc);
	
	if (loc.latitude == 0 && loc.longitude == 0 && loc.u.gmtDelta == 0)
		return(0);
	
	delta = loc.u.gmtDelta & 0x00FFFFFF;
	
	if (delta & 0x00800000)
		delta |= 0xFF000000;
	
	*time -= delta;
	
	return(1);
}

/* begin */           /*- mm 010421 -*/
int __isdst(void)
{
	MachineLocation	loc;

	ReadLocation(&loc);

	if (loc.latitude == 0 && loc.longitude == 0 && loc.u.gmtDelta == 0)
		return(-1);
	if (loc.u.dlsDelta == 0)
		return(0);
	else
		return(1);
}
/*- end */             /*- mm 010421 -*/

#endif /* __MACH__ */

/* Change record:
 * JFH 951013 First code release.
 * JFH 951012 Added #include of <Events.h> for TickCount() (in case
 *			  MacHeaders not included)
 * mm  970521 made use of _mac_unix_epoch_offset_.
 * jz  971222 Increase accuracy of microsecond clock
 * mm  990203 Corrected name of epoch conversion constant
 * mm  000127 Changed Mac epoch to 1970Jan01 to accord with POSIX and MSL on Windows. MW07637
 * mm  001023 Corrected arithmetic for Mac epoch WB1-17713
 * mm  010421 Added __isdst()
 * JWW 010918 Use time_api.h to get clock and time APIs
 * JWW 011027 Added case for Mach-O
 * JWW 021212 Correct Mach-O to get local time from __get_time and adjust __to_gm_time accordingly
 * JWW 030630 On Mach-O, define CLK_TCK if it isn't already to fix compile problems on OS X 10.3
 */