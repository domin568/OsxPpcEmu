/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/05/28 16:22:07 $
 * $Revision: 1.3 $
 */

#include <ansi_parms.h>
#include <stdlib.h>
#include <locale.h>
#include <critical_regions.h>
#include <msl_thread_local_data.h>
#include <lconv.h>
#include <string.h>

static pthread_key_t _msl_local_data_key = 0;

/* this function is called when a thread terminates and it has local data associated with it */
static void _tld_destructor(void *tld)
{
	if (tld != NULL)
		free(tld);
}

/* This function must be called before _InitializeThreadData. */
/* Returns false on error, true on success. */
static int _InitializeThreadDataIndex(void)
{
	if (_msl_local_data_key != 0)
	{
		/* _msl_local_data_key is already initialized */
		return 1;
	}
	
	if (pthread_key_create(&_msl_local_data_key, &_tld_destructor) != 0)
	{
		/* The allocation failed. */
		return 0;
	}
	
	return 1;
}

/* This function sets up a structure of thread local data needed by various MSL functions. */
/* When the thread ends it should call _DisposeThreadData. */
/* Returns false on error, true on success. */
static int _InitializeThreadData(void)
{
	_ThreadLocalData *tld;
	
	tld = (_ThreadLocalData *) pthread_getspecific(_msl_local_data_key);
	
	if (tld == NULL)
	{
		tld = (_ThreadLocalData *) malloc(sizeof(_ThreadLocalData));
		
		if (tld == NULL)
			return 0;
		
		/* All initialization of items in the _ThreadLocalData structure goes here... */
		
		tld->errno = 0;
		tld->random_next = 1;
		tld->strtok_n = (unsigned char *) "";
		tld->strtok_s = (unsigned char *) "";
		tld->locale_name = "C";
		tld->localtime_tm.tm_sec   =  0;
		tld->localtime_tm.tm_min   =  0;
		tld->localtime_tm.tm_hour  =  0;
		tld->localtime_tm.tm_mday  =  1;
		tld->localtime_tm.tm_mon   =  0;
		tld->localtime_tm.tm_year  =  0;
		tld->localtime_tm.tm_wday  =  1;
		tld->localtime_tm.tm_yday  =  0;
		tld->localtime_tm.tm_isdst = -1;
		
		tld->gmtime_tm.tm_sec   =  0;
		tld->gmtime_tm.tm_min   =  0;
		tld->gmtime_tm.tm_hour  =  0;
		tld->gmtime_tm.tm_mday  =  1;
		tld->gmtime_tm.tm_mon   =  0;
		tld->gmtime_tm.tm_year  =  0;
		tld->gmtime_tm.tm_wday  =  1;
		tld->gmtime_tm.tm_yday  =  0;
		tld->gmtime_tm.tm_isdst = -1;
		
		tld->_current_locale.next_locale = NULL;
		strcpy(tld->_current_locale.locale_name, _current_locale.locale_name);
		tld->_current_locale.coll_cmpt_ptr = _current_locale.coll_cmpt_ptr;
		tld->_current_locale.ctype_cmpt_ptr = _current_locale.ctype_cmpt_ptr;
		tld->_current_locale.mon_cmpt_ptr = _current_locale.mon_cmpt_ptr;
		tld->_current_locale.num_cmpt_ptr = _current_locale.num_cmpt_ptr;
		tld->_current_locale.time_cmpt_ptr = _current_locale.time_cmpt_ptr;
		memcpy((void*) &tld->_current_locale.next_locale, (void*) &_current_locale.next_locale,
			sizeof(struct __locale));
		
		tld->__lconv = __lconv;
		
		return (pthread_setspecific(_msl_local_data_key, tld) == 0);
	}
	
	return 1;	/* data is already setup, just return success */
}

int _MSL_CDECL __msl_InitializeMainThreadData(void)
{
    /* Check to see if data was already initialized */
    if (_InitializeThreadDataIndex())
    {
        /* If it wasn't initialized, setup the data for the main thread */
        if (_InitializeThreadData())
        {
            return 1;
        }
    }
    
    return 0;
}

void _MSL_CDECL __msl_DisposeAllThreadData(void)
{
	if (_msl_local_data_key != 0)
	{
		pthread_key_delete(_msl_local_data_key);
		_msl_local_data_key = 0;
	}
}

_ThreadLocalData * _MSL_CDECL __msl_GetThreadLocalData(void)
{
	_ThreadLocalData *tld;
	
	tld = (_ThreadLocalData *) pthread_getspecific(_msl_local_data_key);
	
	if (tld == NULL)
	{
		_InitializeThreadData();
		tld = (_ThreadLocalData *) pthread_getspecific(_msl_local_data_key);
		
		if (tld == NULL)
		    exit(127);
	}
	
	return tld;
}

/* Change record:
 * JWW 021031 Made thread local data available for Mach-O
 */