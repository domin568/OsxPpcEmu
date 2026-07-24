/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:32 $
 * $Revision: 1.10 $
 */
 
/*
 *	
 *	Routines
 *	--------
 *		__read_console
 *		__write_console
 *		__close_console
 */

#include <SIOUX.h>
#include <console.h>
#include <abort_exit.h>
#include <console_io.h>
#include <critical_regions.h>
#include <misc_io.h>

enum console_status {
	no_console,
	console_open,
	console_broken
};

static int console_status = no_console;

static int check_console(void)
{
	int	result = 0;
	
	if (console_status == console_open)
		return(1);
	
	__begin_critical_region(console_status_access);
	
	if (console_status != no_console)
		goto exit;
	
	__stdio_atexit();
	
	if (InstallConsole(0))
	{
		console_status = console_broken;
		goto exit;
	}
	__console_exit = RemoveConsole;
	
	console_status = console_open;
	
	result = 1;
	
exit:
	
	__end_critical_region(console_status_access);
	
	return(result);
}

int __read_console(__file_handle handle, unsigned char * buffer, size_t * count, __ref_con ref_con)
{
#pragma unused(handle,ref_con)

	if (!check_console())
		return(__io_error);
	fflush(stdout);                   /*- mm 960717 -*/
	*count = ReadCharsFromConsole((char *) buffer, *count);
	
	if (*count == -1)
		return(__io_error);
	
	return(__no_io_error);
}

int __write_console(__file_handle handle, unsigned char * buffer, size_t * count, __ref_con ref_con)
{
#pragma unused(handle,ref_con)

	if (!check_console())
		return(__io_error);
	
#if __MACH__
	if (handle == 2)
		*count = WriteCharsToErrorConsole((char *) buffer, *count);
	else
#endif
	*count = WriteCharsToConsole((char *) buffer, *count);
	
	if (*count == -1)
		return(__io_error);
	
	return(__no_io_error);
}

int __close_console(__file_handle handle)
{
#pragma unused(handle)

	return(__no_io_error);
}


/* Change record:
 * JFH 950901 First code release.
 * JFH 951215 Added installation of hook to close console so that RemoveConsole isn't
 *			  called unconditionally at _exit() time.
 * MM  960717 Added flush to make sure that characters awaiting to appear on console
 *            are output before reading is attemmpted.
 * mm  980427 Directed callse to clrscr to SIOUXclrscr
 * mm  981218 Removed change mm 980427
 * JWW 011027 For Mach-O only, call WriteCharsToErrorConsole when writing to stderr
 * JWW 020906 Use generic reference constant instead of specific idle_proc in file I/O
 */