/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:50 $
 * $Revision: 1.16 $
 */
 
/*
 *	Content:	Interface file to ANSI console package ...
 */

#ifndef _MSL_CONSOLE_H
#define _MSL_CONSOLE_H

#include <ansi_parms.h>                     /*- mm 970903 -*/

_MSL_BEGIN_EXTERN_C	/*- cc 010410 -*/

/*
 *	Provides an interface to allow users to set argc & argv on the Mac
 */
_MSL_IMP_EXP_C extern int ccommand(char ***) _MSL_CANT_THROW;

/*
 *	The following five functions provide the UI for the console package.
 *	Users wishing to replace SIOUX with their own console package need
 *	only provide the five functions below in a library.
 */

/*
 *	extern short InstallConsole(short fd);
 *
 *	Installs the Console package, this function will be called right
 *	before any read or write to one of the standard streams.
 *
 *	short fd:		The stream which we are reading/writing to/from.
 *	returns short:	0 no error occurred, anything else error.
 */

extern short InstallConsole(short fd) _MSL_CANT_THROW;

/*
 *	extern void RemoveConsole(void);
 *
 *	Removes the console package.  It is called after all other streams
 *	are closed and exit functions (installed by either atexit or __atexit)
 *	have been called.  Since there is no way to recover from an error,
 *	this function doesn't need to return any.
 */

extern void RemoveConsole(void) _MSL_CANT_THROW;

/*
 *	extern long WriteCharsToConsole(char *buffer, long n);
 *
 *	Writes a stream of output to the Console window.  This function is
 *	called by write.
 *
 *	char *buffer:	Pointer to the buffer to be written.
 *	long n:			The length of the buffer to be written.
 *	returns short:	Actual number of characters written to the stream,
 *					-1 if an error occurred.
 */

extern long WriteCharsToConsole(char *buffer, long n) _MSL_CANT_THROW;

/*
 *	extern long WriteCharsToErrorConsole(char *buffer, long n);
 *
 *	Writes a stream of error output to the Console window.  This function is
 *	called by write.  This function is Mach-O only.
 *
 *	char *buffer:	Pointer to the buffer to be written.
 *	long n:			The length of the buffer to be written.
 *	returns short:	Actual number of characters written to the stream,
 *					-1 if an error occurred.
 */

#if __dest_os == __mac_os_x
extern long WriteCharsToErrorConsole(char *buffer, long n) _MSL_CANT_THROW;
#endif

/*
 *	extern long ReadCharsFromConsole(char *buffer, long n);
 *
 *	Reads from the Console into a buffer.  This function is called by
 *	read.
 *
 *	char *buffer:	Pointer to the buffer which will recieve the input.
 *	long n:			The maximum amount of characters to be read (size of
 *					buffer).
 *	returns short:	Actual number of characters read from the stream,
 *					-1 if an error occurred.
 */

extern long ReadCharsFromConsole(char *buffer, long n) _MSL_CANT_THROW;

/*
 *	extern char *__ttyname(long fildes);
 *
 *	Returns the name of the terminal associated with the file id.  The unix.h
 *	function ttyname calls this function (we need to map the int to a long for
 *	size of int variance).
 *
 *	long filedes:	The file stream's id.
 *	returns char *:	A pointer to the file's name (static global data)
 */

extern char *__ttyname(long fildes) _MSL_CANT_THROW;

/*
*
*    int kbhit()
*
*    returns true if any keyboard key is pressed withoug retrieving the key
*    used for stopping a loop by pressing any key
*/
int kbhit(void) _MSL_CANT_THROW;

/*
*
*    int getch()
*
*    returns the keyboard character pressed when an ascii key is pressed  
*    used for console style menu selections for immediate actions.
*/
int getch(void) _MSL_CANT_THROW;

/*
*     void clrscr()
*
*     clears screen
*/
void clrscr(void) _MSL_CANT_THROW;

_MSL_END_EXTERN_C	/*- cc 010410 -*/

#endif /* _MSL_CONSOLE_H */


/* Change record:
 * mm  970903 Added include of ansi_parms.h to allow compilation without prefix file
 * vss 980807 remove pragma  - no longer supported by compiler
 * cc  010405 removed pragma options align native and reset
 * cc  010410 updated to new namespace macros
 * JWW 011027 Added new output function for writing to stderr (Mach-O only)
 * hh  020603 Added no throw spec to functions
 */