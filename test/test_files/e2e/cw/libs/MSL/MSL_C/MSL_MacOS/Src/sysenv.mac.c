/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:35 $
 * $Revision: 1.8 $
 */
 
/*
 *	Routines
 *	--------
 *		getenv
 *		system
 *
 *
 */

#include <ansi_parms.h>                 /*- mm 970904 -*/
#include <stdlib.h>

char * getenv(const char* name)
{
#pragma unused(name)

	return(NULL);
}

int system(const char* cmdLine)
{
#pragma unused(cmdLine)

	return(NULL);

}

/* Change record:
 * JFH 950721 First code release.
 * mm  970708 Inserted Be changes
 * mm  970904 Added include ansi_parms.h  to allow compilation without prefix
 * vss 990121 Add system call for win32 applications - contributed sources
 * vss 990203 Moved win32 code to sysenv.win32.c
 * JWW 000615 Moved mac code to sysenv.mac.c
 */