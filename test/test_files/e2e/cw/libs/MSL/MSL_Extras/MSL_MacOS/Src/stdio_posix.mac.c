/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/28 15:05:14 $
 * $Revision: 1.4.2.1 $
 */

#include <errno.h>
#include <string.h>
#include <stdio.posix.h>  /* need this for fileno */

#include <ansi_files.h>
#include <file_io.h>
#include <path2fss.h>

#include <Errors.h>
#include <Files.h>
#include <MacTypes.h>	/*- vss 990421 -*/

/* function prototypes (exported) */

int  __ctopstring(const char *cstring, Str255 pstring) _MSL_CANT_THROW;

/* function prototypes for externally defined functions */

extern long __getcreator(long isbinary) _MSL_CANT_THROW;
extern long __gettype(long isbinary) _MSL_CANT_THROW;
extern int  __system7present(void) _MSL_CANT_THROW;
extern char __msl_system_has_new_file_apis(void) _MSL_CANT_THROW;

/*
 *	int __ctopstring(const char *cstring, Str255 pstring)
 *
 *		Converts a cstring into a pascal string.
 */
int __ctopstring(const char *cstring, Str255 pstring) _MSL_CANT_THROW
{
	int				i;
	unsigned int	len; 

	len = strlen(cstring);
	if (len > 255)
		return (-1);

	pstring[0] = len;
	for (i = 1; *cstring; i++)
		pstring[i] = *cstring++;

	return (0);
}

/*
 *	FILE *fdopen(int fildes, char *type)
 *
 *		Converts a fileid into an ANSI C file stream.
 */
FILE *fdopen(int fildes, const char *type) _MSL_CANT_THROW
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		FILE			*str;
		FSForkInfo		theInfo;
		OSErr			err;
		
		err = FSGetForkCBInfo(fildes, 0, NULL, NULL, &theInfo, NULL, NULL);
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
			return (0);
		}
		
		switch (*type)
		{
			case 'w':
			case 'a':
				if ((theInfo.flags & (kioFCBWriteMask >> 8)) == 0)
				{
					errno = EMACOSERR;														/*- mm 010412 -*/
					__MacOSErrNo = paramErr;												/*- mm 010412 -*/
					return (0);
				}
				break;
			case 'r':		/* under non-file sharing file system, an open file always has read access */
			default:
				break;
		}
		
		str = __find_unopened_file();
		if (str == NULL)
			return(0);
		
		return(__handle_reopen(fildes, type, str));
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	FILE			*str;
	Str255			fname;
	FCBPBRec		fcbpb;
	OSErr			err;
	

	fcbpb.ioFCBIndx = 0;
	fcbpb.ioRefNum = fildes;
	fcbpb.ioNamePtr = (StringPtr)fname;

	err = PBGetFCBInfoSync(&fcbpb);
	if (err != noErr) 
	{
		errno = EMACOSERR;														/*- mm 010412 -*/
		__MacOSErrNo = err;														/*- mm 010412 -*/
		return (0);
	}

	switch (*type) {
		case 'w':
		case 'a':
			if ((fcbpb.ioFCBFlags & 0x0100) == 0) 
			{
				errno = EMACOSERR;														/*- mm 010412 -*/
				__MacOSErrNo = paramErr;												/*- mm 010412 -*/
				return (0);
			}
			break;
		case 'r':		/* under non-file sharing file system, an open file always has read access */
		default:
			break;
	}
	
	if (!(str = __find_unopened_file()))
		return(0);
	
	return(__handle_reopen(fildes, type, str));
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

/* Change record:
 * JFH 951012 Modified to interface to new ANSI C library
 * JFH 951230 Removed uses of OLDROUTINENAMES
 * bkoz961221 added wrapper for moto (mmoss)
 * hh  990124 removed __std 8 places
 * vss 990421 Update to 3.2 Universal Headers
 * cc  991108 added ra Carbon Changes done 990611
 * cc  991109 changed TARGET_CARBON to TARGET_API_MAC_CARBON
 * cc  991115 updated and deleted outdated comments
 * JWW 000404 removed fileno() function since it's common code now
 * cc  000517 changed #includes
 * JWW 001030 Use new OS 9 File Manager APIs in _fdopen
 * mm  010122 Made second parameter to _fdopen const char* to match POSIX standard
 * mm  010412 Changes to avoid putting OSErr values into errno. 
 * cc  010622 Changed _chmod to chmod
 * JWW 010927 Renamed file from unix.mac.c to stdio_posix.mac.c and moved chmod() to stat.mac.c
 * cc  020221 Added #include
 */