/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/28 15:05:36 $
 * $Revision: 1.3.2.1 $
 */
 
/*
 *	Content:	Interface file to standard UNIX-style entry points ...
 *
 *	NB:			This file implements some UNIX low level support.  These functions
 *				are not guaranteed to be 100% conformant.
 *
 */

#include <utime.h>

#include <errno.h>

#include <Files.h>
#include <LowMem.h>
#include <MacTypes.h>
#include <time.mac.h>
#include <time.h>
#include <path2fss.h>

/* function prototypes for externally defined functions */

extern int	__ctopstring(const char *cstring, Str255 pstring) _MSL_CANT_THROW;
extern char __msl_system_has_new_file_apis(void) _MSL_CANT_THROW;

/*
 *	Set the file time stamps.
 */
static int __settime(const char *path, unsigned long modtime) _MSL_CANT_THROW
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		FSRef			theRef;
		OSErr			err;
		FSCatalogInfo	theInfo;
		
		err = __msl_path2fsr(path, &theRef);
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
			return (-1);
		}
		
		theInfo.contentModDate.highSeconds = 0;
		theInfo.contentModDate.fraction = 0;
		ConvertLocalTimeToUTC(modtime, &theInfo.contentModDate.lowSeconds);
		
		err = FSSetCatalogInfo(&theRef, kFSCatInfoContentMod, &theInfo);
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
			return (-1);
		}
		
		return (0);
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	HFileInfo		pb;
	short			vrefnum = 0;
	long			dirid = 0L;
	OSErr			err = noErr;
		Str255			ppath;
		
		if (__ctopstring(path, ppath) != noErr) return (-1);

	pb.ioNamePtr = ppath;
	pb.ioVRefNum = vrefnum;
	pb.ioDirID = dirid;
	pb.ioFVersNum = 0;
	pb.ioFDirIndex = 0;

	err = PBHGetFInfoSync((HParmBlkPtr)&pb);
	if (err == noErr) {
		pb.ioNamePtr = ppath;
		pb.ioVRefNum = vrefnum;
		pb.ioDirID = dirid;
		pb.ioFVersNum = 0;
		pb.ioFDirIndex = 0;
		pb.ioFlMdDat = modtime;

		err = PBHSetFInfoSync((HParmBlkPtr)&pb);
	}

	if (err != noErr)
	{
		errno = EMACOSERR;														/*- mm 010412 -*/
		__MacOSErrNo = err;														/*- mm 010412 -*/
	}
	return (err == noErr ? 0 : -1);
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

/*
 *	Set the file time stamps.
 */
int utime(const char *path, const struct utimbuf *buf) _MSL_CANT_THROW
{
	unsigned long modtime = NULL;
	
	if (path) {
		if (buf != NULL && buf->modtime != NULL)
			modtime = buf->modtime;			/* we ignore the access time on the Mac */

		if (modtime == NULL)
			modtime = time(NULL);
		modtime -= _mac_msl_epoch_offset_;

		return (__settime(path, modtime));
	}

	return (-1);
}

/*
 *	Set the file time stamps.
 */
int utimes(const char *path, struct timeval buf[2]) _MSL_CANT_THROW
{
	unsigned long modtime;
	
	if (path) {
		modtime = buf[1].tv_sec;
	
		if (modtime == NULL)
			modtime = time(NULL);
		modtime -= _mac_msl_epoch_offset_;

		return (__settime(path, modtime));
	}

	return (-1);
}

/* Change record:
 * JFH 951230 Removed uses of OLDROUTINENAMES
 * mm  970521 Added correction for difference in 1900Jan01 and 1904Jan01 epochs
 * mm  990203 Corrected name of epoch conversion constant
 * vss 990421 Update to 3.2 Universal Headers
 * mm  000407 Correct setting of mod time.
 * JWW 001030 Use new OS 9 File Manager APIs in __settime
 * mm  010412 Changes to avoid putting OSErr values into errno
 */