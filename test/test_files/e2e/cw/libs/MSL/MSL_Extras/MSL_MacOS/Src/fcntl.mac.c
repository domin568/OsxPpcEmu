/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/28 15:05:02 $
 * $Revision: 1.5.2.1 $
 */

/*
 *	Content:	Interface file to standard UNIX-style entry points ...
 *
 *	NB:			This file implements some UNIX low level support.  These functions
 *				are not guaranteed to be 100% conformant.
 *
 */

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <Aliases.h>
#include <Errors.h>
#include <Files.h>
#include <Finder.h>
#include <LowMem.h>
#include <MacTypes.h>	/*- vss 990421 -*/

#include <abort_exit.h>
#include <path2fss.h>

/* function prototypes for externally defined functions */

extern int	__system7present(void) _MSL_CANT_THROW;
extern int	__ctopstring(const char *cstring, Str255 pstring) _MSL_CANT_THROW;
extern long __getcreator(long isbinary) _MSL_CANT_THROW;
extern long __gettype(long isbinary) _MSL_CANT_THROW;
extern char __msl_system_has_new_file_apis(void) _MSL_CANT_THROW;

/*
 *	int open(const char *path, int oflag)
 *	
 *		Opens a file stream.
 */
int open(const char *path, int oflag, ...) _MSL_CANT_THROW
{
	/* Ensure that exactly one of O_RDONLY, O_RDWR, O_WRONLY is set */   /*- mm 980923 -*/
	if ((((oflag & O_RDONLY)!=0) + ((oflag & O_RDWR)!=0) + ((oflag & O_WRONLY)!=0)) != 1)
		return (-1);
	
	/* Reject POSIX undefined combinations */                            
	if ((oflag & O_RDONLY) && (oflag & O_TRUNC))   
		return (-1);
	
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
	{
		FSRef	theRef;
		FSRef	theParentRef;
		FSSpec	theSpec;
		SInt8	permission;
		OSErr	err;
		SInt16	refNum;
		Boolean targetIsFolder, wasAliased;
		HFSUniStr255 theName;
		HFSUniStr255 theForkName;
		FSCatalogInfo theInfo;
		
		/* Setup permission */
		if ((oflag & 0x07) == O_RDWR)
			permission = fsRdWrPerm;
		else
			permission = (oflag & O_RDONLY) ? fsRdPerm : 0 + (oflag & O_WRONLY) ? fsWrPerm : 0;
		
		err = __msl_path2fsr(path, &theRef);
		
		if (err == fnfErr)
		{
			err = __msl_path2splitfsr(path, &theParentRef, &theName);
			
			if (err == noErr)
				err = fnfErr;
		}
		else if ((oflag & (O_ALIAS | O_NRESOLVE)) == 0)
		{
			FSGetCatalogInfo(&theRef, kFSCatInfoNone, NULL, &theName, &theSpec, &theParentRef);
			ResolveAliasFile(&theSpec, true, &targetIsFolder, &wasAliased);
			FSpMakeFSRef(&theSpec, &theRef);
		}
		
		if ((err != noErr) && (err != fnfErr))
			return (-1);
		
		if (oflag & O_RSRC)			/* open the resource fork of the file */
			FSGetResourceForkName(&theForkName);
		else						/* open the data fork of the file */
			FSGetDataForkName(&theForkName);
		
		if (err == noErr)
			err = FSOpenFork(&theRef, theForkName.length, theForkName.unicode, permission,
				&refNum);
		
		if ((err == noErr) && (oflag & O_CREAT) && (oflag & O_EXCL))
		{
			err = close(refNum);
			return (-1);
		}
		
		if ((err == fnfErr) && (oflag & O_CREAT)) 
		{
			((FileInfo *) &(theInfo.finderInfo))->fileType = __gettype(oflag & O_BINARY);
			((FileInfo *) &(theInfo.finderInfo))->fileCreator = __getcreator(oflag & O_BINARY);
			if (oflag & O_ALIAS)
				((FileInfo *) &(theInfo.finderInfo))->finderFlags = kIsAlias;
			else
				((FileInfo *) &(theInfo.finderInfo))->finderFlags = 0;
			((FileInfo *) &(theInfo.finderInfo))->location.h = 0;
			((FileInfo *) &(theInfo.finderInfo))->location.v = 0;
			((FileInfo *) &(theInfo.finderInfo))->reservedField = 0;
			theInfo.textEncodingHint = __msl_get_system_encoding();
			
			err = FSCreateFileUnicode(&theParentRef, theName.length, theName.unicode,
				kFSCatInfoTextEncoding + kFSCatInfoFinderInfo, &theInfo, &theRef, NULL);
			
			if ((err != noErr) && (err != dupFNErr))
			{
				errno = EMACOSERR;														/*- mm 010412 -*/
				__MacOSErrNo = err;														/*- mm 010412 -*/
				return (-1);
			}
			
			err = FSOpenFork(&theRef, theForkName.length, theForkName.unicode, permission,
				&refNum);
		}

		/*if ((err != noErr) && (err != dupFNErr) && (err != opWrErr))*/				/*- mm 001214 -*/
		if ((err != noErr) && (err != dupFNErr))										/*- mm 001214 -*/
		{
			errno = EMACOSERR;															/*- mm 010412 -*/
			__MacOSErrNo = err;															/*- mm 010412 -*/
			return (-1);
		}
		
		if (oflag & O_TRUNC)
		{
			err = FSSetForkSize(refNum, fsFromStart, 0);
			
			if (err != noErr)
			{
				errno = EMACOSERR;														/*- mm 010412 -*/
				__MacOSErrNo = err;														/*- mm 010412 -*/
				return (-1);
			}
		}
		
		if (oflag & O_APPEND) lseek(refNum, 0, SEEK_END);
		
		return (refNum);
	}
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	else
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	{
		Str255			pname;
		FSSpec			spec;
		char			permission;
		HParamBlockRec	hpb;
		OSErr			err;

		/* convert the c string into a pascal string */
		if (__ctopstring(path, pname) != noErr) return (-1);

		/* Setup permission */
		if ((oflag & 0x07) == O_RDWR)             /*- mm 980417 -*/         
			permission = fsRdWrPerm;
		else
			permission = (oflag & O_RDONLY) ? fsRdPerm : 0 + (oflag & O_WRONLY) ? fsWrPerm : 0;

		/* If System 7 is present, then try to resolve a possible alias */
		if (__system7present()) 
		{
			Boolean targetIsFolder, wasAliased;

			FSMakeFSSpec(0,0,pname,&spec);
			if ((oflag & (O_ALIAS | O_NRESOLVE)) == 0)
				ResolveAliasFile(&spec, true, &targetIsFolder, &wasAliased);
			hpb.fileParam.ioNamePtr = spec.name;
			hpb.fileParam.ioVRefNum = spec.vRefNum;
			hpb.fileParam.ioDirID = spec.parID;
			hpb.ioParam.ioPermssn = permission;

			if (oflag & O_RSRC)			/* open the resource fork of the file */
				err = PBHOpenRFSync(&hpb);
			else						/* open the data fork of the file */
				err = PBHOpenDFSync(&hpb);
		} 
		else 
		{
			/* Try to open the file */
			hpb.fileParam.ioDirID = 0;
			hpb.fileParam.ioVRefNum = 0;
			hpb.fileParam.ioNamePtr = pname;
			hpb.ioParam.ioPermssn = permission;

			if (oflag & O_RSRC)			/* open the resource fork of the file */
		#if TARGET_API_MAC_CARBON
				err = PBHOpenRFSync(&hpb);
		#else
				err = PBOpenRFSync((ParmBlkPtr)&hpb);
		#endif /* TARGET_API_MAC_CARBON */
			else						/* open the data fork of the file */
		#if TARGET_API_MAC_CARBON
				err = PBHOpenDFSync(&hpb);
		#else
				err = PBOpenDFSync((ParmBlkPtr)&hpb);
		#endif /* TARGET_API_MAC_CARBON */
		}

		if ((err == noErr) && (oflag & O_CREAT) && (oflag & O_EXCL))    /*- mm 991210 -*/
		{																/*- mm 991210 -*/
			err = close(hpb.ioParam.ioRefNum);							/*- mm 991210 -*/
			return(-1);													/*- mm 991210 -*/
		}																/*- mm 991210 -*/

		if ((err == fnfErr) && (oflag & O_CREAT)) 
		{
			hpb.fileParam.ioFlVersNum = 0;
			err = PBHCreateSync(&hpb);
			if (err == noErr) 
			{
				/* Set the finder info */
				unsigned long secs;
				unsigned long isbinary = oflag & O_BINARY;

				hpb.fileParam.ioFlFndrInfo.fdType = __gettype(isbinary);
				hpb.fileParam.ioFlFndrInfo.fdCreator = __getcreator(isbinary);
				hpb.fileParam.ioFlFndrInfo.fdFlags = 0;
				if (oflag & O_ALIAS && __system7present())		/* set the alias bit */
					hpb.fileParam.ioFlFndrInfo.fdFlags = kIsAlias;
				else										/* clear all flags */
					hpb.fileParam.ioFlFndrInfo.fdFlags = 0;

				GetDateTime(&secs);
				hpb.fileParam.ioFlCrDat = hpb.fileParam.ioFlMdDat = secs;
				PBHSetFInfoSync(&hpb);
			}
			
			if (err && (err != dupFNErr)) 
			{
				errno = EMACOSERR;															/*- mm 010412 -*/
				__MacOSErrNo = err;															/*- mm 010412 -*/
				return -1;
			}

			if (__system7present()) 
			{
				if (oflag & O_RSRC)			/* open the resource fork of the file */
					err = PBHOpenRFSync(&hpb);
				else						/* open the data fork of the file */
					err = PBHOpenDFSync(&hpb);
			} 
			else 
			{
				if (oflag & O_RSRC)			/* open the resource fork of the file */
			#if TARGET_API_MAC_CARBON
					err = PBHOpenRFSync(&hpb);
			#else
					err = PBOpenRFSync((ParmBlkPtr)&hpb);
			#endif /* TARGET_API_MAC_CARBON */
				else						/* open the data fork of the file */
			#if TARGET_API_MAC_CARBON
					err = PBHOpenDFSync(&hpb);
			#else
					err = PBOpenDFSync((ParmBlkPtr)&hpb);
			#endif /* TARGET_API_MAC_CARBON */
			}
			if (err && (err != dupFNErr) && (err != opWrErr)) 
			{
				errno = EMACOSERR;															/*- mm 010412 -*/
				__MacOSErrNo = err;															/*- mm 010412 -*/
				return -1;
			}
			else
			{
				/* Set no error to continue past the next error check... */
				err = 0;
			}
		}
		
		if (err != noErr) 
		{
			errno = EMACOSERR;
			__MacOSErrNo = err;
			return -1;
		}
		
		if (oflag & O_TRUNC) 
		{
			IOParam pb;
			
			pb.ioRefNum = hpb.ioParam.ioRefNum;
			pb.ioMisc = 0L;
			err = PBSetEOFSync((ParmBlkPtr)&pb);
			if (err != noErr) 
			{
				errno = EMACOSERR;														/*- mm 010412 -*/
				__MacOSErrNo = err;														/*- mm 010412 -*/
				return -1;
			}
		}

		if (oflag & O_APPEND) lseek(hpb.ioParam.ioRefNum,0,SEEK_END);
		
		return (hpb.ioParam.ioRefNum);
	}
#endif /* _MSL_USE_OLD_FILE_APIS */
}

/*
 *	int creat(char *path, mode_t mode)
 *
 *		Creates and opens a file.
 */
int creat(const char *path, mode_t mode) _MSL_CANT_THROW
{
	int	omode = O_WRONLY | O_CREAT | O_TRUNC;
	
	if (mode & O_BINARY)
		omode |= O_BINARY;

	return (open(path, omode));
}


/*
 *	int fcntl(int fildes, int cmd, ...)
 *
 *		General file control routines.
 */
int fcntl(int fildes, int cmd, ...) _MSL_CANT_THROW
{
	if (cmd == F_DUPFD) {
		/* we don't support this one correctly but it does conform */
		/* just return the same file descriptor as the one passed to it */
		return (fildes);
	}

	return (-1);
}

#pragma mark -

#if _MSL_WFILEIO_AVAILABLE

int _wopen(const wchar_t *path, int oflag, ...) _MSL_CANT_THROW
{
	FSRef	theRef;
	FSRef	theParentRef;
	FSSpec	theSpec;
	SInt8	permission;
	OSErr	err;
	SInt16	refNum;
	Boolean targetIsFolder, wasAliased;
	HFSUniStr255 theName;
	HFSUniStr255 theForkName;
	FSCatalogInfo theInfo;
	
	/* Ensure that exactly one of O_RDONLY, O_RDWR, O_WRONLY is set */   /*- mm 980923 -*/
	if ((((oflag & O_RDONLY)!=0) + ((oflag & O_RDWR)!=0) + ((oflag & O_WRONLY)!=0)) != 1)
		return (-1);
	
	/* Reject POSIX undefined combinations */                            
	if ((oflag & O_RDONLY) && (oflag & O_TRUNC))   
		return (-1);
	
	/* Setup permission */
	if ((oflag & 0x07) == O_RDWR)
		permission = fsRdWrPerm;
	else
		permission = (oflag & O_RDONLY) ? fsRdPerm : 0 + (oflag & O_WRONLY) ? fsWrPerm : 0;
	
	err = __msl_wpath2fsr(path, &theRef);
	
	if (err == fnfErr)
	{
		err = __msl_wpath2splitfsr(path, &theParentRef, &theName);
		
		if (err == noErr)
			err = fnfErr;
	}
	else if ((oflag & (O_ALIAS | O_NRESOLVE)) == 0)
	{
		FSGetCatalogInfo(&theRef, kFSCatInfoNone, NULL, &theName, &theSpec, &theParentRef);
		ResolveAliasFile(&theSpec, true, &targetIsFolder, &wasAliased);
		FSpMakeFSRef(&theSpec, &theRef);
	}
	
	if ((err != noErr) && (err != fnfErr))
		return (-1);
	
	if (oflag & O_RSRC)			/* open the resource fork of the file */
		FSGetResourceForkName(&theForkName);
	else						/* open the data fork of the file */
		FSGetDataForkName(&theForkName);
	
	if (err == noErr)
		err = FSOpenFork(&theRef, theForkName.length, theForkName.unicode, permission,
			&refNum);
	
	if ((err == noErr) && (oflag & O_CREAT) && (oflag & O_EXCL))
	{
		err = close(refNum);
		return (-1);
	}
	
	if ((err == fnfErr) && (oflag & O_CREAT)) 
	{
		((FileInfo *) &(theInfo.finderInfo))->fileType = __gettype(oflag & O_BINARY);
		((FileInfo *) &(theInfo.finderInfo))->fileCreator = __getcreator(oflag & O_BINARY);
		if (oflag & O_ALIAS)
			((FileInfo *) &(theInfo.finderInfo))->finderFlags = kIsAlias;
		else
			((FileInfo *) &(theInfo.finderInfo))->finderFlags = 0;
		((FileInfo *) &(theInfo.finderInfo))->location.h = 0;
		((FileInfo *) &(theInfo.finderInfo))->location.v = 0;
		((FileInfo *) &(theInfo.finderInfo))->reservedField = 0;
		theInfo.textEncodingHint = __msl_get_system_encoding();
		
		err = FSCreateFileUnicode(&theParentRef, theName.length, theName.unicode,
			kFSCatInfoTextEncoding + kFSCatInfoFinderInfo, &theInfo, &theRef, NULL);
		
		if ((err != noErr) && (err != dupFNErr))
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
			return (-1);
		}
		
		err = FSOpenFork(&theRef, theForkName.length, theForkName.unicode, permission,
			&refNum);
	}

	/*if ((err != noErr) && (err != dupFNErr) && (err != opWrErr))*/				/*- mm 001214 -*/
	if ((err != noErr) && (err != dupFNErr))										/*- mm 001214 -*/
	{
		errno = EMACOSERR;															/*- mm 010412 -*/
		__MacOSErrNo = err;															/*- mm 010412 -*/
		return (-1);
	}
	
	if (oflag & O_TRUNC)
	{
		err = FSSetForkSize(refNum, fsFromStart, 0);
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
			return (-1);
		}
	}
	
	if (oflag & O_APPEND) lseek(refNum, 0, SEEK_END);
	
	return (refNum);
}

int _wcreat(const wchar_t *path, mode_t mode) _MSL_CANT_THROW
{
	int	omode = O_WRONLY | O_CREAT | O_TRUNC;
	
	if (mode & O_BINARY)
		omode |= O_BINARY;

	return (_wopen(path, omode));
}

#endif /* _MSL_WFILEIO_AVAILABLE */

/* Change record:
 * JH  951210 modified to interface with new ANSI C library
 * JH  951215 Removed SetupExit call
 * JH  951230 Removed uses of OLDROUTINENAMES
 * mm  980417 Change corresponding to value changes for open modes in fcntl.mac.h  MW00042
 * vss 980729 Match open to POSIX standard
 * mm  980923 Added code to reject illegal oflag combinations in open()
 * mm  990108 Added code for umask()       MW07297
 * mm  990115 Added definition of chmod  MW06763
 * vss 990421 Update to 3.2 Universal Headers
 * cc  991108 added ra Carbon Changes done 990611
 * cc  991109 changed TARGET_CARBON to TARGET_API_MAC_CARBON
 * cc  991115 updated and deleted outdated comments
 * mm  991210 Corrected open to reject the combination O_CREAT and O_EXCL
 * JWW 001031 Use new OS 9 File Manager APIs in _open
 * mm  001214 Changed _open to prevent two applications concurrently opening the same file for writing.
 * mm  010412 Changes to avoid putting OSErr values into errno
 * mm  010420 Removed some duplicated code and tidied up.
 * JWW 010614 Use __msl_get_system_encoding to determine the script system to use for HFS+
 * JWW 011009 Fixed open in old-style API code to return -1 when the file to open does not exist
 * JWW 021010 Added wchar_t file I/O routines controlled by _MSL_WFILEIO_AVAILABLE
 */