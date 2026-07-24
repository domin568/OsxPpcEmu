/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/28 15:05:09 $
 * $Revision: 1.3.2.1 $
 */

/*
 *	Content:	Interface file to standard UNIX-style entry points ...
 *
 *	NB:			This file implements some UNIX low level support.  These functions
 *				are not guaranteed to be 100% conformant.
 *
 */

#include <errno.h>
#include <stat.h>
#include <time.mac.h>					/*- mm 970514 -*/
#include <unistd.h>

#include <path2fss.h>

#include <Files.h>
#include <LowMem.h>
#include <MacTypes.h>					/*- vss 990421 -*/

/* function prototypes for externally defined functions */

extern int __ctopstring(const char *cstring, Str255 pstring) _MSL_CANT_THROW;
extern char __msl_system_has_new_file_apis(void) _MSL_CANT_THROW;

/*
 *	static int __stat(short vrefnum, long dirid, Str255 pname, struct stat *buf)
 *
 *		Returns information about a file (called by fstat and stat).
 */
#if _MSL_USE_OLD_FILE_APIS
static int __stat(short vrefnum, long dirid, Str255 pname, struct stat *buf) _MSL_CANT_THROW
{
	HFileInfo		fpb;
	HVolumeParam	vpb;
	OSErr			err;
	Str255			name;

	fpb.ioNamePtr = pname;
	fpb.ioFDirIndex = 0;
	fpb.ioVRefNum = vrefnum;
	fpb.ioDirID = dirid;

	/* get the file's catalog info */
	err = PBGetCatInfoSync((CInfoPBPtr)&fpb);
	if (err == noErr) {
		/* get the volume's info */
		vpb.ioVolIndex = 0;
		vpb.ioNamePtr = name;
		vpb.ioVRefNum = vrefnum;
		err = PBHGetVInfoSync((HParmBlkPtr)&vpb);
		if (err == noErr && buf != NULL) {
			/* fill in the data */
			if (fpb.ioFlAttrib & 0x10)
			{
				buf->st_mode = S_IFDIR;
				buf->st_nlink = 2;
			}				
			else
			{
				buf->st_nlink = 1;
				if (fpb.ioFlFndrInfo.fdFlags & 0x8000)
					buf->st_mode = S_IFLNK;
				else
					buf->st_mode = S_IFREG;
			}
			buf->st_ino = fpb.ioDirID;
			buf->st_dev = fpb.ioVRefNum;
			buf->st_uid = getuid();
			buf->st_gid = getgid();
			buf->st_rdev = 0;
			buf->st_size = fpb.ioFlLgLen;
			buf->st_atime = buf->st_mtime = fpb.ioFlMdDat + _mac_msl_epoch_offset_; /*- mm 970514 -*/ /*- mm 990203 -*/
			buf->st_ctime = fpb.ioFlCrDat + _mac_msl_epoch_offset_;                 /*- mm 970514 -*/ /*- mm 990203 -*/
			buf->st_blksize = vpb.ioVAlBlkSiz;
			buf->st_blocks = (buf->st_size + buf->st_blksize - 1) / buf->st_blksize;
		}
	}

	if (err != noErr)
	{
		errno = EMACOSERR;														/*- mm 010412 -*/
		__MacOSErrNo = err;														/*- mm 010412 -*/
	}
	return (err == noErr ? 0 : -1);
}
#endif /* _MSL_USE_OLD_FILE_APIS */

/*
 *	static int __stat_ref(FSRefPtr theRef, struct stat *buf)
 *
 *		Returns information about a file (called by fstat and stat).
 */
#if _MSL_USE_NEW_FILE_APIS
static int __stat_ref(FSRefPtr theRef, struct stat *buf) _MSL_CANT_THROW
{
	OSErr theErr;
	FSCatalogInfo theInfo;
	FSVolumeInfo theVolInfo;
	UInt32 theSeconds;
	
	theErr = FSGetCatalogInfo(theRef, kFSCatInfoNodeFlags + kFSCatInfoVolume + kFSCatInfoParentDirID +
		kFSCatInfoNodeID + kFSCatInfoCreateDate + kFSCatInfoContentMod + kFSCatInfoAccessDate +
		kFSCatInfoFinderInfo + kFSCatInfoDataSizes, &theInfo, NULL, NULL, NULL);
	
	if (theErr == noErr)
		theErr = FSGetVolumeInfo(theInfo.volume, 0, NULL, kFSVolInfoBlocks, &theVolInfo, NULL, NULL);
	
	if ((theErr == noErr) && (buf != NULL))
	{
		if (theInfo.nodeFlags & kFSNodeIsDirectoryMask)
		{
			buf->st_mode = S_IFDIR;
			buf->st_nlink = 2;
		}
		else
		{
			buf->st_nlink = 1;
			if (((FileInfo *) &(theInfo.finderInfo))->finderFlags & kIsAlias)
				buf->st_mode = S_IFLNK;
			else
				buf->st_mode = S_IFREG;
		}
		
		buf->st_ino = theInfo.nodeID;
		buf->st_dev = theInfo.volume;
		buf->st_uid = getuid();
		buf->st_gid = getgid();
		buf->st_rdev = 0;
		buf->st_size = theInfo.dataLogicalSize;
		
		ConvertUTCToLocalTime(theInfo.accessDate.lowSeconds, &theSeconds);
		buf->st_atime = theSeconds + _mac_msl_epoch_offset_;
		
		ConvertUTCToLocalTime(theInfo.contentModDate.lowSeconds, &theSeconds);
		buf->st_mtime = theSeconds + _mac_msl_epoch_offset_;
		
		ConvertUTCToLocalTime(theInfo.createDate.lowSeconds, &theSeconds);
		buf->st_ctime = theSeconds + _mac_msl_epoch_offset_;
		
		buf->st_blksize = theVolInfo.blockSize;
		buf->st_blocks = (buf->st_size + buf->st_blksize - 1) / buf->st_blksize;
	}
	
	if (theErr != noErr)
	{
		errno = EMACOSERR;														/*- mm 010412 -*/
		__MacOSErrNo = theErr;													/*- mm 010412 -*/
		theErr = -1;
	}
	
	return theErr;
}
#endif /* _MSL_USE_NEW_FILE_APIS */

/*
 *	int stat(char *path, struct stat *buf)
 *
 *		Returns information about a file.
 */
int stat(const char *path, struct stat *buf) _MSL_CANT_THROW
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		OSErr err;
		FSRef theRef;
		
		err = __msl_path2fsr(path, &theRef);
		
		if (err == noErr)
			err = __stat_ref(&theRef, buf);
		
		if (err != noErr)
			err = -1;
		
		return err;
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	Str255			ppath;

	if (path) {
		/* convert the C string into a Pascal string */
		if (__ctopstring(path, ppath) != noErr) return (-1);
	
		return (__stat(0, 0L, ppath, buf));
	}
	return (-1);
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

/*
 *	int fstat(int fildes, struct stat *buf)
 *
 *		Returns information about a file.
 */
int fstat(int fildes, struct stat *buf) _MSL_CANT_THROW
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		OSErr err;
		FSRef theRef;
		
		err = FSGetForkCBInfo(fildes, 0, NULL, NULL, NULL, &theRef, NULL);
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
			return (-1);
		}
		
		return __stat_ref(&theRef, buf);
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
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
	}
	return (err == noErr ? __stat(fcbpb.ioFCBVRefNum, fcbpb.ioFCBParID, fcbpb.ioNamePtr, buf) : -1);
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

/*
 *	int mkdir(const char *path, int mode)
 *
 *		Creates a directory. (NB: mode is ignored on the mac)
 */
int mkdir(const char *path, ...) _MSL_CANT_THROW
{
		OSErr err = -1;
		
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		FSRef theParentRef;
		HFSUniStr255 theName;
		FSCatalogInfo theInfo;
		
		err = __msl_path2splitfsr(path, &theParentRef, &theName);
		
		if (err == noErr)
		{
			theInfo.textEncodingHint = __msl_get_system_encoding();
			
			err = FSCreateDirectoryUnicode(&theParentRef, theName.length, theName.unicode,
				kFSCatInfoTextEncoding, &theInfo, NULL, NULL, NULL);
		}
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	HFileParam		fpb;
	Str255			ppath;

	if (path) {
		/* convert the c string into a pascal string */
		if (__ctopstring(path, ppath) != noErr) return (-1);

		fpb.ioNamePtr = ppath;
		fpb.ioVRefNum = 0;
		fpb.ioDirID = 0L;
		err = PBDirCreateSync((HParmBlkPtr)&fpb);
	}
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
	
	if (err != noErr)
	{
		errno = EMACOSERR;														/*- mm 010412 -*/
		__MacOSErrNo = err;														/*- mm 010412 -*/
	}
	
	return (err == noErr ? 0 : -1);
}

/* int chmod(const char *path, mode_t mode);
 * Set the file permission bits, the set userID bit and the set group ID bit for the
 * file named by path to mode.  The permission bits have no application on the Mac
 * and the other bits are not used on the Mac so this is a dummy placeholder function
 * to prevent compile and link errors.
 */
int chmod(const char *path, mode_t mode) _MSL_CANT_THROW
{
#pragma unused(path, mode)
	return -1;
}

/* Change record:
 * JFH 951230 Removed uses of OLDROUTINENAMES
 * mm  970514 Added correction for difference in 1900Jan01 and 1904Jan01 epochs
 * mm  990203 Corrected name of epoch conversion constant
 * vss 990421 Update to 3.2 Universal Headers
 * cc  000531 changed _mkdir to one arg since second was not used 
 * cc  000531 removed  #pragma unused in mkdir
 * JWW 001031 Use new OS 9 File Manager APIs in __stat_ref and _stat and _fstat and _mkdir
 * mm  010412 Changes to avoid putting OSErr values into errno.
 * JWW 010614 Use __msl_get_system_encoding to determine the script system to use for HFS+
 * cc  010622 Changed _chmod to chmod
 * JWW 010927 Moved chmod to stat.mac.c from unix.mac.c
 */