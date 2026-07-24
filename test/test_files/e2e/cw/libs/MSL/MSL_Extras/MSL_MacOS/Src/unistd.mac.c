/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/28 15:05:19 $
 * $Revision: 1.6.2.1 $
 */

/*
 *	Content:	Interface file to standard UNIX-style entry points ...
 *
 *	NB:			This file implements some UNIX low level support.  These functions
 *				are not guaranteed to be 100% conformant.
 *
 */

#include <console.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <Errors.h>
#include <Files.h>
#include <LowMem.h>
#include <Processes.h>
#include <TextUtils.h>  /*- mm 971010 -*/
#include <MacTypes.h>	/*- vss 990421 -*/
#include <Devices.h>
#include <UnicodeConverter.h>
 
#include <abort_exit.h>
#include <path2fss.h>

/* local typedefs */
typedef struct LaunchStruct {
	StringPtr	name;
	short		memUse;
	char		LC[2];
	long		extBlocLen;
	short		fFlags;
	long		launchFlags;
} LaunchStruct;

/* local globals */
static OSErr error;
static short savedWD;

/* function prototypes for externally defined functions */

extern int	__system7present() _MSL_CANT_THROW;
extern int	__ctopstring(const char *cstring, Str255 pstring) _MSL_CANT_THROW;
extern char __msl_system_has_new_file_apis(void) _MSL_CANT_THROW;

/*
 *	pascal short LaunchApp(struct LaunchStruct *)
 *
 *		Launch an application under System 6.
 */
#if __MC68K__ && !__CFM68K__
static pascal short LaunchApp(LaunchStruct *launchStruct) = { 0x205F, 0xA9F2, 0x3E80 };
#endif /* __MC68K__ && !__CFM68K__ */


#if _MSL_USE_OLD_FILE_APIS
/*
 *	static long getdirname(Str255 s, short vrefnum, long dirnum)
 *
 *		Returns the current directory's name and its parent's DirID.
 */
static long getdirname(Str255 s, short vrefnum, long dirnum) _MSL_CANT_THROW
{
	CInfoPBRec pb;

	pb.dirInfo.ioNamePtr = s;
	pb.dirInfo.ioVRefNum = vrefnum;
	pb.dirInfo.ioFDirIndex = -1;
	pb.dirInfo.ioDrDirID = dirnum;

	PBGetCatInfoSync(&pb);
	return(pb.dirInfo.ioDrParID);
}

/*
 *	static short catdirname(char *buf, int size, short vrefnum, long dirnum)
 *
 *		Recursive call to return the full path to a directory.
 */
static void _catdirname(char *buf, int size, short vrefnum, long dirnum) _MSL_CANT_THROW
{
	Str255			dirname;

	if (dirnum == 2)
		return;

	_catdirname(buf, size, vrefnum, getdirname(dirname, vrefnum, dirnum));
	if (error || (buf[0] + dirname[0] + 2 > size))
		return;

	memcpy(&buf[buf[0] + 1], &dirname[1], dirname[0]);
	buf[0] = buf[0] + dirname[0];
	buf[buf[0] + 1] = ':';
	buf[0] += 1;
}
#endif /* _MSL_USE_OLD_FILE_APIS */

/*
 *	int chdir(const char *path)
 *
 *		Changes the current working directory (actually changes lowmem globals
 *		SFSaveDisk and CurDirStore which are used by open to open a file).
 */
int chdir(const char * path) _MSL_CANT_THROW
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		FSRef theRef;
		OSErr err = -1;
		FSSpec theSpec;
		
		if (path != NULL)
		{
			err = __msl_path2fsr(path, &theRef);
			
			/* JWW - For some reason, HSetVol doesn't work on OS X until after a FSMakeFSSpec */
			/* The result of this FSMakeFSSpec is ignored by MSL - it's just to make OS X happy */
			FSMakeFSSpec(0, 0, "\p", &theSpec);
			
			if (err == noErr)
				err = FSGetCatalogInfo(&theRef, kFSCatInfoNone, NULL, NULL, &theSpec, NULL);
			
			if (err == noErr)
				err = HSetVol(theSpec.name, theSpec.vRefNum, theSpec.parID);
		}
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
		}
		
		return (err == noErr ? 0 : -1);
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS*/
#if _MSL_USE_OLD_FILE_APIS
	WDPBRec			wdpb;

	Str255			ppath;
	OSErr			err = -1;

	if (path) {
		/* convert the c string into a pascal string */
		if (__ctopstring(path, ppath) != noErr) return (-1);
	
		if (ppath[ppath[0]] != ':')
			ppath[++ppath[0]] = ':';

		wdpb.ioNamePtr = ppath;
		wdpb.ioVRefNum = 0;
		wdpb.ioWDDirID = 0;
		err = PBHSetVolSync(&wdpb);
	}

	/* if we reach here we have an error */
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
 *	int close(int fildes)
 *	
 *		Closes a file stream.
 */
int close(int fildes) _MSL_CANT_THROW
{
	if (fildes >= 0 && fildes <= 2)
	{
		return 0;
	}

#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
	{
		OSErr err;
		
		err = FSCloseFork(fildes);
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
		}
		return (err == noErr ? 0 : -1);
	}
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	else
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	{
		HParamBlockRec	pb;
		FCBPBRec		fcb;
		OSErr			err;

	/*	Get volume refnum ... */
	fcb.ioFCBIndx = 0;
	fcb.ioRefNum = fildes;
	fcb.ioNamePtr = NULL;
	err = PBGetFCBInfoSync(&fcb);

	if (err == noErr) {
		pb.fileParam.ioVRefNum = fcb.ioVRefNum;
		pb.fileParam.ioFRefNum = fildes;
	
		err = PBCloseSync((ParmBlkPtr)&pb);
		if (err == noErr) {
			pb.volumeParam.ioNamePtr = NULL;
			pb.volumeParam.ioVRefNum = fcb.ioVRefNum;
			PBFlushVolSync((ParmBlkPtr)&pb);
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
}

/*
 *	char *cuserid(char *string)
 *
 *		Returns the user's name associated with the current process (owner name from
 *		Sharing Setup CP).
 */
char * cuserid(char * string) _MSL_CANT_THROW
{
	char			*name = getlogin();

	if (name != NULL && string != NULL)
		strcpy(string, name);
	return (name == NULL ? NULL : string == NULL ? name : string);
}

/*
 *	int exec(const char *path, ...)
 *
 *		Launchs an application and then quits the current app.
 */
int exec(const char * path, ...) _MSL_CANT_THROW
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		FSRef			theRef;
		OSErr			err = -1;
		LaunchParamBlockRec theLaunch;
		FSSpec theSpec;
		
		if (path != NULL)
		{
			err = __msl_path2fsr(path, &theRef);
			
			if (err != noErr)
				return (-1);
			
			err = FSGetCatalogInfo(&theRef, kFSCatInfoNone, NULL, NULL, &theSpec, NULL);
			
			if (err == noErr)
			{
				memset(&theLaunch, '\0', sizeof(theLaunch));
				
				theLaunch.launchBlockID = extendedBlock;
				theLaunch.launchEPBLength = extendedBlockLen;
				theLaunch.launchControlFlags = launchContinue + launchNoFileFlags;
				theLaunch.launchAppSpec = &theSpec;

				err = LaunchApplication(&theLaunch);
			}
			
			if (err == noErr)
				exit(0);
		}
		
		/* if we reach here we have an error */
		errno = EMACOSERR;														/*- mm 010412 -*/
		__MacOSErrNo = err;														/*- mm 010412 -*/
		return (-1);
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	Str255			ppath;
	OSErr			err = -1;

	if (path) 
	{
		/* convert the c string into a pascal string */
		if (__ctopstring(path, ppath) != noErr) 
			return (-1);
	
		/* under system 7 or greater use the LaunchApplication call */
		if (__system7present()) 
		{
			LaunchParamBlockRec lpb;
			FSSpec spec;
	
			err = FSMakeFSSpec(0,0,ppath,&spec);
			if (err == noErr) 
			{
				memset(&lpb, '\0', sizeof(LaunchParamBlockRec));
	
				lpb.launchBlockID = extendedBlock;
				lpb.launchEPBLength = extendedBlockLen;
				lpb.launchControlFlags = launchContinue + launchNoFileFlags;
				lpb.launchAppSpec = &spec;
	
				err = LaunchApplication(&lpb);
			}
		}
	#if __MC68K__ && !__CFM68K__
		/* only possible way to get here is under 6.0.x on a 68K mac */
		else 
		{
			static LaunchStruct launchStruct;
	
			memset(&launchStruct, '\0', sizeof(LaunchStruct));
			launchStruct.name = ppath;
			err = LaunchApp(&launchStruct);
		}
		#endif /* __MC68K__ && !__CFM68K__ */
		
		if (err == noErr)
			exit(0);
	}

		/* if we reach here we have an error */
		errno = EMACOSERR;														/*- mm 010412 -*/
		__MacOSErrNo = err;														/*- mm 010412 -*/
		return (-1);
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

/*
 *	char *getcwd(char *buf, int size)
 *
 *		Returns the path to the current directory.
 */
char * getcwd(char * buf, int size) _MSL_CANT_THROW
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		OSErr err;
		OSStatus theStatus;
		ByteCount theSourceUsed;
		ByteCount theConvertedLength;
		UnicodeToTextInfo theConverterInfo;
		FSSpec theSpec;
		FSRef theRef;
		FSRef theParentRef;
		FSCatalogInfo theInfo;
		HFSUniStr255 theName;
		int i;
		
		err = -1;
		
		if ((size > 1) && (buf != NULL))
		{
			buf[0] = 0;
			err = FSMakeFSSpec(0, 0, "\p", &theSpec);
			
			if (err == noErr)
				err = FSpMakeFSRef(&theSpec, &theRef);
			
			if (err == noErr)
			{
				while (err == noErr)
				{
					err = FSGetCatalogInfo(&theRef, kFSCatInfoParentDirID, &theInfo, &theName, NULL,
						&theParentRef);
					
					if (err == noErr)
					{
						if (size < theName.length + 1)
							err = -1;
						else
						{
							BlockMoveData(buf, buf + theName.length + 1, strlen(buf) + 1);
							buf[theName.length] = ':';
							
							theStatus = CreateUnicodeToTextInfoByEncoding(__msl_get_system_encoding(),
								&theConverterInfo);
							
							if (theStatus == noErr)
							{
								theStatus = ConvertFromUnicodeToText(theConverterInfo,
									theName.length * 2, theName.unicode, kUnicodeLooseMappingsMask, 0, NULL, NULL,
									NULL, size, &theSourceUsed, &theConvertedLength, buf);
								
								DisposeUnicodeToTextInfo(&theConverterInfo);
							}
							
							if (theStatus != noErr)
							{
								for (i = 0; i < theName.length; i++)
									buf[i] = theName.unicode[i] & 0xFF;
							}
						}
						
						if (theInfo.parentDirID == fsRtParID)
							err = errFSBadFSRef;
						else
							theRef = theParentRef;
					}
				}
				
				if (err == errFSBadFSRef)
					err = noErr;
			}
		}
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
		}
		
		return (err == noErr ? buf : NULL);
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	short			vrefnum;
	long			dirid;
	HVolumeParam	vpb;
	WDPBRec			wdpb;
	int				i,j;

	error = -1;

	if (size > 0 && buf) {
		buf[0] = '\0';

		wdpb.ioNamePtr = NULL;
		error = PBHGetVolSync(&wdpb);

		vrefnum = wdpb.ioWDVRefNum;
		dirid = wdpb.ioWDDirID;

		if (error == noErr) {
			vpb.ioVolIndex = 0;
			vpb.ioNamePtr = (StringPtr)buf;
				vpb.ioVRefNum = vrefnum;	/*- JWW 001031 -*/
	
			error = PBHGetVInfoSync((HParmBlkPtr)&vpb);
			if (error == noErr) {
				buf[buf[0] + 1] = ':';
				buf[0] += 1;
				if (dirid != 2) {
					error = noErr;
					_catdirname(buf, size, vrefnum, dirid);
				}
			}
		}
	}
	if (error == noErr) {	/* convert into a C string */
		for (i = buf[0], j = 0; j < i; j++)
			buf[j] = buf[j+1];
		buf[i] = '\0';
	}

	if (error != noErr)
	{
		errno = EMACOSERR;														/*- mm 010412 -*/
		__MacOSErrNo = error;													/*- mm 010412 -*/
	}
	return (error == noErr ? buf : NULL);
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

/*
 *	char *getlogin(void)
 *
 *		Returns the current user's login name (owner name from Sharing Setup CP).
 */
char * getlogin(void) _MSL_CANT_THROW
{
	static char		login[32];			/* need static data */
	short			savemap;
	StringHandle	h;
	OSErr			err;
	
#if !TARGET_API_MAC_CARBON
	savemap = LMGetCurMap();
	LMSetCurMap(0);						/* search only in the system file's resources */
#endif /* !TARGET_API_MAC_CARBON */
	h = GetString(-16096);				/* the sharing setup's owner name */
	err = ResError();
#if !TARGET_API_MAC_CARBON
	LMSetCurMap(savemap);
#else
	#pragma unused(savemap)	
#endif /* !TARGET_API_MAC_CARBON */

	if (h && err == noErr) 
	{
		HLock((Handle)h);
		sprintf(login, "%#.*s", 31, *h);
		HUnlock((Handle)h);
	}

	if (err != noErr)
	{
		errno = EMACOSERR;														/*- mm 010412 -*/
		__MacOSErrNo = err;														/*- mm 010412 -*/
	}
	return (login[0] ? login : NULL);
}

/*
 *	int isatty(int fildes)
 *
 *		Determines is a filestream is going to the console window.
 */
int isatty(int fildes) _MSL_CANT_THROW
{
	if (fildes >=0 && fildes <= 2)
		return 1;
	else
		return 0;
}

/*
 *	long lseek(int fildes, long offset, int whence)
 *	
 *		Seek in a file (fildes is the MacOS refnum).
 */
long lseek(int fildes, long offset, int whence) _MSL_CANT_THROW
{
	if (fildes >= 0 && fildes <= 2) return -1;
	
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
	{
		OSErr err;
		SInt64 currentpos;
		UInt16 posmode;
		
		err = FSGetForkPosition(fildes, &currentpos);
		
		if (err == noErr)
		{
			switch (whence)
			{
				case SEEK_SET:									/* from start of file */
					posmode = fsFromStart;
					break;
				case SEEK_CUR:									/* from current marker */
					posmode = fsFromMark;
					break;
				case SEEK_END:									/* from EOF marker */
					posmode = fsFromLEOF;
					break;
			}
			
			err = FSSetForkPosition(fildes, posmode, offset);
			
			if (err == eofErr)
			{
				err = FSSetForkSize(fildes, posmode, offset);
				
				if (err == noErr)
					err = FSSetForkPosition(fildes, fsFromLEOF, 0);
			}
			
			if ((err == noErr) && (whence != SEEK_SET))
			{
				err = FSGetForkPosition(fildes, &currentpos);
				offset = currentpos;
			}
		}
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
		}
		
		return (err == noErr ?  offset : -1);
	}
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	else
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	{
	IOParam			pb;
	OSErr			err;
	long            startpos;         /*- mm 960910 -*/
	long            eofpos;           /*- mm 960910 -*/
	
	pb.ioRefNum = fildes;
	PBGetFPosSync((ParmBlkPtr) &pb);  /*- mm 960910 -*/
	startpos = pb.ioPosOffset;        /*- mm 960910 -*/
	pb.ioPosOffset = offset;

	switch (whence) 
	{
		case SEEK_SET:									/* from start of file */
			pb.ioPosMode = fsFromStart;
			break;
		case SEEK_CUR:									/* from current marker */
			pb.ioPosMode = fsFromMark;
			break;
		case SEEK_END:									/* from EOF marker */
			pb.ioPosMode = fsFromLEOF;
			break;
	}

	err = PBSetFPosSync((ParmBlkPtr) &pb);
	if (err == eofErr) 
	{
		pb.ioRefNum = fildes;
		switch (whence) 
		{
			case SEEK_SET:								/* from start of file */
				pb.ioMisc = (Ptr) offset;
				break;
			case SEEK_CUR:								/* from current marker */
				err = PBGetFPosSync((ParmBlkPtr) &pb);
				if (err == noErr) 
				{
					pb.ioRefNum    = fildes;
					eofpos         = pb.ioPosOffset;    /*- mm 960910 -*/
					pb.ioPosOffset = startpos;          /*- mm 960910 -*/
					pb.ioMisc      = (Ptr) (pb.ioPosOffset + offset);
				}
				break;
			case SEEK_END:								/* from EOF marker */
				err = PBGetEOFSync((ParmBlkPtr) &pb);
				if (err == noErr) 
				{
					pb.ioRefNum = fildes;
					pb.ioMisc = (Ptr) (pb.ioMisc + offset);
				}
				break;
		}
		err = PBSetEOFSync((ParmBlkPtr) &pb);

		if (err == noErr) 
		{
			/* retry to lseek */
			pb.ioRefNum = fildes;
			pb.ioPosOffset = offset;

			switch (whence) 
			{
				case SEEK_SET:							/* from start of file */
					pb.ioPosMode = fsFromStart;
					break;
				case SEEK_CUR:							/* from current marker */
					pb.ioPosMode = fsFromMark;
					pb.ioPosOffset = offset - eofpos + startpos; /*- mm 960910 -*/
					break;
				case SEEK_END:							/* from EOF marker */
					pb.ioPosMode = fsFromMark;          /*- mm 980423 -*/
					/*pb.ioPosMode = fsFromLEOF;*/
					break;
			}

			err = PBSetFPosSync((ParmBlkPtr) &pb);
		}
	}

	if (err != noErr)
	{
		errno = EMACOSERR;														/*- mm 010412 -*/
		__MacOSErrNo = err;														/*- mm 010412 -*/
	}	
	return (err == noErr ?  pb.ioPosOffset : -1);
}
#endif /* _MSL_USE_OLD_FILE_APIS */
}

/*
 *	int read(int fildes, void *buf, size_t count)
 *	
 *		Read from a file (fildes is the file's MacOS refnum).
 *  Note: POSIX standard defines return value as of type ssize_t but says int may be used instead    
 */
int read(int fildes, void * buf, size_t count) _MSL_CANT_THROW
{

	if (fildes == 0) 
	{
#if __A5__ || __POWERPC__
		if (InstallConsole(fildes) == 0) 
		{
			__console_exit = RemoveConsole;
			fflush(stdout);
			return ReadCharsFromConsole((char *)buf, count);
		} 
		else
			return -1;
#else
		return -1;
#endif /* __A5__ || __POWERPC__ */
	}
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
	{
		OSErr err;
		ByteCount actualCount;
		
		err = FSReadFork(fildes, fsAtMark, 0, count, buf, &actualCount);
		
		if (err != noErr && err != eofErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
		}	
		return ((err != noErr && err != eofErr) ? -1 : actualCount);
	}
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	else
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	{
		IOParam			pb;
		OSErr			err;
	
		pb.ioRefNum = fildes;
		pb.ioBuffer = (char *)buf;
		pb.ioReqCount = count;
		pb.ioPosMode = fsAtMark;
		pb.ioPosOffset = NULL;

		err = PBReadSync((ParmBlkPtr) &pb);

		if (err != noErr && err != eofErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
		}
		return (err != noErr && err != eofErr) ? -1 : pb.ioActCount;
	}
#endif /* _MSL_USE_OLD_FILE_APIS */
}

/*
 *	int rmdir(const char *path)
 *
 *		Removes a directory (must be empty).
 */
int rmdir(const char * path) _MSL_CANT_THROW
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
			err = FSDeleteObject(&theRef);
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
		}
		return (err == noErr ? 0 : -1);
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	HFileParam		fpb;
	Str255			ppath;
	OSErr			err = -1;

	if (path) 
	{
		/* convert the c string into a pascal string */
		if (__ctopstring(path, ppath) != noErr) return (-1);

		fpb.ioNamePtr = ppath;
		fpb.ioVRefNum = 0;
		fpb.ioDirID = 0L;
		err = PBHDeleteSync((HParmBlkPtr)&fpb);
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
 *	unsigned int sleep(unsigned int seconds)
 *
 *		Pauses program execution for seconds seconds.
 */
unsigned int sleep(unsigned int seconds) _MSL_CANT_THROW
{
	unsigned long			finalTick;                 /*- mm 971006 -*/

	Delay(seconds * 60UL, &finalTick);
	return (0);
}

/*
 *	char *ttyname(int fildes)
 *
 *		Returns the name of the associated terminal or NULL if none.
 */
char * ttyname(int fildes) _MSL_CANT_THROW
{
	if (fildes >=0 && fildes <= 2)
		return __ttyname((long)fildes);
	else
		return NULL;
}

/*
 *	int unlink(const char *path)
 *	
 *		Unlink (i.e. delete) a file.
 */
int unlink(const char * path) _MSL_CANT_THROW
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
			err = FSDeleteObject(&theRef);
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
		}
		return (err == noErr ? 0 : -1);
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	Str255			pname;
	HFileParam		pb;	/*- ra 990612 -*/
	OSErr			err;

	char  *p = (char *) path, *p1 = (char *) pname + 1;
	
	while (*p) *p1++ = *p++; *p1 = 0x00; *pname = p1 - ((char *) pname) -1;

	pb.ioNamePtr = pname;
	pb.ioVRefNum = 0;
	pb.ioFVersNum = 0;
	pb.ioDirID = 0L;	/*- jd 980923 -*/

	err = PBHDeleteSync((HParmBlkPtr) &pb);	/*- ra 990612 -*/

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
 *	int write(int fildes, const void *buf, size_t count)
 *	
 *		Write to a file (fildes is the file's MacOS refnum).
 *  Note: POSIX standard defines return value as of type ssize_t but says int may be used instead    
 */
int write(int fildes, const void *buf, size_t count) _MSL_CANT_THROW
{
	if ((fildes == 1) || (fildes == 2)) {
#if __A5__ || __POWERPC__
		if (InstallConsole(fildes) == 0) {
			__console_exit = RemoveConsole;
			fflush(stdin);
			return WriteCharsToConsole((char *)buf, count);
		} else
			return -1;
#else
		return -1;
#endif /* __A5__ || __POWERPC__ */
	}

#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
	{
		OSErr err;
		ByteCount actualCount;
		
		err = FSWriteFork(fildes, fsAtMark, 0, count, (void *) buf, &actualCount);
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
		}
		return (err == noErr ? actualCount : -1);
	}
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	else
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	{
		IOParam			pb;
		OSErr			err;

		pb.ioRefNum = fildes;
		pb.ioBuffer = (char *)buf;
		pb.ioReqCount = count;
		pb.ioPosMode = fsAtMark;
		pb.ioPosOffset = NULL;
		pb.ioVRefNum = 0;

		err = PBWriteSync((ParmBlkPtr) &pb);

		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
		}
		return (err == noErr ? pb.ioActCount : -1);
	}
#endif /* _MSL_USE_OLD_FILE_APIS */
}

/*
 *	int access(const char *path, int mode)
 *	
 *		Check accessibility of a file.
 */
int access(const char *path, int mode) _MSL_CANT_THROW
{
		if (path == NULL || path == "")
		{
			errno = ENOENT;
			return -1;
		}
		
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
	{
		OSErr err;
		FSRef theRef;
		FSCatalogInfo theInfo;
		
		err = __msl_path2fsr(path, &theRef);
		
		if (err == noErr)
			err = FSGetCatalogInfo(&theRef, kFSCatInfoNodeFlags, &theInfo, NULL, NULL, NULL);
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
			return -1;
		}
		
		if ((theInfo.nodeFlags & kFSNodeLockedMask) && (mode & W_OK))
		{
			errno = EACCES;
			return -1;
		}
		
		return 0;
	}
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	else
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	{
		HParamBlockRec fpb;
		Str255 ppath;
		OSErr err = -1;
		
		/* convert the c string into a pascal string */
		if (__ctopstring(path, ppath) != noErr)
		{
			errno = ENAMETOOLONG;
			return -1;
		}
		
		fpb.fileParam.ioNamePtr = ppath;
		fpb.fileParam.ioVRefNum = 0;
		fpb.fileParam.ioFDirIndex = 0;												/*- JWW 020129 -*/
		fpb.fileParam.ioDirID = 0L;
		fpb.fileParam.ioFVersNum = 0;												/*- JWW 020129 -*/
		err = PBHGetFInfoSync((HParmBlkPtr)&fpb);
		
		if (err != noErr)
		{
			errno = EMACOSERR;														/*- mm 010412 -*/
			__MacOSErrNo = err;														/*- mm 010412 -*/
			return -1;
		}
		
		if ((fpb.fileParam.ioFlAttrib & kioFlAttribLockedMask) && (mode & W_OK))
		{
			errno = EACCES;
			return -1;
		}
		
		return 0;
	}
#endif /* _MSL_USE_OLD_FILE_APIS */
}


/* Change record:
 * JH  951210 Modified to interface with new ANSI C library
 * JH  951215 Added code to install RemoveConsole hook
 * JH  951230 Removed uses of OLDROUTINENAMES
 * KH  961202 Tossed __setup_exit calls
 * mm  960910 Corrected lseek in accordance with BR7278
 * bkoz970415 added ron l's code
 * mm  971006 Changed declaration of final_tick from long to unsigned long to match new OSUtils.h
 * mm  971010 Prefix files no longer required, so this must be found here now
 * mm  980423 Corrected lseek when seeking beyond the EOF to extend the file MW 00445
 * vss 990421 Update to 3.2 Universal Headers
 * jd  980923 Initialized pb.ioDirID in unlink for Carbon?
 * cc  991108 added ra Carbon Changes done 990611
 * cc  991109 changed TARGET_CARBON to TARGET_API_MAC_CARBON
 * cc  991115 updated and deleted outdated comments
 * mm  000607 Changed definitions of read and write to accord with POSIX Standard.
 * JWW 000620 Fixed volume reference number placed in the wrong place inside _getcwd
 * JWW 000809 Added _access functon
 * JWW 001031 Use new OS 9 File Manager APIs functions that make calls to the file system
 * mm  010412 Changes to avoid assigning OSErr values to errno
 * JWW 010530 Fixed lseek to return the actual position in a file with the new file APIs
 * JWW 010614 Use __msl_get_system_encoding to determine the script system to use for HFS+
 * JWW 020129 Initialize fields in the param block for PBHGetFInfoSync that used to be overlooked
 * JWW 020515 Use kUnicodeLooseMappingsMask when converting from unicode to text
 */