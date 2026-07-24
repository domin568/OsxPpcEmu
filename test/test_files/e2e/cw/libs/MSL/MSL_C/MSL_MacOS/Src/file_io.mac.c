/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/21 16:36:31 $
 * $Revision: 1.31.2.1 $
 */

/*
 *	Routines
 *	--------
 *		__open_file
 *		__open_temp_file
 *		__read_file
 *		__write_file
 *		__position_file
 *		__flush_file
 *		__close_file
 *		__temp_file_name
 *		__delete_file
 *		__rename_file
 *
 *		__wopen_file
 *		__wtemp_file_name
 *		__wdelete_file
 *		__wrename_file
 */

#include <ansi_parms.h>

#if __MACH__
	#if _MSL_CARBON_FILE_APIS
		#include <Carbon/Carbon.h>
	#else
		#include <fcntl.h>
		#include <unistd.h>
		#include <sys/stat.h>
		
		#define io_result(ioResult) ((ioResult != -1) ? (int) __no_io_error : (int) __io_error)
	#endif
#else
	#include <Aliases.h>
	#include <Errors.h>
	#include <Files.h>
	#include <OSUtils.h>
	#include <Devices.h>
	#include <Gestalt.h>
	#include <Traps.h>
	#include <OSUtils.h>
#endif /* __MACH__ */

#if _MSL_CARBON_FILE_APIS

#include <string.h>
#include <file_io.h>
#include <path2fss.h>
#include <stdlib.h>     /*- mm 981009 -*/
#include <errno.h>		/*- mm 010918 -*/

#define io_result(ioResult) ((ioResult == noErr) ? (int) __no_io_error : (int) __io_error)

#define _MSL_ALLOW_SHARED_WRITING  0  /* Set this value to 1 for file opening with shared writing */	/*- mm 010924 -*/

/* function prototypes (exported) */

_MSL_IMP_EXP_C long __getcreator(long isbinary);
_MSL_IMP_EXP_C long __gettype(long isbinary);
int	__system7present(void);											/*- mm 980424 -*/

/* non-local globals */
_MSL_IMP_EXP_C long _fcreator = 0L, _ftype = 0L;		/* Creator and Type for files created by the open function */


#if _MSL_USE_OLD_AND_NEW_FILE_APIS
_MSL_IMP_EXP_C char __msl_system_has_new_file_apis(void);
char __msl_system_has_new_file_apis(void)
{
	static char hasNewAPIs = false;
	static char gestaltProbed = false;
	
	if (!gestaltProbed)
	{
		OSErr theErr;
		long theResponse;
		
		theErr = Gestalt(gestaltFSAttr, &theResponse);
		
		if ((theErr == noErr) && (theResponse & (1 << gestaltHasHFSPlusAPIs)))
			hasNewAPIs = true;
		
		gestaltProbed = true;
	}
	
	return hasNewAPIs;
}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */

#if _MSL_USE_OLD_FILE_APIS
static void set_file_type(FSSpec * spec, int binary_file)
{
	CInfoPBRec	pb;
	OSErr				ioResult;
	
	pb.hFileInfo.ioNamePtr   = spec->name;
	pb.hFileInfo.ioVRefNum   = spec->vRefNum;
	pb.hFileInfo.ioFDirIndex = 0;
	pb.hFileInfo.ioDirID     = spec->parID;
	
	if (!(ioResult = PBGetCatInfoSync(&pb)))
	{
		pb.hFileInfo.ioFlFndrInfo.fdType    = __gettype(binary_file);     /*- mm 960729 -*/
		pb.hFileInfo.ioFlFndrInfo.fdCreator = __getcreator(binary_file);  /*- mm 960729 -*/
		pb.hFileInfo.ioDirID                = spec->parID;
		
		ioResult = PBSetCatInfoSync(&pb);
	}
}
#endif /* _MSL_USE_OLD_FILE_APIS */

typedef struct _temp_file_info temp_file_info;							/*- mm 981009 -*/


struct  _temp_file_info
{
	short	refnum;
#if _MSL_USE_OLD_FILE_APIS
	FSSpec	spec;
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
	FSRef	theRef;
#endif /* _MSL_USE_NEW_FILE_APIS */
	struct _temp_file_info * next_struct;								/*- mm 981009 -*/
	struct _temp_file_info * prev_struct;								/*- mm 981009 -*/
};

static temp_file_info*	temp_info_anchor = NULL;						/*- mm 981009 -*/

static temp_file_info * find_temp_info(short refnum)
{
	temp_file_info *	p = temp_info_anchor;							/*- mm 981009 -*/
	
	while(p != NULL)													/*- mm 981009 -*/
	{
		if (p->refnum == refnum)
			return(p);
		p = p->next_struct;												/*- mm 981009 -*/
	}
	
	return(0);
}

/*
 *	int __system7present(void)
 *	
 *		Determines if System 7 is present.
 */
#if TARGET_API_MAC_CARBON
int __system7present(void)
{
	return true;
}
#else
int __system7present(void)
{
	static int system7present = -1;		/* we only need to check once */
	
	if (system7present < 0) {
		system7present = 0;
		if (GetToolTrapAddress(_Gestalt) != GetToolTrapAddress(_Unimplemented))
		{
			long response;
			if (Gestalt(gestaltSystemVersion, &response) == noErr)
				system7present = response >= 0x0700;
		}
	}
	
	return(system7present);
}
#endif /* TARGET_API_MAC_CARBON */

/*
 *	long __getcreator(long isbinary)
 *
 *		Returns the creator to use for a file.
 */
long __getcreator(long isbinary)
{
	if (_fcreator)
		return (_fcreator);
	else if (isbinary)
#if __MOTO__
		return ('???\?');
#else
		return ('????');
#endif /* __MOTO__ */
	else
		return ('CWIE');
}

/*
 *	long __gettype(long isbinary)
 *
 *		Returns the type to use for a file.
 */
long __gettype(long isbinary)
{
	if (_ftype)
		return (_ftype);
	else if (isbinary)
		return ('BINA');
	else
		return ('TEXT');
}

int	__open_file(const char * name, __file_modes mode, __file_handle * handle)
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		FSRef	theRef;
		FSRef	theParentRef;
		FSSpec	theSpec;
		OSErr	ioResult;
		SInt16	refNum;
		Boolean targetIsFolder, wasAliased;
		HFSUniStr255 theName;
		FSCatalogInfo theInfo;
		
		ioResult = __msl_path2fsr(name, &theRef);
		
		if (ioResult == fnfErr)
		{
			ioResult = __msl_path2splitfsr(name, &theParentRef, &theName);
			
			if (ioResult == noErr)
				ioResult = fnfErr;
			else
			{
				errno = EMACOSERR;
				__MacOSErrNo = ioResult;
				return __io_error;
			}
		}
		else
		{
			if (ioResult != noErr)
			{
				errno = EMACOSERR;
				__MacOSErrNo = ioResult;
				return __io_error;
			}
			else
			{
				FSGetCatalogInfo(&theRef, kFSCatInfoNone, NULL, &theName, &theSpec, &theParentRef);
				ResolveAliasFile(&theSpec, true, &targetIsFolder, &wasAliased);
				FSpMakeFSRef(&theSpec, &theRef);
			}
		}
		
		if (ioResult && (ioResult != fnfErr || mode.open_mode == __must_exist))
		{															/*- mm 020107 -*/
			errno = EMACOSERR;										/*- mm 020107 -*/
			__MacOSErrNo = ioResult;								/*- mm 020107 -*/
			return(__io_error);
		}															/*- mm 020107 -*/
		
		if (ioResult != noErr)
		{
			((FileInfo *) &(theInfo.finderInfo))->fileType = __gettype(mode.binary_io);
			((FileInfo *) &(theInfo.finderInfo))->fileCreator = __getcreator(mode.binary_io);
			((FileInfo *) &(theInfo.finderInfo))->finderFlags = 0;
			((FileInfo *) &(theInfo.finderInfo))->location.h = 0;
			((FileInfo *) &(theInfo.finderInfo))->location.v = 0;
			((FileInfo *) &(theInfo.finderInfo))->reservedField = 0;
			theInfo.textEncodingHint = __msl_get_system_encoding();
			
			ioResult = FSCreateFileUnicode(&theParentRef, theName.length, theName.unicode,
				kFSCatInfoTextEncoding + kFSCatInfoFinderInfo, &theInfo, &theRef, NULL);
			
			if (ioResult == noErr)
			{
#if (_MSL_ALLOW_SHARED_WRITING == 1)												/*- mm 010926 -*/
				ioResult = FSOpenFork(&theRef, 0, NULL,								/*- mm 010926 -*/
					(mode.io_mode == __read) ? fsRdPerm : fsRdWrShPerm, &refNum);	/*- mm 010926 -*/
#else																				/*- mm 010926 -*/
				ioResult = FSOpenFork(&theRef, 0, NULL,
					(mode.io_mode == __read) ? fsRdPerm : fsRdWrPerm, &refNum);
#endif   /* _MSL_ALLOW_SHARED_WRITING */											/*- mm 010926 -*/
			}
		}
		else
		{
#if (_MSL_ALLOW_SHARED_WRITING == 1)												/*- mm 010926 -*/
			ioResult = FSOpenFork(&theRef, 0, NULL,									/*- mm 010926 -*/
				(mode.io_mode == __read) ? fsRdPerm : fsRdWrShPerm, &refNum);		/*- mm 010926 -*/
#else																				/*- mm 010926 -*/
			ioResult = FSOpenFork(&theRef, 0, NULL,
				(mode.io_mode == __read) ? fsRdPerm : fsRdWrPerm, &refNum);
#endif   /* _MSL_ALLOW_SHARED_WRITING */											/*- mm 010926 -*/
			if ((ioResult == noErr) && mode.open_mode == __create_or_truncate)  
			{
				ioResult = FSSetForkSize(refNum, fsFromStart, 0);
				
				if (ioResult != noErr)
					FSCloseFork(refNum);
			}
		}
		
		if (ioResult != noErr)
		{
			errno = EMACOSERR;														/*- mm 010918 -*/
			__MacOSErrNo = ioResult;												/*- mm 010918 -*/
			return(__io_error);
		}
		*handle = refNum;
		
		return(__no_io_error);
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
		FSSpec			spec;
		OSErr			ioResult;
	HParamBlockRec	pb;
	
	ioResult = __path2fss(name, &spec);
	if (__system7present())												/*- mm 980424 -*/
	{																	/*- mm 980424 -*/
		Boolean targetIsFolder, wasAliased;								/*- mm 980424 -*/
		ResolveAliasFile(&spec, true, &targetIsFolder, &wasAliased);	/*- mm 980424 -*/
	}																	/*- mm 980424 -*/
	
	if (ioResult && (ioResult != fnfErr || mode.open_mode == __must_exist))
	{																	/*- mm 020107 -*/
		errno = EMACOSERR;												/*- mm 020107 -*/
		__MacOSErrNo = ioResult;										/*- mm 020107 -*/
		return(__io_error);
	}																	/*- mm 020107 -*/
	
	pb.ioParam.ioNamePtr    = spec.name;
	pb.ioParam.ioVRefNum    = spec.vRefNum;
#if (_MSL_ALLOW_SHARED_WRITING == 1)
	pb.ioParam.ioPermssn    = (mode.io_mode == __read) ? fsRdPerm : fsRdWrShPerm;
#else
	pb.ioParam.ioPermssn    = (mode.io_mode == __read) ? fsRdPerm : fsRdWrPerm;
#endif
	pb.ioParam.ioMisc       = 0;
	pb.fileParam.ioFVersNum = 0;
	pb.fileParam.ioDirID    = spec.parID;
	
	if (ioResult)
	{
		if (!(ioResult = PBHCreateSync(&pb)))
		{
			set_file_type(&spec, mode.binary_io);
			ioResult = PBHOpenDFSync(&pb);  /*- HH 971025 -*/
		}
	}
	else
	{
		if (!(ioResult = PBHOpenDFSync(&pb)) && mode.open_mode == __create_or_truncate)  
		                                  /*- HH 971025 -*/
		{
			pb.ioParam.ioMisc = 0;
			
			ioResult = PBSetEOFSync((ParmBlkPtr) &pb);
			
			if (ioResult)
				PBCloseSync((ParmBlkPtr) &pb);
		}
	}
	
	if (ioResult)
	{																	/*- mm 020107 -*/
		errno = EMACOSERR;												/*- mm 020107 -*/
		__MacOSErrNo = ioResult;										/*- mm 020107 -*/
		return(__io_error);
	}																	/*- mm 020107 -*/
	
	*handle = pb.ioParam.ioRefNum;
	
	return(__no_io_error);
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

int __open_temp_file(__file_handle * handle)
{
	char					temp_name[L_tmpnam];
	temp_file_info *		info;
	FSSpec					spec;
	int						ioResult;
	
	__temp_file_name(temp_name, &spec);
	
	if (!(info = find_temp_info(0)))
	{
		if (!(info = malloc(sizeof(temp_file_info))))						/*- mm 981009 -*/
			return(__io_error);												/*- mm 981009 -*/
		memset((void *)info, 0, sizeof(temp_file_info));					/*- mm 981009 -*/
		info->next_struct = temp_info_anchor;								/*- mm 981009 -*/
		if (temp_info_anchor != NULL) 										/*- mm 000105 -*/
			temp_info_anchor->prev_struct = info;							/*- mm 000105 -*/
		temp_info_anchor  = info;											/*- mm 981009 -*/
		info->prev_struct = NULL;											/*- mm 981009 -*/
	}		
	
	ioResult = __open_file(temp_name, __temp_file_mode, handle);
	
	if (ioResult == __no_io_error)
	{
		info->refnum = *handle;
		
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
		if (__msl_system_has_new_file_apis())
		{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
			FSpMakeFSRef(&spec, &(info->theRef));
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
		}
		else
		{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
		info->spec   = spec;
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
		}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
	}
	
	return(ioResult);
}

int __read_file(__file_handle handle, unsigned char * buffer, size_t * count, __ref_con ref_con)
{
	__idle_proc idle_proc = (__idle_proc) ref_con;
	
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		FSForkIOParam pb;
		
		pb.ioCompletion = 0;
		pb.forkRefNum   = handle;
		pb.buffer       = (Ptr) buffer;
		pb.requestCount = *count;
		pb.positionMode = fsAtMark;
		pb.positionOffset = 0;
		
		if (idle_proc)
		{
			PBReadForkAsync(&pb);
			
			while (pb.ioResult > 0)
				(*idle_proc)();
		}
		else
			PBReadForkSync(&pb);
		
		*count = pb.actualCount;
		
		if (pb.ioResult == eofErr)
			if (*count != 0)
				return(__no_io_error);
			else
				return(__io_EOF);
		
		return(io_result(pb.ioResult));
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	IOParam	pb;
	
	pb.ioCompletion = 0;
	pb.ioRefNum     = handle;
	pb.ioBuffer     = (Ptr) buffer;
	pb.ioReqCount   = *count;
	pb.ioPosMode    = fsAtMark;
	
	if (idle_proc)
	{
		PBReadAsync((ParmBlkPtr) &pb);
		
		while (pb.ioResult > 0)
			(*idle_proc)();
	}
	else
		PBReadSync((ParmBlkPtr) &pb);
	
	*count = pb.ioActCount;
	
	if (pb.ioResult == eofErr)
		if (*count != 0)
			return(__no_io_error);
		else
			return(__io_EOF);     /*- mm 961031 -*/
	
	return(io_result(pb.ioResult));
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

int __write_file(__file_handle handle, unsigned char * buffer, size_t * count, __ref_con ref_con)
{
	__idle_proc idle_proc = (__idle_proc) ref_con;
	
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		FSForkIOParam pb;
		
		pb.ioCompletion = 0;
		pb.forkRefNum   = handle;
		pb.buffer       = (Ptr) buffer;
		pb.requestCount = *count;
		pb.positionMode = fsAtMark;
		pb.positionOffset = 0;
		
		if (idle_proc)
		{
			PBWriteForkAsync(&pb);
			
			while (pb.ioResult > 0)
				(*idle_proc)();
		}
		else
			PBWriteForkSync(&pb);
		
		*count = pb.actualCount;
		
		return(io_result(pb.ioResult));
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	IOParam	pb;
	
	pb.ioCompletion = 0;
	pb.ioRefNum     = handle;
	pb.ioBuffer     = (Ptr) buffer;
	pb.ioReqCount   = *count;
	pb.ioPosMode    = fsAtMark;
	
	if (idle_proc)
	{
		PBWriteAsync((ParmBlkPtr) &pb);
		
		while (pb.ioResult > 0)
			(*idle_proc)();
	}
	else
		PBWriteSync((ParmBlkPtr) &pb);
	
	*count = pb.ioActCount;
	
	return(io_result(pb.ioResult));
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

/* Begin replacement mm 980612 */
int __position_file(__file_handle handle, unsigned long * position, int mode, __ref_con ref_con)
{
	__idle_proc idle_proc = (__idle_proc) ref_con;
	
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		FSForkIOParam	pb;
		SInt64			eof, absPos;
		
		pb.ioCompletion = 0;
		pb.forkRefNum   = handle;
		
		if (idle_proc)
		{
			PBGetForkSizeAsync(&pb);
			
			while (pb.ioResult > 0)
				(*idle_proc)();
		}
		else
			PBGetForkSizeSync(&pb);
		
		if (pb.ioResult != noErr)
			return(__io_error);
		
		eof = pb.positionOffset;
		
		switch (mode)
		{
			case SEEK_END:
				absPos = eof + *((signed long *) position);
				break;
				
			case SEEK_SET:
				absPos = *((signed long *) position);
				break;
				
			default:
				return(__io_error);
		}

		if (absPos < 0)
			return(__io_error);
		
		if (absPos > eof)
		{
			pb.positionMode   = fsFromStart;
	  		pb.positionOffset = absPos;
	  	
			if (idle_proc)
			{
				PBSetForkSizeAsync(&pb);
				
				while (pb.ioResult > 0)
					(*idle_proc)();
			}
			else
				PBSetForkSizeSync(&pb);
		}
		
		if (pb.ioResult != noErr)
			return(__io_error);
		
		pb.positionMode   = fsFromStart;
		pb.positionOffset = absPos;
		
		if (idle_proc)
		{
			PBSetForkPositionAsync(&pb);
			
			while (pb.ioResult > 0)
				(*idle_proc)();
		}
		else
			PBSetForkPositionSync(&pb);

		*position = absPos;
		
		return(io_result(pb.ioResult));
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
		IOParam	pb;
		long	eof, absPos;
	
	pb.ioCompletion = 0;
	pb.ioRefNum     = handle;
	
	if (idle_proc)
	{
		PBGetEOFAsync((ParmBlkPtr) &pb);
		
		while (pb.ioResult > 0)
			(*idle_proc)();
	}
	else
		PBGetEOFSync((ParmBlkPtr) &pb);
	
	if (pb.ioResult != noErr)
		return(__io_error);
	
	eof = (long) pb.ioMisc;
	
	switch (mode)
	{
		case SEEK_END:
			absPos = eof + *position;
			break;
			
		case SEEK_SET:
			absPos = *position;
			break;
			
		default:
			return(__io_error);
	}

	if (absPos < 0)
		return(__io_error);
	
	if (absPos > eof)
	{
  	pb.ioMisc = (Ptr) absPos;
  	
		if (idle_proc)
		{
			PBSetEOFAsync((ParmBlkPtr) &pb);
			
			while (pb.ioResult > 0)
				(*idle_proc)();
		}
		else
			PBSetEOFSync((ParmBlkPtr) &pb);
	}
	
	if (pb.ioResult != noErr)
		return(__io_error);
	
	pb.ioPosMode   = fsFromStart;
	pb.ioPosOffset = absPos;
	
	if (idle_proc)
	{
		PBSetFPosAsync((ParmBlkPtr) &pb);
		
		while (pb.ioResult > 0)
			(*idle_proc)();
	}
	else
		PBSetFPosSync((ParmBlkPtr) &pb);

	*position = absPos;
	
	return(io_result(pb.ioResult));
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}
/* End replacement mm 980612 */

int __close_file(__file_handle handle)
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		temp_file_info *	info;
		temp_file_info *	p;
		OSErr				ioResult;
		
		info = find_temp_info(handle);
		
		ioResult = FSCloseFork(handle);
		
		if ((ioResult == noErr) && (info != NULL))
			ioResult = FSDeleteObject(&(info->theRef));
		
		if (info != NULL)
		{
			if (temp_info_anchor == info)
			{
				temp_info_anchor = info->next_struct;
				if (temp_info_anchor != NULL)
					temp_info_anchor->prev_struct = NULL;
			}
			else
			{
				if ((p = info->next_struct) != NULL)
					p->prev_struct = info->prev_struct;
  				if (info->prev_struct != NULL)
					(info->prev_struct)->next_struct = info->next_struct;
			}
			free(info);
		}
		
		return(io_result(ioResult));
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	temp_file_info *	info;
	temp_file_info *	p;
	HParamBlockRec		pb;
		OSErr				ioResult;
	
	info = find_temp_info(handle);
	
	pb.ioParam.ioRefNum = handle;
	
	if (!(ioResult = PBCloseSync((ParmBlkPtr) &pb)) && info)
	{
		pb.ioParam.ioNamePtr = info->spec.name;
		pb.ioParam.ioVRefNum = info->spec.vRefNum;
		pb.fileParam.ioDirID = info->spec.parID;
		
		ioResult = PBHDeleteSync(&pb);
	}
	
	if (info)
	{
			if (temp_info_anchor == info)									/*- mm 981009 -*/
			{																/*- mm 981009 -*/
				temp_info_anchor = info->next_struct;						/*- mm 981009 -*/
				if (temp_info_anchor != NULL) 								/*- mm 000105 -*/
					temp_info_anchor->prev_struct = NULL;					/*- mm 981009 -*/
			}																/*- mm 981009 -*/
			else															/*- mm 981009 -*/
			{																/*- mm 981009 -*/
				if ((p = info->next_struct) != NULL)						/*- mm 981009 -*/
					p->prev_struct = info->prev_struct;						/*- mm 981009 -*/
  				if (info->prev_struct != NULL)  							/*- mm 010202 -*/
			(info->prev_struct)->next_struct = info->next_struct;			/*- mm 981009 -*/
			}																/*- mm 981009 -*/
			free(info);  													/*- mm 981009 -*/
		}
		
		return(io_result(ioResult));
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

void __temp_file_name(char * name_str, void * fsspec)
{
	static unsigned long	counter     = 0x00000000;
	char					temp_name[] = "temp00000000";
	unsigned long			count;
	char *					name_ptr;
	int						i, n;
	OSErr					ioResult;
	FSSpec					spec;
	
	do 
	{
		count = counter++;
		
		name_ptr = &temp_name[strlen(temp_name)];
	
		for (i = 8; i--;)
		{
			n = count & 0x0F;
			
			count >>= 4;
			
			if (n < 10)
				n += '0';
			else
				n += 'A' - 10;
				
			*--name_ptr = n;
		}
		
	} while (!(ioResult = __path2fss(temp_name, &spec)));
	
	strcpy(name_str, temp_name);
	
	if (fsspec)
		* (FSSpec *) fsspec = spec;
}

int __delete_file(const char * name)
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		FSRef			theRef;
		OSErr			ioResult;
		
		ioResult = __msl_path2fsr(name, &theRef);
		
		if (ioResult != noErr)
			return(__io_error);
		
		ioResult = FSDeleteObject(&theRef);
		
		return(io_result(ioResult));
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
		FSSpec			spec;
		OSErr			ioResult;
		HParamBlockRec	pb;
		
		ioResult = __path2fss(name, &spec);
		
		if (ioResult)
			return(__io_error);
		
		pb.ioParam.ioNamePtr    = spec.name;
		pb.ioParam.ioVRefNum    = spec.vRefNum;
		pb.fileParam.ioFVersNum = 0;
		pb.fileParam.ioDirID    = spec.parID;
		
		ioResult = PBHDeleteSync(&pb);
		
		return(io_result(ioResult));
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

int __rename_file(const char * old_name, const char * new_name)
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		FSRef			old_ref, old_parent, new_parent;
		HFSUniStr255	theName;
		OSErr			ioResult;
		
		ioResult = __msl_path2fsr(old_name, &old_ref);
		
		if ((ioResult != noErr) && (ioResult != notAFileErr))
			return(__io_error);
		
		ioResult = FSGetCatalogInfo(&old_ref, kFSCatInfoNone, NULL, NULL, NULL, &old_parent);
		
		if (ioResult != noErr)
			return(__io_error);
		
		ioResult = __msl_path2splitfsr(new_name, &new_parent, &theName);
		
		if ((ioResult != noErr) && (ioResult != fnfErr))
			return(__io_error);
		
		ioResult = FSCompareFSRefs(&old_parent, &new_parent);
		
		if (ioResult != noErr)
			return(__io_error);
		
		ioResult = FSRenameUnicode(&old_ref, theName.length, theName.unicode,
			__msl_get_system_encoding(), NULL);
		
		return(io_result(ioResult));
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
		FSSpec			old_spec, new_spec;
		OSErr			ioResult;
	HParamBlockRec	pb;
	
	if (((ioResult = __path2fss(old_name, &old_spec)) != 0) && (ioResult != notAFileErr)) /*- mm 980416 -*/
		return(__io_error);
	
	if ((ioResult = __path2fss(new_name, &new_spec)) != 0 && ioResult != fnfErr)
		return(__io_error);
	
	if (old_spec.vRefNum != new_spec.vRefNum || old_spec.parID != new_spec.parID)
		return(__io_error);
	
	if (!ioResult)
		return(__io_error);
	
	pb.ioParam.ioNamePtr    = old_spec.name;
	pb.ioParam.ioVRefNum    = old_spec.vRefNum;
	pb.fileParam.ioFVersNum = 0;
	pb.ioParam.ioMisc       = (Ptr) new_spec.name;
	pb.fileParam.ioDirID    = old_spec.parID;
	
	return(io_result(PBHRenameSync(&pb)));      
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

#pragma mark -

#if _MSL_USE_NEW_FILE_APIS && _MSL_WFILEIO_AVAILABLE

#include <wstring.h>

int	__wopen_file(const wchar_t * name, __file_modes mode, __file_handle * handle)
{
	FSRef	theRef;
	FSRef	theParentRef;
	FSSpec	theSpec;
	OSErr	ioResult;
	SInt16	refNum;
	Boolean targetIsFolder, wasAliased;
	HFSUniStr255 theName;
	FSCatalogInfo theInfo;
	
	ioResult = __msl_wpath2fsr(name, &theRef);
	
	if (ioResult == fnfErr)
	{
		ioResult = __msl_wpath2splitfsr(name, &theParentRef, &theName);
		
		if (ioResult == noErr)
			ioResult = fnfErr;
		else
		{
			errno = EMACOSERR;
			__MacOSErrNo = ioResult;
			return __io_error;
		}
	}
	else
	{
		if (ioResult != noErr)
		{
			errno = EMACOSERR;
			__MacOSErrNo = ioResult;
			return __io_error;
		}
		else
		{
			FSGetCatalogInfo(&theRef, kFSCatInfoNone, NULL, &theName, &theSpec, &theParentRef);
			ResolveAliasFile(&theSpec, true, &targetIsFolder, &wasAliased);
			FSpMakeFSRef(&theSpec, &theRef);
		}
	}
	
	if (ioResult && (ioResult != fnfErr || mode.open_mode == __must_exist))
	{															/*- mm 020107 -*/
		errno = EMACOSERR;										/*- mm 020107 -*/
		__MacOSErrNo = ioResult;								/*- mm 020107 -*/
		return(__io_error);
	}															/*- mm 020107 -*/
	
	if (ioResult != noErr)
	{
		((FileInfo *) &(theInfo.finderInfo))->fileType = __gettype(mode.binary_io);
		((FileInfo *) &(theInfo.finderInfo))->fileCreator = __getcreator(mode.binary_io);
		((FileInfo *) &(theInfo.finderInfo))->finderFlags = 0;
		((FileInfo *) &(theInfo.finderInfo))->location.h = 0;
		((FileInfo *) &(theInfo.finderInfo))->location.v = 0;
		((FileInfo *) &(theInfo.finderInfo))->reservedField = 0;
		theInfo.textEncodingHint = __msl_get_system_encoding();
		
		ioResult = FSCreateFileUnicode(&theParentRef, theName.length, theName.unicode,
			kFSCatInfoTextEncoding + kFSCatInfoFinderInfo, &theInfo, &theRef, NULL);
		
		if (ioResult == noErr)
		{
#if (_MSL_ALLOW_SHARED_WRITING == 1)												/*- mm 010926 -*/
			ioResult = FSOpenFork(&theRef, 0, NULL,								/*- mm 010926 -*/
				(mode.io_mode == __read) ? fsRdPerm : fsRdWrShPerm, &refNum);	/*- mm 010926 -*/
#else																				/*- mm 010926 -*/
			ioResult = FSOpenFork(&theRef, 0, NULL,
				(mode.io_mode == __read) ? fsRdPerm : fsRdWrPerm, &refNum);
#endif   /* _MSL_ALLOW_SHARED_WRITING */											/*- mm 010926 -*/
		}
	}
	else
	{
#if (_MSL_ALLOW_SHARED_WRITING == 1)												/*- mm 010926 -*/
		ioResult = FSOpenFork(&theRef, 0, NULL,									/*- mm 010926 -*/
			(mode.io_mode == __read) ? fsRdPerm : fsRdWrShPerm, &refNum);		/*- mm 010926 -*/
#else																				/*- mm 010926 -*/
		ioResult = FSOpenFork(&theRef, 0, NULL,
			(mode.io_mode == __read) ? fsRdPerm : fsRdWrPerm, &refNum);
#endif   /* _MSL_ALLOW_SHARED_WRITING */											/*- mm 010926 -*/
		if ((ioResult == noErr) && mode.open_mode == __create_or_truncate)  
		{
			ioResult = FSSetForkSize(refNum, fsFromStart, 0);
			
			if (ioResult != noErr)
				FSCloseFork(refNum);
		}
	}
	
	if (ioResult != noErr)
	{
		errno = EMACOSERR;														/*- mm 010918 -*/
		__MacOSErrNo = ioResult;												/*- mm 010918 -*/
		return(__io_error);
	}
	*handle = refNum;
	
	return(__no_io_error);
}

void __wtemp_file_name(wchar_t * name_str, void * fsspec)
{
	static unsigned long	counter     = 0x00000000;
	wchar_t					temp_name[] = L"temp00000000";
	unsigned long			count;
	wchar_t *				name_ptr;
	int						i, n;
	OSErr					ioResult;
	FSSpec					spec;
	
	do 
	{
		count = counter++;
		
		name_ptr = &temp_name[wcslen(temp_name)];
	
		for (i = 8; i--;)
		{
			n = count & 0x0F;
			
			count >>= 4;
			
			if (n < 10)
				n += L'0';
			else
				n += L'A' - 10;
				
			*--name_ptr = n;
		}
		
	} while (!(ioResult = __wpath2fss(temp_name, &spec)));
	
	wcscpy(name_str, temp_name);
	
	if (fsspec)
		* (FSSpec *) fsspec = spec;
}

int __wdelete_file(const wchar_t * name)
{
	FSRef			theRef;
	OSErr			ioResult;
	
	ioResult = __msl_wpath2fsr(name, &theRef);
	
	if (ioResult != noErr)
		return(__io_error);
	
	ioResult = FSDeleteObject(&theRef);
	
	return(io_result(ioResult));
}

int __wrename_file(const wchar_t * old_name, const wchar_t * new_name)
{
	FSRef			old_ref, old_parent, new_parent;
	HFSUniStr255	theName;
	OSErr			ioResult;
	
	ioResult = __msl_wpath2fsr(old_name, &old_ref);
	
	if ((ioResult != noErr) && (ioResult != notAFileErr))
		return(__io_error);
	
	ioResult = FSGetCatalogInfo(&old_ref, kFSCatInfoNone, NULL, NULL, NULL, &old_parent);
	
	if (ioResult != noErr)
		return(__io_error);
	
	ioResult = __msl_wpath2splitfsr(new_name, &new_parent, &theName);
	
	if ((ioResult != noErr) && (ioResult != fnfErr))
		return(__io_error);
	
	ioResult = FSCompareFSRefs(&old_parent, &new_parent);
	
	if (ioResult != noErr)
		return(__io_error);
	
	ioResult = FSRenameUnicode(&old_ref, theName.length, theName.unicode,
		__msl_get_system_encoding(), NULL);
	
	return(io_result(ioResult));
}

#endif /* _MSL_USE_NEW_FILE_APIS && _MSL_WFILEIO_AVAILABLE */

#else

#pragma mark -

#include <string.h>
#include <file_io.h>
#include <stdlib.h>     /*- mm 981009 -*/
#include <errno.h>		/*- mm 010918 -*/

#define _MSL_READWRITEMASK 3

typedef struct _temp_file_info temp_file_info;

struct  _temp_file_info
{
	short	refnum;
	char	*thePathname;
	struct _temp_file_info * next_struct;
	struct _temp_file_info * prev_struct;
};

static temp_file_info *temp_info_anchor = NULL;

static temp_file_info *find_temp_info(short refnum)
{
	temp_file_info *p = temp_info_anchor;
	
	while (p != NULL)
	{
		if (p->refnum == refnum)
			return(p);
		
		p = p->next_struct;
	}
	
	return NULL;
}

int	__open_file(const char * name, __file_modes mode, __file_handle * handle)
{
	int ioResult;
	int openmode;
	
	openmode = 0;
	
	if ((mode.io_mode & _MSL_READWRITEMASK) == __read) (void) (openmode |= O_RDONLY);
	if ((mode.io_mode & _MSL_READWRITEMASK) == __write) openmode |= O_WRONLY;
	if ((mode.io_mode & _MSL_READWRITEMASK) == __read_write) openmode |= O_RDWR;
	if (mode.io_mode & __append) openmode |= O_APPEND;
	
	if (mode.open_mode == __create_if_necessary) openmode |= O_CREAT;
	if (mode.open_mode == __create_or_truncate) openmode |= (O_CREAT | O_TRUNC);
	
	ioResult = open(name, openmode, DEFFILEMODE);
	
	*handle = ioResult;
	
	return io_result(ioResult);
}

int __open_temp_file(__file_handle * handle)
{
	char					temp_name[L_tmpnam];
	temp_file_info *		info;
	int						ioResult;
	
	__temp_file_name(temp_name, NULL);
	
	if (!(info = find_temp_info(0)))
	{
		if (!(info = malloc(sizeof(temp_file_info))))						/*- mm 981009 -*/
			return(__io_error);												/*- mm 981009 -*/
		memset((void *)info, 0, sizeof(temp_file_info));					/*- mm 981009 -*/
		info->next_struct = temp_info_anchor;								/*- mm 981009 -*/
		if (temp_info_anchor != NULL) 										/*- mm 000105 -*/
			temp_info_anchor->prev_struct = info;							/*- mm 000105 -*/
		temp_info_anchor  = info;											/*- mm 981009 -*/
		info->prev_struct = NULL;											/*- mm 981009 -*/
	}		
	
	ioResult = __open_file(temp_name, __temp_file_mode, handle);
	
	if (ioResult == __no_io_error)
	{
		info->refnum = *handle;
		info->thePathname = malloc(strlen(temp_name) + 1);
		if (info->thePathname != NULL)
			strcpy(info->thePathname, temp_name);
	}
	
	return ioResult;
}

int __read_file(__file_handle handle, unsigned char * buffer, size_t * count, __ref_con)
{
	int actual;
	int result;
	
	actual = read(handle, buffer, *count);
	
	*count = actual;
	
	if (actual > 0)
		result = __no_io_error;
	else if (actual == 0)
		result = __io_EOF;
	else
		result = __io_error;
	
	return result;
}

int __write_file(__file_handle handle, unsigned char * buffer, size_t * count, __ref_con)
{
	int actual;
	int result;
	
	actual = write(handle, buffer, *count);
	
	if (actual >= *count)
		result = __no_io_error;
	else
		result = __io_error;
	
	*count = actual;
	
	return result;
}

int __position_file(__file_handle handle, unsigned long * position, int mode, __ref_con)
{
	off_t offset;
	off_t actual;
	
	offset = *((signed long *) position);
	
	/* JWW - Check for error conditions here because the BSD C library doesn't.  Evil BSD C. */
	if (offset < 0)
	{
 		if (mode == SEEK_SET)
 			actual = 0;
 		else
 		{
 			actual = lseek(handle, 0, mode);
 			
 			if (actual == ((off_t) -1)) return __io_error;
 		}
 		
 		if (actual + offset < 0) return __io_error;
	}
	
	actual = lseek(handle, offset, mode);
	
	*position = actual;
	
	return (actual != ((off_t) -1)) ? (int) __no_io_error : (int) __io_error;
}

int __close_file(__file_handle handle)
{
	temp_file_info *	info;
	temp_file_info *	p;
	int					ioResult;
	
	info = find_temp_info(handle);
	
	ioResult = close(handle);
	
	if ((ioResult == 0) && (info != NULL) && (info->thePathname != NULL))
		ioResult = unlink(info->thePathname);
	
	if (info != NULL)
	{
		if (temp_info_anchor == info)
		{
			temp_info_anchor = info->next_struct;
			if (temp_info_anchor != NULL)
				temp_info_anchor->prev_struct = NULL;
		}
		else
		{
			if ((p = info->next_struct) != NULL)
				p->prev_struct = info->prev_struct;
			if (info->prev_struct != NULL)
				(info->prev_struct)->next_struct = info->next_struct;
		}
		
		if (info->thePathname != NULL)
			free(info->thePathname);
		
		free(info);
	}
	
	return io_result(ioResult);
}

void __temp_file_name(char *name_str, void *)
{
	static unsigned long	counter     = 0x00000000;
	char					temp_name[] = "temp00000000";
	unsigned long			count;
	char *					name_ptr;
	int						i, n;
	int						ioResult;
	
	do 
	{
		count = counter++;
		
		name_ptr = &temp_name[strlen(temp_name)];
	
		for (i = 8; i--;)
		{
			n = count & 0x0F;
			
			count >>= 4;
			
			if (n < 10)
				n += '0';
			else
				n += 'A' - 10;
				
			*--name_ptr = n;
		}
		
	} while ((ioResult = open(temp_name, O_RDWR | O_CREAT | O_EXCL)) == -1);
	
	if (ioResult != -1)
	{
		close(ioResult);
		unlink(temp_name);
	}
	
	strcpy(name_str, temp_name);
}

int __delete_file(const char * name)
{
	int ioResult;
	
	ioResult = unlink(name);
	
	return io_result(ioResult);
}

/* JWW - The BSD rename() function is used when compiling for Mach-O and not using Carbon APIs */
/*int __rename_file(const char * old_name, const char * new_name)
{
}*/

#pragma mark -

#if _MSL_WFILEIO_AVAILABLE

#include <mbstring.h>
#include <wstring.h>

#define MAXPATH 1024

static char *__msl_wcs_to_utf_8(const wchar_t * name)
{
	int i;
	int size;
	int total_size;
	char *converted;
	static char utf_8[MAXPATH];
	
	total_size = 0;
	converted = utf_8;
	for (i = 0; (i < wcslen(name)) && (total_size < MAXPATH); i++)
	{
		if (total_size < MAXPATH - 3)
		{
			size = __unicode_to_UTF8(converted, name[i]);
			converted += size;
			total_size += size;
		}
	}
	*converted = 0;
	
	return utf_8;
}

int	__wopen_file(const wchar_t * name, __file_modes mode, __file_handle * handle)
{
	return __open_file(__msl_wcs_to_utf_8(name), mode, handle);
}

void __wtemp_file_name(wchar_t *name_str, void *)
{
	char name[MAXPATH];
	char *char_name;
	
	char_name = name;
	__temp_file_name(char_name, NULL);
	
	do
	{
		*name_str = *char_name;
		name_str++;
		char_name++;
		
	} while (*char_name != 0);
}

int __wdelete_file(const wchar_t * name)
{
	return __delete_file(__msl_wcs_to_utf_8(name));
}

int __wrename_file(const wchar_t * old_name, const wchar_t * new_name)
{
	char old_name_utf_8[MAXPATH];
	
	strcpy(old_name_utf_8, __msl_wcs_to_utf_8(old_name));
	
	return rename(old_name_utf_8, __msl_wcs_to_utf_8(new_name));
}

#endif /* _MSL_WFILEIO_AVAILABLE */

#endif /* _MSL_CARBON_FILE_APIS */

/* Change record:
 * JFH 950814 First code release.
 * JFH 951213 Changed synch read, write, and seek calls to asynch calls followed by a
 *			  completion loop that repeatedly calls the file's idle_proc. Although you
 *			  can theoretically do anything in the idle_proc, the safest (and intended)
 *			  course is to call YieldToAnyThread().
 * JFH 960102 Oops! Didn't get that last one quite right. Now if idle_proc is NULL, call
 *			  will be made synchronously. Before, if idle_proc was NULL I was skipping the
 *			  call to idle_proc AND the wait loop. Instead of just fixing, I will make the
 *			  call synchronously to let various system hacks run (like AppleShare).
 * mm  960729 Made it possible for users to set creator and file_type
 * mm  960911 Corrected action of fseek to go beyond end of file.  See BR7278
 * mm  961031 Changes for Pascal
 * HH  971025 You can use the PBHOpen function to open the data fork of a file.  Because PBHOpen
 *            will also open devices, it's safter to use the PBHOppenDF function instead.  PBHOpenDF
 *            is exactly like the PBHOpen function except that PBHOpenDF allows you to open a file
 *            whose name begins with a period (.).
 * mm  980416 Allow the renaming of directories---requires the complementary change made to __path2fss
 *			  to note that a directory has been found.  MW00456
 * mm  980424 Make fopen resolve aliases if possible.  MW00294
 * mm  980612 Rewrite of __position_file.c to avoid a bug in OS 8's AppleShare client: fix from Jon Hueras
 * mm  981009 Change of temp_file_info structure to allow an indefinite number of files.
 * mm  000105 Correct backward chain of tem file info's.  IR9908-4158 Thanks to Dieter Kohl
 * JWW 001030 Added OS 9 API file manager calls to support >32 character names & >2GB files
 * mm  010202 Added further test for null pointers as in mm 000105
 * JWW 010614 Use __msl_get_system_encoding to determine the script system to use for HFS+
 * JWW 010730 Export __msl_system_has_new_file_apis(), __getcreator(), and __gettype()
 * mm  010918 Add setting of errno and __MacOSErrNo on open failure
 * mm  010924 Add wrapper to file to be opened for shared writing
 * JWW 011027 Added case for Mach-O targeting the System.framework instead of Carbon.framework
 * JWW 011115 Use _MSL_ALLOW_SHARED_WRITING in old file APIs as well as new HFS+ ones
 * mm  020107 Added some missing settings of __MacOSErrNo, thanks to WB1-29743, Dave Swifford
 * JWW 020208 Return an error from __open_file when converting a pathname to a FSRef has an error
 * JWW 020520 Export _fcreator and _ftype from shared libraries with _MSL_IMP_EXP_C
 * JWW 020906 Use generic reference constant instead of specific idle_proc in file I/O
 * JWW 021010 Added wchar_t file I/O routines controlled by _MSL_WFILEIO_AVAILABLE
 */