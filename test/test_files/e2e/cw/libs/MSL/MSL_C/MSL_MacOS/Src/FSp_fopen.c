/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/08/20 20:44:27 $
 * $Revision: 1.22.2.1 $
 */

/*
 *	Routines
 *	--------
 *		FSp_fopen
 *		FSRef_fopen
 *		FSRefParentAndFilename_fopen
 *
 *	Description
 *	-----------
 *
 *		FSp_fopen:
 *		This function is essentially a variant of fopen that takes a FSSpec instead of a
 *		pathname.  It takes a FSSpec and opens the file with FSpOpenDF.  It then uses
 *		__handle_open to attach the file to an ANSI file stream.
 *
 *		FSRef_fopen:
 *		This function is essentially a variant of fopen that takes a FSRef instead of a
 *		pathname.  It takes a FSRef and opens the file with FSOpenFork.  It then uses
 *		__handle_open to attach the file to an ANSI file stream.
 *
 *		FSRefParentAndFilename_fopen:
 *		This function is essentially a variant of fopen that takes a FSRef and unicode
 *		filename instead of a pathname.  It takes a FSRef and filename and opens the file
 *		with FSOpenFork.  It then uses __handle_open to attach the file to an ANSI file stream.
 *
 */

#if __MACH__
	#include <CarbonCore/CarbonCore.h>
	#include <cstdio>
#else
	#include <Errors.h>
	#include <Files.h>
	#include <Script.h>
#endif

#include <file_io.h>
#include <FSp_fopen.h>

#if _MSL_CARBON_FILE_APIS

#include <path2fss.h>

#if defined(__cplusplus) && defined(_MSL_USING_NAMESPACE)
	using namespace std;
#endif

/* function prototypes for externally defined functions */
_MSL_BEGIN_EXTERN_C	/*- cc 010410 -*/
	extern long __getcreator(long isbinary);
	extern long __gettype(long isbinary);
	extern char __msl_system_has_new_file_apis(void);
_MSL_END_EXTERN_C	/*- cc 010410 -*/

FILE * FSp_fopen(ConstFSSpecPtr spec, const char * open_mode)
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
	OSErr theErr;
	FSRef theRef;
	FSRef theParentRef;
	FSSpec theSpec;
	HFSUniStr255 theName;
	FSCatalogInfo theInfo;
	__std(__file_modes) mode;
	FILE *theFile;
	
	theFile = NULL;
	
	theErr = FSpMakeFSRef(spec, &theRef);
	
	if (theErr == noErr)
		theFile = FSRef_fopen(&theRef, open_mode);
	else
	{
		if (!__get_file_modes(open_mode, &mode))
			return NULL;
		
		if ((theErr != fnfErr) || (mode.open_mode == __std(__must_exist)))
			return NULL;
		
		/* Find the parent folder of the new file to open */
		theErr = FSMakeFSSpec(spec->vRefNum, spec->parID, "\p", &theSpec);
		
		if (theErr == noErr)
			theErr = FSpMakeFSRef(&theSpec, &theParentRef);
		
		if (theErr == noErr)
		{
			((FileInfo *) &(theInfo.finderInfo))->fileType = (OSType) __gettype(mode.binary_io);
			((FileInfo *) &(theInfo.finderInfo))->fileCreator = (OSType) __getcreator(mode.binary_io);
			((FileInfo *) &(theInfo.finderInfo))->finderFlags = 0;
			((FileInfo *) &(theInfo.finderInfo))->location.h = 0;
			((FileInfo *) &(theInfo.finderInfo))->location.v = 0;
			((FileInfo *) &(theInfo.finderInfo))->reservedField = 0;
			theInfo.textEncodingHint = __msl_get_system_encoding();
			
			__msl_text2unicode(spec->name[0], (char *) &(spec->name[1]), &theName);
			
			theErr = FSCreateFileUnicode(&theParentRef, theName.length, theName.unicode,
				kFSCatInfoTextEncoding + kFSCatInfoFinderInfo, &theInfo, &theRef, NULL);
			
			if (theErr == noErr)
				theFile = FSRef_fopen(&theRef, open_mode);
		}
	}
	
	return theFile;
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	__std(__file_modes)	mode;
	SInt8				permission;
	OSErr				ioResult;
	short				refNum;
	OSType				file_type;
	OSType				creator;			/*- mm 990222 -*/
	FILE *				file;
	
	if (!__get_file_modes(open_mode, &mode))
		return(NULL);
	
	permission = (mode.io_mode == __std(__read)) ? fsRdPerm : fsRdWrPerm;
	
	ioResult = FSpOpenDF(spec, permission, &refNum);
	
	if (ioResult)
	{
		if (ioResult != fnfErr || mode.open_mode == __std(__must_exist))
			return(NULL);
		
		file_type = (OSType) __gettype(mode.binary_io);			/*- mm 990222 -*/
		creator   = (OSType) __getcreator(mode.binary_io);		/*- mm 990222 -*/
		
		if (!(ioResult = FSpCreate(spec, creator, file_type, smSystemScript)))
			ioResult = FSpOpenDF(spec, permission, &refNum);
		
		if (ioResult)
			return(NULL);
	}
	else if (mode.open_mode == __std(__create_or_truncate))
	{
		ioResult = SetEOF(refNum, 0);
		
		if (ioResult)
		{
			FSClose(refNum);
			return(NULL);
		}
	}
	
	file = __handle_open(refNum, open_mode);
	
	if (!file)
		FSClose(refNum);
	
	return(file);
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

#if _MSL_USE_NEW_FILE_APIS

FILE * FSRef_fopen(const FSRef *theRef, const char *open_mode)
{
	__std(__file_modes)	mode;
	SInt8				permission;
	OSErr				ioResult;
	short				refNum;
	FILE *				file;
	
	if (!__get_file_modes(open_mode, &mode))
		return(NULL);
	
	permission = (mode.io_mode == __std(__read)) ? fsRdPerm : fsRdWrPerm;
	
	ioResult = FSOpenFork(theRef, 0, NULL, permission, &refNum);
	
	if (ioResult != noErr)
	{
		return(NULL);
	}
	else if (mode.open_mode == __std(__create_or_truncate))
	{
		ioResult = FSSetForkSize(refNum, fsFromStart, 0);
		
		if (ioResult != noErr)
		{
			FSCloseFork(refNum);
			return(NULL);
		}
	}
	
	file = __handle_open(refNum, open_mode);
	
	if (!file)
		FSCloseFork(refNum);
	
	return(file);
}

FILE * FSRefParentAndFilename_fopen(const FSRef *theParentRef, ConstHFSUniStr255Param theName,
	const char *open_mode)
{
	OSErr theErr;
	FSRef theRef;
	FSCatalogInfo theInfo;
	__std(__file_modes) mode;
	FILE *theFile;
	
	theFile = NULL;
	
	if (!__get_file_modes(open_mode, &mode))
		return NULL;
	
	theErr = FSMakeFSRefUnicode(theParentRef, theName->length, theName->unicode,
		__msl_get_system_encoding(), &theRef);
	
	if (theErr == noErr)
		theFile = FSRef_fopen(&theRef, open_mode);
	else
	{
		if (theErr != fnfErr || mode.open_mode == __std(__must_exist))
			return NULL;
		
		((FileInfo *) &(theInfo.finderInfo))->fileType = (OSType) __gettype(mode.binary_io);
		((FileInfo *) &(theInfo.finderInfo))->fileCreator = (OSType) __getcreator(mode.binary_io);
		((FileInfo *) &(theInfo.finderInfo))->finderFlags = 0;
		((FileInfo *) &(theInfo.finderInfo))->location.h = 0;
		((FileInfo *) &(theInfo.finderInfo))->location.v = 0;
		((FileInfo *) &(theInfo.finderInfo))->reservedField = 0;
		theInfo.textEncodingHint = __msl_get_system_encoding();
		
		theErr = FSCreateFileUnicode(theParentRef, theName->length, theName->unicode,
			kFSCatInfoTextEncoding + kFSCatInfoFinderInfo, &theInfo, &theRef, NULL);
		
		if (theErr == noErr)
			theFile = FSRef_fopen(&theRef, open_mode);
	}
	
	return theFile;
}

#endif /* _MSL_USE_NEW_FILE_APIS */

#else

/* Find the text encoding currently in use by the system */
static TextEncoding __msl_get_system_encoding(void)
{
	OSStatus theStatus;
	TextEncoding theEncoding;
	
	theStatus = UpgradeScriptInfoToTextEncoding(smSystemScript, kTextLanguageDontCare,
		kTextRegionDontCare, NULL, &theEncoding);
	
	if (theStatus != noErr)
		theEncoding = kTextEncodingMacRoman;
	
	return theEncoding;
}

/* Convert a C string to a unicode HFSUniStr255 */
static void __msl_text2unicode(const short theLength, const char *theText, HFSUniStr255 *theUnicodeText)
{
	int i;
	OSStatus theStatus;
	ByteCount theSourceUsed;
	ByteCount theConvertedLength;
	TextToUnicodeInfo theConverterInfo;
	
	theStatus = CreateTextToUnicodeInfoByEncoding(__msl_get_system_encoding(), &theConverterInfo);
	
	if (theStatus == noErr)
	{
		theStatus = ConvertFromTextToUnicode(theConverterInfo, theLength, theText, kNilOptions,
			0, NULL, NULL, NULL, sizeof(theUnicodeText->unicode), &theSourceUsed, &theConvertedLength,
			(UniCharArrayPtr) &(theUnicodeText->unicode));
		
		theUnicodeText->length = (UInt16) (theConvertedLength / 2);
		
		DisposeTextToUnicodeInfo(&theConverterInfo);
	}
	
	if (theStatus != noErr)
	{
		theUnicodeText->length = (UInt16) theLength;
		
		for (i = 0; i < theLength; i++)
			theUnicodeText->unicode[i] = theText[i];
	}
}

FILE * FSp_fopen(ConstFSSpecPtr spec, const char * open_mode)
{
	OSErr theErr;
	FSRef theRef;
	FSRef theParentRef;
	FSSpec theSpec;
	HFSUniStr255 theName;
	FSCatalogInfo theInfo;
	__std(__file_modes) mode;
	FILE *theFile;
	
	theFile = NULL;
	
	theErr = FSpMakeFSRef(spec, &theRef);
	
	if (theErr == noErr)
		theFile = FSRef_fopen(&theRef, open_mode);
	else
	{
		if (!__get_file_modes(open_mode, &mode))
			return NULL;
		
		if ((theErr != fnfErr) || (mode.open_mode == __std(__must_exist)))
			return NULL;
		
		/* Find the parent folder of the new file to open */
		theErr = FSMakeFSSpec(spec->vRefNum, spec->parID, "\p", &theSpec);
		
		if (theErr == noErr)
			theErr = FSpMakeFSRef(&theSpec, &theParentRef);
		
		if (theErr == noErr)
		{
			theInfo.textEncodingHint = __msl_get_system_encoding();
			
			__msl_text2unicode(spec->name[0], (char *) &(spec->name[1]), &theName);
			
			theErr = FSCreateFileUnicode(&theParentRef, theName.length, theName.unicode,
				kFSCatInfoTextEncoding, &theInfo, &theRef, NULL);
			
			if (theErr == noErr)
				theFile = FSRef_fopen(&theRef, open_mode);
		}
	}
	
	return theFile;
}

FILE * FSRef_fopen(const FSRef *theRef, const char *open_mode)
{
	OSStatus theStatus;
	UInt8 thePath[2048];
	
	theStatus = FSRefMakePath(theRef, thePath, sizeof(thePath));
	
	if (theStatus != noErr)
		return NULL;
	else
		return fopen((char *) &thePath, open_mode);
}

FILE * FSRefParentAndFilename_fopen(const FSRef *theParentRef, ConstHFSUniStr255Param theName,
	const char *open_mode)
{
	OSErr theErr;
	FSRef theRef;
	FSCatalogInfo theInfo;
	__std(__file_modes) mode;
	FILE *theFile;
	
	theFile = NULL;
	
	if (!__get_file_modes(open_mode, &mode))
		return NULL;
	
	theErr = FSMakeFSRefUnicode(theParentRef, theName->length, theName->unicode,
		__msl_get_system_encoding(), &theRef);
	
	if (theErr == noErr)
		theFile = FSRef_fopen(&theRef, open_mode);
	else
	{
		if (theErr != fnfErr || mode.open_mode == __std(__must_exist))
			return NULL;
		
		theInfo.textEncodingHint = __msl_get_system_encoding();
		
		theErr = FSCreateFileUnicode(theParentRef, theName->length, theName->unicode,
			kFSCatInfoTextEncoding, &theInfo, &theRef, NULL);
		
		if (theErr == noErr)
			theFile = FSRef_fopen(&theRef, open_mode);
	}
	
	return theFile;
}

#endif /* _MSL_CARBON_FILE_APIS */

/* Change record:
 * JFH 951213 First code release.
 * JFH 951230 Added explicit #includes of <Errors.h> and <Script.h>
 * mm  990222 Modified to set type and creator from unix.mac.c
 * JWW 000510 Compiles correctly with the C++ compiler (even though this is a .c file :-)
 * JWW 001029 Added FSRef_fopen() function to allow opening files via a FSRef
 * JWW 010510 Fixed FSp_fopen() to use the new HFS+ APIs if available
 * JWW 010709 Added FSRefParentAndFilename_fopen()
 * JWW 010727 Wrapped __msl_system_has_new_file_apis() declaration with extern "C" stuff for C++
 * JWW 010730 Initialize the mode variable in FSp_fopen() when using the HFS+ APIs
 * JWW 011015 Changed const FSRefPtr to const FSRef * in order to get the correct const-ness
 * JWW 011126 Added case for Mach-O file I/O using the System.framework instead of Carbon.framework
 * JWW 020221 Make sure routines return NULL as the FILE* if an error is encountered during an open
 * JWW 020607 Add some __std() wrappers around items which are in the C++ std namespace
 */