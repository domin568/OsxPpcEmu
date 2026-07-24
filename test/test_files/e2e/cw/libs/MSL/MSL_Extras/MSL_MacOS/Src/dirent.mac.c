/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/28 15:04:56 $
 * $Revision: 1.3.2.1 $
 */

#include <Files.h>
#include <MacMemory.h>

#include <dirent.h>

#include <errno.h>
#include <stdlib.h>

#include <path2fss.h>

/* function prototypes for externally defined functions */

extern int __ctopstring(const char *cstring, Str255 pstring) _MSL_CANT_THROW;
extern char __msl_system_has_new_file_apis(void) _MSL_CANT_THROW;

#if _MSL_USE_OLD_FILE_APIS
static DIR *__msl_opendir(short vrefnum, long dirid, Str255 pname) _MSL_CANT_THROW
{
	CInfoPBRec cpb;
	OSErr err;
	DIR *ref;
	
	cpb.dirInfo.ioNamePtr = pname;
	cpb.dirInfo.ioFDirIndex = 0;
	cpb.dirInfo.ioVRefNum = vrefnum;
	cpb.dirInfo.ioDrDirID = dirid;
	
	/* get the directory catalog info */
	err = PBGetCatInfoSync(&cpb);
	
	if (err == noErr)
	{
		ref = (DIR *) malloc(sizeof(DIR));
		
		if (ref == NULL)
		{
			errno = ENOMEM;
			return NULL;
		}
		
		ref->_d__index = 1;
		ref->_d__vrefnum = cpb.dirInfo.ioVRefNum;
		ref->_d__dirid = cpb.dirInfo.ioDrDirID;
		
		return ref;
	}
	
	errno = EMACOSERR;
	__MacOSErrNo = err;
	
	return NULL;
}
#endif /* _MSL_USE_OLD_FILE_APIS */

#if _MSL_USE_NEW_FILE_APIS
static DIR *__msl_opendir_ref(FSRef *theRef) _MSL_CANT_THROW
{
	OSErr err;
	FSIterator theIterator;
	DIR *ref;
	
	err = FSOpenIterator(theRef, kFSIterateFlat, &theIterator);
	
	if (err == noErr)
	{
		ref = (DIR *) malloc(sizeof(DIR));
		
		if (ref != NULL)
		{
			ref->_d__ref = malloc(sizeof(FSRef));
			ref->_d__iterator = malloc(sizeof(FSIterator));
			
			if ((ref->_d__ref == NULL) || (ref->_d__iterator == NULL))
			{
				if (ref->_d__ref == NULL)
					free(ref->_d__ref);
				
				if (ref->_d__iterator == NULL)
					free(ref->_d__iterator);
				
				free(ref);
				ref = NULL;
			}
		}
		
		if (ref == NULL)
		{
			FSCloseIterator(theIterator);
			
			errno = ENOMEM;
			return NULL;
		}
		
		*((FSRef *) ref->_d__ref) = *theRef;
		*((FSIterator *) ref->_d__iterator) = theIterator;
		
		return ref;
	}
	
	errno = EMACOSERR;
	__MacOSErrNo = err;
	
	return NULL;
}
#endif /* _MSL_USE_NEW_FILE_APIS */

DIR *opendir(const char *spec) _MSL_CANT_THROW
{
	if (spec == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
	{
		OSErr err;
		FSRef theRef;
		
		err = __msl_path2fsr(spec, &theRef);
		
		if (err == noErr)
			return __msl_opendir_ref(&theRef);
		
		errno = EMACOSERR;
		__MacOSErrNo = err;
		
		return NULL;
	}
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	else
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	{
	Str255 ppath;
	
	/* convert the C string into a Pascal string */
	if (__ctopstring(spec, ppath) != noErr)
	{
		errno = ENAMETOOLONG;
		return NULL;
	}
	
	return (__msl_opendir(0, 0L, ppath));
	}
#endif /* _MSL_USE_OLD_FILE_APIS */
}

struct dirent *readdir (DIR *ref) _MSL_CANT_THROW
{
	if (ref == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
	{
	OSErr err;
	short theLength;
	ItemCount actualObjects;
	HFSUniStr255 theName;
	
	err = FSGetCatalogInfoBulk(*((FSIterator *) ref->_d__iterator), 1, &actualObjects, NULL,
		kFSCatInfoNone, NULL, NULL, NULL, &theName);
	
	if (err == noErr)
	{
		theLength = sizeof(ref->_d__dirent.d_name) - 1;
		__msl_unicode2text(&theName, &theLength, (char *) &(ref->_d__dirent.d_name));
		ref->_d__dirent.d_name[theLength] = 0;
		
		return &(ref->_d__dirent);
	}
	else if (err == errFSNoMoreItems)
	{
		/* End of directory found, so return but leave errno set to zero */
		return NULL;
	}
	
	errno = EMACOSERR;
	__MacOSErrNo = err;
	
	return NULL;
	}
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	else
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	{
	OSErr err;
	CInfoPBRec cpb;
	Str255 name;
	
	cpb.dirInfo.ioNamePtr = (StringPtr) &name;
	cpb.dirInfo.ioVRefNum = ref->_d__vrefnum;
	cpb.dirInfo.ioDrDirID = ref->_d__dirid;
	cpb.dirInfo.ioFDirIndex = ref->_d__index;
	
	err = PBGetCatInfoSync(&cpb);
	
	if (err == noErr)
	{
		BlockMoveData(&(name[1]), ref->_d__dirent.d_name, name[0]);
		ref->_d__dirent.d_name[name[0]] = 0;
		
		(ref->_d__index)++;
		
		return &(ref->_d__dirent);
	}

	/* End of directory found, so return but leave errno set to zero */
	return NULL;
	}
#endif /* _MSL_USE_OLD_FILE_APIS */
}

void rewinddir(DIR *ref) _MSL_CANT_THROW
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
	FSCloseIterator(*((FSIterator *) ref->_d__iterator));
	FSOpenIterator(&(*((FSRef *) ref->_d__ref)), kFSIterateFlat,
		&(*((FSIterator *) ref->_d__iterator)));
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
	ref->_d__index = 1;
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
}

int closedir(DIR *ref) _MSL_CANT_THROW
{
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
		FSCloseIterator(*((FSIterator *) ref->_d__iterator));
		
		free(ref->_d__ref);
		free(ref->_d__iterator);
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
	
	free(ref);
	
	return 0;
}


/* Change record:
 * JWW 010529 Added dirent routines
 */