/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/28 15:05:48 $
 * $Revision: 1.5.2.1 $
 */

/*
 *	Content:	Interface file to standard UNIX-style entry points ...
 *
 *	NB:			This file implements some UNIX low level support.  These functions
 *				are not guaranteed to be 100% conformant.
 */

#include <utsname.h>
#include <TextUtils.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <Gestalt.h>
#include <LowMem.h>
#include <OSUtils.h>
#include <ToolUtils.h>
#include <Traps.h>
#include <MacTypes.h>

/*
 *	int uname(struct utsname *name)
 *
 *		Returns information about the current system.
 */
int uname(struct utsname *name)_MSL_CANT_THROW
{
	static char		macname[] = "MacOS";
	long			system, machine;
	short			num, savemap;
	Str255			string;
	StringHandle	h;
	OSErr			err = noErr;

	if (name) {
		memset(name, '\0', sizeof(struct utsname));
		strcpy(name->sysname, macname);
	#if !TARGET_API_MAC_CARBON
		if (GetToolTrapAddress(_Gestalt) != GetToolTrapAddress(_Unimplemented)) {
	#else
		#pragma unused(savemap)
	#endif /* !TARGET_API_MAC_CARBON */
			if ((err = Gestalt(gestaltSystemVersion, &system)) == noErr) {
			#if !TARGET_API_MAC_CARBON
				savemap = LMGetCurMap();
				LMSetCurMap(0);						/* search only in the system file's resources */
			#endif /* !TARGET_API_MAC_CARBON */
				h = GetString(-16413);				/* the sharing setup machine name */
				err = ResError();
			#if !TARGET_API_MAC_CARBON
				LMSetCurMap(savemap);
			#endif /* !TARGET_API_MAC_CARBON */
				if (h && err == noErr) {
					HLock((Handle)h);
					sprintf(name->nodename, "%#.*s", _UTSNAME_FIELD_LENGTH-1, *h);	/*- mm 990104 -*/
					HUnlock((Handle)h);
				}

				num = (system & 0xff00) >> 8;
				sprintf(name->release, "%hx", num);

				num = (system & 0xff);
				sprintf(name->version, "%hx", num);

				if (Gestalt(gestaltMachineType, &machine) == noErr) {
					GetIndString(string, kMachineNameStrID, machine);
					sprintf(name->machine, "%#.*s", _UTSNAME_FIELD_LENGTH-1, string);	/*- mm 990104 -*/
				} else {
					strcpy(name->machine, "Unknown");
				}
				
				if (err != noErr)
				{
					errno = EMACOSERR;														/*- mm 010412 -*/
					__MacOSErrNo = err;														/*- mm 010412 -*/
					return (-1);															/*- mm -1-412 -*/
				}
				return (0);
			}
	#if !TARGET_API_MAC_CARBON
		}
	#endif /* !TARGET_API_MAC_CARBON */
	}

	/* if we reach here we have an error */
	errno = EMACOSERR;														/*- mm 010412 -*/
	__MacOSErrNo = err;														/*- mm 010412 -*/
	return (-1);
}

/* Change record:
 * mf  971006 added fixes to compile w/ 3.0.1  universal headers
 * mm  990104 Made use of _UTSNAME_FIELD_LENGTH instead of a magic number.
 * vss 990421 Update to 3.2 Universal Headers
 * cc  991108 added ra Carbon Changes done 990611
 * cc  991109 changed TARGET_CARBON to TARGET_API_MAC_CARBON
 * cc  991115 updated and deleted outdated comments
 * mm  010412 Changes to avoid putting OSErr values into errno
 * JWW 020304 Don't return an error when unknown machine is found, just return the name "Unknown"
 */