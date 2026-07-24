/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/28 15:05:41 $
 * $Revision: 1.3.2.1 $
 */

/*
 *	Content:	Interface file to standard UNIX-style entry points ...
 *
 *	NB:			This file implements some UNIX low level support.  These functions
 *				are not guaranteed to be 100% conformant.
 */

#ifndef _MSL_UTIME_MAC_H
#define _MSL_UTIME_MAC_H

#pragma options align=native

_MSL_BEGIN_EXTERN_C

	/* struct for utimes */
	struct timeval {
		int tv_sec;						/* seconds */
		int tv_usec;					/* microseconds (ignored on the Mac) */
	};

_MSL_END_EXTERN_C

#pragma options align=reset

#endif /* _MSL_UTIME_MAC_H */

/* Change record:
 * hh  971207 Must use modern headers to keep from leaking "using"
 * hh  971207 Added namespace support
 * vss 980807 remove pragma  - no longer supported by compiler
 * hh  990124 fixed __std 2 places
 * JWW 000928 balanced align directives (align=native needs align=reset)
 * cc  010410 updated to new namespace macros
 * JWW 010618 Use cname headers exclusively to prevent namespace pollution in C++
 * JWW 010621 Moved #include <ctime> to the main utime.h header
 */