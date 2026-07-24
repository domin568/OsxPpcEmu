/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/28 15:05:30 $
 * $Revision: 1.4.2.2 $
 */

/*
 *	Content:	Interface file to standard UNIX-style entry points ...
 *
 *	NB:			This file implements some UNIX low level support.  These functions
 *				are not guaranteed to be 100% conformant.
 *
 */

#ifndef	_MSL_UNIX_MAC_H
#define	_MSL_UNIX_MAC_H

#include <csignal>

_MSL_BEGIN_EXTERN_C

	/*
	 *	Globals for setting the type and creator of new files ...
	 */
	extern _MSL_IMP_EXP_C long _fcreator, _ftype;
	_MSL_IMP_EXP_C long __getcreator(long) _MSL_CANT_THROW;
	_MSL_IMP_EXP_C long __gettype(long) _MSL_CANT_THROW;
	
	__inline long __myraise(long _a) _MSL_CANT_THROW {return (__std(raise)(_a));}												

_MSL_END_EXTERN_C

#endif  /* _MSL_UNIX_MAC_H */

/* Change record:
 * mm  962906 Added function prototypes for __gettype and __getcreator
 * hh  971207 Must use modern headers to keep from leaking "using"
 * hh  971207 Added namespace support
 * vss 980807 remove pragma  - no longer supported by compiler
 * hh  990124 fixed __std 2 places
 * cc  000515 fixed #includes moved them to unix.h
 * JWW 000928 removed spurious align directive
 * cc  010410 updated to new namespace macros
 * JWW 010927 Moved __myraise out from "common" unix.h header into the unix.mac.h
 */