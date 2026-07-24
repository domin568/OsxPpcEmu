/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:50 $
 * $Revision: 1.2 $
 */

#ifndef _MSL_CSTDIO_MACH
#define _MSL_CSTDIO_MACH

#include <ansi_parms.h>

_MSL_BEGIN_EXTERN_C

#define L_cuserid 9
#define L_ctermid 1024

char *ctermid(char *);
char *tempnam(const char *, const char *);

_MSL_END_EXTERN_C

#endif /*_MSL_CSTDIO_MACH */

/* Change record:
 * JWW 021211 Added cases for using extra parts of BSD and POSIX through the MSL headers
 */