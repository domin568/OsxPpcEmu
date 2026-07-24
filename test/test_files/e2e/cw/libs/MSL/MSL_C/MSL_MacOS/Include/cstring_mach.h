/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:51 $
 * $Revision: 1.2 $
 */

#ifndef _MSL_CSTRING_MACH
#define _MSL_CSTRING_MACH

#include <ansi_parms.h>
#include <size_t.h>

_MSL_BEGIN_EXTERN_C

int bcmp(const void *, const void *, __std(size_t));
void bcopy(const void *, void *, __std(size_t));
void bzero(void *, __std(size_t));
int ffs(int);
char *index(const char *, int);
void *memccpy(void *, const void *, int, __std(size_t));
char *rindex(const char *, int);
int strcasecmp(const char *, const char *);
char *strdup(const char *);
__std(size_t) strlcat(char *, const char *, __std(size_t));
__std(size_t) strlcpy(char *, const char *, __std(size_t));
void strmode(int, char *);
int strncasecmp(const char *, const char *, __std(size_t));
char *strsep(char **, const char *);
char *strtok_r(char *, const char *, char **);
void swab(const void *, void *, __std(size_t));

_MSL_END_EXTERN_C

#endif /*_MSL_CSTRING_MACH */

/* Change record:
 * JWW 021211 Added cases for using extra parts of BSD and POSIX through the MSL headers
 */