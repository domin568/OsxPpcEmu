/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/04/25 18:32:41 $
 * $Revision: 1.3 $
 */

#ifndef _MSL_CTIME_MACH
#define _MSL_CTIME_MACH

#include <ansi_parms.h>

_MSL_BEGIN_EXTERN_C

extern char *tzname[];

void tzset(void);

char *asctime_r(const struct __std(tm) *, char *);
char *ctime_r(const __std(time_t) *, char *);
struct __std(tm) *gmtime_r(const __std(time_t) *, struct __std(tm) *);
struct __std(tm) *localtime_r(const __std(time_t) *, struct __std(tm) *);
char *strptime(const char *, const char *, struct __std(tm) *);
char *timezone(int, int);
void tzsetwall(void);
__std(time_t) timelocal(struct __std(tm) * const);
__std(time_t) timegm(struct __std(tm) * const);

struct timespec;
int nanosleep(const struct timespec *, struct timespec *);

_MSL_END_EXTERN_C

#endif /*_MSL_CSTDIO_MACH */

/* Change record:
 * JWW 021211 Added cases for using extra parts of BSD and POSIX through the MSL headers
 * ejs 030425 Added forward decl for struct timespec
 */