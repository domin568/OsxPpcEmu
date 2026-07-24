/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:51 $
 * $Revision: 1.2 $
 */

#ifndef _MSL_CSTDLIB_MACH
#define _MSL_CSTDLIB_MACH

#include <ansi_parms.h>
#include <size_t.h>

#include <sys/types.h> /* JWW - To get u_int32_t */

_MSL_BEGIN_EXTERN_C

int putenv(const char *);
int setenv(const char *, const char *, int);

double drand48(void);
double erand48(unsigned short[3]);
long jrand48(unsigned short[3]);
void lcong48(unsigned short[7]);
long lrand48(void);
long mrand48(void);
long nrand48(unsigned short[3]);
unsigned short *seed48(unsigned short[3]);
void srand48(long);

u_int32_t arc4random(void);
void arc4random_addrandom(unsigned char *, int);
void arc4random_stir(void);
char *getbsize(int *, long *);
char *cgetcap(char *, char *, int);
int cgetclose(void);
int cgetent(char **, char **, char *);
int cgetfirst(char **, char **);
int cgetmatch(char *, char *);
int cgetnext(char **, char **);
int cgetnum(char *, char *, long *);
int cgetset(char *);
int cgetstr(char *, char *, char **);
int cgetustr(char *, char *, char **);

int daemon(int, int);
char *devname(int, int);
int getloadavg(double[], int);

long a64l(const char *);
char *l64a(long);

char *group_from_gid(unsigned long, int);
int heapsort(void *, __std(size_t), __std(size_t), int (*)(const void *, const void *));
char *initstate(unsigned long, char *, long);
int mergesort(void *, __std(size_t), __std(size_t), int (*)(const void *, const void *));
int radixsort(const unsigned char **, int, const unsigned char *, unsigned);
int sradixsort(const unsigned char **, int, const unsigned char *, unsigned);
int rand_r(unsigned *);
long random(void);
void *reallocf(void *, __std(size_t));
char *realpath(const char *, char resolved_path[]);
char *setstate(char *);
void srandom(unsigned long);
char *user_from_uid(unsigned long, int);

long long strtoq(const char *, char **, int);
unsigned long long strtouq(const char *, char **, int);

void unsetenv(const char *);

_MSL_END_EXTERN_C

#endif /*_MSL_CSTDLIB_MACH */

/* Change record:
 * JWW 021211 Added cases for using extra parts of BSD and POSIX through the MSL headers
 */