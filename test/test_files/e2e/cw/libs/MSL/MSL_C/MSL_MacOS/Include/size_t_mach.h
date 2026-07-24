/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/07/01 18:47:07 $
 * $Revision: 1.7.2.1 $
 */
 
#ifndef _MSL_SIZE_T_MACH_H
#define _MSL_SIZE_T_MACH_H

#include <ppc/ansi.h>

	#ifndef _MSL_SIZE_T_TYPE
	#define _MSL_SIZE_T_TYPE _BSD_SIZE_T_
	#endif
	
	#if !defined(__cplusplus) || !defined(_MSL_USING_NAMESPACE)
		#ifndef	_BSD_SIZE_T_DEFINED_
			#define	_BSD_SIZE_T_DEFINED_
		#else
			#ifndef _MSL_SIZE_T_DEFINED
				#define _MSL_SIZE_T_DEFINED
			#endif
		#endif
	#endif
	
	#ifndef _BSD_SSIZE_T_DEFINED_
		#define _BSD_SSIZE_T_DEFINED_
		typedef _BSD_SSIZE_T_ ssize_t;
	#endif

#endif /* _MSL_SIZE_T_MACH_H */

/* Change record:
 * JWW 011108 Define size_t as BSD does
 * JWW 011112 Add the _MSL_SIZE_T_DEFINED guard in case BSD C defines size_t before MSL
 * JWW 020114 Make sure size_t is defined outside of the std:: namespace for C++
 * JWW 020129 The last change was wrong.  Do not leak size_t from the C++ std namespace
 * ejs 030328 Add define guards for _MSL_SIZE_T_TYPE
 * JWW 030701 Define ssize_t as well as size_t to get more POSIX headers to work with MSL
 */