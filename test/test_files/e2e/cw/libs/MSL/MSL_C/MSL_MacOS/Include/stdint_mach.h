/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/02/24 22:24:12 $
 * $Revision: 1.4 $
 */

#ifndef _MSL_STDINT_MACH_H
#define _MSL_STDINT_MACH_H

#include <ansi_parms.h>

#include <cstdint_mach.h>

#if defined(__cplusplus) && defined(_MSL_USING_NAMESPACE)
/*	using std::int8_t;
	using std::int16_t;
	using std::int32_t;*/
	using std::uint8_t;
	using std::uint16_t;
	using std::uint32_t;
	using std::int_least8_t;
	using std::int_least16_t;
	using std::int_least32_t;
	using std::uint_least8_t;
	using std::uint_least16_t;
	using std::uint_least32_t;
	using std::int_fast8_t;
	using std::int_fast16_t;
	using std::int_fast32_t;
	using std::uint_fast8_t;
	using std::uint_fast16_t;
	using std::uint_fast32_t;
#if _MSL_LONGLONG
/*	using std::int64_t;*/
	using std::uint64_t;
	using std::int_least64_t;
	using std::uint_least64_t;
	using std::int_fast64_t;
	using std::uint_fast64_t;
#endif
/*	using std::intptr_t;
	using std::uintptr_t;*/
	using std::intmax_t;
	using std::uintmax_t;
#endif

#endif /* _MSL_STDINT_MACH_H */

/* Change record:
 * JWW 020712 Added cases for building on top of the BSD C 3.1 library
 * JWW 030224 Changed __MSL_LONGLONG_SUPPORT__ flag into the new more configurable _MSL_LONGLONG
 */