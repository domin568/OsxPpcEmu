/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:31 $
 * $Revision: 1.3 $
 */

#include <ansi_parms.h>
#include <stdlib.h>

#if __ALTIVEC__ && _MSL_MALLOC_IS_ALTIVEC_ALIGNED

	void* vec_malloc(size_t size);
	void* vec_calloc(size_t nmemb, size_t size);
	void* vec_realloc(void* ptr, size_t size);
	void vec_free(void* ptr);

	void*
	vec_malloc(size_t size)
	{
		return malloc(size);
	}

	void*
	vec_calloc(size_t nmemb, size_t size)
	{
		return calloc(nmemb, size);
	}

	void*
	vec_realloc(void* ptr, size_t size)
	{
		return realloc(ptr, size);
	}

	void
	vec_free(void* ptr)
	{
		free(ptr);
	}

#endif /* __ALTIVEC__ */

/* Change record:
 * JWW 011126 New file to define vec_malloc and friends for Mach-O
 */