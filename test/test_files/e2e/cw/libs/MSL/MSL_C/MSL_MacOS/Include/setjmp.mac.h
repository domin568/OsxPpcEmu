/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:51 $
 * $Revision: 1.10 $
 */

#ifndef _MSL_SETJMP_MAC_H
#define _MSL_SETJMP_MAC_H

#define _MSL_SETJMP_LONGJMP_DEFINED

#if __MACH__
	
	_MSL_BEGIN_NAMESPACE_STD
	_MSL_BEGIN_EXTERN_C
	
	/* JWW - Match the definitions in <ppc/setjmp.h> */
	#define _MSL_JBLEN (26 + 36 + 129 + 1)
	typedef int jmp_buf[_MSL_JBLEN];
	
	_MSL_END_EXTERN_C
	_MSL_END_NAMESPACE_STD
	
	/* JWW - Match the prototype for setjmp in <ppc/setjmp.h>, put it in the global namespace */
	_MSL_BEGIN_EXTERN_C
		extern int setjmp(__std(jmp_buf)) _MSL_CANT_THROW;
	_MSL_END_EXTERN_C
	
	_MSL_BEGIN_NAMESPACE_STD
	_MSL_BEGIN_EXTERN_C
	
	/* JWW - Match the prototype for longjmp in <ppc/setjmp.h> */
	extern void longjmp(jmp_buf, int) _MSL_CANT_THROW;
	
	/* JWW - Map the MSL vector setjmp and longjmp to the system setjmp and longjmp */
	int __vec_setjmp(jmp_buf) _MSL_CANT_THROW;
	#if _MSL_USE_INLINE
		_MSL_INLINE int __vec_setjmp(jmp_buf _j) _MSL_CANT_THROW { return setjmp(_j); }
	#endif
	
	void __vec_longjmp(jmp_buf, int) _MSL_CANT_THROW;
	#if _MSL_USE_INLINE
		_MSL_INLINE void __vec_longjmp(jmp_buf _j, int _val) _MSL_CANT_THROW { longjmp(_j, _val); }
	#endif
	
	_MSL_END_EXTERN_C
	_MSL_END_NAMESPACE_STD
	
#else
	
	#pragma options align=native
	
	_MSL_BEGIN_NAMESPACE_STD
	_MSL_BEGIN_EXTERN_C
	
		#if __VEC__
			
			typedef __vector unsigned long jmp_buf[29];
			
			#ifndef __SETJMP_NOT_INTERNAL__
				#pragma internal on
			#endif
			
				_MSL_IMP_EXP_C int __vec_setjmp(jmp_buf) _MSL_CANT_THROW;
			
			#ifndef __SETJMP_NOT_INTERNAL__
				#pragma internal reset
			#endif
			
			int __vec_longjmp(jmp_buf, int) _MSL_CANT_THROW;
			
			#define setjmp(jmp_buf)	__std(__vec_setjmp(jmp_buf))  /*- hh 990521 -*/
			
			void longjmp(jmp_buf, int) _MSL_CANT_THROW;
			#if _MSL_USE_INLINE
				_MSL_INLINE void longjmp(jmp_buf j, int val) _MSL_CANT_THROW { __vec_longjmp(j, val); }
			#endif
			
		#else
			
			typedef long *jmp_buf[70];
			
			#ifndef __SETJMP_NOT_INTERNAL__
				#pragma internal on
			#endif
			
				_MSL_IMP_EXP_C int __setjmp(jmp_buf) _MSL_CANT_THROW;
			
			#ifndef __SETJMP_NOT_INTERNAL__
				#pragma internal reset
			#endif
			
			#define setjmp(jmp_buf)	__std(__setjmp(jmp_buf))  /*- hh 990521 -*/
			void longjmp(jmp_buf,int) _MSL_CANT_THROW;
			
		#endif
	
	_MSL_END_EXTERN_C
	_MSL_END_NAMESPACE_STD
	
	#pragma options align=reset
	
#endif /* __MACH__ */

#endif /* _MSL_SETJMP_MAC_H */

/* Change record:
 * JWW 011101 New file to make setjmp information platform independent
 * JWW 011107 Added Mach-O setjmp/longjmp stuff - simply matching prototypes for the BSD routines
 * JWW 020228 Test _MSL_USE_INLINE before using _MSL_INLINE to avoid link warning with inlining off
 * JWW 020414 Put Mach-O setjmp() in the global namespace with C++ as it's supposed to mimic a macro
 * hh  020603 Added no throw spec to functions
 */