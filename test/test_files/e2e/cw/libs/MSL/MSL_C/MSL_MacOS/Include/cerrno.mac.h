/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/06/11 21:53:15 $
 * $Revision: 1.6 $
 */

#ifndef _MSL_CERRNO_MAC_H
#define _MSL_CERRNO_MAC_H

#include <ansi_parms.h>

#if( __dest_os == __mac_os_x)
	#define EAGAIN			35	/* Resource temporarily unavailable */	
	#define EDEADLK			11	/* Resource deadlock avoided */	
	#define EDEVERR			83	/* Device error, e.g. paper out */
#if _MSL_C99											/*- mm 030304 -*/
	#define EILSEQ			90	/* Wide character encoding error */
#endif													/*- mm 030304 -*/
	#define ENAMETOOLONG	63	/* File name too long */	
	#define ENOLCK			77	/* No locks available */
	#define ENOSYS			78	/* Function not implemented */	
	#define ENOTEMPTY		66	/* Directory not empty */	
	#define EPWROFF			82	/* Device power is off */

	#define	EADDRINUSE		48	/* Address already in use */
	#define	EADDRNOTAVAIL	49	/* Can't assign requested address */
	#define	EAFNOSUPPORT	47	/* Address family not supported by protocol family */
	#define	EALREADY		37	/* Operation already in progress */
	#define	EAUTH			80	/* Authentication error */
	#define EBADARCH		86	/* Bad CPU type in executable */
	#define EBADEXEC		85	/* Bad executable */
	#define EBADMACHO		88	/* Malformed Macho file */
	#define	EBADRPC			72	/* RPC struct is bad */
	#define	ECONNABORTED	53	/* Software caused connection abort */
	#define	ECONNREFUSED	61	/* Connection refused */
	#define	ECONNRESET		54	/* Connection reset by peer */
	#define	EDESTADDRREQ	39	/* Destination address required */
	#define	EDQUOT			69	/* Disc quota exceeded */
	#define	EFTYPE			79	/* Inappropriate file type or format */
	#define	EHOSTDOWN		64	/* Host is down */
	#define	EHOSTUNREACH	65	/* No route to host */
	#define	EINPROGRESS		36	/* Operation now in progress */
	#define	EISCONN			56	/* Socket is already connected */
	#define	ELOOP			62	/* Too many levels of symbolic links */
	#define	EMSGSIZE		40	/* Message too long */
	#define	ENEEDAUTH		81	/* Need authenticator */
	#define	ENETDOWN		50	/* Network is down */
	#define	ENETRESET		52	/* Network dropped connection on reset */
	#define	ENETUNREACH		51	/* Network is unreachable */
	#define	ENOBUFS			55	/* No buffer space available */
	#define	ENOPROTOOPT		42	/* Protocol not available */
	#define	ENOTBLK			15	/* Block device required */
	#define	ENOTCONN		57	/* Socket is not connected */
	#define	ENOTSOCK		38	/* Socket operation on non-socket */
	#define ENOTSUP			45	/* Operation not supported */
	#define	EOVERFLOW		84	/* Value too large to be stored in data type */
	#define	EPFNOSUPPORT	46	/* Protocol family not supported */
	#define	EPROCLIM		67	/* Too many processes */
	#define	EPROCUNAVAIL	76	/* Bad procedure for program */
	#define	EPROGMISMATCH	75	/* Program version wrong */
	#define	EPROGUNAVAIL	74	/* RPC prog. not avail */
	#define	EPROTONOSUPPORT	43	/* Protocol not supported */
	#define	EPROTOTYPE		41	/* Protocol wrong type for socket */
	#define	EREMOTE			71	/* Too many levels of remote in path */
	#define	ERPCMISMATCH	73	/* RPC version wrong */
	#define ESHLIBVERS		87	/* Shared library version mismatch */
	#define	ESHUTDOWN		58	/* Can't send after socket shutdown */
	#define	ESOCKTNOSUPPORT	44	/* Socket type not supported */
	#define	ESTALE			70	/* Stale NFS file handle */
	#define	ETIMEDOUT		60	/* Operation timed out */
	#define	ETOOMANYREFS	59	/* Too many references: can't splice */
	#define	ETXTBSY			26	/* Text file busy */
	#define	EUSERS			68	/* Too many users */
	
	#define	EOPNOTSUPP		ENOTSUP	/* Operation not supported */
	#define	EWOULDBLOCK		EAGAIN	/* Operation would block */
#endif

#define EMACOSERR			89	/* Mac OS error */

_MSL_BEGIN_EXTERN_C						
	
	_MSL_IMP_EXP_C _MSL_TLS extern short __MacOSErrNo;		/*- mm 010411 -*/ /*- mm 010412 -*/ /*- mm 010621 -*/	/*- cc 011128 -*/
	
_MSL_END_EXTERN_C							

#endif /* _MSL_CERRNO_MAC_H */

/* Change record:
 * bkoz960829 added error info for x86, powerTV
 * mm  960930 changed C++ comments to C comments for ANSI strict
 * KO  961217 Added an extern C wrapper to errno. This is needed for the new CW11 x86
 *			  name mangling.
 * KO  961219 Added a Win32 ifdef so errno is part of the thread local data structure
 *        	  rather than a global.
 * mm  970416 Removed errors that no longer apply
 * mm  970708 Inserted Be changes
 * hh  971206 Changed filename from errno.h to cerrno and added namespace support
 * hh  971230 added RC_INVOKED wrapper
 * vss 990121 Remove powerTV wrappers
 * mf  030199 removed errno from std, and also added guard for single threaded lib
 * mm  991216 Added an error code for access().
 * cc  000209 Added EEXIST and ENOTEMPTY
 * cc  000218 Added if POSIX
 * cc  000403 added EISDIR for use by open (needed to build CVS on windows)
 * cc  000410 moved dest_os win32 #defines into POSIX 
 * JWW 001208 Added case for targeting Mach-O
 * cc  000326 removed dest_os to be_os
 * cc  010409 updated to JWW new namespace macros 	
 * mm  010411 Changed error macros and added __MacOSErrNo
 * cc  010531 Added _GetThreadLocalData's flag
 * mm  010621 Change to omit non-standard #include <MacTypes.h>
 * JWW 011027 Use _MSL_USING_MW_C_HEADERS as generic header test instead of specific Mach-O test
 * cc  011128 Made __tls _MSL_TLS
 * cc  011203 Added _MSL_CDECL for new name mangling 
 * JWW 020129 Removed unnecessary test for RC_INVOKED macro
 * JWW 020414 Added more error codes for Mach-O to make things compatible with the Apple BSD C
 * mm  030304 Added _MSL_C99 wrapper
 */