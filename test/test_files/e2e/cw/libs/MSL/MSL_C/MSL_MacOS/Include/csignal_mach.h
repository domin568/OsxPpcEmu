/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/04/25 19:19:00 $
 * $Revision: 1.6 $
 */

#ifndef _MSL_CSIGNAL_MACH_H
#define _MSL_CSIGNAL_MACH_H

#include <ansi_parms.h>

_MSL_BEGIN_EXTERN_C

	typedef unsigned int sigset_t;
	
	#define	SIGHUP		1
	#define	SIGINT		2
	#define	SIGQUIT		3
	#define	SIGILL		4
	#define	SIGTRAP		5
	#define	SIGABRT		6
	#define	SIGIOT		SIGABRT
	#define	SIGEMT		7
	#define	SIGFPE		8
	#define	SIGKILL		9
	#define	SIGBUS		10
	#define	SIGSEGV		11
	#define	SIGSYS		12
	#define	SIGPIPE		13
	#define	SIGALRM		14
	#define	SIGTERM		15
	#define	SIGURG		16
	#define	SIGSTOP		17
	#define	SIGTSTP		18
	#define	SIGCONT		19
	#define	SIGCHLD		20
	#define	SIGTTIN		21
	#define	SIGTTOU		22
	#define	SIGIO		23
	#define	SIGXCPU		24
	#define	SIGXFSZ		25
	#define	SIGVTALRM	26
	#define	SIGPROF		27
	#define SIGWINCH	28
	#define SIGINFO		29
	#define SIGUSR1		30
	#define SIGUSR2		31
	
	
	#include <sys/types.h>
	
	struct sigaction;
	struct sigcontext;
	struct sigvec;
	
	int	kill(pid_t, int);
	int	sigaction(int, const struct sigaction *, struct sigaction *);
	int	sigaddset(sigset_t *, int);
	int	sigdelset(sigset_t *, int);
	int	sigemptyset(sigset_t *);
	int	sigfillset(sigset_t *);
	int	sigismember(const sigset_t *, int);
	int	sigpending(sigset_t *);
	int	sigprocmask(int, const sigset_t *, sigset_t *);
	int	sigsuspend(const sigset_t *);
	
	int	killpg(pid_t, int);
	int	sigblock(int);
	int	siginterrupt(int, int);
	int	sighold(int);
	int	sigrelse(int);
	int	sigpause(int);
	int	sigreturn(struct sigcontext *);
	int	sigsetmask(int);
	int	sigvec(int, struct sigvec *, struct sigvec *);
	void psignal(unsigned int, const char *);
	
	#define	sigaddset(set, signo)	(*(set) |= 1 << ((signo) - 1), 0)
	#define	sigdelset(set, signo)	(*(set) &= ~(1 << ((signo) - 1)), 0)
	#define	sigemptyset(set)		(*(set) = 0, 0)
	#define	sigfillset(set)			(*(set) = ~(sigset_t)0, 0)
	#define	sigismember(set, signo)	((*(set) & (1 << ((signo) - 1))) != 0)

_MSL_END_EXTERN_C

#endif /* _MSL_CSIGNAL_MACH_H */

/* Change record:
 * JWW 020711 When compiling for Mach-O, define a sigset_t type to be compatible with the system
 * JWW 021010 When compiling for Mach-O, use the BSD values for the SIGxxx macros
 * JWW 021211 Added cases for using extra parts of BSD and POSIX through the MSL headers
 * ejs 030425 Added forward decls for structs sigaction, sigcontext, sigvec
 */