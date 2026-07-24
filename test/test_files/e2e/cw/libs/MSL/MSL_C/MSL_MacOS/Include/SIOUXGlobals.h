/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:52 $
 * $Revision: 1.13 $
 */

/*****************************************************************************/
/*  Project...: C++ and ANSI-C Compiler Environment                          */
/*  Purpose...: SIOUX's public globals				                	     */
/*****************************************************************************/

#ifndef _MSL_SIOUXGLOBALS_H
#define _MSL_SIOUXGLOBALS_H

#ifndef SIOUX_USE_WASTE
	#define SIOUX_USE_WASTE 0
#endif

#pragma options align=mac68k

#if __MACH__
	#include <Carbon/Carbon.h>
#else
	#include <Controls.h>
	#include <TextEdit.h>
	#include <MacTypes.h>	
	#include <MacWindows.h>
#endif

#if SIOUX_USE_WASTE
	#include <WASTE.h>
#endif

typedef enum tSIOUXState {
	OFF = 0,
	IDLE,
	PRINTFING,
	SCANFING,
	TERMINATED,
	ABORTED
} tSIOUXState;
	
typedef struct tSIOUXWin {
	WindowPtr	window;						/*	Documents Window, WindowRecord is Opaque in Carbon*/
#if SIOUX_USE_WASTE
	WEReference		edit;
	long			linesInFolder;			/*	Number of lines in the window */	// ¥¥¥LC
#else
	TEHandle		edit;					/*	TextEdit Handle  */
	short			linesInFolder;			/*	Number of lines in the window */
#endif /* SIOUX_USE_WASTE */
	ControlHandle 	vscroll;		     	/*	Vertical scrollbar */
	Boolean			dirty;					/*	Is the document dirty (applies only to textWindow) */
	short			vrefnum;				/*	The window's file position on disk ... */
	long			dirid;
	Str63			fname;
} tSIOUXWin, *pSIOUXWin;

#if SIOUX_USE_WASTE							/*- mm 980511 -*/
	extern SInt32   SIOUXselstart;    			/* The starting point for a read (can't read before this) ...*/
#else
	extern short    SIOUXselstart;    			/* The starting point for a read (can't read before this) ...*/
#endif /* SIOUX_USE_WASTE                   /*- mm 980511 -*/

extern Rect 		SIOUXDragRect;			/*	The global drag rect ...*/
extern Rect			SIOUXBigRect;			/*	The global clip rect ...*/
extern Boolean		SIOUXQuitting;			/*	Are we quitting? ...*/
extern Boolean		SIOUXUseWaitNextEvent;	/*	Can we use WaitNextEvent? ...*/
extern tSIOUXState	SIOUXState;				/*	Used to signal that we are trying to get a string ...*/
extern pSIOUXWin	SIOUXTextWindow;		/*	Pointer to the SIOUX text window structure ...*/

#pragma options align=reset

#endif /* _MSL_SIOUXGLOBALS_H */

/* Change record:
 * mm  960930 Converted C++ comments to C comments to compiile with ANSI strict
 * mm  980511 Change to allow WASTE to handle files longer than 32k.  MW07031
 * vss 990421 Update to 3.2 Universal Headers
 * cc  991108 Added ra Carbon changes done 990612
 * JWW 011027 Added case for Mach-O
 */