/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/05/05 12:38:51 $
 * $Revision: 1.14 $
 */

/*****************************************************************************/
/*  Project...: C++ and ANSI-C Compiler Environment                          */
/*  Purpose...: SIOUX's public globals				                	     */
/*****************************************************************************/

#include <SIOUX.h>  

#include "SIOUXGlobals.h"

#if __MACH__
	#include <Carbon/Carbon.h>
#else
	#include <Fonts.h>
#endif

/* The starting point for a read (can't read before this) ...*/
#if SIOUX_USE_WASTE
	SInt32 SIOUXselstart = 0;
#else
	short SIOUXselstart = 0;
#endif /* SIOUX_USE_WASTE */

/*	The global drag rect ...*/
Rect SIOUXDragRect = {100, 100, 32000, 32000};

/*	The global clip rect ...*/
Rect SIOUXBigRect = {-32000, -32000, 32000, 32000};

/*	Are we quitting? ...*/
Boolean SIOUXQuitting = false;

/*	Can we use WaitNextEvent? ...*/
Boolean SIOUXUseWaitNextEvent = false;

/*	User customizable SIOUX settings ...*/
tSIOUXSettings SIOUXSettings =
{
	true,					/* Do we initialize the ToolBox ... */
	true,					/* Is SIOUX running in standalone mode ... */
	true,					/* Do we draw the SIOUX menus ... */
	false,					/* Do we close the SIOUX window on program termination ... */
	true,					/* Do we offer to save on a close ... */
	false,					/* Do we draw the status line ... */
	NULL,					/* Pointer to window title preset by user mm 980609 */
	4,						/* if non-zero, replace tabs with 'tabspaces' spaces ... */
	80, 24,					/* The initial size of the SIOUX window ... */
	0, 0,					/* The topleft window position (in pixels) (0,0 centers on main screen) ... */
	kFontIDMonaco,			/* SIOUX's font ... */
	9,						/* SIOUX's font size ... */
	normal,					/* SIOUX's textface (i.e. bold, etc...) ... */
	0,						/* Value to pass to WaitNextEvent for the sleep time ... */
	
	/* SIOUX-WASTE specific settings -- these will have no effect on a non-SIOUX-WASTE project */
	true,					/* WASTE will use Drag and Drop, if available */
	true,					/* if false, selections in a non-active window will not be outlined */
	false,					/* tell WASTE to allocate its main data structures from temporary memory */
	/* END SIOUX-WASTE specific settings */

	false					/* Does SIOUX act like console.stubs.c ... */
	
#if TARGET_API_MAC_CARBON
	,	/* Separate the previous setting from the next one */
	true					/* Does SIOUX use FrontNonFloatingWindow intead of FrontWindow ... */
#endif
};

/*	Used to signal that we are trying to get a string ...*/
tSIOUXState SIOUXState = OFF;

/*	Pointer to the SIOUX text window structure ...*/
pSIOUXWin SIOUXTextWindow;

/* Change record:
 *  mm 971006 Changed font name to match new Universal Headers
 *  mm 980511 Change to allow WASTE to handle files longer than 32k.  MW07031
 *  mm 980609 Change that allows user to specify window title before the SIOUX window is created.
 * JWW 010807 Added stub mode setting
 * JWW 010917 Added floating window mode to SIOUX
 */