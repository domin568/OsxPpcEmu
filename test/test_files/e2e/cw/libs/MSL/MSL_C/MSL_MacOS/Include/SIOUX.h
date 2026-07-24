/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/04/21 21:54:03 $
 * $Revision: 1.20 $
 */
 
/*
 *	Content:	Interface file for SIOUX, containing all accessible entries ...
 */

#ifndef _MSL_SIOUX_H
#define _MSL_SIOUX_H

#include <ansi_parms.h>            /*- mm 970903 -*/

#if __MOTO__
	#include <Events.h>
#endif

#pragma options align=mac68k

/*
 *	Structure for holding the SIOUX specific settings ...
 *	default values are:
 *		{TRUE, TRUE, TRUE, FALSE, TRUE, FALSE, NULL, 4, 80, 24, 0, 0, monaco, 9, normal,
 *			TRUE, TRUE,	FALSE, 0};	// SIOUX-WE specific
 */

typedef struct tSIOUXSettings {
	char		 	initializeTB,			/* Do we initialize the ToolBox ... */
					standalone,				/* Is SIOUX running in standalone mode ... */
					setupmenus,				/* Do we draw the SIOUX menus ... */
					autocloseonquit,		/* Do we close the SIOUX window on program termination ... */
					asktosaveonclose,		/* Do we offer to save on a close ... */
					showstatusline;			/* Do we draw the status line ... */
	unsigned char  	*userwindowtitle;		/* Pointer to window title preset by user mm 980609 */

	short			tabspaces,				/* if non-zero, replace tabs with 'tabspaces' spaces ... */
					columns, rows,			/* The initial size of the SIOUX window ... */
					toppixel, leftpixel,	/* The topleft window position (in pixels) ... */
											/* 	(0,0 centers on main screen) ... */
					fontid, fontsize,
					fontface,				/* SIOUX's font, size and textface (i.e. bold, etc...) ... */
					sleep;					/* Value to pass to WaitNextEvent for the sleep time ... */
	
	/* SIOUX-WASTE specific settings -- these will have no effect on a non-SIOUX-WASTE project */
	char			enabledraganddrop,	/* WASTE will use Drag and Drop, if available 			*/
					outlinehilite,			/* if false, selections in a non-active window will	*/
												/* not be outlined--the selection "disappears".			*/
												/* if enabledraganddrop == true, this feature will be	*/
												/* activated no matter the value of outlinehilite		*/
					wasteusetempmemory;			/* tell WASTE to allocate its main data structures from temporary memory */
/*	long			wastemaxbuffersize; /* setting to limit the size of the WASTE text. Not yet implemented */
	/* END SIOUX-WASTE specific settings */
	
	char			stubmode;				/* Does SIOUX act like console.stubs.c ... */
	
#if TARGET_API_MAC_CARBON
	char			usefloatingwindows;		/* Does SIOUX use FrontNonFloatingWindow intead of FrontWindow ... */
#endif
} tSIOUXSettings;

_MSL_IMP_EXP_SIOUX extern tSIOUXSettings	SIOUXSettings;	/* SIOUX's settings structure ... */

_MSL_BEGIN_EXTERN_C	/*- cc 010410 -*/

/*
 *	extern short SIOUXHandleOneEvent(EventRecord *initialevent);
 *
 *	Tells SIOUX to handle one event.  If initialevent is NULL, then SIOUX
 *	will poll the eventqueue for an event.  For applications which wish to
 *	use an embedded SIOUX window, call this function at the beginning of
 *	your eventloop, and pass it your current event ...
 *
 *	EventRecord *userevent:	The user's event from their call to Get/WaitNextEvent.
 *	returns short:			Was the event handled by SIOUX?
 */
struct EventRecord;
_MSL_IMP_EXP_SIOUX extern short SIOUXHandleOneEvent(struct EventRecord *userevent) _MSL_CANT_THROW;

/*
 *	extern void SIOUXSetTitle(unsigned char title[256]);
 *
 *	Change the SIOUX window's title ...
 *
 *	unsigned char title[256]:	contains a pascal string.
 */

_MSL_IMP_EXP_SIOUX extern void SIOUXSetTitle(unsigned char title[256]) _MSL_CANT_THROW;

_MSL_END_EXTERN_C	/*- cc 010410 -*/

#pragma options align=reset

#endif /* _MSL_SIOUX_H */

/* Change record:
 * mm  970903 Added #include <ansi_parms.h>
 * mm  980427 Addec SIOUXclrscr  MW06842
 * mm  980609 Change that allows user to specify window title before the SIOUX window is created.
 * vss 980807 remove pragma  - no longer supported by compiler
 * mm  981218 Removed mm 980427 change	
 * cc  010410 updated to new namespace macros
 * JWW 010807 Added stub mode setting
 * JWW 010917 Added floating window mode to SIOUX
 * hh  020603 Added no throw spec to functions
 * ejs 030421 Added forward decl for struct EventRecord
 */