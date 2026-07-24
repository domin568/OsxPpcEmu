/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:34 $
 * $Revision: 1.17 $
 */

/*****************************************************************************/
/*  Project...: C++ and ANSI-C Compiler Environment                          */
/*  Purpose...: Menu related functions for SIOUX			                 */
/*****************************************************************************/

#include <SIOUX.h>

#include "SIOUXGlobals.h"
#include "SIOUXWindows.h"

#if SIOUX_USE_WASTE
	#include "LongControls.h"		/* •••LC */
#endif /* SIOUX_USE_WASTE */

#include <string.h>

#if __MACH__
	#include <Carbon/Carbon.h>
#else
	#include <ConditionalMacros.h>		/*- JWW 000315 -*/
	#include <Gestalt.h>
	#include <Icons.h>
	#include <LowMem.h> 
	#include <Processes.h>
	#include <Sound.h>               /*- mm 971006 -*/
	#include <ToolUtils.h>
	#include <ControlDefinitions.h>
#endif

#undef bool	/* JWW - in case it was defined in stdbool.h */
#pragma bool on
#ifndef TRUE		/*- ra 990611 -*/
#define TRUE true
#endif
#ifndef FALSE
#define FALSE false
#endif

/*	The following are declared in unix.c in the ANSI libraries ...*/
#ifdef __cplusplus
extern "C" {
#endif

#if !__MSL__
	extern char __system7present;
	extern void __CheckForSystem7(void);
#else
	extern int __system7present(void);
#endif /* ! __MSL__ */

#ifdef __cplusplus
}
#endif

/************************************************************************/
/* Purpose..: Get the frontmost nonfloating window						*/
/* Input....: ---														*/
/* Returns..: Pointer to the window        								*/
/************************************************************************/
WindowRef SIOUXFrontWindow(void)
{
	WindowRef theWindow;
	
#if TARGET_API_MAC_CARBON
	if (SIOUXSettings.usefloatingwindows)
		theWindow = FrontNonFloatingWindow();
	else
#endif
		theWindow = FrontWindow();
	
	return theWindow;
}

/************************************************************************/
/* Purpose..: Check if the window belongs to us							*/
/* Input....: Pointer to the window										*/
/* Returns..: TRUE ours                    								*/
/************************************************************************/
static void FlashControl(ControlHandle theControl)
{
	unsigned long aLong;

	HiliteControl(theControl, 1);
	Delay(8L, &aLong);
	HiliteControl(theControl, 0);
}

/************************************************************************/
/* Purpose..: Frame a control											*/
/* Input....: Control Handle											*/
/* Returns..: ---                    									*/
/************************************************************************/
static void FrameControl(ControlHandle theControl)
{
	Rect myRect;
#if TARGET_API_MAC_CARBON
	Boolean isDefault;
	Boolean hasAppearance11;
	long result;
	
	hasAppearance11 = false;
	
	if (Gestalt(gestaltAppearanceVersion, &result) == noErr)
		hasAppearance11 = (result >= 0x0110);
	
	if (hasAppearance11)
	{
		isDefault = true;
		SetControlData(theControl, kControlEntireControl, kControlPushButtonDefaultTag,
			sizeof(isDefault), &isDefault);
		DrawOneControl(theControl);
	}
	else
#endif /* TARGET_API_MAC_CARBON */
	{
#if TARGET_API_MAC_CARBON
		Rect controlBounds;
		GetControlBounds( theControl, &controlBounds );
		myRect.top = controlBounds.top - 4;
		myRect.left = controlBounds.left - 4;
		myRect.bottom = controlBounds.bottom + 4;
		myRect.right = controlBounds.right + 4;	
#else	
		HLock((Handle)theControl);
		myRect.top = (*theControl)->contrlRect.top - 4;
		myRect.left = (*theControl)->contrlRect.left - 4;
		myRect.bottom = (*theControl)->contrlRect.bottom + 4;
		myRect.right = (*theControl)->contrlRect.right + 4;
		HUnlock((Handle)theControl);
#endif /* TARGET_API_MAC_CARBON */
	
		PenNormal();
		PenSize(3,3);
		FrameRoundRect(&myRect,16,16);
		PenNormal();
	}
}

/************************************************************************/
/* Purpose..: Set the cancel control									*/
/* Input....: Control Handle											*/
/* Returns..: ---                    									*/
/************************************************************************/
static void SetCancelControl(ControlHandle theControl)
{
#if !TARGET_API_MAC_CARBON
	#pragma unused(theControl)
#else
	Boolean isCancel;
	Boolean hasAppearance11;
	long result;
	
	hasAppearance11 = false;
	
	if (Gestalt(gestaltAppearanceVersion, &result) == noErr)
		hasAppearance11 = (result >= 0x0110);
	
	if (hasAppearance11)
	{
		isCancel = true;
		SetControlData(theControl, kControlEntireControl, kControlPushButtonCancelTag,
			sizeof(isCancel), &isCancel);
		DrawOneControl(theControl);
	}
#endif /* TARGET_API_MAC_CARBON */
}

/************************************************************************/
/* Purpose..: Check if the window belongs to us							*/
/* Input....: Pointer to the window										*/
/* Returns..: TRUE ours                    								*/
/************************************************************************/
Boolean SIOUXIsAppWindow(WindowPtr window)
{
	if ((SIOUXTextWindow == NULL) || (window != SIOUXTextWindow->window))
		return FALSE;
	else
		return TRUE;
}

/************************************************************************/
/* Purpose..: Handles vertical scrolling		 						*/
/* Input....: Handle to the control										*/
/* Input....: part selected												*/
/* Returns..: ---                        								*/
/************************************************************************/
void AdjustText(void)
/*
  this function was originally defined as static void AdjustText( void )
  it was changed to allow access from SIOUX.c and enable Home, End, PageUp
  and PageDown key operation. Something to be aware of in case it breaks
  in the future.  --pcg
*/
{
	/*	Since we can only do an adjust text on the textWindow ...*/
#if SIOUX_USE_WASTE
	WEReference theTE = SIOUXTextWindow->edit;
	long change;
	LongRect weViewRect, weDestRect;
	
	WEGetViewRect( &weViewRect, theTE );
	WEGetDestRect( &weDestRect, theTE );
	
	change = weViewRect.top -
			 weDestRect.top -
			 LCGetValue(SIOUXTextWindow->vscroll) *				/*•••LC */
			 WEGetHeight( 0, 1, SIOUXTextWindow->edit );
	
	if (change != 0) {
		WEScroll(0, change, theTE);
	}
#else
	TEHandle theTE = SIOUXTextWindow->edit;
	short change;
	
	change = (*theTE)->viewRect.top -
			 (*theTE)->destRect.top -
			 GetControlValue(SIOUXTextWindow->vscroll) *
			 (*theTE)->lineHeight;

	if (change != 0) {
		TEScroll(0, change, theTE);
	}
#endif /* SIOUX_USE_WASTE */
}

/************************************************************************/
/* Purpose..: Handles vertical scrolling 								*/
/* Input....: Handle to the control										*/
/* Input....: part selected												*/
/* Returns..: ---                        								*/
/************************************************************************/
static void SetTextView(pSIOUXWin theWindow)
{
#if SIOUX_USE_WASTE
	WEReference theTE = theWindow->edit;
	WindowPtr theWP = theWindow->window;
	
	LongRect weViewRect, weDestRect;
	Rect tempRect;
	
#if TARGET_API_MAC_CARBON
	GetWindowPortBounds(theWP, &tempRect);  /*- RA 000114 -*/
#else
	tempRect = theWP->portRect;
#endif /* TARGET_API_MAC_CARBON */
	WERectToLongRect( &tempRect, &weViewRect );
	/*	Adjust for the scrollbars ...*/
	weViewRect.right -= 16;
	/*	Adjust for the status line ...*/
	if (SIOUXSettings.showstatusline)
		weViewRect.top += WEGetHeight( 0, 1, theTE ) + 4;
	
	WELongRectToRect( &weViewRect, &tempRect );
	InsetRect(&tempRect, 4, 4);
	WERectToLongRect( &tempRect, &weViewRect );
	
	theWindow->linesInFolder = (weViewRect.bottom - weViewRect.top) /
								WEGetHeight( 0, 1, theTE );
	weViewRect.bottom = weViewRect.top +
								(WEGetHeight( 0, 1, theTE ) * theWindow->linesInFolder);
	
	WESetViewRect( &weViewRect, theTE );
	WEGetDestRect( &weDestRect, theTE );
	weDestRect.right = weViewRect.right;
	WESetDestRect( &weViewRect, theTE );
	
	WECalText(theTE);

#else
	TEHandle theTE = theWindow->edit;
	WindowPtr theWP = theWindow->window;
	
	Rect tempRect;
#if TARGET_API_MAC_CARBON
	GetWindowPortBounds(theWP, &(*theTE)->viewRect);
	GetWindowPortBounds(theWP, &tempRect);
#else
	(*theTE)->viewRect = theWP->portRect;
	tempRect = theWP->portRect;
#endif /* TARGET_API_MAC_CARBON */
	/*	Adjust for the scrollbars ...*/
	(*theTE)->viewRect.right -= 16;
	/*	Adjust for the status line ...*/
	if (SIOUXSettings.showstatusline)
		(*theTE)->viewRect.top += (*theTE)->lineHeight + 4;
	
	InsetRect(&(*theTE)->viewRect, 4, 4);
	
	theWindow->linesInFolder = ((*theTE)->viewRect.bottom - (*theTE)->viewRect.top) /
								(*theTE)->lineHeight;
	
	(*theTE)->viewRect.bottom = (*theTE)->viewRect.top +
								((*theTE)->lineHeight * theWindow->linesInFolder);
	
	(*theTE)->destRect.right = (*theTE)->viewRect.right;
	
	TECalText(theTE);

#endif /* SIOUX_USE_WASTE */
}

/************************************************************************/
/* Purpose..: Draw the framing lines ...		  						*/
/* Input....: Pointer to the window	    								*/
/* Returns..: ---                        								*/
/************************************************************************/
void SIOUXDrawGrowBox(WindowPtr theWindow)
{
	Rect aRect;
	short width, height;
	GrafPtr savePort;

	GetPort(&savePort);
	SetPortWindowPort(theWindow);/*- ra 990612 -*/

#if TARGET_API_MAC_CARBON
	{
		Rect portRect;
		GetWindowPortBounds(theWindow, &portRect);
		width = portRect.right - portRect.left;
		height = portRect.bottom - portRect.top;
	}
#else
	width = theWindow->portRect.right - theWindow->portRect.left;
	height = theWindow->portRect.bottom - theWindow->portRect.top;
#endif /* TARGET_API_MAC_CARBON */
	
    SetRect(&aRect, width - 15, -1, width, height);
    ClipRect(&aRect);
    DrawGrowIcon(theWindow);
    ClipRect(&SIOUXBigRect);

	SetPort(savePort);
}
				
/************************************************************************/
/* Purpose..: Update the window ...  									*/
/* Input....: Pointer to the Window										*/
/* Returns..: ---                        								*/
/************************************************************************/
void SIOUXUpdateWindow(WindowPtr theWindow)
{
	GrafPtr savePort;
	Rect portRect;
	
	GetPort(&savePort);
	SetPortWindowPort(theWindow);	/*- ra 990612 -*/

	BeginUpdate(theWindow);
#if TARGET_API_MAC_CARBON
	GetWindowPortBounds(theWindow, &portRect);
	EraseRect(&portRect);
#else
	portRect = theWindow->portRect;
	EraseRect(&portRect);
#endif /* TARGET_API_MAC_CARBON */
	if (theWindow == SIOUXTextWindow->window) { /*- ra 990612 -*/
		DrawControls(theWindow);
		SIOUXDrawGrowBox(theWindow);
		SIOUXUpdateStatusLine(theWindow);
		
#if SIOUX_USE_WASTE
		WEUpdate(nil, SIOUXTextWindow->edit); /*- ra 990612 -*/
#else
		TEUpdate(&portRect, SIOUXTextWindow->edit);
#endif /* SIOUX_USE_WASTE */
	
	}
	EndUpdate(theWindow);

	SetPort(savePort);
}

/************************************************************************/
/* Purpose..: Update the Scrollbar's state		 						*/
/* Input....: ---														*/
/* Returns..: ---                        								*/
/************************************************************************/
void SIOUXUpdateScrollbar(void)
{
#if SIOUX_USE_WASTE
	long topLineNumber;
	long lines;
	long height;
	WEReference theTE = SIOUXTextWindow->edit;
	
	LongRect weViewRect, weDestRect;
	WEGetViewRect( &weViewRect, theTE );
	WEGetDestRect( &weDestRect, theTE );
	
	height = WEGetHeight( 0, 1, theTE );
	topLineNumber = (weViewRect.top - weDestRect.top) /
					WEGetHeight( 0, 1, theTE );
	
	lines = WECountLines( theTE ) - SIOUXTextWindow->linesInFolder;
	/*	Following is to correct a bug in TextEdit where if the last char*/
	/*	is an eol the line count will be wrong ...*/
	/* Apparently, this is needed for WASTE as well.  -pcg */
	if ((WEGetTextLength( theTE ) > 0) &&
		( WEGetChar( WEGetTextLength( theTE ) - 1, theTE ) == 0x0d ))
	{
		lines++;
	}
#else
	short topLineNumber;
	short lines;
	TEHandle theTE = SIOUXTextWindow->edit;
	
	topLineNumber = ((*theTE)->viewRect.top - (*theTE)->destRect.top) /
					((*theTE)->lineHeight);
	
	lines = (*theTE)->nLines - SIOUXTextWindow->linesInFolder;
	/*	Following is to correct a bug in TextEdit where if the last char*/
	/*	is an eol the line count will be wrong ...*/
	if (((*theTE)->teLength > 0) &&
		((*(*theTE)->hText)[(*theTE)->teLength - 1] == 0x0d))
	{
		lines++;
	}
#endif /* SIOUX_USE_WASTE */

	if (lines < 0) {
		lines = 0;
	}

#if SIOUX_USE_WASTE
	LCSetMax(SIOUXTextWindow->vscroll, lines);		/* •••LC */
	LCSetValue(SIOUXTextWindow->vscroll, topLineNumber);
#else
	SetControlMaximum(SIOUXTextWindow->vscroll, lines);
	SetControlValue(SIOUXTextWindow->vscroll, topLineNumber);
#endif /* SIOUX_USE_WASTE */
}

/************************************************************************/
/* Purpose..: Handles vertical scrolling		 						*/
/* Input....: Handle to the control										*/
/* Input....: Distance to scroll										*/
/* Returns..: ---                        								*/
/************************************************************************/
#if SIOUX_USE_WASTE
	void MoveScrollBox(ControlHandle theControl, long scrollDistance)
#else
	void MoveScrollBox(ControlHandle theControl, short scrollDistance)
#endif /* SIOUX_USE_WASTE */
/*
  this function was originally defined as static void MoveScrollBox( void )
  it was changed to allow access from SIOUX.c and enable Home, End, PageUp
  and PageDown key operation. Something to be aware of in case it breaks
  in the future.  --pcg
*/
{
#if SIOUX_USE_WASTE
	long oldSetting = LCGetValue(theControl);		/*•••LC */
	long maxValue = LCGetMax(theControl);
	long setting;
#else
	short oldSetting = GetControlValue(theControl);
	short maxValue = GetControlMaximum(theControl);
	short setting;
#endif /* SIOUX_USE_WASTE */
	
	setting = oldSetting - scrollDistance;
	if (setting < 0) {
		setting = 0;
	} else {
		if (setting > maxValue) {
			setting = maxValue;
		}
	}

#if SIOUX_USE_WASTE									/*•••LC */
	LCSetValue(theControl, setting);
#else
	SetControlValue(theControl, setting);
#endif /* SIOUX_USE_WASTE */
}

/************************************************************************/
/* Purpose..: Draws SIOUX's status line			 						*/
/* Input....: Pointer to the window										*/
/* Returns..: ---                        								*/
/************************************************************************/
void SIOUXUpdateStatusLine(WindowPtr theWindow)
{
	GrafPtr saveport;
	Rect box;
	char *state = "SIOUX state:";
	char *idle = "idle.";
	char *printfing = "handling output.";
	char *scanfing = "handling input.";
	char *terminated = "application has terminated.";
	char *aborted = "application has aborted.";
#if SIOUX_USE_WASTE
	SInt32 lineHeight = WEGetHeight( 0, 1, SIOUXTextWindow->edit );
#else
	short lineHeight = (*SIOUXTextWindow->edit)->lineHeight;
#endif /* SIOUX_USE_WASTE */

	Rect portRect;

	if (!SIOUXSettings.showstatusline)
		return;

	GetPort(&saveport);
	SetPortWindowPort(theWindow);	/*- ra 990612 -*/

#if TARGET_API_MAC_CARBON
	GetWindowPortBounds(theWindow, &portRect);
#else
	portRect = theWindow->portRect;
#endif /* TARGET_API_MAC_CARBON */

	SetRect(&box,0,0,portRect.right - 15,lineHeight + 4 - 1);
	InsetRect(&box, -1, -1);
	ClipRect(&box);
	InsetRect(&box, 1, 1);
	box.left = 80;
	EraseRect(&box);

	MoveTo(0, lineHeight + 4 - 1);
	Line(portRect.right - 15, 0);
	TextFont(SIOUXSettings.fontid);
	TextSize(SIOUXSettings.fontsize);
	TextFace(SIOUXSettings.fontface);

	/*	Draw SIOUX State: */
	MoveTo(4, lineHeight);
	DrawText(state,0,strlen(state));
	/*	Draw state ... */
	MoveTo(80, lineHeight);
	switch(SIOUXState) {
		case IDLE:
			DrawText(idle,0,strlen(idle));
			break;
		case PRINTFING:
			DrawText(printfing,0,strlen(printfing));
			break;
		case SCANFING:
			DrawText(scanfing,0,strlen(scanfing));
			break;
		case TERMINATED:
			DrawText(terminated,0,strlen(terminated));
			break;
		case ABORTED:
			DrawText(aborted,0,strlen(aborted));
			break;
		case OFF:
		default:
			break;
	}

    ClipRect(&SIOUXBigRect);
    SetPort(saveport);
}

/************************************************************************/
/* Purpose..: Grow the window (doesn't draw the bottom line)			*/
/* Input....: Pointer to window to grow                     			*/
/* Input....: Initial mouse point										*/
/* Returns..: ---														*/
/************************************************************************/
void SIOUXMyGrowWindow(WindowPtr theWindow, Point thePoint)
{
	GrafPtr savePort;
	Rect scrollRect;
	long result;
#if SIOUX_USE_WASTE
	SInt32 lineHeight = WEGetHeight( 0, 1, SIOUXTextWindow->edit );
	long cntlheight;
#else
	short lineHeight = (*SIOUXTextWindow->edit)->lineHeight;
	short cntlheight;
#endif /* SIOUX_USE_WASTE */

	Rect portRect;

	GetPort(&savePort);
	SetPortWindowPort(theWindow);	/*- ra 990612 -*/
	
#if TARGET_API_MAC_CARBON
	GetWindowPortBounds(theWindow, &portRect);
#else
	portRect = theWindow->portRect;
#endif /* TARGET_API_MAC_CARBON */
	result = GrowWindow(theWindow, thePoint, &SIOUXDragRect);
	if (result == 0)
		return;

#if TARGET_API_MAC_CARBON
	GetWindowPortBounds(theWindow, &portRect);
#else
	portRect = theWindow->portRect;
#endif /* TARGET_API_MAC_CARBON */

	EraseRect(&portRect);

	SizeWindow(theWindow,
			   (((LoWord(result) - 24) / CharWidth('0')) * CharWidth('0')) + 24,
			   (((HiWord(result) - 8) / lineHeight) * lineHeight) + 8,
			   false);

#if TARGET_API_MAC_CARBON
	GetWindowPortBounds(theWindow, &portRect);
#else
	portRect = theWindow->portRect;
#endif /* TARGET_API_MAC_CARBON */

#if TARGET_API_MAC_CARBON
	InvalWindowRect(theWindow, &portRect);
#else
	InvalRect(&portRect);
#endif /* TARGET_API_MAC_CARBON */
	/* jd 980924 - SIOUXMyGrowWindow() should only be called from HandleMouseDownEvent(),
	   and by that time as well it should be confirmed as well that theWindow is the
	   same as the SIOUXTextWindow->window. But just to be safe.... */
	
	if ( theWindow == SIOUXTextWindow->window ) {
		SetTextView(SIOUXTextWindow);
	} else {
		/* jd - if you hit this, I wish you good luck */
	SetTextView((pSIOUXWin)theWindow);
	}


	cntlheight = portRect.top - 1;
	if (SIOUXSettings.showstatusline)
		cntlheight += lineHeight + 4;
	
	/* jd - see my comments above about calling SetTextView */
	
	if ( theWindow == SIOUXTextWindow->window ) {
		MoveControl(SIOUXTextWindow->vscroll,
				portRect.right - 15,
				cntlheight);
	} else {
		/* jd - again, if you get here, good luck */
	MoveControl(((pSIOUXWin)theWindow)->vscroll,
				portRect.right - 15,
				cntlheight);
	}
	
	/*	16 pixels wide and top - bottom of screen plus 1 at both ends ...*/
	cntlheight = portRect.bottom - portRect.top - 13;
	if (SIOUXSettings.showstatusline)
		cntlheight -= lineHeight + 4;
		
	/* jd - see above comments again */
	if ( theWindow == SIOUXTextWindow->window ) {
		SizeControl(SIOUXTextWindow->vscroll, 16, cntlheight);
	} else {
	SizeControl(((pSIOUXWin)theWindow)->vscroll, 16, cntlheight);
	}
	
	/* jd- ditto with the above comments */
#if TARGET_API_MAC_CARBON
	{
		ControlHandle	theScroll;
		if ( theWindow == SIOUXTextWindow->window ) {
			theScroll = SIOUXTextWindow->vscroll;
		} else {
			theScroll = ((pSIOUXWin)theWindow)->vscroll;
		}
		GetControlBounds( theScroll, &scrollRect );
		ValidWindowRect( GetControlOwner( theScroll ), &scrollRect );
	}
#else
	if ( theWindow == SIOUXTextWindow->window ) {
		scrollRect = (*(SIOUXTextWindow->vscroll))->contrlRect;
	} else {
	scrollRect = (*((pSIOUXWin)theWindow)->vscroll)->contrlRect;
	}
	ValidRect(&scrollRect);
#endif /* TARGET_API_MAC_CARBON */
	
	SIOUXUpdateScrollbar();
	AdjustText();
	
	SetPort(savePort);
}

/************************************************************************/
/* Purpose..: Handles vertical scrolling 								*/
/* Input....: Handle to the control										*/
/* Input....: part selected												*/
/* Returns..: ---                        								*/
/************************************************************************/
static pascal void VActionProc(ControlHandle theControl, short part)
{
	/*	Since the graphics window will not have a scrollbar,*/
	/*	then we can assume that if we are in	this procedure the frontwindow*/
	/*	is the textWindow ...*/
#if SIOUX_USE_WASTE
	WEReference theTE = SIOUXTextWindow->edit;
	long scrollAdjust;
	LongRect weViewRect;
#else
	TEHandle theTE = SIOUXTextWindow->edit;
	short scrollAdjust;
#endif /* SIOUX_USE_WASTE */
	
	if (part == 0) {
		return;
	}

	switch (part) {
		case kControlUpButtonPart:
		case kControlDownButtonPart:
			scrollAdjust = 1;
			break;
		case kControlPageUpPart:
		case kControlPageDownPart:
#if SIOUX_USE_WASTE
			WEGetViewRect( &weViewRect, theTE );
			scrollAdjust = (weViewRect.bottom - weViewRect.top) /
			   		 	   WEGetHeight( 0, 1, theTE );
#else
			scrollAdjust = ((*theTE)->viewRect.bottom - (*theTE)->viewRect.top) /
			   		 	   ((*theTE)->lineHeight);
#endif /* SIOUX_USE_WASTE */
			break;
	}

	if ((part == kControlDownButtonPart) || (part == kControlPageDownPart)) {
		scrollAdjust = -scrollAdjust;
	}
	MoveScrollBox(theControl, scrollAdjust);
	AdjustText();
}

/************************************************************************/
/* Purpose..: Handles a click in the content region of a window 		*/
/* Input....: The window clicked in ...									*/
/* Input....: The event which occurred ...								*/
/* Returns..: ---                        								*/
/************************************************************************/
void SIOUXDoContentClick(WindowPtr window, EventRecord *theEvent)
{
	short part;
	ControlHandle theControl;
	GrafPtr savePort;
#if SIOUX_USE_WASTE
	LongRect weViewRect;
	Rect tempRect;
	SInt32 weSelStart, weSelEnd;
#endif /* SIOUX_USE_WASTE */
	
	GetPort(&savePort);
	SetPortWindowPort(window);	/*- ra 990612 -*/
	GlobalToLocal(&theEvent->where);

	if ((part = FindControl(theEvent->where, window, &theControl)) == 0) {
	
#if SIOUX_USE_WASTE
		/*	Check to see if the user clicked in the textWindow ...*/
		WEGetViewRect( &weViewRect, SIOUXTextWindow->edit );
		WELongRectToRect( &weViewRect, &tempRect );
		if (PtInRect(theEvent->where, &tempRect)) {
			WEClick(theEvent->where,
					theEvent->modifiers,
					theEvent->when,
					SIOUXTextWindow->edit);

			WEGetSelection( &weSelStart, &weSelEnd, SIOUXTextWindow->edit );
			if ( ( weSelStart == weSelEnd) &&
				!SIOUXisinrange(SIOUXselstart, SIOUXTextWindow->edit))
			{
				WESetSelection(SIOUXselstart, SIOUXselstart, SIOUXTextWindow->edit);
			}
#else
		/*	Check to see if the user clicked in the textWindow ...*/
		if (PtInRect(theEvent->where, &((*SIOUXTextWindow->edit)->viewRect))) {
			TEClick(theEvent->where,
					(theEvent->modifiers & shiftKey) != 0,
					SIOUXTextWindow->edit);
			if (((*SIOUXTextWindow->edit)->selStart == (*SIOUXTextWindow->edit)->selEnd) &&
				!SIOUXisinrange(SIOUXselstart, SIOUXTextWindow->edit))
			{
				TESetSelect(SIOUXselstart, SIOUXselstart, SIOUXTextWindow->edit);
			}
#endif /* SIOUX_USE_WASTE */
			
			SIOUXUpdateScrollbar();
		}
	} else if (part == kControlIndicatorPart) {
		TrackControl(theControl, theEvent->where, 0L);
#if SIOUX_USE_WASTE		/* •••LC */
		LCSynch(theControl);
#endif /* SIOUX_USE_WASTE */
		AdjustText();
	} else {
		ControlActionUPP tempUPP;
		
		tempUPP = NewControlActionUPP(VActionProc);
		TrackControl(theControl, theEvent->where, tempUPP);
	#if TARGET_API_MAC_CARBON
		DisposeControlActionUPP(tempUPP); /*- RA 990611 -*/
	#else
		DisposeRoutineDescriptor(tempUPP);
	#endif /* TARGET_API_MAC_CARBON */	

	}
	SetPort(savePort);
}

#if SIOUX_USE_WASTE
static pascal void ScrollProc ( WEReference /*edit*/ )
{
	SIOUXUpdateScrollbar ( ) ;
}
#endif

/************************************************************************/
/* Purpose..: Initialize the SIOUX textWindow							*/
/* Input....: Number of columns											*/
/* Input....: Number of rows											*/
/* Returns..: TRUE the window was initialized							*/
/************************************************************************/
Boolean SIOUXSetupTextWindow(void)
{
	Rect aRect = {0,0,1,1};
	FontInfo fi;
	
#if SIOUX_USE_WASTE
	static WEScrollUPP scrollProc = nil ;
	LongRect tempLongRect;
	long lineHeight, screenHeight, screenWidth;
	UInt32 weFeatures;/*SInt32 response; */	/* •••MP */
#else
	short lineHeight, screenHeight, screenWidth;
#endif /* SIOUX_USE_WASTE */
	
	ProcessSerialNumber psn;
	ProcessInfoRec pinfo;
	OSErr err;
	Str63	AppName = "\p";
	FSSpec	spec;
	GrafPtr saveport;
#if TARGET_API_MAC_CARBON
	BitMap	screenBitMap;
	Rect	screenBits;
	GetQDGlobalsScreenBits(&screenBitMap);
	screenBits = screenBitMap.bounds;
#else
	Rect screenBits = qd.screenBits.bounds;
#endif /* TARGET_API_MAC_CARBON */

	/*	Get process Info*/

	GetPort(&saveport);

#if ! __MSL__
	if (__system7present == -1)
		__CheckForSystem7();

	if (__system7present)
#else
  #if !__MACH__
	if (__system7present())
  #endif
#endif /* __MSL__ */
	{
		err = GetCurrentProcess(&psn);
		pinfo.processName = AppName;
		pinfo.processInfoLength = sizeof(pinfo);
		pinfo.processAppSpec = &spec;
		err = GetProcessInformation(&psn,&pinfo);

		if (spec.name[0] <= 59) {
			spec.name[++(spec.name[0])] = '.';
			spec.name[++(spec.name[0])] = 'o';
			spec.name[++(spec.name[0])] = 'u';
			spec.name[++(spec.name[0])] = 't';
		}
		if (SIOUXSettings.userwindowtitle != NULL)   /*- mm 980609 -*/
			BlockMoveData(SIOUXSettings.userwindowtitle, spec.name, 
											(long)SIOUXSettings.userwindowtitle[0]+1);

	}

	if (*AppName == 0)
		BlockMoveData("\pSIOUX TextWindow", AppName, 17L);

	/*	Initialize the TextWindPtr ...*/
	SIOUXTextWindow = (pSIOUXWin)NewPtr(sizeof(tSIOUXWin));
	if (SIOUXTextWindow == 0)
		return FALSE;
/*	SIOUXTextWindow = &SIOUXTextWindowBuf*/

	/*- jd 980923 -*/
	SIOUXTextWindow->window = NewWindow(NULL,
										&aRect,
										spec.name,
										FALSE,
										documentProc,
										(WindowPtr)-1L,
										FALSE,
										0L);
	if ( SIOUXTextWindow->window == NULL ) {
		return (FALSE);
	}
	
	SetPortWindowPort(SIOUXTextWindow->window);	/*- ra 990612 -*/

	/*	Set the font information ...*/
	TextFont(SIOUXSettings.fontid);
	TextSize(SIOUXSettings.fontsize);
	TextFace(SIOUXSettings.fontface);
	GetFontInfo(&fi);
	lineHeight = fi.ascent + fi.descent + fi.leading;

	/*	Size the window ...*/
	SIOUXSettings.columns = (SIOUXSettings.columns <= 0) ? 80 : SIOUXSettings.columns;
	SIOUXSettings.rows = (SIOUXSettings.rows <= 0) ? 24 : SIOUXSettings.rows;
	if (SIOUXSettings.showstatusline)
		aRect.bottom = 2*4 + (SIOUXSettings.rows + 1)*lineHeight + 4;	/*	2*indent + ... + titlebar*/
	else
		aRect.bottom = 2*4 + (SIOUXSettings.rows)*lineHeight + 4;	/*	2*indent + ... + titlebar*/
	aRect.right = 2*4 + SIOUXSettings.columns*CharWidth('0') + 16,	/*	2*indent + ... + scrollbar*/

#if TARGET_API_MAC_CARBON
	screenHeight = screenBits.bottom - screenBits.top - GetMBarHeight() - 24;	/*	screen height ...*/
	screenWidth = screenBits.right - screenBits.left;
#else
	screenHeight = screenBits.bottom - screenBits.top - LMGetMBarHeight() - 24;	/*	screen height ...*/
	screenWidth = screenBits.right - screenBits.left;
#endif /* TARGET_API_MAC_CARBON */

	if (aRect.bottom > screenHeight)
		aRect.bottom = ((screenHeight - 2*4 - 4) / lineHeight) * lineHeight + 2*4 + 4;

	/*	Move the window to the correct place ...*/
	if (SIOUXSettings.toppixel == 0 && SIOUXSettings.leftpixel == 0) {
		if (aRect.right > screenWidth) /*	The window is wider than the screen*/
			aRect.right = ((screenWidth - 2*4 - 16 - 20) / CharWidth('0')) * CharWidth('0') + 2*4 + 16;

	#if TARGET_API_MAC_CARBON
		MoveWindow (SIOUXTextWindow->window,
					((screenBits.right - screenBits.left - aRect.right) / 2),
					((screenHeight - aRect.bottom) / 5 + GetMBarHeight() + 24),
					FALSE);
	#else
		MoveWindow (SIOUXTextWindow->window,
					((screenBits.right - screenBits.left - aRect.right) / 2),
					((screenHeight - aRect.bottom) / 5 + LMGetMBarHeight() + 24),
					FALSE);
	#endif /* TARGET_API_MAC_CARBON */
	} else
		MoveWindow (SIOUXTextWindow->window,
					SIOUXSettings.leftpixel, SIOUXSettings.toppixel,
					FALSE);
	/*	Now make it the correct size ...*/
	SizeWindow(SIOUXTextWindow->window, aRect.right, aRect.bottom, TRUE);

	/*	Create the vertical scrollbar ...*/
#if TARGET_API_MAC_CARBON
	GetWindowPortBounds(SIOUXTextWindow->window, &aRect);
#else
	aRect = SIOUXTextWindow->window->portRect;
#endif /* TARGET_API_MAC_CARBON */
	aRect.left = aRect.right - 15;
	aRect.right += 1;
	aRect.bottom -= 14;
	aRect.top -= 1;
	if (SIOUXSettings.showstatusline)
		aRect.top += lineHeight + 4;	/*	factor in the status window ...*/

	SIOUXTextWindow->vscroll = NewControl(SIOUXTextWindow->window, &aRect, "\p",
									 TRUE, 0, 0, 0, scrollBarProc, 0L);

#if SIOUX_USE_WASTE		/* •••LC */
	/*	Attach a LongControls record to the scrollbar */
	err = LCAttach(SIOUXTextWindow->vscroll);	/* what do I do with the error code? */
#endif

	ShowWindow(SIOUXTextWindow->window);

	/*	Create the TEHandle ...*/
#if TARGET_API_MAC_CARBON
	GetPortBounds(GetQDGlobalsThePort(),&aRect);
#else
	aRect = qd.thePort->portRect;
#endif /* TARGET_API_MAC_CARBON */
	aRect.right -= 15;
	if (SIOUXSettings.showstatusline)
		aRect.top += lineHeight + 4;
	InsetRect(&aRect, 4, 4);

#if SIOUX_USE_WASTE
	WERectToLongRect( &aRect, &tempLongRect );
	weFeatures = ( weDoAutoScroll | weDoDrawOffscreen | weDoMonoStyled );
	if ( SIOUXSettings.wasteusetempmemory )
		weFeatures |= weDoUseTempMem;
	if ( SIOUXSettings.enabledraganddrop )
		weFeatures |= ( weDoDragAndDrop | weDoOutlineHilite );
	if ( SIOUXSettings.outlinehilite )
		weFeatures |= weDoOutlineHilite;
	err = WENew(&tempLongRect, &tempLongRect, weFeatures, &SIOUXTextWindow->edit);
	
	/*	install the scroll callback */
	if ( scrollProc == nil )
	{
		scrollProc = NewWEScrollUPP( ScrollProc );  /*- RA 990109 -*/
	}
	err = WESetInfo( weScrollProc, & scrollProc, SIOUXTextWindow->edit );

#else
	SIOUXTextWindow->edit = TENew(&aRect, &aRect);

	TEAutoView(TRUE, SIOUXTextWindow->edit);
#endif /* SIOUX_USE_WASTE */
	
	SIOUXTextWindow->linesInFolder = SIOUXSettings.rows;	/*	Number of lines visible ...*/
	SIOUXTextWindow->dirty = 0;								/*	Window is clean ...*/
	SIOUXTextWindow->dirid = 0;								/*	Window hasn't been saved yet ...*/

	SIOUXUpdateWindow(SIOUXTextWindow->window);

	SetPort(saveport);
	return(TRUE);
}

/****************************************************************/
/* Purpose..: Display a simple aboutbox  						*/
/* Input....: ---												*/
/* Returns..: ---												*/
/****************************************************************/
void SIOUXDoAboutBox(void)
{
	WindowPtr wp;
	GrafPtr savePort;
	EventRecord theEvent;
	Boolean isNewAuthor;
#if SIOUX_USE_WASTE
	Rect aRect = {0, 0,196, 320};
#else
	Rect aRect = {0, 0,125, 260};
#endif /* SIOUX_USE_WASTE */
	RGBColor aRed = {65535, 0, 0};
	RGBColor aBlack = {0, 0, 0};
	short height, width;
#if TARGET_API_MAC_CARBON
	BitMap	screenBitMap;
	Rect	screenBits;
	Cursor theArrow;
	GetQDGlobalsScreenBits(&screenBitMap);
	screenBits = screenBitMap.bounds;
	SetCursor(GetQDGlobalsArrow(&theArrow));
	isNewAuthor = GetCurrentKeyModifiers() != 0;
#else
	Rect screenBits = qd.screenBits.bounds;
	SetCursor(&qd.arrow);
	isNewAuthor = FALSE;
#endif /* TARGET_API_MAC_CARBON */

	GetPort(&savePort);
	
	/* Center it horizontally and 20% down vertically */
#if TARGET_API_MAC_CARBON
	width = (screenBits.right - screenBits.left - aRect.right) / 2;
	height = (screenBits.bottom - screenBits.top - GetMBarHeight() - aRect.bottom) / 5 + GetMBarHeight();
#else
	width = (qd.screenBits.bounds.right - qd.screenBits.bounds.left - aRect.right) / 2;
	height = (qd.screenBits.bounds.bottom - qd.screenBits.bounds.top - LMGetMBarHeight() - aRect.bottom) / 5 + LMGetMBarHeight();
#endif /* TARGET_API_MAC_CARBON */
		
	OffsetRect(&aRect, width, height);
	
	/* Create a simple window without button ... */
	if ((wp = NewWindow(0L, &aRect, "\p", TRUE, dBoxProc, (WindowPtr)-1L, FALSE, 0L)) == 0L) {
		SysBeep(1);
		return;
	}
	
	SetPortWindowPort(wp); /*- ra 990612 -*/
	TextFont(0);
	/* Draw the text into the window ... */
	TextSize(36);
	TextFace(bold);
	RGBForeColor(&aRed);
	
#if SIOUX_USE_WASTE
	SetRect(&aRect, 0, 5, 320, 55);
	TETextBox("SIOUX-WASTE", 11, &aRect, teCenter);
	TextSize(12);
	TextFace(0);
	RGBForeColor(&aBlack);
	SetRect(&aRect, 0, 55, 320, 75);
	TETextBox("Simple Input/Output User eXchange", 33, &aRect, teCenter);
	
	SetRect(&aRect, 0, 75, 320, 92);
	if (isNewAuthor)
		TETextBox("By: Josef W. Wankerl", 20, &aRect, teCenter);
	else
		TETextBox("By: Berardino E. Baratta", 24, &aRect, teCenter);
	SetRect(&aRect, 0, 92, 320, 112);
	TETextBox("© 1993-2002 Metrowerks Corporation", 34, &aRect, teCenter);
	
	SetRect(&aRect, 0, 112, 320, 129);
	TETextBox("WASTE Text Engine", 17, &aRect, teCenter);
	SetRect(&aRect, 0, 129, 320, 149);
	TETextBox("© 1993-2000 Marco Piovanelli", 28, &aRect, teCenter);
	
	SetRect(&aRect, 0, 149, 320, 166);
	TETextBox("TextEdit-to-WASTE conversion", 28, &aRect, teCenter);
	SetRect(&aRect, 0, 166, 320, 186);
	TETextBox("© 1999 Paul Goracke", 19, &aRect, teCenter);
#else
	SetRect(&aRect, 0, 5, 260, 55);
	TETextBox("SIOUX", 5, &aRect, teCenter);
	TextSize(12);
	TextFace(0);
	RGBForeColor(&aBlack);
	SetRect(&aRect, 0, 55, 260, 75);
	TETextBox("Simple Input/Output User eXchange", 33, &aRect, teCenter);
	SetRect(&aRect, 0, 75, 260, 95);
	if (isNewAuthor)
		TETextBox("By: Josef W. Wankerl", 20, &aRect, teCenter);
	else
		TETextBox("By: Berardino E. Baratta", 24, &aRect, teCenter);
	SetRect(&aRect, 0, 95, 260, 115);
	TETextBox("© Metrowerks Corporation 1993-2002", 34, &aRect, teCenter);
#endif /* SIOUX_USE_WASTE */
	
	if (SIOUXUseWaitNextEvent)
	{
		while (!WaitNextEvent(mDownMask | keyDownMask, &theEvent, SIOUXSettings.sleep, NULL))
			/* just loop */ ;
	}
	else 
	{
		while (!GetNextEvent(mDownMask | keyDownMask, &theEvent))
			/* just loop */ ;
	}
	
	DisposeWindow(wp);
	SetPort(savePort);
}

/****************************************************************/
/* Purpose..: Display an alert style window  					*/
/* Input....: Do we initialize the toolbox                      */
/* Input....: The window's rectangle                       		*/
/* Returns..: TRUE the window was opened                        */
/****************************************************************/
void SIOUXCantSaveAlert(StrFileName filename) /*- ra 990612 -*/
{
	WindowPtr wp, theWindow;
	GrafPtr savePort;
	EventRecord theEvent;
	Handle theIcon;
	ControlHandle okButton, dummyCntl;
	Rect aRect = {0, 0, 75, 270};
	Boolean done = FALSE;
	Boolean gotEvent;
	char aString[100] = "An error occurred while saving “";
	short length;
	short height, width;
#if TARGET_API_MAC_CARBON
	BitMap	screenBitMap;
	Rect	screenBits;
	Cursor theArrow;
	SetCursor(GetQDGlobalsArrow(&theArrow));
	GetQDGlobalsScreenBits(&screenBitMap);
	screenBits = screenBitMap.bounds;
#else
	Rect screenBits = qd.screenBits.bounds;
	SetCursor(&qd.arrow);
#endif /* TARGET_API_MAC_CARBON */

	GetPort(&savePort);
	
	/*	Center it horizontally and 20% down vertically*/
#if TARGET_API_MAC_CARBON
	width = (screenBits.right - screenBits.left - aRect.right) / 2;
	height = (screenBits.bottom - screenBits.top - GetMBarHeight() - aRect.bottom) / 5 + GetMBarHeight();
#else
	width = (qd.screenBits.bounds.right - qd.screenBits.bounds.left - aRect.right) / 2;
	height = (qd.screenBits.bounds.bottom - qd.screenBits.bounds.top - LMGetMBarHeight() - aRect.bottom) / 5 + LMGetMBarHeight();
#endif /* TARGET_API_MAC_CARBON */
	
	OffsetRect(&aRect, width, height);
	
	/*	Create a simple window with an OK button*/
	if ((wp = NewWindow(0L, &aRect, "\p", TRUE, dBoxProc,
						(WindowPtr)-1L, FALSE, 0L)) == 0L)
	{
		SysBeep(10);
		return;
	}

	SetPortWindowPort(wp);	/*- ra 990612 -*/
	TextFont(0);
	TextSize(12);
	TextFace(0);
	SetRect(&aRect, 50, 4, 260, 46);
	length = strlen(aString);
	BlockMoveData(&filename[1], &aString[length], filename[0]);
	aString[length + filename[0] + 1] = '\0';
	strcat(aString, "”.");
	TETextBox(aString, strlen(aString), &aRect, teForceLeft);

	SetRect(&aRect, 8, 8, 40, 40);
	theIcon = GetIcon(0);
	PlotIcon(&aRect, theIcon);

	SetRect(&aRect, 105, 50, 165, 68);
	okButton = NewControl(wp, &aRect, "\pOK", TRUE, 0, 0, 0, pushButProc|kControlUsesOwningWindowsFontVariant, 0);

	/*	Outline the default button ...*/
	FrameControl(okButton);
	
	while (!done) {
		if (SIOUXUseWaitNextEvent)
			gotEvent = WaitNextEvent(mDownMask | keyDownMask, &theEvent, SIOUXSettings.sleep, NULL);
		else 
			gotEvent = GetNextEvent(mDownMask | keyDownMask, &theEvent);
		
		if(gotEvent) {
			if (theEvent.what == mouseDown) {
				if ((FindWindow(theEvent.where, &theWindow) == inContent) && (theWindow == wp)) {
					GlobalToLocal(&theEvent.where);
					if (FindControl(theEvent.where, wp, &dummyCntl) == kControlButtonPart)
						if (TrackControl(dummyCntl, theEvent.where, 0L) != 0) {
							done = TRUE;
						}
				}
			} else if (theEvent.what == keyDown) {
				char key;
				
				key = theEvent.message & charCodeMask;
				if (key == 0x0d || key == 0x03) {
					FlashControl(okButton);
					done = TRUE;
				}
			}
		}
	}
	
	DisposeControl(okButton);
	DisposeWindow(wp);
	/* ReleaseResource(theIcon);*/             /*- mm 980415 -*/
	SetPort(savePort);
}
/****************************************************************/
/* Purpose..: Ask the user if he/she wishes to save				*/
/* Input....: The name of the file                       		*/
/* Returns..: Yes, No, Cancel			                        */
/****************************************************************/
short SIOUXYesNoCancelAlert(StrFileName filename)	
{
	WindowPtr wp, theWindow;
	GrafPtr savePort;
	EventRecord theEvent;
	Handle theIcon;
	short item;
	ControlHandle yesButton, noButton, cancelButton, dummyCntl;
	Rect aRect = {0, 0, 89, 386};
	char aString[110] = "Do you wish to save “";
	Boolean done = FALSE;
	Boolean gotEvent;
	short length;
	short height, width;
#if TARGET_API_MAC_CARBON
	BitMap	screenBitMap;
	Rect	screenBits;
	Cursor theArrow;
	SetCursor(GetQDGlobalsArrow(&theArrow));
	GetQDGlobalsScreenBits(&screenBitMap);
	screenBits = screenBitMap.bounds;
#else
	Rect screenBits = qd.screenBits.bounds;
	SetCursor(&qd.arrow);
#endif /* TARGET_API_MAC_CARBON */

	GetPort(&savePort);
	
	/*	Center it horizontally and 20% down vertically*/
#if TARGET_API_MAC_CARBON
	width = (screenBits.right - screenBits.left - aRect.right) / 2;
	height = (screenBits.bottom - screenBits.top - GetMBarHeight() - aRect.bottom) / 5 + GetMBarHeight();
#else
	width = (qd.screenBits.bounds.right - qd.screenBits.bounds.left - aRect.right) / 2;
	height = (qd.screenBits.bounds.bottom - qd.screenBits.bounds.top - LMGetMBarHeight() - aRect.bottom) / 5 + LMGetMBarHeight();
#endif /* TARGET_API_MAC_CARBON */
	
	OffsetRect(&aRect, width, height);
	
	/*	Create a simple window without button ...*/
	if ((wp = NewWindow(0L, &aRect, "\p", TRUE, dBoxProc,
						(WindowPtr)-1L, FALSE, 0L)) == 0L)
	{
		SysBeep(10);
		return (-1);
	}

	SetPortWindowPort(wp);	/*- ra 990612 -*/
	/*	Draw the text box ...*/
	TextFont(0);
	TextSize(12);
	TextFace(0);
	SetRect(&aRect, 78, 12, 373, 44);
	length = strlen(aString);
	BlockMoveData(&filename[1], &aString[length], filename[0]);
	aString[length + filename[0] + 1] = '\0';
	strcat(aString, "” before quitting?");
	TETextBox(aString, strlen(aString), &aRect, teForceLeft);
	/*	Draw the icon*/
	SetRect(&aRect, 23, 12, 55, 44);
	theIcon = GetIcon(2);
	PlotIcon(&aRect, theIcon);
	if (SIOUXSettings.standalone) {
		/*	Draw the Don't Save button ...*/
		SetRect(&aRect, 78, 57, 165, 77);
		noButton = NewControl(wp, &aRect, "\pDon’t Save", TRUE, 0, 0, 0, pushButProc|kControlUsesOwningWindowsFontVariant, 0);
		/*	Draw the Cancel button ...*/
		SetRect(&aRect, 224, 57, 297, 77);
		cancelButton = NewControl(wp, &aRect, "\pCancel", TRUE, 0, 0, 0, pushButProc|kControlUsesOwningWindowsFontVariant, 0);
	} else {
		/*	Draw the Don't Save button ...*/
		SetRect(&aRect, 207, 57, 297, 77);
		noButton = NewControl(wp, &aRect, "\pDon’t Save", TRUE, 0, 0, 0, pushButProc|kControlUsesOwningWindowsFontVariant, 0);
	}
	/*	Draw the Save button ...*/
	SetRect(&aRect, 307, 57, 374, 77);
	yesButton = NewControl(wp, &aRect, "\pSave", TRUE, 0, 0, 0, pushButProc|kControlUsesOwningWindowsFontVariant, 0);

	/*	Outline the default button ...*/
	FrameControl(noButton);
	
	if (SIOUXSettings.standalone)
		SetCancelControl(cancelButton);
	
	while (!done) {
		if (SIOUXUseWaitNextEvent)
			gotEvent = WaitNextEvent(mDownMask | keyDownMask, &theEvent, SIOUXSettings.sleep, NULL);
		else 
			gotEvent = GetNextEvent(mDownMask | keyDownMask, &theEvent);
		
		if(gotEvent) {
			if (theEvent.what == mouseDown) {
				if ((FindWindow(theEvent.where, &theWindow) == inContent) && (theWindow == wp)) {
					GlobalToLocal(&theEvent.where);
					if (FindControl(theEvent.where, wp, &dummyCntl) == kControlButtonPart)
						if (TrackControl(dummyCntl, theEvent.where, 0L) != 0) {
							if (dummyCntl == yesButton)
								item = 1;
							if (dummyCntl == noButton)
								item = 2;
							if (SIOUXSettings.standalone && dummyCntl == cancelButton)
								item = 3;
							done = TRUE;
						}
				}
			} else if (theEvent.what == keyDown) {
				char key;
				
				key = theEvent.message & charCodeMask;
				if (key == 'Y' || key == 'y' || key == 'S' || key == 's') {
					item = 1;
					FlashControl(yesButton);
					done = TRUE;
				} else if (key == 'N' || key == 'n' ||
						   key == 'D' || key == 'd' ||
						   key == 0x0d || key == 0x03) {
					/*	CR or ENTER key go here*/
					item = 2;
					FlashControl(noButton);
					done = TRUE;
				} else if (SIOUXSettings.standalone) {
					if ((key == '.' && (theEvent.modifiers & cmdKey)) || (key == 0x1b)) {
						/*	ESCAPE key or command - . go here*/
						item = 3;
						FlashControl(cancelButton);
						done = TRUE;
					}
				}
			}
		}
	}
	
	DisposeControl(yesButton);
	DisposeControl(noButton);
	if (SIOUXSettings.standalone)
		DisposeControl(cancelButton);
	DisposeWindow(wp);
	/* ReleaseResource(theIcon); */          /*- mm 980415 -*/
	SetPort(savePort);
	return (item);
}

#pragma bool reset

/* Change record:
 * BB  930410 Removed all calls to c2pstr and p2cstr so that we no
 *			  longer need to import MacOS.lib
 * BB  940121 Added SIOUXDrawGrowBox to handle custom grow icon
 * BB  940121 Also expanded the text area to use the larger terect
 * BB  940403 Changed the default button in the "do you want to save"
 *			  Dialog from Yes to No, also made the dialog a little larger.
 * JH  951230 Removed uses of OLDROUTINENAMES. Added #include <Icons.h>
 * bk  960902 need to add the following headers to free from ansiprefix.h
 * mm  971006 Added #include of Sound.h because of change in universal headers
 * mm  980415 Removed two ReleaseResource statements that released a shared resource MW00225
 * mm  980609 Changes that allow user to specify window title before the SIOUX window is created.
 * ra  990612 Window created with spec.name to work around MacOS X bug
 * cc  991108 added ra Carbon Changes done 990611 
 * cc  991109 changed TARGET_CARBON to TARGET_API_MAC_CARBON
 * cc  991111 added #include <ControlDefinitions.h>      
 * cc  991115 updated and deleted outdated carbon comments  
 * ra  000114 Fixed Carbon bug in SetTextView.
 * ra  000127 Removed a C++ comment because of ANSI Strict
 * cc  000229 Removed #include <ControlDefinitions.h> with out the ifdef
 * JWW 000315 Fixed <ControlDefinitions.h> #ifdef to check universal interfaces version number
 * JWW 000531 Cleaned up dialogs to look better under the Aqua interface
 * JWW 000718 Adjusted about box text layout to draw properly with new 2000 copyright years
 * JWW 010726 It's now 2001, and somehow we're Metrowerks Corporation instead of Inc.
 * JWW 010910 Do not set the absent Cancel button as default if not in standalone mode
 * JWW 010917 Added floating window mode to SIOUX
 * JWW 011027 Added case for Mach-O
 */