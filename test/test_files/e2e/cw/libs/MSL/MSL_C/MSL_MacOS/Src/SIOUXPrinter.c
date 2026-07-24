/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/06/16 00:02:20 $
 * $Revision: 1.11 $
 */
 
/*****************************************************************************/
/*  Project...: C++ and ANSI-C Compiler Environment                          */
/*  Purpose...: Printing functions for SIOUX			            	     */
/*****************************************************************************/

#define PM_USE_SESSION_APIS 0

#include "SIOUXGlobals.h"
#include "SIOUXPrinter.h"
#include "SIOUXWindows.h"

#include <stdio.h>
#include <string.h>

#if __MACH__
	#include <Carbon/Carbon.h>
	
	typedef Handle THPrint;
#else
	#include <Fonts.h> 
	#include <PMApplication.h>
	#include <Printing.h>
#endif

#undef bool	/* JWW - in case it was defined in stdbool.h */
#pragma bool on
#ifndef TRUE		/*- ra 990611 -*/
#define TRUE true
#endif
#ifndef FALSE
#define FALSE false
#endif

/*	Local defines ...*/
enum {
	TOPMARGIN = 20,
	LEFTMARGIN = 20,
	BOTTOMMARGIN = 20
};

/*	Private globals ...*/
#if TARGET_API_MAC_CARBON
	static PMPageFormat gPageFormat = kPMNoPageFormat;
	static PMPrintSettings gPrintSettings = kPMNoPrintSettings;
	static Handle gFlattenedFormat = NULL;
	static Handle gFlattenedSettings = NULL;
#else
	static THPrint prRecHdl = 0L;
#endif	/* TARGET_API_MAC_CARBON */

/************************************************************************/
/*  Purpose..:  Concatenate two pascal string                           */
/*  Input....:  pointer to destination string                           */
/*  Input....:  pointer to concat string                                */
/*  Return...:  ---                                                     */
/************************************************************************/
static void pstrcat(StringPtr to, StringPtr append)
{
    short i, n;

    i = *append++;
    n = *to;
    if (i + n > 255)
        i = 255 - n;
    *to += i;
    to += n + 1;
    while (i-- > 0)
        *to++ = *append++;
}

/************************************************************************/
/*  Purpose.............:   Setup internals for printing                */
/*  Input...............:   ---                                         */
/*  Return..............:   TRUE: ok; FALSE: error                      */
/************************************************************************/
static Boolean InitPrint(void)
{
#if TARGET_API_MAC_CARBON
	OSStatus theStatus;
	
	if (gFlattenedFormat != NULL)
	{
		theStatus = PMUnflattenPageFormat(gFlattenedFormat, &gPageFormat);
		
		if (theStatus != noErr)
			return FALSE;
	}
	
	if (gFlattenedSettings != NULL)
	{
		theStatus = PMUnflattenPrintSettings(gFlattenedSettings, &gPrintSettings);
		
		if (theStatus != noErr)
			return FALSE;
	}
	
	if (gPageFormat != kPMNoPageFormat)
		theStatus = PMValidatePageFormat(gPageFormat, kPMDontWantBoolean);
	else
	{
		theStatus = PMNewPageFormat(&gPageFormat);
		
		if ((theStatus == noErr) && (gPageFormat != kPMNoPageFormat))
			theStatus = PMDefaultPageFormat(gPageFormat);
	}
	
	return (theStatus == noErr);
#else
    if (prRecHdl == 0L) {
        PrOpen();
        if (PrError() != noErr)
            return(FALSE);  /*	 no printing manager*/
        prRecHdl = (THPrint) NewHandle(sizeof(TPrint)); /*	 alloc space for print struct*/
        if (prRecHdl == 0)
        	goto cleanup;	/*	couldn't allocate the handle ...*/
        PrintDefault(prRecHdl);
        if (PrError() != noErr)
			goto cleanup;	/*	 couldn't setup default print values ...*/
        PrClose();          /*	 setup print structure*/
    }
    return(TRUE);
cleanup:
	DisposeHandle((Handle)prRecHdl);
	prRecHdl = 0L;
	PrClose();
	return(FALSE);
#endif	/* TARGET_API_MAC_CARBON */
}

/****************************************************************/
/* Purpose..: Setup the page format for printing				*/
/* Input....: ---                       						*/
/* Returns..: ---                        						*/
/****************************************************************/
void SIOUXDoPageSetup(void)
{
#if TARGET_API_MAC_CARBON
	OSStatus theStatus;
	Boolean isAccepted;
	
	theStatus = PMBegin();
	if (theStatus != noErr)
		return;
	
	if (InitPrint())
		theStatus = PMPageSetupDialog(gPageFormat, &isAccepted);
	
	if (theStatus == noErr)
	{
		if (gFlattenedFormat != NULL)
		{
			DisposeHandle(gFlattenedFormat);
			gFlattenedFormat = NULL;
		}
		
		theStatus = PMFlattenPageFormat(gPageFormat, &gFlattenedFormat);
	}
	
	if (gPageFormat != kPMNoPageFormat)
	{
		theStatus = PMDisposePageFormat(gPageFormat);
		gPageFormat = kPMNoPageFormat;
	}
	
	theStatus = PMEnd();
#else
	Boolean dummy;

    if (!InitPrint())
        return;
    PrOpen();
    if (PrError())
        return;

	dummy = PrStlDialog(prRecHdl);
    PrClose();
#endif /* TARGET_API_MAC_CARBON */
}

/****************************************************************/
/* Purpose..: Draw a line of text  								*/
/* Input....: ---                       						*/
/* Returns..: ---                        						*/
/****************************************************************/
/* original MWerks def: static void DoDrawText(char *ptr, short count)  --pcg */
static void DoDrawText(char *ptr, long count)
{
	char *ptr1, *ptr2;
#if SIOUX_USE_WASTE
	long length;
#else
	short length;
#endif /* SIOUX_USE_WASTE */
	
	ptr1 = ptr;
	ptr2 = ptr + count;
	while (ptr < ptr2) {
		while (ptr1 < ptr2) {
			ptr1++;
		}
		if ((length = ptr1 - ptr) > 0) {
			DrawText(ptr, 0, ptr1 - ptr);
		}
		ptr = ptr1;
	}
}

/****************************************************************/
/* Purpose..: Print the document  								*/
/* Input....: ---                       						*/
/* Returns..: ---                        						*/
/****************************************************************/
static void PrintText(char **localText, long textLength,
						THPrint prRecHdl, short font, short size)
{
#if TARGET_API_MAC_CARBON
	#pragma unused(prRecHdl)
	OSStatus theStatus;
	PMPrintContext thePrintingPort;
	PMRect prRect;
#else
	TPPrPort prPort;
	Rect prRect;
#endif /* TARGET_API_MAC_CARBON */
	FontInfo fInfo;
	char *ptr1, *ptr2;
	short linesPerPage;
	short lineBase;
	short lineHeight;
	long curPage = 0L;
#if SIOUX_USE_WASTE
	long length;
	long curLine = 0;
	long lastLineOnPage = 0;
#else
	short length;
	short curLine = 0;
	short lastLineOnPage = 0;
#endif /* SIOUX_USE_WASTE */
	
#if TARGET_API_MAC_CARBON
	theStatus = PMGetAdjustedPageRect(gPageFormat, &prRect);
	if (theStatus != noErr)
		return;
	
	theStatus = PMBeginDocument(gPrintSettings, gPageFormat, &thePrintingPort);
	if (theStatus != noErr)
		return;
#else
	prPort = PrOpenDoc(prRecHdl, 0L, 0L);
	SetPort((GrafPtr)prPort);
	prRect = (*prRecHdl)->prInfo.rPage;
#endif /* TARGET_API_MAC_CARBON */
	TextFont(font);
	TextSize(size);
	TextFace(0);
	GetFontInfo(&fInfo);
	lineHeight = fInfo.leading + fInfo.ascent + fInfo.descent;
	linesPerPage = (prRect.bottom - prRect.top - BOTTOMMARGIN - TOPMARGIN) / lineHeight;
	HLock(localText);
	ptr1 = ptr2 = (*localText);
	while (ptr1 < (*localText) + textLength) {
#if TARGET_API_MAC_CARBON
		theStatus = PMBeginPage(thePrintingPort, NULL);
		
		if (theStatus != noErr)
			break;
#else
		PrOpenPage(prPort, 0L);
#endif /* TARGET_API_MAC_CARBON */
		curPage++;
		lastLineOnPage += linesPerPage;
		/*	Print the title info at the top of the page ...*/
		{
			Str63 aStr = "Page: ";
			Str63 scratchStr;
			
			TextFont(kFontIDGeneva);   /*- mm 971006 -*/
			TextSize(9);
			TextFace(bold);
			MoveTo(prRect.left + LEFTMARGIN, prRect.top + 9);
			GetWTitle(SIOUXTextWindow->window, scratchStr);	/*- ra 990612 -*/
			DrawString(scratchStr);
			sprintf((char *)scratchStr, "%ld", curPage);
			strcat((char *)aStr, (char *)scratchStr);
			MoveTo(prRect.right - LEFTMARGIN - StringWidth(aStr),
				   prRect.top + 9);
			DrawText(aStr, 0, strlen((char *)aStr));
			MoveTo(prRect.left + LEFTMARGIN, prRect.top + TOPMARGIN - 5);
			Line((prRect.right - 2 * LEFTMARGIN - prRect.left), 0);
		}
		TextFont(font);
		TextSize(size);
		TextFace(0);
		MoveTo(prRect.left + LEFTMARGIN,
			   (lineBase = prRect.top + TOPMARGIN + lineHeight));
		while ((++curLine != lastLineOnPage) && (ptr1 < (*localText) + textLength)) {
			/*	Print a line ...*/
			while ((ptr1 <= (*localText) + textLength) && (*ptr1++ != (char)'\r')) ;
			if ((length = (short)(ptr1 - ptr2) - 1) > 0) {
				DoDrawText(ptr2, length);
			}
			MoveTo(prRect.left + LEFTMARGIN, (lineBase += lineHeight));
			ptr2 = ptr1;
		}
#if TARGET_API_MAC_CARBON
		theStatus = PMEndPage(thePrintingPort);
#else
		PrClosePage(prPort);
#endif /* TARGET_API_MAC_CARBON */
	}
	HUnlock(localText);
#if TARGET_API_MAC_CARBON
	theStatus = PMEndDocument(thePrintingPort);
#else
	PrCloseDoc(prPort);
#endif /* TARGET_API_MAC_CARBON */
}

/****************************************************************/
/* Purpose..: Start the printing process						*/
/* Input....: ---                       						*/
/* Returns..: ---                        						*/
/****************************************************************/
void SIOUXDoPrintText(void)
{
	/*	Length of the text ...*/
#if SIOUX_USE_WASTE
	long textLength = (long)WEGetTextLength( SIOUXTextWindow->edit );
#else
	long textLength = (long)(*SIOUXTextWindow->edit)->teLength;
#endif /* SIOUX_USE_WASTE */
	/*	GrafPtr to the textWindow ...*/
#if TARGET_API_MAC_CARBON
	GrafPtr grafWindow = GetWindowPort(SIOUXTextWindow->window);
#else
	GrafPtr grafWindow = (GrafPtr)SIOUXTextWindow->window;
#endif
	GrafPtr savePort;

#if TARGET_API_MAC_CARBON
	OSStatus theStatus;
	Boolean isAccepted;
	
	theStatus = PMBegin();
	if (theStatus != noErr)
		return;
	
	if (InitPrint())
	{
		if (gPrintSettings != kPMNoPrintSettings)
			theStatus = PMValidatePrintSettings(gPrintSettings, kPMDontWantBoolean);
		else
		{
			theStatus = PMNewPrintSettings(&gPrintSettings);
			
			if ((theStatus == noErr) && (gPrintSettings != kPMNoPrintSettings))
				theStatus = PMDefaultPrintSettings(gPrintSettings);
		}
		
		if (theStatus == noErr)
		{
			theStatus = PMPrintDialog(gPrintSettings, gPageFormat, &isAccepted);
			
			if (isAccepted)
			{
				GetPort(&savePort);
				
#if SIOUX_USE_WASTE
				PrintText( WEGetText( SIOUXTextWindow->edit ), textLength, NULL,
						  GetPortTextFont(grafWindow), GetPortTextSize(grafWindow));
#else
				PrintText((*SIOUXTextWindow->edit)->hText, textLength, NULL,
						  GetPortTextFont(grafWindow), GetPortTextSize(grafWindow));
#endif /* SIOUX_USE_WASTE */
				
				SetPort(savePort);
			}
		}
	}
	
	if (theStatus == noErr)
	{
		if (gFlattenedFormat != NULL)
		{
			DisposeHandle(gFlattenedFormat);
			gFlattenedFormat = NULL;
		}
		
		theStatus = PMFlattenPageFormat(gPageFormat, &gFlattenedFormat);
	}
	
	if (theStatus == noErr)
	{
		if (gFlattenedSettings != NULL)
		{
			DisposeHandle(gFlattenedSettings);
			gFlattenedSettings = NULL;
		}
		
		theStatus = PMFlattenPrintSettings(gPrintSettings, &gFlattenedSettings);
	}
	
	if (gPageFormat != kPMNoPageFormat)
	{
		theStatus = PMDisposePageFormat(gPageFormat);
		gPageFormat = kPMNoPageFormat;
	}
	
	if (gPrintSettings != kPMNoPrintSettings)
	{
		theStatus = PMDisposePrintSettings(gPrintSettings);
		gPrintSettings = kPMNoPrintSettings;
	}
	
	theStatus = PMEnd();
	
#else
	short copies;
	TPrStatus prStatus;

	if (!InitPrint()) {
		return;
	}
	PrOpen();
	if (PrError()) {
		return;
	}
	SetCursor(&qd.arrow);
	if (PrJobDialog(prRecHdl) != 0) {
		SetCursor(*GetCursor(watchCursor));
		GetPort(&savePort);
		copies = ((*prRecHdl)->prJob.bJDocLoop == bDraftLoop) ?
				 (*prRecHdl)->prJob.iCopies : 1;
		for (/* initialized above */;copies > 0; copies--) {
#if SIOUX_USE_WASTE
			PrintText( WEGetText( SIOUXTextWindow->edit ), textLength, prRecHdl,
					  grafWindow->txFont, grafWindow->txSize);
#else
			PrintText((*SIOUXTextWindow->edit)->hText, textLength, prRecHdl,
					  grafWindow->txFont, grafWindow->txSize);
#endif /* SIOUX_USE_WASTE */
			PrPicFile(prRecHdl, 0L, 0L, 0L, &prStatus);
		}
		SetPort(savePort);
	}
	PrClose();
#endif /* TARGET_API_MAC_CARBON */
}

#pragma bool reset

/* Change record:
 * BB  930110 replace NumToString by sprintf so that no toolbox glue code
 * 			  is being called ...
 * bk  960902 added bool defines for compiling w/o macheaders
 * mm  971006 Changed font name to match new Universal headers
 * cc  991108 added ra Carbon Changes done 990611
 * cc  991109 changed TARGET_CARBON to TARGET_API_MAC_CARBON
 * cc  991115 updated and deleted outdated comments
 * JWW 000601 Added Carbon printing code
 * JWW 011027 Added case for Mach-O
 */