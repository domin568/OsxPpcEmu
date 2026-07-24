/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:31 $
 * $Revision: 1.20 $
 */

#include <ansi_parms.h>

#if __MACH__
	#include <Carbon/Carbon.h>
	
	#if !_MSL_CARBON_FILE_APIS
		#include <fcntl.h>
		#include <sys/stat.h>
	#endif /* !_MSL_CARBON_FILE_APIS */
	
	struct StandardFileReply {
	  Boolean             sfGood;
	  Boolean             sfReplacing;
	  OSType              sfType;
	  FSSpec              sfFile;
	  ScriptCode          sfScript;
	  short               sfFlags;
	  Boolean             sfIsFolder;
	  Boolean             sfIsVolume;
	  long                sfReserved1;
	  short               sfReserved2;
	};
	typedef struct StandardFileReply        StandardFileReply;
#else
	#include	<Dialogs.h>
	#include	<Icons.h>
	#include	<LowMem.h>
	#include    <MacErrors.h>
	#include	<Processes.h>
	#include	<StandardFile.h>
	#include	<TextUtils.h>

	#if TARGET_API_MAC_CARBON
		#include	<AEDataModel.h>	/*- ra 990612 -*/
		#include	<ControlDefinitions.h>
		#include	<Navigation.h>	/*- ra 990612 -*/
	#endif /* TARGET_API_MAC_CARBON */
#endif

#include	<console.h>
#include 	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

#include	"abort_exit.h"
#include 	"file_io.h"

/* function prototypes for externally defined functions */
extern long __getcreator(long isbinary);
extern long __gettype(long isbinary);
extern char __msl_system_has_new_file_apis(void);

#if !_MSL_CARBON_FILE_APIS
	/* JWW - For Mach-O MSL using POSIX APIs, always use TEXT and CWIE as type and creator */
	long __getcreator(long) {return 'CWIE';}
	long __gettype(long) {return 'TEXT';}
#endif /* !_MSL_CARBON_FILE_APIS */

#define		NoItem		12
#define		stdInBase	5
#define		stdOutBase	7
#define		MAX_ARGS	25

#define		kOK			1
#define		kQUIT		2

#pragma options align=mac68k         /*- mm 960606 -*/

typedef struct {
	Handle	h;
	Rect	box;
	char	kind;
} ItemListEntry;

static struct {
	short	count;
	ItemListEntry	item[NoItem];
} itemList = {
	NoItem-1,
	0,{11,351,31,409},0x04,
	0,{45,351,65,409},0x04,
	0,{32,10,46,85},0x88,
	0,{32,92,46,333},0x10,
	0,{99,63,117,169},0x06,
	0,{131,62,149,202},0x06,
	0,{99,276,117,382},0x06,
	0,{131,276,149,416},0x06,
	0,{80,0,81,428},0x80,
	0,{80,213,170,214},0x80,
	0,{106,16,138,48},0x80,
	0,{109,230,141,262},0x80
	
};

#pragma options align=reset             /*- mm 960606 -*/

static short soutICON[] = {
	0x0001, 0x0000, 0x0002, 0x8000, 0x0004, 0x4000, 0x0008, 0x2000,
	0x0010, 0x1000, 0x0020, 0x0800, 0x0040, 0x0400, 0x0080, 0x0200,
	0x0100, 0x0100, 0x0200, 0x0080, 0x0400, 0x0040, 0x0800, 0x0020,
	0x1000, 0x0010, 0x2000, 0x0008, 0x4000, 0x3F04, 0x8000, 0x4082,
	0x4000, 0x8041, 0x2001, 0x3022, 0x1001, 0xC814, 0x080E, 0x7F8F,
	0x0402, 0x3007, 0x0201, 0x0007, 0x0100, 0x8007, 0x0080, 0x6007,
	0x0840, 0x1FE7, 0x1820, 0x021F, 0x3F10, 0x0407, 0x7F08, 0x0800,
	0x3F04, 0x1000, 0x1802, 0x2000, 0x0801, 0x4000, 0x0000, 0x8000
};

static short sinICON[] = {
	0x0001, 0x0000, 0x0802, 0x8000, 0x0C04, 0x4000, 0x7E08, 0x2000,
	0x7F10, 0x1000, 0x7E20, 0x0800, 0x0C40, 0x0400, 0x0880, 0x0200,
	0x0100, 0x0100, 0x0200, 0x0080, 0x0400, 0x0040, 0x0800, 0x0020,
	0x1000, 0x0010, 0x2000, 0x0008, 0x4000, 0x3F04, 0x8000, 0x4082,
	0x4000, 0x8041, 0x2001, 0x3022, 0x1001, 0xC814, 0x080E, 0x7F8F,
	0x0402, 0x3007, 0x0201, 0x0007, 0x0100, 0x8007, 0x0080, 0x6007,
	0x0040, 0x1FE7, 0x0020, 0x021F, 0x0010, 0x0407, 0x0008, 0x0800,
	0x0004, 0x1000, 0x0002, 0x2000, 0x0001, 0x4000, 0x0000, 0x8000
};

static DialogPtr	theDialog;
static Rect			bounds = {66,44,226,470};
static Str63		AppName;
static char			argStr[255];
static char 		*argv[MAX_ARGS + 1];
static int			stdinSel, stdoutSel;

static pascal Boolean myFilter(DialogPtr theDialog,EventRecord *theEvent, short *theItem);

/*
	Standard File isn't supported under Carbon, so instead we have our
	own wrappers to bridge between Standard File and Navigation
	Services.  Runtime support for Navigation Services for MacOS 8
	will be added later.
*/

/*- cc 991111 -*/
#if TARGET_API_MAC_CARBON
static pascal void NavEventProc(NavEventCallbackMessage inSelector, NavCBRecPtr ioParams,
							NavCallBackUserData ioUserData)
{
#pragma unused(ioParams, ioUserData)

	short item = -1;

	if (inSelector == kNavCBEvent) 
	{
		myFilter(theDialog, (ioParams->eventData.eventDataParms.event), &item);
	}
}


/*- cc 991111 -*/
static pascal Boolean NavObjectFilterProc(AEDesc* theItem, void* info, 
							NavCallBackUserData callBackUD,
							NavFilterModes filterMode)
{
#pragma unused(theItem, info, callBackUD, filterMode)

/*	OSErr theErr = noErr;
	Boolean display = true;
	NavFileOrFolderInfo* theInfo = (NavFileOrFolderInfo*) info;
	
	if (theItem->descriptorType == typeFSS)
	{
		if (theInfo->isFolder)
			display = false;
	}
	
	return display;*/

	return true;	/* JWW - Allow both files and folders for navigation */
} 
#endif /* TARGET_API_MAC_CARBON */


static void GetFile( StandardFileReply *outReply )
{
#if TARGET_API_MAC_CARBON
	NavDialogOptions NavOptions;
	NavReplyRecord NavReply;
	Size theSize;
	AEKeyword theKeyword;
	DescType theType;
	NavEventUPP myEventUPP;
	NavObjectFilterUPP myFilterUPP;
	OSErr	err;
	
	NavGetDefaultDialogOptions(&NavOptions);
	NavOptions.dialogOptionFlags = (NavOptions.dialogOptionFlags | kNavSelectDefaultLocation);
	NavOptions.dialogOptionFlags = (NavOptions.dialogOptionFlags | kNavNoTypePopup);
	NavOptions.dialogOptionFlags = (NavOptions.dialogOptionFlags & ~kNavAllowPreviews);
	NavOptions.dialogOptionFlags = (NavOptions.dialogOptionFlags & ~kNavAllowMultipleFiles);
	
	myEventUPP = NewNavEventUPP(NavEventProc);
	myFilterUPP = NewNavObjectFilterUPP(NavObjectFilterProc);
	
	err = NavGetFile(NULL, &NavReply, &NavOptions, myEventUPP, NULL, myFilterUPP, NULL, NULL);
	
	DisposeNavEventUPP(myEventUPP);
	DisposeNavObjectFilterUPP(myFilterUPP);
	
	if (err != noErr)
		outReply->sfGood = false;
	else
		outReply->sfGood = NavReply.validRecord;
	
	if (outReply->sfGood)
	{
		err = AEGetNthPtr(&(NavReply.selection), 1, typeFSS, &theKeyword, &theType,
			&(outReply->sfFile), sizeof(outReply->sfFile), &theSize);
		
		if (err != noErr)
			outReply->sfGood = false;
		
		NavDisposeReply(&NavReply);
	}
#else
	StandardGetFile(NULL, -1, NULL, outReply);
#endif /* TARGET_API_MAC_CARBON */
}


static void PutFile( StandardFileReply *outReply )
{
#if TARGET_API_MAC_CARBON 
	NavDialogOptions NavOptions;
	NavReplyRecord NavReply;
	Size theSize;
	AEKeyword theKeyword;
	DescType theType;
	NavEventUPP myEventUPP;
	OSErr	err;
	
	NavGetDefaultDialogOptions(&NavOptions);
	NavOptions.dialogOptionFlags = (NavOptions.dialogOptionFlags | kNavSelectDefaultLocation);
	NavOptions.dialogOptionFlags = (NavOptions.dialogOptionFlags | kNavNoTypePopup);
	NavOptions.dialogOptionFlags = (NavOptions.dialogOptionFlags & ~kNavAllowPreviews);
	NavOptions.dialogOptionFlags = (NavOptions.dialogOptionFlags & ~kNavAllowMultipleFiles);
	
	BlockMoveData(outReply->sfFile.name, NavOptions.savedFileName, outReply->sfFile.name[0] + 1);
	
	myEventUPP = NewNavEventUPP(NavEventProc);
	
	err = NavPutFile(NULL, &NavReply, &NavOptions, myEventUPP, __gettype(false), __getcreator(false), NULL);
	
	DisposeNavEventUPP(myEventUPP);
	
	if (err != noErr)
		outReply->sfGood = false;
	else
	{
		outReply->sfGood = NavReply.validRecord;
		outReply->sfReplacing = NavReply.replacing;
		outReply->sfScript = NavReply.keyScript;
	}
	
	if (outReply->sfGood)
	{
		err = AEGetNthPtr(&(NavReply.selection), 1, typeFSS, &theKeyword, &theType,
			&(outReply->sfFile), sizeof(outReply->sfFile), &theSize);
		
		if (err != noErr)
			outReply->sfGood = false;
		else
			NavCompleteSave(&NavReply, kNavTranslateInPlace);
		
		outReply->sfType = __gettype(false);
		
		NavDisposeReply(&NavReply);
	}
#else
	StandardPutFile("\p", outReply->sfFile.name, outReply);
#endif /* TARGET_API_MAC_CARBON */		
}


static Handle ItemHandle(short ItemNumber)
{
	short 	kind;
	Handle	item;
	Rect 	box;
	
	GetDialogItem(theDialog, ItemNumber, &kind, &item, &box);
	
	return (item);
}


static void centerDialog(Rect *bounds)
{
	short screenWidth, screenHeight, dlogWidth, dlogHeight;
	Rect  screenRect;
	
	GDHandle theMainDevice = GetMainDevice();
	Rect r = (**theMainDevice).gdRect;					/* center within the main monitor	*/
	MacSetRect(&screenRect, r.left, r.top, r.right, r.bottom);
	screenRect.top += GetMBarHeight();					/* teaking into account the mbar	*/
		
	screenHeight = screenRect.bottom - screenRect.top;	/* get main monitor height				*/
	screenWidth  = screenRect.right  - screenRect.left;	/* and its width									*/
	
	dlogHeight = bounds->bottom - bounds->top;			/* do the same for our dialog			*/
	dlogWidth  = bounds->right  - bounds->left;
	
	bounds->top    = screenRect.top + screenHeight/5;	/* position 20% down the screen		*/
	bounds->left   = screenRect.left + (screenWidth - dlogWidth)/2; /* centered of course	*/
	bounds->bottom = bounds->top  + dlogHeight;
	bounds->right  = bounds->left + dlogWidth;
}


static void CopyIcon(short icon[], Rect *rect)
{
	BitMap	iconMap;
	Rect	destRect = *rect;
	
	iconMap.baseAddr = (Ptr)icon;
	iconMap.rowBytes = 4;
	SetRect(&iconMap.bounds, 0, 0, 32, 32);
	
#if TARGET_API_MAC_CARBON
	CopyBits(&iconMap, (BitMap *)*GetPortPixMap(GetQDGlobalsThePort()), &iconMap.bounds, &destRect, srcCopy, NULL );
#else	
	CopyBits(&iconMap, &qd.thePort->portBits, &iconMap.bounds, &destRect, srcCopy, NULL );
#endif /* TARGET_API_MAC_CARBON */
}


/****************************************************************/
/* Purpose..: Flash an item										*/
/* Input....: The item's number									*/
/* Returns..: ---                    							*/
/****************************************************************/
static void FlashControl(ControlHandle theControl)
{
	unsigned long aLong;

	HiliteControl(theControl, 1);
	Delay(8L, &aLong);
	HiliteControl(theControl, 0);
}


static pascal Boolean myFilter(DialogPtr theDialog,EventRecord *theEvent, short *theItem)
{
	WindowPtr		theWindow;
	Rect			myRect;
	short			kind;
	Handle			item;
	char			aChar;
	
	switch(theEvent->what) {
		case updateEvt:
			theWindow = (WindowPtr) theEvent->message;
			
#if TARGET_API_MAC_CARBON
			{
				RgnHandle theVisRgn = NewRgn();
			
				SetPortDialogPort(theDialog);
				
				if (theVisRgn != NULL)
				{
					GetPortVisibleRegion(GetDialogPort(theDialog), theVisRgn);
					UpdateDialog(theDialog, theVisRgn);
					DisposeRgn(theVisRgn);
				}
			}
#else
			MacSetPort(theWindow); 	/*- ra 990612 -*/
			UpdateDialog(theWindow, theDialog->visRgn);
#endif /* TARGET_API_MAC_CARBON */
			
			PenNormal();
		
#if TARGET_API_MAC_CARBON
			{
				Pattern theGray;
				PenPat(GetQDGlobalsGray(&theGray));
			}
#else 
			PenPat(&qd.gray);
#endif /* TARGET_API_MAC_CARBON */
			GetDialogItem(theDialog, 9, &kind, &item, &myRect);
			MoveTo(myRect.left, myRect.top);
			LineTo(myRect.right, myRect.top);
			
			GetDialogItem(theDialog, 10, &kind, &item, &myRect);
			MoveTo(myRect.left, myRect.top);
			LineTo(myRect.left, myRect.bottom);
			
#if !TARGET_API_MAC_CARBON
			PenNormal();
			PenSize(3, 3);
			GetDialogItem(theDialog, 1, &kind, &item, &myRect);
			InsetRect(&myRect, -4, -4);
			FrameRoundRect(&myRect, 16, 16);
			PenNormal();
#endif /* !TARGET_API_MAC_CARBON */

			GetDialogItem(theDialog, 11, &kind, &item, &myRect);
			CopyIcon(sinICON, &myRect);
			
			GetDialogItem(theDialog, 12, &kind, &item, &myRect);
			CopyIcon(soutICON, &myRect);
			
			break;
		case keyDown:
			aChar = theEvent->message & charCodeMask;

			if ((aChar == 0x0d) || (aChar == 0x03))
			{
				*theItem = kOK;
				FlashControl((ControlHandle) ItemHandle(kOK));
				return 1;
			} else if ((theEvent->modifiers & cmdKey) && (aChar == '.'))
			{
				*theItem = kQUIT;
				FlashControl((ControlHandle) ItemHandle(kQUIT));
				return 1;
			}
			break;
	}
	
	return 0;
}


static void BuildDialog(void)
{
	Handle items;
	OSErr err;
	
#if !TARGET_API_MAC_CARBON
	/* Toolbox is automatically initialized when CarbonLib is loaded */
	InitGraf(&qd.thePort);
	InitFonts();
	InitWindows();
	TEInit();
	InitDialogs(NULL);
#endif /* !TARGET_API_MAC_CARBON */
	
	err = PtrToHand(&itemList, &items, sizeof(itemList));
	
	centerDialog(&bounds);
	theDialog = NewDialog(NULL, &bounds, AppName, 1, 5,(WindowPtr) -1, 0, 0, items);
	
	SetControlTitle((ControlHandle) ItemHandle(kOK), "\pOK");
	SetControlTitle((ControlHandle) ItemHandle(kQUIT), "\pQuit");
	SetDialogItemText(ItemHandle(3), "\pArgument:");
	SetControlTitle((ControlHandle) ItemHandle(5), "\pConsole");
	SetControlTitle((ControlHandle) ItemHandle(6), "\pFile");
	SetControlTitle((ControlHandle) ItemHandle(7), "\pConsole");
	SetControlTitle((ControlHandle) ItemHandle(8), "\pFile");
	
	SetControlValue((ControlHandle) ItemHandle(stdInBase), 1);
	SetControlValue((ControlHandle) ItemHandle(stdOutBase), 1);
	
#if TARGET_API_MAC_CARBON
	{
		Boolean isDefault;
		
		isDefault = true;
		SetControlData((ControlHandle) ItemHandle(kOK), kControlEntireControl,
			kControlPushButtonDefaultTag, sizeof(isDefault), &isDefault);
	}
#endif
}


static void SetRadioState(short base,short count,short select)
{
	int i;
	
	for (i=base;count--;i++)
		SetControlValue((ControlHandle) ItemHandle(i),i== select);
}


static StringPtr TruncFileName(StringPtr FileName)
{
	static Str255 myFileName;
	
	BlockMove(FileName,myFileName,*FileName+1);
	TruncString(100,myFileName,smTruncEnd);
	return myFileName;
}


static int ParseArgs(char *s)
{
	int  n = 1, Quote = 0;
	char *p = s, *p1, c;
	
	p1 = (char *) argStr;
	
	while ((c = *p++) != 0) {
		if (c==' ') continue;
		
		argv[n++] = p1;
		
		if (n > MAX_ARGS)				/*- mm 970404 -*/
			return (n-1);				/*- mm 970404 -*/
		do
		{
			if (c=='\\' && *p++) 
				c = *p++;
			else
			{
				if ((c=='"') || (c == '\''))
				{
					if (!Quote)
					{
						Quote = c;
						continue;
					}
					
					if (c == Quote)
					{
						Quote = 0;
						continue;
					}
				}
			}
			
			*p1++ = c;
		} while (*p && ((c = *p++) != ' ' || Quote));
		
		*p1++ = 0;
	}
	
	return n;
}


int ccommand(char ***arg)
{
	StandardFileReply inReply, outReply;
	ProcessSerialNumber psn;
	ProcessInfoRec pinfo;
	FSSpec  spec;
	OSErr	err;
	short	refNum;
	DialogItemIndex	theItem;
	Str255	argument;
	int		arglen;
	ModalFilterUPP myFilterUPP;
	
	err = GetCurrentProcess(&psn);
	pinfo.processName = AppName;
	pinfo.processInfoLength = sizeof(pinfo);
	pinfo.processAppSpec = &spec;
	err = GetProcessInformation(&psn, &pinfo);
	
	argv[0] = (char *) &AppName[1];
	if (AppName[0] + 1 == sizeof(AppName))
		(AppName[0])--;
	AppName[AppName[0] + 1] = 0;
	
	if (spec.name[0] < 28)
	{
		BlockMoveData(spec.name, outReply.sfFile.name, sizeof(spec.name));
		BlockMoveData(".out", outReply.sfFile.name+spec.name[0]+1, 4);
		outReply.sfFile.name[0] = spec.name[0] + 4;
	}
	else
		*outReply.sfFile.name = 0;	
	
	BuildDialog();
	
#if TARGET_API_MAC_CARBON
	SetWTitle(GetDialogWindow(theDialog), spec.name);
	{
		Cursor	theArrow;
		SetCursor(GetQDGlobalsArrow(&theArrow));
	}
	ShowWindow(GetDialogWindow(theDialog));
	myFilterUPP = NewModalFilterUPP(myFilter);
#else
	SetWTitle(theDialog, AppName);
	SetCursor(&qd.arrow);
	ShowWindow(theDialog);
	myFilterUPP = NewModalFilterProc((ProcPtr) myFilter);
#endif /* TARGET_API_MAC_CARBON */
	
	while (1)
	{
		ModalDialog(myFilterUPP, &theItem);
		
		switch(theItem)
		{
			case kOK:
				if (stdinSel)
				{
#if _MSL_CARBON_FILE_APIS

#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
					FSRef theRef;
					
					err = FSpMakeFSRef(&inReply.sfFile, &theRef);
					
					if (err == noErr)
						err = FSOpenFork(&theRef, 0, NULL, fsRdPerm, &refNum);
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
					err = FSpOpenDF(&inReply.sfFile, fsRdPerm, &refNum);
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */

#else

				{
					FSRef theRef;
					UInt8 thePath[2048];
					
					err = FSpMakeFSRef(&inReply.sfFile, &theRef);
					
					if (err == noErr)
						err = FSRefMakePath(&theRef, thePath, sizeof(thePath));
					
					if (err == noErr)
					{
						refNum = open((const char *) thePath, O_RDONLY, DEFFILEMODE);
						
						if (refNum == -1)
							err = paramErr;
					}
				}

#endif /* _MSL_CARBON_FILE_APIS */
					
					if (!err)
					{
						__handle_reopen(refNum, "r", stdin);
						/*_Files[0]->_Handle = refNum;*/
					}
				}
				
				if (stdoutSel)
				{
					if (outReply.sfReplacing) FSpDelete(&outReply.sfFile);
					
					err = FSpCreate(&outReply.sfFile, __getcreator(false), __gettype(false), outReply.sfScript);
					
					if ((err == 0) || (err == dupFNErr))
					{
#if _MSL_CARBON_FILE_APIS

#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	if (__msl_system_has_new_file_apis())
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_NEW_FILE_APIS
					FSRef theRef;
					
					err = FSpMakeFSRef(&outReply.sfFile, &theRef);
					
					if (err == noErr)
						err = FSOpenFork(&theRef, 0, NULL, fsWrPerm, &refNum);
#endif /* _MSL_USE_NEW_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
	else
	{
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */
#if _MSL_USE_OLD_FILE_APIS
						err = FSpOpenDF(&outReply.sfFile, fsWrPerm, &refNum);
#endif /* _MSL_USE_OLD_FILE_APIS */
#if _MSL_USE_OLD_AND_NEW_FILE_APIS
	}
#endif /* _MSL_USE_OLD_AND_NEW_FILE_APIS */

#else

				{
					FSRef theRef;
					UInt8 thePath[2048];
					
					err = FSpMakeFSRef(&inReply.sfFile, &theRef);
					
					if (err == noErr)
						err = FSRefMakePath(&theRef, thePath, sizeof(thePath));
					
					if (err == noErr)
					{
						refNum = open((const char *) thePath, O_WRONLY | O_CREAT | O_TRUNC, DEFFILEMODE);
						
						if (refNum == -1)
							err = paramErr;
					}
				}

#endif /* _MSL_CARBON_FILE_APIS */
						
						if (!err)
						{
							__handle_reopen(refNum, "w", stdout);
							/*_Files[1]->_Handle = refNum;
							  _Files[1]->_Mode = _MOPENW; */
							err = 0;
						}
					}
					
					/*if (err) fprintf(stderr,"Output redirection failed! Error: %d\n",err);*/
				}
				
				GetDialogItemText(ItemHandle(4), (StringPtr) argument);
				/*convert argument to C string*/
				arglen = argument[0];
				memmove(argument, argument+1, arglen);
				argument[arglen] = '\0';
				
				DisposeDialog(theDialog);
				
#if TARGET_API_MAC_CARBON
				DisposeModalFilterUPP(myFilterUPP);
#else	
				DisposeRoutineDescriptor((UniversalProcPtr) myFilterUPP);
#endif /* TARGET_API_MAC_CARBON */
				
				*arg = argv;
				return ParseArgs((char *)argument);
			case kQUIT:
				DisposeDialog(theDialog);
				
#if TARGET_API_MAC_CARBON
				DisposeModalFilterUPP(myFilterUPP);
#else	
				DisposeRoutineDescriptor((UniversalProcPtr) myFilterUPP);
#endif /* TARGET_API_MAC_CARBON */
				
				exit(0);
			case stdInBase+1:
				GetFile(&inReply);
				HiliteControl((ControlHandle) ItemHandle(kQUIT), 0);
				if (inReply.sfGood)
				{
					SetControlTitle((ControlHandle) ItemHandle(theItem), TruncFileName(inReply.sfFile.name));
					SetRadioState(stdInBase, 2, theItem);
					stdinSel = 1;
				}
				break;
			case stdInBase:
				SetRadioState(stdInBase, 2, theItem);
				SetControlTitle((ControlHandle) ItemHandle(theItem+1), "\pFile");
				stdinSel = 0;
				break;
			case stdOutBase+1:
				PutFile(&outReply);
				HiliteControl((ControlHandle) ItemHandle(kQUIT), 0);
				if (outReply.sfGood)
				{
					SetControlTitle((ControlHandle) ItemHandle(theItem), TruncFileName(outReply.sfFile.name));
					SetRadioState(stdOutBase, 2, theItem);
					stdoutSel = 1;
				}
				break;
			case stdOutBase:
				SetRadioState(stdOutBase, 2, theItem);
				SetControlTitle((ControlHandle) ItemHandle(theItem+1), "\pFile");
				stdoutSel = 0;
				break;
		}
	}
}

/* Change record:
 * mm  960606 The Dialog manager expects item lists to use 68k alignment. 
 * bkoz961221 line 331 added moto wrappter (mmoss)
 * bkoz970211 added A4 section, seems as if our compiler chokes on empty source files
 * mm  970404 Limited number of args parsed to MAX_ARGS, remainder ignored.
 * mf  971006 added fixes to compile w/ 3.0.1  universal headers
 * vss 990830 Removed duplicate SetControlTitle(... "\pOK"); at line 230 
 * cc  991108 added ra Carbon Changes done 990611
 * cc  991109 changed TARGET_CARBON to TARGET_API_MAC_CARBON
 * cc  991111 added 'static' 
 * cc  991115 updated and deleted outdated comments
 * JWW 000612 Fixed problems with Navigation Services when targeting Carbon
 * JWW 000626 Default button throbs (bleck!) properly on OS X
 * JWW 000821 Zero terminate argv[0] (the program name)
 * JWW 001127 Allow folder navigation when choosing files for input redirection
 * JWW 010612 Added OS 9 API file manager calls to support >32 character names & >2GB files
 * JWW 010606 Open output file for writing with new HFS+ APIs instead of the input file
 * JWW 011027 Added case for Mach-O
 */