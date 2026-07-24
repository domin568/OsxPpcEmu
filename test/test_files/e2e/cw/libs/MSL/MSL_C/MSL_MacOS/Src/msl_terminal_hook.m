/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/08/20 02:04:57 $
 * $Revision: 1.3.2.2 $
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include <Carbon/Carbon.h>

#define kTerminalSignature 'trmx'
#define kDoScriptClass 'core'
#define kDoScript 'dosc'
#define kCount 'cnte'
#define keyWithCommand 'cmnd'
#define keyInWindow 'kfil'

/* Add in some necessary prototypes in case MSL was used to compile this file instead of BSD C */
#ifdef __MSL__
	int pclose(FILE *);
	FILE *popen(const char *, const char *);
	int fileno(FILE *);
#endif

static Boolean __msl_search_for_terminal(ProcessSerialNumber *thePSN,
	Boolean isWaitingForProcessToAppear)
{
	OSErr theErr;
	ProcessInfoRec theInfo;
	
	/* Start at the beginning of the process list */
	thePSN->highLongOfPSN = 0;
	thePSN->lowLongOfPSN = kNoProcess;
	
	theInfo.processInfoLength = sizeof(theInfo);
	theInfo.processName = NULL;
	theInfo.processAppSpec = NULL;
	do
	{
		theErr = GetNextProcess(thePSN);
		
		if (theErr == noErr)
			theErr = GetProcessInformation(thePSN, &theInfo);
		
		/* Restart the search if Terminal wasn't found and it is in the process of being started */
		if ((theErr == procNotFound) && isWaitingForProcessToAppear)
		{
			theErr = noErr;
			thePSN->highLongOfPSN = 0;
			thePSN->lowLongOfPSN = kNoProcess;
		}
	} while ((theErr == noErr) && (theInfo.processSignature != kTerminalSignature));
	
	return (theErr == noErr);
}

static OSErr __msl_launch_terminal(ProcessSerialNumber *thePSN, Boolean *isOldProcess)
{
	OSErr theErr;
	FSRef theTerminalRef;
	
	theErr = noErr;
	/* Test to see if the Terminal is already running, and if so, grab its process number */
	*isOldProcess = __msl_search_for_terminal(thePSN, false);
	
	if (!*isOldProcess)
	{
		/* Find the Terminal application since it wasn't running */
		theErr = LSFindApplicationForInfo(kTerminalSignature, NULL, NULL, &theTerminalRef, NULL);
		
		/* Launch the Terminal */
		if (theErr == noErr)
			theErr = LSOpenFSRef(&theTerminalRef, NULL);
		
		/* Wait for the Terminal process number to appear in the list of running processes */
		if (theErr == noErr)
			__msl_search_for_terminal(thePSN, true);
	}
	
	return theErr;
}

static OSErr __msl_tell_terminal_to_launch_pathname(ProcessSerialNumber *thePSN,
	Boolean isOldProcess, char *pathname)
{
	OSErr theErr;
	AEAddressDesc theTarget;
	AppleEvent theEvent;
	AEDesc theIndexDesc;
	AEDesc theNullDesc;
	AEDesc theWindowDesc;
	SInt32 theIndex;
	int i, j;
	long theResponse;
	char theCommand[2048];
	
	theErr = AECreateDesc(typeProcessSerialNumber, thePSN, sizeof(*thePSN), &theTarget);
	
	if (theErr == noErr)
	{
		theErr = AECreateAppleEvent(kDoScriptClass, kDoScript, &theTarget, kAutoGenerateReturnID,
			kAnyTransactionID, &theEvent);
		
		AEDisposeDesc(&theTarget);
		
		if (theErr == noErr)
		{
			/* Start with a 'clear' command to freshen up the terminal window */
			theCommand[0] = 'c';
			theCommand[1] = 'l';
			theCommand[2] = 'e';
			theCommand[3] = 'a';
			theCommand[4] = 'r';
			theCommand[5] = ';';
			i = 0;
			j = 6;
			
			/* Escape any special characters in the pathname */
			while ((pathname[i] != 0) && (j < (sizeof(theCommand) + 5)))
			{
				if ((pathname[i] == ' ') || (pathname[i] == '"') || (pathname[i] == '\'') ||
					(pathname[i] == '(') || (pathname[i] == ')') || (pathname[i] == '\\') ||
					(pathname[i] == '&'))
				{
					theCommand[j] = '\\';
					j++;
				}
				
				theCommand[j] = pathname[i];
				
				i++;
				j++;
			}
			
			theCommand[j] = ';';
			theCommand[j + 1] = 'e';
			theCommand[j + 2] = 'x';
			theCommand[j + 3] = 'i';
			theCommand[j + 4] = 't';
			theCommand[j + 5] = 0;
			
			theErr = Gestalt(gestaltSystemVersion, &theResponse);
			if ((theErr == noErr) && (theResponse < 0x1020))
				/* Give the 10.1 or earlier Terminal the pathname to the current application */
				theErr = AEPutParamPtr(&theEvent, keyWithCommand, typeChar, &theCommand,
					strlen(theCommand));
			else
			{
				/* Give the 10.2 and later Terminal the pathname to the current application */
				theErr = AEPutParamPtr(&theEvent, keyDirectObject, typeChar, &theCommand,
					strlen(theCommand));
				
				/* If Terminal wasn't already running, run the application in the first window */
				/* (Otherwise the Terminal creates a new window for the application */
				if ((theErr == noErr) && !isOldProcess)
				{
					theIndex = 1;
					theErr = AECreateDesc(typeSInt32, &theIndex, sizeof(theIndex), &theIndexDesc);
					
					if (theErr == noErr)
					{
						theErr = AECreateDesc(typeNull, NULL, 0, &theNullDesc);
						
						if (theErr != noErr)
							AEDisposeDesc(&theIndexDesc);
						else
						{
							theErr = CreateObjSpecifier(cWindow, &theNullDesc, formAbsolutePosition,
								&theIndexDesc, true, &theWindowDesc);
							
							if (theErr == noErr)
							{
								theErr = AEPutParamDesc(&theEvent, keyInWindow, &theWindowDesc);
								AEDisposeDesc(&theWindowDesc);
							}
						}
					}
				}
			}
			
			/* Bring the Terminal to the front */
			if (theErr == noErr)
				theErr = SetFrontProcess(thePSN);
			
			/* Tell the Terminal to launch the application */
			if (theErr == noErr)
				theErr = AESend(&theEvent, NULL, kAENoReply + kAECanInteract,
					kAENormalPriority, kAEDefaultTimeout, NULL, NULL);
			
			AEDisposeDesc(&theEvent);
		}
	}
	
	return theErr;
}

static void __msl_start_under_terminal(char *pathname)
{
	OSErr theErr;
	ProcessSerialNumber thePSN;
	Boolean isOldProcess;
	
	/* Get the process number of the Terminal, launching it if necessary */
	theErr = __msl_launch_terminal(&thePSN, &isOldProcess);
	
	/* Tell the Terminal to run the current application */
	if (theErr == noErr)
		theErr = __msl_tell_terminal_to_launch_pathname(&thePSN, isOldProcess, pathname);
	
	/* If all went well, quit the app that was launched from the Finder */
	if (theErr == noErr)
		exit(0);
}

static Boolean __msl_is_being_debugged(void)
{
	Boolean isBeingDebugged;
	int i;
	ssize_t theSize;
	FILE *psFile;
	char psCommand[50];
	char theBuffer[2048];
	
	isBeingDebugged = false;
	
	sprintf(psCommand, "ps -c -p %d", getppid());
	psFile = popen(psCommand, "r");
	
	if (psFile != NULL)
	{
		theSize = read(fileno(psFile), theBuffer, sizeof(theBuffer));
		pclose(psFile);
		
		i = 0;
		while (((i + 2) < theSize) && !isBeingDebugged)
		{
			if (((theBuffer[i] == 'g') || (theBuffer[i] == 'G')) &&
				((theBuffer[i + 1] == 'd') || (theBuffer[i + 1] == 'D')) &&
				((theBuffer[i + 2] == 'b') || (theBuffer[i + 2] == 'B')))
				isBeingDebugged = true;
			else
				i++;
		}
	}
	
	return isBeingDebugged;
}

static void __msl_console_startup(void)
{
	OSErr theErr;
	FILE *ttyFile;
	ssize_t theSize;
	char firstChar;
	ProcessSerialNumber thePSN;
	ProcessInfoRec theInfo;
	FSSpec theSpec;
	FSRef theRef;
	char thePath[2048];
	
	/* Launch the 'tty' command to find out what terminal is currently in use */
	ttyFile = popen("tty", "r");
	
	if (ttyFile != NULL)
	{
		theSize = read(fileno(ttyFile), &firstChar, sizeof(firstChar));
		pclose(ttyFile);
		
		/* A file launched from the terminal has its tty name start as "/dev/tty" */
		/* A file launched from the Finder has its tty name as "not a tty" */
		if ((theSize == sizeof(firstChar)) && (firstChar != '/') && !__msl_is_being_debugged())
		{
			theErr = GetCurrentProcess(&thePSN);
			
			if (theErr == noErr)
			{
				theInfo.processInfoLength = sizeof(theInfo);
				theInfo.processName = NULL;
				theInfo.processAppSpec = &theSpec;
				theErr = GetProcessInformation(&thePSN, &theInfo);
			}
			
			if (theErr == noErr)
				theErr = FSpMakeFSRef(&theSpec, &theRef);
			
			if (theErr == noErr)
				theErr = FSRefMakePath(&theRef, (UInt8 *) thePath, sizeof(thePath));
			
			if (theErr == noErr)
				__msl_start_under_terminal(thePath);
		}
	}
}
#pragma CALL_ON_MODULE_BIND __msl_console_startup

#ifdef __mwlinker__
	#pragma INIT_BEFORE_TERM_AFTER on
#endif