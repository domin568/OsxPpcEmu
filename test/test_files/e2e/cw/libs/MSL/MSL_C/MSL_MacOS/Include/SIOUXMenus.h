/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:52 $
 * $Revision: 1.11 $
 */

/*****************************************************************************/
/*  Project...: C++ and ANSI-C Compiler Environment                          */
/*  Purpose...: Menu related functions for SIOUX			                 */
/*****************************************************************************/

#ifndef _MSL_SIOUXMENUS_H
#define _MSL_SIOUXMENUS_H

#if __MWERKS__
	#pragma options align=mac68k
#endif

/* Menu IDs ...*/
enum {
	APPLEID 		= 32000,
	APPLEABOUT 		= 1
};

enum {
	FILEID			= 32001,
	FILESAVE 		= 4,
	FILEPAGESETUP	= 6,
	FILEPRINT		= 7,
	FILEQUIT		= 9
};

enum {
	EDITID			= 32002,
	EDITCUT			= 3,
	EDITCOPY		= 4,
	EDITPASTE		= 5,
	EDITCLEAR		= 6,
	EDITSELECTALL	= 8
};


_MSL_BEGIN_EXTERN_C	/*- cc 010410 -*/

	/*Function prototypes ...*/
	_MSL_IMP_EXP_SIOUX extern void		SIOUXSetupMenus(void);
	_MSL_IMP_EXP_SIOUX extern void		SIOUXUpdateMenuItems(void);
	_MSL_IMP_EXP_SIOUX extern short		SIOUXDoSaveText(void);
	_MSL_IMP_EXP_SIOUX extern void		SIOUXDoEditCut(void);
	_MSL_IMP_EXP_SIOUX extern void		SIOUXDoEditCopy(void);
	_MSL_IMP_EXP_SIOUX extern void		SIOUXDoEditPaste(void);
	_MSL_IMP_EXP_SIOUX extern void		SIOUXDoEditClear(void);
	_MSL_IMP_EXP_SIOUX extern void		SIOUXDoEditSelectAll(void);
	_MSL_IMP_EXP_SIOUX extern void		SIOUXDoMenuChoice(long menuValue);

_MSL_END_EXTERN_C	/*- cc 010410 -*/


#if __MWERKS__
	#pragma options align=reset
#endif

#endif /* _MSL_SIOUXMENUS_H */

/* Change record:
 * mm  960930 Changed C++ comments to C comments for ANSI strict
 * cc  010410 updated to new namespace macros 		  
 */
