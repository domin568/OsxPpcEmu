/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:51 $
 * $Revision: 1.12 $
 */
 
#ifndef _MSL_LONGCONTROLS_H
#define _MSL_LONGCONTROLS_H

#include <ansi_parms.h>   
#ifndef __CONTROLS__
	#include <Controls.h>
#endif

_MSL_BEGIN_EXTERN_C	/*- cc 010410 -*/

	_MSL_IMP_EXP_C OSErr LCAttach ( ControlRef inControl ) _MSL_CANT_THROW ;
	_MSL_IMP_EXP_C void LCDetach ( ControlRef inControl ) _MSL_CANT_THROW ;
	_MSL_IMP_EXP_C void LCSetValue ( ControlRef inControl, SInt32 inValue ) _MSL_CANT_THROW ;
	_MSL_IMP_EXP_C void LCSetMin ( ControlRef inControl, SInt32 inValue ) _MSL_CANT_THROW ;
	_MSL_IMP_EXP_C void LCSetMax ( ControlRef inControl, SInt32 inValue ) _MSL_CANT_THROW ;
	_MSL_IMP_EXP_C SInt32 LCGetValue ( ControlRef inControl ) _MSL_CANT_THROW ;
	_MSL_IMP_EXP_C SInt32 LCGetMin ( ControlRef inControl ) _MSL_CANT_THROW ;
	_MSL_IMP_EXP_C SInt32 LCGetMax ( ControlRef inControl ) _MSL_CANT_THROW ;
	_MSL_IMP_EXP_C void LCSynch ( ControlRef inControl ) _MSL_CANT_THROW ;

_MSL_END_EXTERN_C	/*- cc 010410 -*/

#endif /* _MSL_LONGCONTROLS_H */

/* Change record:
 * cc  000620 added #include <ansi_parms.h>  so header can compile standalone
 * cc  010410 updated to new namespace macros 		  
 * hh  020603 Added no throw spec to functions
 */