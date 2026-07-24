/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:33 $
 * $Revision: 1.7 $
 */
 
/*
 *	Macintosh Controls with Long Values
 *
 *	Copyright © 1993-1997 Marco Piovanelli
 *	All Rights Reserved
 *
 *	C port by John C. Daub
 */

#ifndef __LONGCONTROLS__
#include "LongControls.h"
#endif

//	MacOS #includes

#ifndef __FIXMATH__
#include <FixMath.h>
#endif

#ifndef __TOOLUTILS__
#include <ToolUtils.h>
#endif

//	ANSI #includes

#include <limits.h>

//	useful #defines

#define BSL(A, B)	(((long) (A)) << (B))

// long control auxiliary record used for keeping long settings
// a handle to this record is stored in the reference field of the control record

typedef struct LCAuxRec
{
	SInt32	value;	// long value
	SInt32	min;	// long min
	SInt32	max;	// long max
} LCAuxRec, * LCAuxPtr, ** LCAuxHandle ;

OSErr LCAttach ( ControlRef inControl )
{
	Handle		aux ;
	LCAuxPtr	pAux ;
	SInt16 controlMin, controlMax, controlValue ;

	/*	allocate the auxiliary record that will hold long settings */
	if ( ( aux = NewHandleClear ( sizeof ( LCAuxRec ) ) ) == nil )
	{
		return	MemError ( ) ;
	}

	/*	store a handle to the auxiliary record in the contrlRfCon field */
	SetControlReference ( inControl, ( SInt32 ) aux ) ;

	/*	copy current control settings into the auxiliary record */

	controlMin = GetControlMinimum ( inControl ) ;
	controlMax = GetControlMaximum ( inControl ) ;
	controlValue = GetControlValue ( inControl ) ;
	
	pAux = * ( LCAuxHandle ) aux ;
	pAux -> value = controlValue ;
	pAux -> min = controlMin ;
	pAux -> max = controlMax ;

	return noErr ;
}

void LCDetach ( ControlRef inControl )
{
	Handle aux ;

	if ( ( aux = ( Handle ) GetControlReference ( inControl ) ) != nil )
	{
		SetControlReference ( inControl, 0L ) ;
		DisposeHandle ( aux ) ;
	}
}

void LCSetValue ( ControlRef inControl, SInt32 inValue )
{
	LCAuxPtr pAux ;
	SInt16 controlMin, controlMax, newControlValue ;

	pAux = * ( LCAuxHandle ) GetControlReference ( inControl ) ;

	/*	make sure inValue is in the range min...max */
	if ( inValue < pAux -> min )
	{
		inValue = pAux -> min ;
	}
	if ( inValue > pAux -> max )
	{
		inValue = pAux -> max ;
	}

	/*	save inValue in auxiliary record */
	pAux -> value = inValue ;

	/*	calculate new thumb position */
	controlMin = GetControlMinimum ( inControl ) ;
	controlMax = GetControlMaximum ( inControl ) ;
	newControlValue = controlMin + FixRound ( FixMul ( FixDiv ( inValue - pAux -> min,
		pAux -> max - pAux -> min), BSL ( controlMax - controlMin, 16 ) ) ) ;

	/*	do nothing if the thumb position hasn't changed */
	if ( newControlValue != GetControlValue ( inControl ) )
	{
		SetControlValue ( inControl, newControlValue ) ;
	}
}

void LCSetMin ( ControlRef inControl, SInt32 inMin )
{
	LCAuxPtr pAux;

	pAux = * ( LCAuxHandle ) GetControlReference ( inControl ) ;

	/*	make sure inMin is less than or equal to max */
	if ( inMin > pAux -> max )
	{
		inMin = pAux -> max ;
	}

	/*	save inMin in auxiliary record */
	pAux -> min = inMin ;

	/*	set control minimum to inMin or SHRT_MIN, whichever is greater */
	SetControlMinimum ( inControl, ( inMin >= SHRT_MIN ) ? inMin : SHRT_MIN ) ;

	/*	reset value */
	LCSetValue ( inControl, pAux -> value ) ;
}

void LCSetMax ( ControlRef inControl, SInt32 inMax )
{
	LCAuxPtr pAux ;

	pAux = * ( LCAuxHandle ) GetControlReference ( inControl ) ;

	/*	make sure inMax is greater than or equal to min */
	if ( inMax < pAux -> min )
	{
		inMax = pAux -> min ;
	}

	/*	save inMax in auxiliary record */
	pAux -> max = inMax ;

	/*	set control maximum to inMax or SHRT_MAX, whichever is less */
	SetControlMaximum ( inControl, ( inMax <= SHRT_MAX ) ? inMax : SHRT_MAX ) ;

	/*	reset value */
	LCSetValue ( inControl, pAux -> value ) ;
}

SInt32 LCGetValue ( ControlRef inControl )
{
	return ( * ( LCAuxHandle ) GetControlReference ( inControl ) ) -> value ;
}

SInt32 LCGetMin ( ControlRef inControl )
{
	return ( * ( LCAuxHandle ) GetControlReference ( inControl ) ) -> min ;
}

SInt32 LCGetMax ( ControlRef inControl )
{
	return ( * ( LCAuxHandle ) GetControlReference ( inControl ) ) -> max ;
}

void LCSynch ( ControlRef inControl )
{
	LCAuxPtr pAux ;
	SInt16 controlMin, controlMax, controlValue ;

	controlMin = GetControlMinimum ( inControl ) ;
	controlMax = GetControlMaximum ( inControl ) ;
	controlValue = GetControlValue ( inControl ) ;
	pAux = * ( LCAuxHandle ) GetControlReference ( inControl ) ;

	/*	calculate new long value */
	pAux -> value = pAux -> min + FixMul ( FixRatio ( controlValue - controlMin,
				  controlMax - controlMin ), pAux -> max - pAux -> min ) ;
}

/* Change record:
 * cc  010307 made the change record 
 * JWW 010917 Made LCAttach not call the toolbox after dereferencing LCAuxHandle since it could move memory
 */