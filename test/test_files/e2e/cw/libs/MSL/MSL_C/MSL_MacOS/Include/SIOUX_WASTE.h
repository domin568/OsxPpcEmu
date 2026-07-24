/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:52 $
 * $Revision: 1.7 $
 */
 
/* This file is only required when using the SIOUX source code to
   compile, e.g. building a new library. It sets the preprocessor
   options to include WASTE support.
   
   If your SIOUX lib is compiled properly (i.e. you're using an
   MSL-compatible lib in an MSL project), you do not need to include
   this file--just SIOUX.h if you want to change SIOUX settings.
   
   --pcg
*/

#ifndef _MSL_SIOUX_WASTE_H
#define _MSL_SIOUX_WASTE_H

#include <SIOUXPrefix.h>

#define SIOUX_USE_WASTE		1
#define WASTE_IC_SUPPORT	1
#define WASTE_DEBUG			0
#define	WASTE_OBJECTS		0

#endif /* _MSL_SIOUX_WASTE_H */

/* Change record:
 * cc  010306 made a change record
 */