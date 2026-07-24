/* Metrowerks Standard Library
 * Copyright © 1995-2003 Metrowerks Corporation.  All rights reserved.
 *
 * $Date: 2003/01/13 15:23:53 $
 * $Revision: 1.10 $
 */

/*
 *		Notes
 *		-----
 *  This file is used to set the resolution of the microsecond clock.  Defining __TIMESIZE_DOUBLE__
 *  will cause clock_t to be redefined as a double, which redefines the clock function to be a
 *  double as well.  See time.h and time.mac.c for implementation details.
 *
 *  If you wish a higher resolution microsecond clock as defined by the MacOS operating system,
 *  enable __TIMESIZE_DOUBLE__ below by removing the comments surrounding it and ensure that
 *  all of your code using the clock routine understands the new type double.
 */

#ifndef _MSL_TIMESIZE_MAC_H
#define _MSL_TIMESIZE_MAC_H

#define __TIMESIZE_DOUBLE__  

#endif /* _MSL_TIMESIZE_MAC_H */

/* Change record:
 * vss 971222 New file.
 * JWW 010621 Turn on __TIMESIZE_DOUBLE__ by default
 */