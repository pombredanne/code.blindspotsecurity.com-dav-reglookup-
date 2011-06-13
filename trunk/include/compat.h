/*
 * Copyright (C) 2005-2010 Timothy D. Morgan
 * Copyright (C) 2010 Michael Cohen
 * Copyright (C) 2005 Gerald (Jerry) Carter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: regfi.h 252 2011-05-08 17:33:49Z tim $
 */

#ifndef _COMPAT_H
#define _COMPAT_H

/* GCC-specific macro for library exports */
#ifdef _EXPORT
#undef _EXPORT
#endif
#ifdef REGFI_WIN32
#define _EXPORT() __declspec(dllexport)
#else
#define _EXPORT() __attribute__((visibility("default")))
#endif

#ifndef EOVERFLOW
# define EOVERFLOW E2BIG
#endif

#endif /*_COMPAT_H*/
