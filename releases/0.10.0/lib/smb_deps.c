/*
 * This file contains miscellaneous pieces of code which regfio.c
 * depends upon, from the Samba Subversion tree.  See:
 *   http://websvn.samba.org/cgi-bin/viewcvs.cgi/trunk/source/
 *
 * Copyright (C) 2005-2006,2009 Timothy D. Morgan
 * Copyright (C) 1992-2005 Samba development team 
 *               (see individual files under Subversion for details.)
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
 * $Id$
 */

#include "../include/smb_deps.h"


/* These act as replacements for numerous Samba memory allocation
 *   functions. 
 */
void* zalloc(size_t size)
{
  void* ret_val = NULL;
  if((size > 0) && (ret_val = (void*)malloc(size)) != NULL)
    memset(ret_val, 0, size);

  return ret_val;
}

void* zcalloc(size_t size, unsigned int count)
{
  return zalloc(size*count);
}

/* From lib/time.c */

/****************************************************************************
 Put a 8 byte filetime from a time_t
 This takes real GMT as input and converts to kludge-GMT
****************************************************************************/
void unix_to_nt_time(NTTIME *nt, time_t t)
{
  double d;
  
  if (t==0) 
  {
    nt->low = 0;
    nt->high = 0;
    return;
  }
  
  if (t == TIME_T_MAX) 
  {
    nt->low = 0xffffffff;
    nt->high = 0x7fffffff;
    return;
  }		
  
  if (t == -1) 
  {
    nt->low = 0xffffffff;
    nt->high = 0xffffffff;
    return;
  }		
  
  /* this converts GMT to kludge-GMT */
  /* XXX: This was removed due to difficult dependency requirements.  
   *      So far, times appear to be correct without this adjustment, but 
   *      that may be proven wrong with adequate testing. 
   */
  /* t -= TimeDiff(t) - get_serverzone(); */
  
  d = (double)(t);
  d += TIME_FIXUP_CONSTANT;
  d *= 1.0e7;
  
  nt->high = (uint32)(d * (1.0/(4.0*(double)(1<<30))));
  nt->low  = (uint32)(d - ((double)nt->high)*4.0*(double)(1<<30));
}


/****************************************************************************
 Interpret an 8 byte "filetime" structure to a time_t
 It's originally in "100ns units since jan 1st 1601"

 An 8 byte value of 0xffffffffffffffff will be returned as (time_t)0.

 It appears to be kludge-GMT (at least for file listings). This means
 its the GMT you get by taking a localtime and adding the
 serverzone. This is NOT the same as GMT in some cases. This routine
 converts this to real GMT.
****************************************************************************/
time_t nt_time_to_unix(const NTTIME* nt)
{
  double d;
  time_t ret;
  /* The next two lines are a fix needed for the 
     broken SCO compiler. JRA. */
  time_t l_time_min = TIME_T_MIN;
  time_t l_time_max = TIME_T_MAX;
  
  if (nt->high == 0 || (nt->high == 0xffffffff && nt->low == 0xffffffff))
    return(0);
  
  d = ((double)nt->high)*4.0*(double)(1<<30);
  d += (nt->low&0xFFF00000);
  d *= 1.0e-7;
  
  /* now adjust by 369 years to make the secs since 1970 */
  d -= TIME_FIXUP_CONSTANT;
  
  if (d <= l_time_min)
    return (l_time_min);
  
  if (d >= l_time_max)
    return (l_time_max);
  
  ret = (time_t)(d+0.5);
  
  /* this takes us from kludge-GMT to real GMT */
  /* XXX: This was removed due to difficult dependency requirements.  
   *      So far, times appear to be correct without this adjustment, but 
   *      that may be proven wrong with adequate testing. 
   */
  /*
    ret -= get_serverzone();
    ret += LocTimeDiff(ret);
  */

  return(ret);
}

/* End of stuff from lib/time.c */
