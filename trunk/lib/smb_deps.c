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
  if((ret_val = (void*)malloc(size)) != NULL)
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

/* From parse_prs.c */

/*******************************************************************
 Attempt, if needed, to grow a data buffer.
 Also depends on the data stream mode (io).
 ********************************************************************/
bool prs_grow(prs_struct *ps, uint32 extra_space)
{
  uint32 new_size;
  char *new_data;
  
  ps->grow_size = MAX(ps->grow_size, ps->data_offset + extra_space);
  
  if(ps->data_offset + extra_space <= ps->buffer_size)
    return true;
  
  /*
   * We cannot grow the buffer if we're not reading
   * into the prs_struct, or if we don't own the memory.
   */
  
  if(ps->io || !ps->is_dynamic)
    return false;
  
  /*
   * Decide how much extra space we really need.
   */
  extra_space -= (ps->buffer_size - ps->data_offset);
  if(ps->buffer_size == 0) 
  {
    /*
     * Ensure we have at least a PDU's length, or extra_space, 
     * whichever is greater.
     */  
    new_size = MAX(MAX_PDU_FRAG_LEN,extra_space);
    
    if((new_data = zalloc(new_size)) == NULL)
      return false;
  } 
  else 
  {
    /*
     * If the current buffer size is bigger than the space needed, just 
     * double it, else add extra_space.
     */
    new_size = MAX(ps->buffer_size*2, ps->buffer_size + extra_space);		
    
    if ((new_data = (char*)realloc(ps->data_p, new_size)) == NULL)
      return false;
    
    memset(&new_data[ps->buffer_size], '\0', 
	   (size_t)(new_size - ps->buffer_size));
  }
  ps->buffer_size = new_size;
  ps->data_p = new_data;
  
  return true;
}


/*******************************************************************
 Align a the data_len to a multiple of align bytes - filling with
 zeros.
 ********************************************************************/
bool prs_align(prs_struct *ps)
{
  uint32 mod = ps->data_offset & (ps->align-1);
  
  if (ps->align != 0 && mod != 0) 
  {
    uint32 extra_space = (ps->align - mod);
    if(!prs_grow(ps, extra_space))
      return false;
    memset(&ps->data_p[ps->data_offset], '\0', (size_t)extra_space);
    ps->data_offset += extra_space;
  }
  
  return true;
}


/**
 * Initialise an expandable parse structure.
 *
 * @param size Initial buffer size.  If >0, a new buffer will be
 * created with malloc().
 *
 * @return false if allocation fails, otherwise true.
 **/

bool prs_init(prs_struct *ps, uint32 size, void *ctx, bool io)
{
  if(ps == NULL)
    return false;
  memset(ps, 0, sizeof(prs_struct));

  ps->io = io;
  ps->bigendian_data = RPC_LITTLE_ENDIAN;
  ps->align = RPC_PARSE_ALIGN;
  ps->is_dynamic = false;
  ps->data_offset = 0;
  ps->buffer_size = 0;
  ps->data_p = NULL;
  ps->mem_ctx = ctx;
  
  if (size != 0) 
  {
    ps->buffer_size = size;
    if((ps->data_p = (char *)zalloc((size_t)size)) == NULL)
      return false;

    ps->is_dynamic = true; /* We own this memory. */
  }
  
  return true;
}


char *prs_mem_get(prs_struct *ps, uint32 extra_size)
{
  if(ps->io) 
  {
    /*
     * If reading, ensure that we can read the requested size item.
     */
    if (ps->data_offset + extra_size > ps->buffer_size)
      return NULL;
  } 
  else 
  {
    /*
     * Writing - grow the buffer if needed.
     */
    if(!prs_grow(ps, extra_size))
      return NULL;
  }

  return &ps->data_p[ps->data_offset];
}


/*******************************************************************
 Stream a uint32.
 ********************************************************************/
bool prs_uint32(const char *name, prs_struct *ps, int depth, uint32 *data32)
{
  char *q = prs_mem_get(ps, sizeof(uint32));
  if (q == NULL)
    return false;
  
  if (ps->io) 
  {
    if (ps->bigendian_data)
      *data32 = RIVAL(q,0);
    else
      *data32 = IVAL(q,0);
  } 
  else 
  {
    if (ps->bigendian_data)
      RSIVAL(q,0,*data32);
    else
      SIVAL(q,0,*data32);
  }
  ps->data_offset += sizeof(uint32);
  
  return true;
}


/******************************************************************
 Stream an array of uint32s. Length is number of uint32s.
 ********************************************************************/
bool prs_uint32s(const char *name, prs_struct *ps, 
		 int depth, uint32 *data32s, int len)
{
  int i;
  char *q = prs_mem_get(ps, len * sizeof(uint32));
  if (q == NULL)
    return false;
  
  if (ps->io) 
  {
    if (ps->bigendian_data) 
    {
      for (i = 0; i < len; i++)
	data32s[i] = RIVAL(q, 4*i);
    } 
    else 
    {
      for (i = 0; i < len; i++)
	data32s[i] = IVAL(q, 4*i);
    }
  } 
  else 
  {
    if (ps->bigendian_data) 
    {
      for (i = 0; i < len; i++)
	RSIVAL(q, 4*i, data32s[i]);
    } 
    else 
    {
      for (i = 0; i < len; i++)
	SIVAL(q, 4*i, data32s[i]);
    }
  }
  ps->data_offset += (len * sizeof(uint32));
  
  return true;
}


/*******************************************************************
 Stream a uint16.
 ********************************************************************/
bool prs_uint16(const char *name, prs_struct *ps, int depth, uint16 *data16)
{
  char *q = prs_mem_get(ps, sizeof(uint16));
  if (q == NULL)
    return false;
  
  if (ps->io) 
  {
    if (ps->bigendian_data)
      *data16 = RSVAL(q,0);
    else
      *data16 = SVAL(q,0);
  } 
  else 
  {
    if (ps->bigendian_data)
      RSSVAL(q,0,*data16);
    else
      SSVAL(q,0,*data16);
  }
  ps->data_offset += sizeof(uint16);
  
  return true;
}


/*******************************************************************
 prs_uint16 wrapper. Call this and it sets up a pointer to where the
 uint16 should be stored, or gets the size if reading.
 ********************************************************************/
bool prs_uint16_pre(const char *name, prs_struct *ps, int depth, 
		    uint16 *data16, uint32 *offset)
{
  *offset = ps->data_offset;
  if (ps->io) 
  {
    /* reading. */
    return prs_uint16(name, ps, depth, data16);
  } 
  else 
  {
    char *q = prs_mem_get(ps, sizeof(uint16));
    if(q ==NULL)
      return false;
    ps->data_offset += sizeof(uint16);
  }
  return true;
}


/*******************************************************************
 prs_uint16 wrapper.  call this and it retrospectively stores the size.
 does nothing on reading, as that is already handled by ...._pre()
 ********************************************************************/
bool prs_uint16_post(const char *name, prs_struct *ps, int depth, 
		     uint16 *data16, uint32 ptr_uint16, uint32 start_offset)
{
  if (!ps->io) 
  {
    /* 
     * Writing - temporarily move the offset pointer.
     */
    uint16 data_size = ps->data_offset - start_offset;
    uint32 old_offset = ps->data_offset;
    
    ps->data_offset = ptr_uint16;
    if(!prs_uint16(name, ps, depth, &data_size)) 
    {
      ps->data_offset = old_offset;
      return false;
    }
    ps->data_offset = old_offset;
  } 
  else 
    ps->data_offset = start_offset + (uint32)(*data16);

  return true;
}


/*******************************************************************
 Stream a uint8.
 ********************************************************************/
bool prs_uint8(const char *name, prs_struct *ps, int depth, uint8 *data8)
{
  char *q = prs_mem_get(ps, 1);
  if (q == NULL)
    return false;
  
  if (ps->io)
    *data8 = CVAL(q,0);
  else
    SCVAL(q,0,*data8);
  
  ps->data_offset += 1;
  
  return true;
}


/******************************************************************
 Stream an array of uint8s. Length is number of uint8s.
 ********************************************************************/
bool prs_uint8s(const char *name, prs_struct *ps, int depth, 
		uint8* data8s, int len)
{
  int i;
  char *q = prs_mem_get(ps, len);
  if (q == NULL)
    return false;
  
  if (ps->io) 
  {
    for (i = 0; i < len; i++)
      data8s[i] = CVAL(q,i);
  } 
  else 
  {
    for (i = 0; i < len; i++)
      SCVAL(q, i, data8s[i]);
  }
  
  ps->data_offset += len;
  
  return true;
}


/*******************************************************************
 Set the current offset (external interface).
 ********************************************************************/
bool prs_set_offset(prs_struct *ps, uint32 offset)
{
  if(offset <= ps->data_offset) 
  {
    ps->data_offset = offset;
    return true;
  }
  
  if(!prs_grow(ps, offset - ps->data_offset))
    return false;
  
  ps->data_offset = offset;
  return true;
}

/* End of stuff from parse_prs.c */

/* From rpc_parse/parse_misc.c */

/*******************************************************************
 Reads or writes a struct uuid
********************************************************************/
bool smb_io_uuid(const char *desc, struct uuid *uuid, 
		 prs_struct *ps, int depth)
{
  if (uuid == NULL)
    return false;
  depth++;
  
  if(!prs_uint32 ("data   ", ps, depth, &uuid->time_low))
    return false;
  if(!prs_uint16 ("data   ", ps, depth, &uuid->time_mid))
    return false;
  if(!prs_uint16 ("data   ", ps, depth, &uuid->time_hi_and_version))
    return false;
  
  if(!prs_uint8s ("data   ", ps, depth, 
		  uuid->clock_seq, sizeof(uuid->clock_seq)))
    return false;

  if(!prs_uint8s ("data   ", ps, depth, uuid->node, sizeof(uuid->node)))
    return false;
  
  return true;
}


/*******************************************************************
 Reads or writes an NTTIME structure.
********************************************************************/
bool smb_io_time(const char *desc, NTTIME *nttime, prs_struct *ps, int depth)
{
  if (nttime == NULL)
    return false;
  depth++;

  if(!prs_align(ps))
    return false;
	
  if(!prs_uint32("low ", ps, depth, &nttime->low)) /* low part */
    return false;
  if(!prs_uint32("high", ps, depth, &nttime->high)) /* high part */
    return false;

  return true;
}
