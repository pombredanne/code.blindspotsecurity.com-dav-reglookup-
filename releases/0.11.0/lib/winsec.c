/*
 * This file contains refactored Samba code used to interpret Windows
 * Security Descriptors. See:
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

#include "winsec.h"


/******************************************************************************
 * Non-talloc() interface for parsing a descriptor.
 ******************************************************************************/
WINSEC_DESC* winsec_parse_descriptor(const uint8_t* buf, uint32_t buf_len)
{
  return winsec_parse_desc(NULL, buf, buf_len);
}


/******************************************************************************
 * Free a descriptor.  Not needed if using talloc and a parent context is freed.
 ******************************************************************************/
void winsec_free_descriptor(WINSEC_DESC* desc)
{
  talloc_free(desc);
}


/******************************************************************************
 * Parses a WINSEC_DESC structure and substructures.
 ******************************************************************************/
WINSEC_DESC* winsec_parse_desc(void* talloc_ctx, 
			       const uint8_t* buf, uint32_t buf_len)
{
  WINSEC_DESC* ret_val;

  if (buf == NULL || buf_len <  WINSEC_DESC_HEADER_SIZE)
    return NULL;

  if((ret_val = talloc(talloc_ctx, WINSEC_DESC)) == NULL)
    return NULL;

  ret_val->revision = buf[0];
  ret_val->sbz1 = buf[1];
  ret_val->control = SVAL(buf, 0x2);

  if(!(ret_val->control & WINSEC_DESC_SELF_RELATIVE))
    fprintf(stderr, "DEBUG: NOT self-relative!\n");

  ret_val->off_owner_sid = IVAL(buf, 0x4);
  ret_val->off_grp_sid = IVAL(buf, 0x8);
  ret_val->off_sacl = IVAL(buf, 0xC);
  ret_val->off_dacl = IVAL(buf, 0x10);

  /* A basic sanity check to ensure our offsets are within our buffer.
   * Additional length checking is done in secondary parsing functions.
   */
  if((ret_val->off_owner_sid >= buf_len)
     || (ret_val->off_grp_sid >= buf_len)
     || (ret_val->off_sacl >= buf_len)
     || (ret_val->off_dacl >= buf_len))
  {
    talloc_free(ret_val);
    return NULL;
  }

  if(ret_val->off_owner_sid == 0)
    ret_val->owner_sid = NULL;
  else
  {
    ret_val->owner_sid = winsec_parse_dom_sid(ret_val, 
					      buf + ret_val->off_owner_sid,
					      buf_len - ret_val->off_owner_sid);
    if(ret_val->owner_sid == NULL)
    {
      talloc_free(ret_val);
      return NULL;
    }
  }

  if(ret_val->off_grp_sid == 0) 
    ret_val->grp_sid = NULL;
  else
  {
    ret_val->grp_sid = winsec_parse_dom_sid(ret_val, buf + ret_val->off_grp_sid,
					    buf_len - ret_val->off_grp_sid);
    if(ret_val->grp_sid == NULL)
    {
      talloc_free(ret_val);
      return NULL;
    }
  }

  if((ret_val->control & WINSEC_DESC_SACL_PRESENT) && ret_val->off_sacl)
  {
    ret_val->sacl = winsec_parse_acl(ret_val, buf + ret_val->off_sacl,
				     buf_len - ret_val->off_sacl);
    if(ret_val->sacl == NULL)
    {
      talloc_free(ret_val);
      return NULL;
    }
  }
  else
    ret_val->sacl = NULL;

  if((ret_val->control & WINSEC_DESC_DACL_PRESENT) && ret_val->off_dacl != 0) 
  {
    ret_val->dacl = winsec_parse_acl(ret_val, buf + ret_val->off_dacl,
				     buf_len - ret_val->off_dacl);
    if(ret_val->dacl == NULL)
    {
      talloc_free(ret_val);
      return NULL;
    }
  }
  else
    ret_val->dacl = NULL;

  return ret_val;
}


/******************************************************************************
 * Parses a WINSEC_ACL structure and all substructures.
 ******************************************************************************/
WINSEC_ACL* winsec_parse_acl(void* talloc_ctx,
			     const uint8_t* buf, uint32_t buf_len)
{
  uint32_t i, offset;
  WINSEC_ACL* ret_val;

  /*
   * Note that the size is always a multiple of 4 bytes due to the
   * nature of the data structure.
   */
  if (buf == NULL || buf_len < 8)
    return NULL;

  if((ret_val = talloc(talloc_ctx, WINSEC_ACL)) == NULL)
    return NULL;
  
  ret_val->revision = SVAL(buf, 0x0);
  ret_val->size     = SVAL(buf, 0x2);
  ret_val->num_aces = IVAL(buf, 0x4);

  /* The num_aces can be at most around 4k because anything greater
   * wouldn't fit in the 16 bit size even if every ace was as small as
   * possible. 
   */
  if((ret_val->size > buf_len) || (ret_val->num_aces > 4095))
  {
    talloc_free(ret_val);
    return NULL;
  }

  /* Even if the num_aces is zero, allocate memory as there's a difference
   * between a non-present DACL (allow all access) and a DACL with no ACE's
   * (allow no access).
   */
  if((ret_val->aces = talloc_array(ret_val, WINSEC_ACE*, 
				   ret_val->num_aces+1)) == NULL)
  {
    talloc_free(ret_val);
    return NULL;
  }

  offset = 8;
  for(i=0; i < ret_val->num_aces; i++)
  {
    ret_val->aces[i] = winsec_parse_ace(ret_val->aces, 
					buf+offset, buf_len-offset);
    if(ret_val->aces[i] == NULL)
    {
      talloc_free(ret_val);
      return NULL;
    }

    offset += ret_val->aces[i]->size;
    if(offset > buf_len)
    {
      talloc_free(ret_val);
      return NULL;
    }
  }
  ret_val->aces[ret_val->num_aces] = NULL;

  return ret_val;
}


/******************************************************************************
 * Parses a WINSEC_ACE structure and all substructures.
 ******************************************************************************/
WINSEC_ACE* winsec_parse_ace(void* talloc_ctx,
			     const uint8_t* buf, uint32_t buf_len)
{
  uint32_t offset;
  WINSEC_ACE* ret_val;

  if(buf == NULL || buf_len < WINSEC_ACE_MIN_SIZE)
    return NULL;

  if((ret_val = talloc(talloc_ctx, WINSEC_ACE)) == NULL)
    return NULL;

  ret_val->type = buf[0];
  ret_val->flags = buf[1];
  ret_val->size = SVAL(buf, 0x2);
  ret_val->access_mask = IVAL(buf, 0x4);

  offset = 0x8;

  /* check whether object access is present */
  if (winsec_ace_object(ret_val->type))
  {
    ret_val->obj_flags = IVAL(buf, offset);
    offset += 4;

    if(ret_val->obj_flags & WINSEC_ACE_OBJECT_PRESENT)
    {
      ret_val->obj_guid = winsec_parse_uuid(ret_val, 
					    buf+offset, buf_len-offset);
      if(ret_val->obj_guid == NULL)
      {
	talloc_free(ret_val);
	return NULL;
      }
      offset += sizeof(WINSEC_UUID);
    }
    else
      ret_val->obj_guid = NULL;

    if(ret_val->obj_flags & WINSEC_ACE_OBJECT_INHERITED_PRESENT)
    {
      ret_val->inh_guid = winsec_parse_uuid(ret_val, 
					    buf+offset, buf_len-offset);
      if(ret_val->inh_guid == NULL)
      {
	talloc_free(ret_val);
	return NULL;
      }
      offset += sizeof(WINSEC_UUID);
    }
    else
      ret_val->inh_guid = NULL;
  }

  ret_val->trustee = winsec_parse_dom_sid(ret_val, buf+offset, buf_len-offset);
  if(ret_val->trustee == NULL)
  {
    talloc_free(ret_val);
    return NULL;
  }
  
  return ret_val;
}


/******************************************************************************
 * Parses a WINSEC_DOM_SID structure.
 ******************************************************************************/
WINSEC_DOM_SID* winsec_parse_dom_sid(void* talloc_ctx,
				     const uint8_t* buf, uint32_t buf_len)
{
  uint32_t i;
  WINSEC_DOM_SID* ret_val;

  if(buf == NULL || buf_len < 8)
    return NULL;

  /*  if((ret_val = (WINSEC_DOM_SID*)zalloc(sizeof(WINSEC_DOM_SID))) == NULL)*/
  if((ret_val = talloc(talloc_ctx, WINSEC_DOM_SID)) == NULL)
    return NULL;

  ret_val->sid_rev_num = buf[0];
  ret_val->num_auths = buf[1];
  memcpy(ret_val->id_auth, buf+2, 6);

  /* XXX: should really issue a warning here... */
  if (ret_val->num_auths > WINSEC_MAX_SUBAUTHS)
    ret_val->num_auths = WINSEC_MAX_SUBAUTHS;

  if(buf_len < ret_val->num_auths*sizeof(uint32_t)+8)
  {
    talloc_free(ret_val);
    return NULL;
  }
  
  for(i=0; i < ret_val->num_auths; i++)
    ret_val->sub_auths[i] = IVAL(buf, 8+i*sizeof(uint32_t));

  return ret_val;
}


/******************************************************************************
 * Parses a WINSEC_UUID struct.
 ******************************************************************************/
WINSEC_UUID* winsec_parse_uuid(void* talloc_ctx,
			       const uint8_t* buf, uint32_t buf_len)
{
  WINSEC_UUID* ret_val;

  if(buf == NULL || buf_len < sizeof(WINSEC_UUID))
    return false;

  if((ret_val = talloc(talloc_ctx, WINSEC_UUID)) == NULL)
    return NULL;
  
  ret_val->time_low = IVAL(buf, 0x0);
  ret_val->time_mid = SVAL(buf, 0x4);
  ret_val->time_hi_and_version = SVAL(buf, 0x6);
  
  memcpy(ret_val->clock_seq, buf+0x8, 2);
  memcpy(ret_val->node, buf+0xB, 6);

  return ret_val;
}


/******************************************************************************
 * Calculates the size of a SID.
 ******************************************************************************/
size_t winsec_sid_size(const WINSEC_DOM_SID* sid)
{
  if (sid == NULL)
    return 0;

  return sid->num_auths * sizeof(uint32_t) + 8;
}


/******************************************************************************
 * Compare the auth portion of two SIDs.
 ******************************************************************************/
int winsec_sid_compare_auth(const WINSEC_DOM_SID* sid1, const WINSEC_DOM_SID* sid2)
{
  int i;

  if (sid1 == sid2)
    return 0;
  if (!sid1)
    return -1;
  if (!sid2)
    return 1;

  if (sid1->sid_rev_num != sid2->sid_rev_num)
    return sid1->sid_rev_num - sid2->sid_rev_num;

  for (i = 0; i < 6; i++)
    if (sid1->id_auth[i] != sid2->id_auth[i])
      return sid1->id_auth[i] - sid2->id_auth[i];

  return 0;
}


/******************************************************************************
 * Compare two SIDs.
 ******************************************************************************/
int winsec_sid_compare(const WINSEC_DOM_SID* sid1, const WINSEC_DOM_SID* sid2)
{
  int i;

  if (sid1 == sid2)
    return 0;
  if (!sid1)
    return -1;
  if (!sid2)
    return 1;

  /* Compare most likely different rids, first: i.e start at end */
  if (sid1->num_auths != sid2->num_auths)
    return sid1->num_auths - sid2->num_auths;

  for (i = sid1->num_auths-1; i >= 0; --i)
    if (sid1->sub_auths[i] != sid2->sub_auths[i])
      return sid1->sub_auths[i] - sid2->sub_auths[i];

  return winsec_sid_compare_auth(sid1, sid2);
}


/******************************************************************************
 * Compare two SIDs.
 ******************************************************************************/
bool winsec_sid_equal(const WINSEC_DOM_SID* sid1, const WINSEC_DOM_SID* sid2)
{
  return winsec_sid_compare(sid1, sid2) == 0;
}


/******************************************************************************
 * Compares two WINSEC_DESC structures.
 ******************************************************************************/
bool winsec_desc_equal(WINSEC_DESC* s1, WINSEC_DESC* s2)
{
  /* Trivial cases */
  if (!s1 && !s2)
    return true;
  if (!s1 || !s2)
    return false;

  /* Check top level stuff */
  if (s1->revision != s2->revision)
    return false;

  if (s1->control != s2->control)
    return false;

  /* Check owner and group */
  if (!winsec_sid_equal(s1->owner_sid, s2->owner_sid))
    return false;

  if (!winsec_sid_equal(s1->grp_sid, s2->grp_sid)) 
    return false;

  /* Check ACLs present in one but not the other */
  if ((s1->dacl && !s2->dacl) || (!s1->dacl && s2->dacl) ||
      (s1->sacl && !s2->sacl) || (!s1->sacl && s2->sacl)) 
  { return false; }

  /* Sigh - we have to do it the hard way by iterating over all
     the ACEs in the ACLs */
  if(!winsec_acl_equal(s1->dacl, s2->dacl) || !winsec_acl_equal(s1->sacl, s2->sacl)) 
    return false;

  return true;
}



/******************************************************************************
 * Compares two WINSEC_ACL structures.
 ******************************************************************************/
bool winsec_acl_equal(WINSEC_ACL* s1, WINSEC_ACL* s2)
{
  unsigned int i, j;

  /* Trivial cases */
  if (!s1 && !s2) 
    return true;
  if (!s1 || !s2) 
    return false;

  /* Check top level stuff */
  if (s1->revision != s2->revision)
    return false;

  if (s1->num_aces != s2->num_aces)
    return false;

  /* The ACEs could be in any order so check each ACE in s1 against 
     each ACE in s2. */

  for (i = 0; i < s1->num_aces; i++)
  {
    bool found = false;

    for (j = 0; j < s2->num_aces; j++) 
    {
      if (winsec_ace_equal(s1->aces[i], s2->aces[j])) 
      {
	found = true;
	break;
      }
    }

    if (!found)
      return false;
  }

  return true;
}


/******************************************************************************
 * Compares two WINSEC_ACE structures.
 ******************************************************************************/
bool winsec_ace_equal(WINSEC_ACE* s1, WINSEC_ACE* s2)
{
  /* Trivial cases */
  if (!s1 && !s2) 
    return true;
  if (!s1 || !s2) 
    return false;

  /* Check top level stuff */
  if (s1->type != s2->type || s1->flags != s2->flags ||
      s1->access_mask != s2->access_mask)
  { return false; }

  /* Check SID */
  if (!winsec_sid_equal(s1->trustee, s2->trustee))
    return false;

  return true;
}


/******************************************************************************
 * Check if ACE has OBJECT type.
 ******************************************************************************/
bool winsec_ace_object(uint8_t type)
{
  if (type == WINSEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT ||
      type == WINSEC_ACE_TYPE_ACCESS_DENIED_OBJECT ||
      type == WINSEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT ||
      type == WINSEC_ACE_TYPE_SYSTEM_ALARM_OBJECT) 
  { return true; }

  return false;
}
