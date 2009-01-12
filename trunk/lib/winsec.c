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

#include "../include/winsec.h"



/*******************************************************************
 * Parses a SEC_DESC structure.
 *******************************************************************/
bool sec_io_desc(const char *desc, SEC_DESC **ppsd, prs_struct *ps, int depth)
{
  uint32 old_offset;
  uint32 max_offset = 0; /* after we're done, move offset to end */
  uint32 tmp_offset = 0;

  SEC_DESC *psd;

  if (ppsd == NULL || ps == NULL)
    return false;

  psd = *ppsd;
  if (psd == NULL) 
  {
    if((psd = (SEC_DESC*)zalloc(sizeof(SEC_DESC))) == NULL)
      return false;
    *ppsd = psd;
  }

  depth++;

  /* start of security descriptor stored for back-calc offset purposes */
  old_offset = ps->data_offset;

  if(!prs_uint16("revision ", ps, depth, &psd->revision)
     || !prs_uint16("type     ", ps, depth, &psd->type))
  {
    free(psd);
    *ppsd = NULL;
    return false;
  }

  if(!prs_uint32("off_owner_sid", ps, depth, &psd->off_owner_sid)
     || !prs_uint32("off_grp_sid  ", ps, depth, &psd->off_grp_sid)
     || !prs_uint32("off_sacl     ", ps, depth, &psd->off_sacl)
     || !prs_uint32("off_dacl     ", ps, depth, &psd->off_dacl))
  {
    free(psd);
    *ppsd = NULL;    
    return false;
  }
  max_offset = MAX(max_offset, ps->data_offset);

  if (psd->off_owner_sid != 0) 
  {
    tmp_offset = ps->data_offset;
    if(!prs_set_offset(ps, old_offset + psd->off_owner_sid))
    {
      free(psd);
      *ppsd = NULL;
      return false;
    }

    /* reading */
    if((psd->owner_sid = (DOM_SID*)zalloc(sizeof(DOM_SID))) == NULL)
    {
      free(psd);
      *ppsd = NULL;
      return false;
    }

    if(!smb_io_dom_sid("owner_sid ", psd->owner_sid , ps, depth))
    {
      free(psd->owner_sid);
      free(psd);
      *ppsd = NULL;
      return false;
    }

    max_offset = MAX(max_offset, ps->data_offset);

    if (!prs_set_offset(ps,tmp_offset))
    {
      free(psd->owner_sid);
      free(psd);
      *ppsd = NULL;
      return false;
    }
  }

  if (psd->off_grp_sid != 0) 
  {
    tmp_offset = ps->data_offset;
    if(!prs_set_offset(ps, old_offset + psd->off_grp_sid))
    {
      free(psd->owner_sid);
      free(psd);
      *ppsd = NULL;
      return false;
    }

    /* reading */
    if((psd->grp_sid = (DOM_SID*)zalloc(sizeof(DOM_SID))) == NULL)
    {
      free(psd->owner_sid);
      free(psd);
      *ppsd = NULL;
      return false;
    }

    if(!smb_io_dom_sid("grp_sid", psd->grp_sid, ps, depth))
    {
      free(psd->grp_sid);
      free(psd->owner_sid);
      free(psd);
      *ppsd = NULL;
      return false;
    }
			
    max_offset = MAX(max_offset, ps->data_offset);

    if (!prs_set_offset(ps,tmp_offset))
    {
      free(psd->grp_sid);
      free(psd->owner_sid);
      free(psd);
      *ppsd = NULL;
      return false;
    }
  }

  if ((psd->type & SEC_DESC_SACL_PRESENT) && psd->off_sacl) 
  {
    tmp_offset = ps->data_offset;
    if(!prs_set_offset(ps, old_offset + psd->off_sacl)
       || !sec_io_acl("sacl", &psd->sacl, ps, depth))
    {
      free(psd->grp_sid);
      free(psd->owner_sid);
      free(psd);
      *ppsd = NULL;
      return false;
    }
    max_offset = MAX(max_offset, ps->data_offset);
    if (!prs_set_offset(ps,tmp_offset))
    {
      free(psd->grp_sid);
      free(psd->owner_sid);
      free(psd);
      *ppsd = NULL;
      return false;
    }
  }

  if ((psd->type & SEC_DESC_DACL_PRESENT) && psd->off_dacl != 0) 
  {
    tmp_offset = ps->data_offset;
    if(!prs_set_offset(ps, old_offset + psd->off_dacl)
       || !sec_io_acl("dacl", &psd->dacl, ps, depth))
    {
      free(psd->grp_sid);
      free(psd->owner_sid);
      free(psd);
      *ppsd = NULL;
      return false;
    }
    max_offset = MAX(max_offset, ps->data_offset);
    if (!prs_set_offset(ps,tmp_offset))
    {
      free(psd->grp_sid);
      free(psd->owner_sid);
      free(psd);
      *ppsd = NULL;
      return false;
    }
  }

  if(!prs_set_offset(ps, max_offset))
  {
    free(psd->grp_sid);
    free(psd->owner_sid);
    free(psd);
    *ppsd = NULL;
    return false;
  }

  return true;
}


/*******************************************************************
 Reads or writes a DOM_SID structure.
********************************************************************/
bool smb_io_dom_sid(const char *desc, DOM_SID *sid, prs_struct *ps, int depth)
{
  int i;

  if (sid == NULL)
    return false;
  depth++;

  if(!prs_uint8 ("sid_rev_num", ps, depth, &sid->sid_rev_num))
    return false;

  if(!prs_uint8 ("num_auths  ", ps, depth, &sid->num_auths))
    return false;

  for (i = 0; i < 6; i++)
  {
    fstring tmp;
    snprintf(tmp, sizeof(tmp) - 1, "id_auth[%d] ", i);
    if(!prs_uint8 (tmp, ps, depth, &sid->id_auth[i]))
      return false;
  }

  /* oops! XXXX should really issue a warning here... */
  if (sid->num_auths > MAXSUBAUTHS)
    sid->num_auths = MAXSUBAUTHS;

  if(!prs_uint32s("sub_auths ", ps, depth, 
		  sid->sub_auths, sid->num_auths))
  { return false; }

  return true;
}



/*******************************************************************
 Reads or writes a SEC_ACCESS structure.
********************************************************************/
bool sec_io_access(const char *desc, SEC_ACCESS *t, prs_struct *ps, int depth)
{
  if (t == NULL)
    return false;

  depth++;
	
  if(!prs_uint32("mask", ps, depth, &t->mask))
    return false;

  return true;
}


/*******************************************************************
 Reads or writes a SEC_ACE structure.
********************************************************************/
bool sec_io_ace(const char *desc, SEC_ACE *psa, prs_struct *ps, int depth)
{
  uint32 old_offset;
  uint32 offset_ace_size;

  if (psa == NULL)
    return false;

  depth++;
	
  old_offset = ps->data_offset;

  if(!prs_uint8("type ", ps, depth, &psa->type))
    return false;

  if(!prs_uint8("flags", ps, depth, &psa->flags))
    return false;

  if(!prs_uint16_pre("size ", ps, depth, &psa->size, &offset_ace_size))
    return false;

  if(!sec_io_access("info ", &psa->info, ps, depth))
    return false;

  /* check whether object access is present */
  if (!sec_ace_object(psa->type)) 
  {
    if (!smb_io_dom_sid("trustee  ", &psa->trustee , ps, depth))
      return false;
  } 
  else 
  {
    if (!prs_uint32("obj_flags", ps, depth, &psa->obj_flags))
      return false;

    if (psa->obj_flags & SEC_ACE_OBJECT_PRESENT)
      if (!smb_io_uuid("obj_guid", &psa->obj_guid, ps,depth))
	return false;

    if (psa->obj_flags & SEC_ACE_OBJECT_INHERITED_PRESENT)
      if (!smb_io_uuid("inh_guid", &psa->inh_guid, ps,depth))
	return false;

    if(!smb_io_dom_sid("trustee  ", &psa->trustee , ps, depth))
      return false;
  }

  if(!prs_uint16_post("size ", ps, depth, &psa->size, 
		      offset_ace_size, old_offset))
  { return false; }

  return true;
}


/*******************************************************************
 Reads or writes a SEC_ACL structure.  

 First of the xx_io_xx functions that allocates its data structures
 for you as it reads them.
********************************************************************/
bool sec_io_acl(const char *desc, SEC_ACL **ppsa, prs_struct *ps, int depth)
{
  unsigned int i;
  uint32 old_offset;
  uint32 offset_acl_size;
  SEC_ACL* psa;

  /*
   * Note that the size is always a multiple of 4 bytes due to the
   * nature of the data structure.  Therefore the prs_align() calls
   * have been removed as they through us off when doing two-layer
   * marshalling such as in the printing code (RPC_BUFFER).  --jerry
   */

  if (ppsa == NULL || ps == NULL)
    return false;

  psa = *ppsa;

  if(psa == NULL) 
  {
    /*
     * This is a read and we must allocate the stuct to read into.
     */
    if((psa = (SEC_ACL*)zalloc(sizeof(SEC_ACL))) == NULL)
      return false;
    *ppsa = psa;
  }

  depth++;	
  old_offset = ps->data_offset;

  if(!prs_uint16("revision", ps, depth, &psa->revision)
     || !prs_uint16_pre("size     ", ps, depth, &psa->size, &offset_acl_size)
     || !prs_uint32("num_aces ", ps, depth, &psa->num_aces))
  {
    free(psa);
    *ppsa = NULL;
    return false;
  }

  /*
   * Even if the num_aces is zero, allocate memory as there's a difference
   * between a non-present DACL (allow all access) and a DACL with no ACE's
   * (allow no access).
   */
  if((psa->ace = (SEC_ACE*)zcalloc(sizeof(SEC_ACE), psa->num_aces+1)) == NULL)
  {
    free(psa);
    *ppsa = NULL;
    return false;
  }

  for (i = 0; i < psa->num_aces; i++) 
  {
    fstring tmp;
    snprintf(tmp, sizeof(tmp)-1, "ace_list[%02d]: ", i);
    if(!sec_io_ace(tmp, &psa->ace[i], ps, depth))
    {
      free(psa);
      *ppsa = NULL;
      return false;
    }
  }

  if(!prs_uint16_post("size     ", ps, depth, &psa->size, 
		      offset_acl_size, old_offset))
  { 
    free(psa);
    *ppsa = NULL;
    return false; 
  }

  return true;
}


/*****************************************************************
 Calculates size of a sid.
*****************************************************************/  
size_t sid_size(const DOM_SID *sid)
{
  if (sid == NULL)
    return 0;

  return sid->num_auths * sizeof(uint32) + 8;
}


/*****************************************************************
 Compare the auth portion of two sids.
*****************************************************************/  
int sid_compare_auth(const DOM_SID *sid1, const DOM_SID *sid2)
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


/*****************************************************************
 Compare two sids.
*****************************************************************/  
int sid_compare(const DOM_SID *sid1, const DOM_SID *sid2)
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

  return sid_compare_auth(sid1, sid2);
}


/*****************************************************************
 Compare two sids.
*****************************************************************/  
bool sid_equal(const DOM_SID *sid1, const DOM_SID *sid2)
{
  return sid_compare(sid1, sid2) == 0;
}



/*******************************************************************
 Check if ACE has OBJECT type.
********************************************************************/
bool sec_ace_object(uint8 type)
{
  if (type == SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT ||
      type == SEC_ACE_TYPE_ACCESS_DENIED_OBJECT ||
      type == SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT ||
      type == SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT) {
    return true;
  }
  return false;
}


/*******************************************************************
 Compares two SEC_ACE structures
********************************************************************/
bool sec_ace_equal(SEC_ACE *s1, SEC_ACE *s2)
{
  /* Trivial cases */
  if (!s1 && !s2) 
    return true;
  if (!s1 || !s2) 
    return false;

  /* Check top level stuff */
  if (s1->type != s2->type || s1->flags != s2->flags ||
      s1->info.mask != s2->info.mask) 
  { return false; }

  /* Check SID */
  if (!sid_equal(&s1->trustee, &s2->trustee))
    return false;

  return true;
}


/*******************************************************************
 Compares two SEC_ACL structures
********************************************************************/
bool sec_acl_equal(SEC_ACL *s1, SEC_ACL *s2)
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
      if (sec_ace_equal(&s1->ace[i], &s2->ace[j])) 
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


/*******************************************************************
 Compares two SEC_DESC structures
********************************************************************/
bool sec_desc_equal(SEC_DESC *s1, SEC_DESC *s2)
{
  /* Trivial cases */
  if (!s1 && !s2)
    return true;
  if (!s1 || !s2)
    return false;

  /* Check top level stuff */
  if (s1->revision != s2->revision)
    return false;

  if (s1->type!= s2->type)
    return false;

  /* Check owner and group */
  if (!sid_equal(s1->owner_sid, s2->owner_sid))
    return false;

  if (!sid_equal(s1->grp_sid, s2->grp_sid)) 
    return false;

  /* Check ACLs present in one but not the other */
  if ((s1->dacl && !s2->dacl) || (!s1->dacl && s2->dacl) ||
      (s1->sacl && !s2->sacl) || (!s1->sacl && s2->sacl)) 
  { return false; }

  /* Sigh - we have to do it the hard way by iterating over all
     the ACEs in the ACLs */
  if(!sec_acl_equal(s1->dacl, s2->dacl) || !sec_acl_equal(s1->sacl, s2->sacl)) 
    return false;

  return true;
}
