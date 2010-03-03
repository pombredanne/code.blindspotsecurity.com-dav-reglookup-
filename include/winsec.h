/* 
 * Copyright (C) 2005,2009-2010 Timothy D. Morgan
 * Copyright (C) 1992-2005 Samba development team 
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

/**
 * @file
 *
 * A small library for interpreting Windows Security Descriptors.
 * This library was originally based on Samba source from:
 *   http://websvn.samba.org/cgi-bin/viewcvs.cgi/trunk/source/
 *
 * The library has been heavily rewritten and improved based on information
 * provided by Microsoft at: 
 *    http://msdn.microsoft.com/en-us/library/cc230366%28PROT.10%29.aspx
 */

#ifndef _WINSEC_H
#define _WINSEC_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "talloc.h"
#include "byteorder.h"


/* This is the maximum number of subauths in a SID, as defined here:
 *   http://msdn.microsoft.com/en-us/library/cc230371(PROT.10).aspx
 */
#define WINSEC_MAX_SUBAUTHS 15

#define WINSEC_DESC_HEADER_SIZE     (5 * sizeof(uint32_t))
#define WINSEC_ACL_HEADER_SIZE      (2 * sizeof(uint32_t))
#define WINSEC_ACE_MIN_SIZE         16

/* XXX: Fill in definitions of other flags */
/* This self relative flag means offsets contained in the descriptor are relative
 * to the descriptor's offset.  This had better be true in the registry.
 */
#define WINSEC_DESC_SELF_RELATIVE   0x8000
#define WINSEC_DESC_SACL_PRESENT    0x0010
#define WINSEC_DESC_DACL_PRESENT    0x0004

#define WINSEC_ACE_OBJECT_PRESENT              0x00000001 
#define WINSEC_ACE_OBJECT_INHERITED_PRESENT    0x00000002
#define WINSEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT  0x5
#define WINSEC_ACE_TYPE_ACCESS_DENIED_OBJECT   0x6
#define WINSEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT    0x7
#define WINSEC_ACE_TYPE_SYSTEM_ALARM_OBJECT    0x8


/** XXX: document this. */
typedef struct _winsec_uuid
{
  /** XXX: document this. */
  uint32_t time_low;

  /** XXX: document this. */
  uint16_t time_mid;

  /** XXX: document this. */
  uint16_t time_hi_and_version;

  /** XXX: document this. */
  uint8_t  clock_seq[2];

  /** XXX: document this. */
  uint8_t  node[6];
} WINSEC_UUID;


/** XXX: document this. */
typedef struct _winsec_sid
{
  /** SID revision number */
  uint8_t  sid_rev_num;

  /** Number of sub-authorities */
  uint8_t  num_auths;

  /** Identifier Authority */
  uint8_t  id_auth[6];

  /** Pointer to sub-authorities.
   * 
   * @note The values in these uint32_t's are in *native* byteorder, not
   * neccessarily little-endian...... JRA.
   */
  uint32_t sub_auths[WINSEC_MAX_SUBAUTHS];   /* XXX: Make this dynamically allocated? */
} WINSEC_DOM_SID;


/** XXX: document this. */
typedef struct _winsec_ace
{
  /** xxxx_xxxx_ACE_TYPE - e.g allowed / denied etc */
  uint8_t type;

  /** xxxx_INHERIT_xxxx - e.g OBJECT_INHERIT_ACE */
  uint8_t flags;

  /** XXX: finish documenting */
  uint16_t size;

  /** XXX: finish documenting */
  uint32_t access_mask;
  
  /* This stuff may be present when type is XXXX_TYPE_XXXX_OBJECT */

  /** xxxx_ACE_OBJECT_xxxx e.g present/inherited present etc */
  uint32_t  obj_flags;

  /** Object GUID */
  WINSEC_UUID* obj_guid;

  /** Inherited object GUID */
  WINSEC_UUID* inh_guid;

  /* eof object stuff */
  
  /** XXX: finish documenting */
  WINSEC_DOM_SID* trustee;

} WINSEC_ACE;


/** XXX: document this. */
typedef struct _winsec_acl
{
  /** 0x0003 */
  uint16_t revision;

  /** Size, in bytes, of the entire ACL structure */
  uint16_t size;

  /** Number of Access Control Entries */
  uint32_t num_aces;
  
  /** XXX: document this. */
  WINSEC_ACE** aces;

} WINSEC_ACL;


/** XXX: document this. */
typedef struct _winsec_desc
{
  /** 0x01 */
  uint8_t revision;

  /** XXX: better explain this
   *
   * "If the Control field has the RM flag set, then this field contains the
   *  resource manager (RM) control value. ... Otherwise, this field is reserved
   *  and MUST be set to zero." -- Microsoft.
   *  See:
   *   http://msdn.microsoft.com/en-us/library/cc230371%28PROT.10%29.aspx
   */
  uint8_t sbz1;

  /** WINSEC_DESC_* flags */
  uint16_t control;
  
  /** Offset to owner sid */
  uint32_t off_owner_sid;

  /** Offset to group sid */
  uint32_t off_grp_sid;

  /** Offset to system list of permissions */
  uint32_t off_sacl;

  /** Offset to list of permissions */
  uint32_t off_dacl;

  /** XXX: document this */
  WINSEC_DOM_SID* owner_sid; 

  /** XXX: document this */
  WINSEC_DOM_SID* grp_sid;

  /** System ACL */
  WINSEC_ACL* sacl;

  /** User ACL */
  WINSEC_ACL* dacl;

} WINSEC_DESC;


/**
 *
 * XXX: finish documenting
 */
WINSEC_DESC* winsec_parse_descriptor(const uint8_t* buf, uint32_t buf_len);


/**
 *
 * XXX: finish documenting
 */
void winsec_free_descriptor(WINSEC_DESC* desc);

/**
 *
 * XXX: finish documenting
 */
WINSEC_DESC* winsec_parse_desc(void* talloc_ctx,
			       const uint8_t* buf, uint32_t buf_len);

/**
 *
 * XXX: finish documenting
 */
WINSEC_ACL* winsec_parse_acl(void* talloc_ctx, 
			     const uint8_t* buf, uint32_t buf_len);

/**
 *
 * XXX: finish documenting
 */
WINSEC_ACE* winsec_parse_ace(void* talloc_ctx, 
			     const uint8_t* buf, uint32_t buf_len);

/**
 *
 * XXX: finish documenting
 */
WINSEC_DOM_SID* winsec_parse_dom_sid(void* talloc_ctx, 
				     const uint8_t* buf, uint32_t buf_len);

/**
 *
 * XXX: finish documenting
 */
WINSEC_UUID* winsec_parse_uuid(void* talloc_ctx, 
			       const uint8_t* buf, uint32_t buf_len);


/**
 *
 * XXX: finish documenting
 */
size_t winsec_sid_size(const WINSEC_DOM_SID* sid);

/**
 *
 * XXX: finish documenting
 */
int winsec_sid_compare_auth(const WINSEC_DOM_SID* sid1, const WINSEC_DOM_SID* sid2);

/**
 *
 * XXX: finish documenting
 */
int winsec_sid_compare(const WINSEC_DOM_SID* sid1, const WINSEC_DOM_SID* sid2);

/**
 *
 * XXX: finish documenting
 */
bool winsec_sid_equal(const WINSEC_DOM_SID* sid1, const WINSEC_DOM_SID* sid2);

/**
 *
 * XXX: finish documenting
 */
bool winsec_desc_equal(WINSEC_DESC* s1, WINSEC_DESC* s2);

/**
 *
 * XXX: finish documenting
 */
bool winsec_acl_equal(WINSEC_ACL* s1, WINSEC_ACL* s2);

/**
 *
 * XXX: finish documenting
 */
bool winsec_ace_equal(WINSEC_ACE* s1, WINSEC_ACE* s2);

/**
 *
 * XXX: finish documenting
 */
bool winsec_ace_object(uint8_t type);

#endif /* _WINSEC_H */
