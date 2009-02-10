/*
 * This file contains refactored Samba code used to interpret Windows
 * Security Descriptors. See:
 *   http://websvn.samba.org/cgi-bin/viewcvs.cgi/trunk/source/
 *
 * Revisions have been made based on information provided by Microsoft
 * at: 
 *    http://msdn.microsoft.com/en-us/library/cc230366(PROT.10).aspx
 *
 * Copyright (C) 2005,2009 Timothy D. Morgan
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

#include "smb_deps.h"


/* This is the maximum number of subauths in a SID, as defined here:
 *   http://msdn.microsoft.com/en-us/library/cc230371(PROT.10).aspx
 */
#define WINSEC_MAX_SUBAUTHS 15

#define WINSEC_DESC_HEADER_SIZE     (5 * sizeof(uint32_t))
#define WINSEC_ACL_HEADER_SIZE      (2 * sizeof(uint32_t))
#define WINSEC_ACE_MIN_SIZE         16

/* TODO: Fill in definitions of other flags */
/* This means offsets contained in the descriptor are relative to the
 * descriptor's offset.  This had better be true in the registry. 
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


typedef struct _winsec_uuid 
{
       uint32 time_low;
       uint16 time_mid;
       uint16 time_hi_and_version;
       uint8  clock_seq[2];
       uint8  node[6];
} WINSEC_UUID;


typedef struct _winsec_sid
{
  uint8_t  sid_rev_num;             /* SID revision number */
  uint8_t  num_auths;               /* Number of sub-authorities */
  uint8_t  id_auth[6];              /* Identifier Authority */
  /*
   *  Pointer to sub-authorities.
   *
   * @note The values in these uint32_t's are in *native* byteorder, not
   * neccessarily little-endian...... JRA.
   */
  /* XXX: Make this dynamically allocated? */
  uint32_t sub_auths[WINSEC_MAX_SUBAUTHS];
} WINSEC_DOM_SID;


typedef struct _winsec_ace
{
	uint8_t type;  /* xxxx_xxxx_ACE_TYPE - e.g allowed / denied etc */
	uint8_t flags; /* xxxx_INHERIT_xxxx - e.g OBJECT_INHERIT_ACE */
	uint16_t size;
	uint32_t access_mask;

	/* this stuff may be present when type is XXXX_TYPE_XXXX_OBJECT */
	uint32_t  obj_flags;   /* xxxx_ACE_OBJECT_xxxx e.g present/inherited present etc */
	WINSEC_UUID* obj_guid;  /* object GUID */
	WINSEC_UUID* inh_guid;  /* inherited object GUID */		
        /* eof object stuff */

	WINSEC_DOM_SID* trustee;

} WINSEC_ACE;

typedef struct _winsec_acl
{
	uint16_t revision; /* 0x0003 */
	uint16_t size;     /* size in bytes of the entire ACL structure */
	uint32_t num_aces; /* number of Access Control Entries */

	WINSEC_ACE** aces;

} WINSEC_ACL;

typedef struct _winsec_desc
{
	uint8_t revision; /* 0x01 */
	uint8_t sbz1;     /* "If the Control field has the RM flag set,
			   *  then this field contains the resource
			   *  manager (RM) control value. ... Otherwise,
			   *  this field is reserved and MUST be set to
			   *  zero." -- Microsoft.  See reference above.
			   */
	uint16_t control; /* WINSEC_DESC_* flags */

	uint32_t off_owner_sid; /* offset to owner sid */
	uint32_t off_grp_sid  ; /* offset to group sid */
	uint32_t off_sacl     ; /* offset to system list of permissions */
	uint32_t off_dacl     ; /* offset to list of permissions */

	WINSEC_DOM_SID* owner_sid; 
	WINSEC_DOM_SID* grp_sid;
	WINSEC_ACL* sacl;       /* system ACL */
	WINSEC_ACL* dacl;       /* user ACL */

} WINSEC_DESC;


/* XXX: Need API functions to deallocate these structures */
WINSEC_DESC* winsec_parse_desc(const uint8_t* buf, uint32_t buf_len);
WINSEC_ACL* winsec_parse_acl(const uint8_t* buf, uint32_t buf_len);
WINSEC_ACE* winsec_parse_ace(const uint8_t* buf, uint32_t buf_len);
WINSEC_DOM_SID* winsec_parse_dom_sid(const uint8_t* buf, uint32_t buf_len);
WINSEC_UUID* winsec_parse_uuid(const uint8_t* buf, uint32_t buf_len);

size_t winsec_sid_size(const WINSEC_DOM_SID* sid);
int winsec_sid_compare_auth(const WINSEC_DOM_SID* sid1, const WINSEC_DOM_SID* sid2);
int winsec_sid_compare(const WINSEC_DOM_SID* sid1, const WINSEC_DOM_SID* sid2);
bool winsec_sid_equal(const WINSEC_DOM_SID* sid1, const WINSEC_DOM_SID* sid2);
bool winsec_desc_equal(WINSEC_DESC* s1, WINSEC_DESC* s2);
bool winsec_acl_equal(WINSEC_ACL* s1, WINSEC_ACL* s2);
bool winsec_ace_equal(WINSEC_ACE* s1, WINSEC_ACE* s2);
bool winsec_ace_object(uint8_t type);

#endif /* _WINSEC_H */
