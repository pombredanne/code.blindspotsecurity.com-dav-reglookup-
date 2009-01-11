/*
 * This file contains miscellaneous pieces of code which regfio.c
 * depends upon, from the Samba Subversion tree.  See:
 *   http://websvn.samba.org/cgi-bin/viewcvs.cgi/trunk/source/
 *
 * Copyright (C) 2005,2009 Timothy D. Morgan
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
 * $Id $
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "smb_deps.h"


/* From smb.h */

#define MAXSUBAUTHS 15

typedef struct sid_info
{
  uint8  sid_rev_num;             /**< SID revision number */
  uint8  num_auths;               /**< Number of sub-authorities */
  uint8  id_auth[6];              /**< Identifier Authority */
  /*
   *  Pointer to sub-authorities.
   *
   * @note The values in these uint32's are in *native* byteorder, not
   * neccessarily little-endian...... JRA.
   */
  uint32 sub_auths[MAXSUBAUTHS];
} DOM_SID;

/* End of stuff from smb.h */


/* From rpc_secdesc.h */

typedef struct security_info_info
{
	uint32 mask;

} SEC_ACCESS;

typedef struct security_ace_info
{
	uint8 type;  /* xxxx_xxxx_ACE_TYPE - e.g allowed / denied etc */
	uint8 flags; /* xxxx_INHERIT_xxxx - e.g OBJECT_INHERIT_ACE */
	uint16 size;

	SEC_ACCESS info;

	/* this stuff may be present when type is XXXX_TYPE_XXXX_OBJECT */
	uint32  obj_flags; /* xxxx_ACE_OBJECT_xxxx e.g present/inherited present etc */
	struct uuid obj_guid;  /* object GUID */
	struct uuid inh_guid;  /* inherited object GUID */		
        /* eof object stuff */

	DOM_SID trustee;

} SEC_ACE;

typedef struct security_acl_info
{
	uint16 revision; /* 0x0003 */
	uint16 size; /* size in bytes of the entire ACL structure */
	uint32 num_aces; /* number of Access Control Entries */

	SEC_ACE *ace;

} SEC_ACL;

typedef struct security_descriptor_info
{
	uint16 revision; /* 0x0001 */
	uint16 type;     /* SEC_DESC_xxxx flags */

	uint32 off_owner_sid; /* offset to owner sid */
	uint32 off_grp_sid  ; /* offset to group sid */
	uint32 off_sacl     ; /* offset to system list of permissions */
	uint32 off_dacl     ; /* offset to list of permissions */

	SEC_ACL *dacl; /* user ACL */
	SEC_ACL *sacl; /* system ACL */
	DOM_SID *owner_sid; 
	DOM_SID *grp_sid;

} SEC_DESC;

/* End of stuff from rpc_secdesc.h */



/* From rpc_secdes.h */

#define SEC_DESC_DACL_PRESENT		0x0004
#define SEC_DESC_SACL_PRESENT		0x0010
#define  SEC_DESC_HEADER_SIZE (2 * sizeof(uint16) + 4 * sizeof(uint32))
   /* thanks for Jim McDonough <jmcd@us.ibm.com> */
#define SEC_ACE_OBJECT_PRESENT        0x00000001 
#define SEC_ACE_OBJECT_INHERITED_PRESENT 0x00000002

#define SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT	0x5
#define SEC_ACE_TYPE_ACCESS_DENIED_OBJECT     	0x6
#define SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT      	0x7
#define SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT	0x8

/* End of stuff from rpc_secdes.h */

/* From rpc_parse/parse_misc.c */

bool smb_io_dom_sid(const char *desc, DOM_SID *sid, prs_struct *ps, int depth);

/* End of stuff from rpc_parse/parse_misc.c */

/* From lib/util_sid.c */

size_t sid_size(const DOM_SID *sid);
int sid_compare_auth(const DOM_SID *sid1, const DOM_SID *sid2);
int sid_compare(const DOM_SID *sid1, const DOM_SID *sid2);
bool sid_equal(const DOM_SID *sid1, const DOM_SID *sid2);

/* End of stuff from lib/util_sid.c */

/* From lib/secace.c */

bool sec_ace_object(uint8 type);

/* End of stuff from lib/secace.c */

/* From rpc_parse/parse_sec.c */

bool sec_io_access(const char *desc, SEC_ACCESS *t, prs_struct *ps, int depth);
bool sec_io_ace(const char *desc, SEC_ACE *psa, prs_struct *ps, int depth);
bool sec_io_acl(const char *desc, SEC_ACL **ppsa, prs_struct *ps, int depth);
bool sec_io_desc(const char *desc, SEC_DESC **ppsd, prs_struct *ps, int depth);

/* End of stuff from rpc_parse/parse_sec.c */

/* From lib/secace.c */

bool sec_ace_equal(SEC_ACE *s1, SEC_ACE *s2);

/* End of stuff from lib/secace.c */

/* From lib/secacl.c */

bool sec_acl_equal(SEC_ACL *s1, SEC_ACL *s2);

/* End of stuff from lib/secacl.c */

/* From lib/secdesc.c */

bool sec_desc_equal(SEC_DESC *s1, SEC_DESC *s2);

/* End of stuff from lib/secdesc.c */
