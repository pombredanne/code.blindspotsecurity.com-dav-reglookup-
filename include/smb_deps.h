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
 * $Id$
 */

#ifndef _SMB_DEPS_H
#define _SMB_DEPS_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "byteorder.h"

#define DEBUG(lvl,body) 0

void* zalloc(size_t size);
void* zcalloc(size_t size, unsigned int count);

/* From includes.h */

#define uint8 unsigned char
#define int16 short
#define uint16 unsigned short
#define int32 int
#define uint32 unsigned int

#define SMB_STRUCT_STAT struct stat
#define QSORT_CAST (int (*)(const void *, const void *))

#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))

extern int DEBUGLEVEL;

#define DLIST_ADD(list, p) \
{ \
        if (!(list)) { \
		(list) = (p); \
		(p)->next = (p)->prev = NULL; \
	} else { \
		(list)->prev = (p); \
		(p)->next = (list); \
		(p)->prev = NULL; \
		(list) = (p); \
	}\
}

/* End of stuff from includes.h */

/* From smb.h */

typedef struct nttime_info
{
  uint32 low;
  uint32 high;
} NTTIME;

/* End of stuff from smb.h */

/* From smb_macros.h */

#define TALLOC_ZERO_P(ctx, type) (type *)_talloc_zero(ctx, sizeof(type), #type)
#define SMB_MALLOC_P(type) (type *)malloc_(sizeof(type))
#define TALLOC_ARRAY(ctx, type, count) (type *)_talloc_array(ctx, sizeof(type), count, #type)
#define TALLOC_ZERO_ARRAY(ctx, type, count) (type *)_talloc_zero_array(ctx, sizeof(type), count, #type)
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

/* End of stuff from smb_macros.h */

/* From ntdomain.h */

struct uuid {
       uint32 time_low;
       uint16 time_mid;
       uint16 time_hi_and_version;
       uint8  clock_seq[2];
       uint8  node[6];
};

typedef struct _prs_struct {
	bool io; /* parsing in or out of data stream */
	/* 
	 * If the (incoming) data is big-endian. On output we are
	  * always little-endian.
	   */ 
	   bool bigendian_data;
	   uint8 align; /* data alignment */
	   bool is_dynamic; /* Do we own this memory or not ? */
	   uint32 data_offset; /* Current working offset into data. */
	   uint32 buffer_size; /* Current allocated size of the buffer. */
	   uint32 grow_size; /* size requested via prs_grow() calls */
	   char *data_p; /* The buffer itself. */
	   void *mem_ctx; /* When unmarshalling, use this.... */
} prs_struct;

#define MARSHALL 0
#define UNMARSHALL 1

#define RPC_LITTLE_ENDIAN  0
#define RPC_PARSE_ALIGN    4

/* End of stuff from ntdomain.h */


/* From lib/time.c */

#define CHAR_BIT 8
#define TIME_T_MIN ((time_t)0 < (time_t) -1 ? (time_t) 0 \
		    : ~ (time_t) 0 << (sizeof (time_t) * CHAR_BIT - 1))
#define TIME_T_MAX (~ (time_t) 0 - TIME_T_MIN)
#define TIME_FIXUP_CONSTANT (369.0*365.25*24*60*60-(3.0*24*60*60+6.0*60*60))

void unix_to_nt_time(NTTIME* nt, time_t t);
time_t nt_time_to_unix(const NTTIME* nt);

/* End of stuff from lib/time.c */

/* From rpc_dce.h */

#define MAX_PDU_FRAG_LEN 0x10b8 /* this is what w2k sets */

/* End of stuff from rpc_dce.h */

/* From parse_prs.h */

bool prs_grow(prs_struct *ps, uint32 extra_space);
bool prs_align(prs_struct *ps);
bool prs_init(prs_struct *ps, uint32 size, void *ctx, bool io);
char *prs_mem_get(prs_struct *ps, uint32 extra_size);
bool prs_uint32(const char *name, prs_struct *ps, int depth, uint32 *data32);
bool prs_uint32s(const char *name, prs_struct *ps, 
		 int depth, uint32 *data32s, int len);
bool prs_uint16(const char *name, prs_struct *ps, int depth, uint16 *data16);
bool prs_uint16_pre(const char *name, prs_struct *ps, int depth, 
		    uint16 *data16, uint32 *offset);
bool prs_uint16_post(const char *name, prs_struct *ps, int depth, 
		     uint16 *data16, uint32 ptr_uint16, uint32 start_offset);
bool prs_uint8(const char *name, prs_struct *ps, int depth, uint8 *data8);
bool prs_uint8s(const char *name, prs_struct *ps, int depth, 
		uint8* data8s, int len);
bool prs_set_offset(prs_struct *ps, uint32 offset);

/* End of stuff from parse_prs.h */


/* From pstring.h */

#define FSTRING_LEN 256
typedef char fstring[FSTRING_LEN];

/* End of stuff from pstring.h */

/* From rpc_parse/parse_misc.c */

bool smb_io_uuid(const char *desc, struct uuid *uuid, 
		 prs_struct *ps, int depth);
bool smb_io_time(const char *desc, NTTIME *nttime, prs_struct *ps, int depth);

/* End of stuff from rpc_parse/parse_misc.c */

#endif /* _SMB_DEPS_H */
