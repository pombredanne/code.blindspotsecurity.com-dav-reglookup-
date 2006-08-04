/*
 * Branched from Samba project, Subversion repository version #6903:
 *   http://websvn.samba.org/cgi-bin/viewcvs.cgi/trunk/source/include/regfio.h
 *
 * Unix SMB/CIFS implementation.
 * Windows NT registry I/O library
 *
 * Copyright (C) 2005-2006 Timothy D. Morgan
 * Copyright (C) 2005 Gerald (Jerry) Carter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
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

/************************************************************
 * Most of this information was obtained from 
 * http://www.wednesday.demon.co.uk/dosreg.html
 * Thanks Nigel!
 ***********************************************************/

#ifndef _REGFIO_H
#define _REGFIO_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "smb_deps.h"

/******************************************************************************/
/* Macros */
 
/* Registry data types */
#define REG_NONE                       0
#define REG_SZ		               1
#define REG_EXPAND_SZ                  2
#define REG_BINARY 	               3
#define REG_DWORD	               4
#define REG_DWORD_LE	               4  /* DWORD, little endian */
#define REG_DWORD_BE	               5  /* DWORD, big endian */
#define REG_LINK                       6
#define REG_MULTI_SZ  	               7
#define REG_RESOURCE_LIST              8
#define REG_FULL_RESOURCE_DESCRIPTOR   9
#define REG_RESOURCE_REQUIREMENTS_LIST 10
#define REG_QWORD                      11 /* 64-bit little endian */
/* XXX: Has MS defined a REG_QWORD_BE? */
/* Not a real type in the registry */
#define REG_KEY                        255


#define REGF_BLOCKSIZE		0x1000
#define REGF_ALLOC_BLOCK	0x1000

/* header sizes for various records */

#define REGF_HDR_SIZE		4
#define HBIN_HDR_SIZE		4
#define HBIN_HEADER_REC_SIZE	0x24
#define REC_HDR_SIZE		2

#define REGF_OFFSET_NONE	0xffffffff

/* Flags for the vk records */

#define VK_FLAG_NAME_PRESENT	0x0001
#define VK_DATA_IN_OFFSET	0x80000000

/* NK record macros */

#define NK_TYPE_LINKKEY		0x0010
#define NK_TYPE_NORMALKEY	0x0020
#define NK_TYPE_ROOTKEY		0x002c

#define HBIN_STORE_REF(x, y) { x->hbin = y; y->ref_count++ };
/* if the count == 0; we can clean up */
#define HBIN_REMOVE_REF(x, y){ x->hbin = NULL; y->ref_count-- };


/* HBIN block */
struct regf_hbin;
typedef struct regf_hbin {
  struct regf_hbin* prev;
  struct regf_hbin* next;
  uint32 file_off;       /* my offset in the registry file */
  uint32 free_off;       /* offset to free space within the hbin record */
  uint32 free_size;      /* amount of data left in the block */
  int    ref_count;      /* how many active records are pointing to this
                          * block (not used currently) 
			  */
	
  uint8  header[HBIN_HDR_SIZE]; /* "hbin" */
  uint32 first_hbin_off; /* offset from first hbin block */
  uint32 block_size;     /* block size of this block is
                          * usually a multiple of 4096Kb 
			  */
  prs_struct ps;	 /* data */
  bool dirty;            /* has this hbin block been modified? */
} REGF_HBIN;

/* ??? List -- list of key offsets and hashed names for consistency */
typedef struct {
  uint32 nk_off;
  uint8 keycheck[sizeof(uint32)];
} REGF_HASH_REC;

typedef struct {
  REGF_HBIN *hbin;       /* pointer to HBIN record (in memory) containing 
			  * this nk record 
			  */
  uint32 hbin_off;	 /* offset from beginning of this hbin block */
  uint32 rec_size;	 /* ((start_offset - end_offset) & 0xfffffff8) */
  
  uint8 header[REC_HDR_SIZE];
  uint16 num_keys;
  REGF_HASH_REC *hashes;
} REGF_LF_REC;

/* Key Value */

typedef struct {
  REGF_HBIN *hbin;	/* pointer to HBIN record (in memory) containing 
			 * this nk record 
			 */
  uint32 hbin_off;	/* offset from beginning of this hbin block */
  uint32 rec_size;	/* ((start_offset - end_offset) & 0xfffffff8) */
  uint32 rec_off;	/* offset stored in the value list */
  
  uint8  header[REC_HDR_SIZE];
  char*  valuename;
  uint32 data_size;
  uint32 data_off;
  uint8* data;
  uint32 type;
  uint16 flag;
} REGF_VK_REC;


/* Key Security */
struct _regf_sk_rec;

typedef struct _regf_sk_rec {
  struct _regf_sk_rec *next, *prev;
  REGF_HBIN *hbin;	/* pointer to HBIN record (in memory) containing 
			 * this nk record 
			 */
  uint32 hbin_off;	/* offset from beginning of this hbin block */
  uint32 rec_size;	/* ((start_offset - end_offset) & 0xfffffff8) */
  
  uint32 sk_off;	/* offset parsed from NK record used as a key
			 * to lookup reference to this SK record 
			 */
  
  uint8  header[REC_HDR_SIZE];
  uint32 prev_sk_off;
  uint32 next_sk_off;
  uint32 ref_count;
  uint32 size;
  SEC_DESC *sec_desc;
} REGF_SK_REC;

/* Key Name */ 

typedef struct {
  REGF_HBIN *hbin;	/* pointer to HBIN record (in memory) containing 
			 * this nk record 
			 */
  uint32 hbin_off;	/* offset from beginning of this hbin block */
  uint32 subkey_index;	/* index to next subkey record to return */
  uint32 rec_size;	/* ((start_offset - end_offset) & 0xfffffff8) */
  
  /* header information */
  uint8  header[REC_HDR_SIZE];
  uint16 key_type;
  NTTIME mtime;
  uint32 parent_off;	/* back pointer in registry hive */
  uint32 classname_off;	
  char *classname;
  char *keyname;
  
  /* max lengths */
  uint32 max_bytes_subkeyname;	    /* max subkey name * 2 */
  uint32 max_bytes_subkeyclassname; /* max subkey classname length (as if) */
  uint32 max_bytes_valuename;	    /* max valuename * 2 */
  uint32 max_bytes_value;           /* max value data size */
  
  /* unknowns */
  uint32 unk_index;		    /* nigel says run time index ? */
  
  /* children */
  uint32 num_subkeys;
  uint32 subkeys_off;	/* hash records that point to NK records */	
  uint32 num_values;
  uint32 values_off;	/* value lists which point to VK records */
  uint32 sk_off;	/* offset to SK record */
  
  /* link in the other records here */
  REGF_LF_REC subkeys;
  REGF_VK_REC *values;
  REGF_SK_REC *sec_desc;
	
} REGF_NK_REC;

/* REGF block */
 
typedef struct {
  /* run time information */
  int fd;	  /* file descriptor */
  int open_flags; /* flags passed to the open() call */
  void *mem_ctx;  /* memory context for run-time file access information */
  REGF_HBIN *block_list; /* list of open hbin blocks */
  
  /* file format information */
  
  uint8  header[REGF_HDR_SIZE];	/* "regf" */
  uint32 data_offset;		/* offset to record in the first (or any?) 
				 * hbin block 
				 */
  uint32 last_block;		/* offset to last hbin block in file */
  uint32 checksum;		/* XOR of bytes 0x0000 - 0x01FB */
  NTTIME mtime;
  
  REGF_SK_REC *sec_desc_list;	/* list of security descriptors referenced 
				 * by NK records 
				 */
  
  /* unknowns used to simply writing */
  uint32 unknown1;
  uint32 unknown2;
  uint32 unknown3;
  uint32 unknown4;
  uint32 unknown5;
  uint32 unknown6;
} REGF_FILE;


/******************************************************************************/
/* Function Declarations */

const char*   regfio_type_val2str(unsigned int val);
int           regfio_type_str2val(const char* str);

char*         regfio_get_sacl(SEC_DESC *sec_desc);
char*         regfio_get_dacl(SEC_DESC *sec_desc);
char*         regfio_get_owner(SEC_DESC *sec_desc);
char*         regfio_get_group(SEC_DESC *sec_desc);

REGF_FILE*    regfio_open( const char *filename );
int           regfio_close( REGF_FILE *r );

REGF_NK_REC*  regfio_rootkey( REGF_FILE *file );
REGF_NK_REC*  regfio_fetch_subkey( REGF_FILE *file, REGF_NK_REC *nk );

#endif	/* _REGFIO_H */
