/*
 * Branched from Samba project, Subversion repository version #6903:
 *   http://viewcvs.samba.org/cgi-bin/viewcvs.cgi/trunk/source/include/regfio.h?rev=6903&view=auto
 *
 * Unix SMB/CIFS implementation.
 * Windows NT registry I/O library
 *
 * Copyright (C) 2005-2008 Timothy D. Morgan
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

#ifndef _REGFI_H
#define _REGFI_H

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
#include "void_stack.h"
#include "range_list.h"

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
#define REG_KEY                        0x7FFFFFFF


#define REGF_BLOCKSIZE		0x1000
#define REGF_ALLOC_BLOCK	0x1000  /* Minimum allocation unit for hbins */
#define REGF_MAX_DEPTH		512

/* header sizes for various records */

#define REGF_MAGIC_SIZE		4
#define HBIN_MAGIC_SIZE		4
#define HBIN_HEADER_REC_SIZE	0x20
#define REC_HDR_SIZE		2

#define REGF_OFFSET_NONE	0xffffffff
#define REGFI_NK_MIN_LENGTH     0x4C
#define REGFI_VK_MIN_LENGTH     0x14
#define REGFI_SK_MIN_LENGTH     0x14

/* Flags for the vk records */

#define VK_FLAG_NAME_PRESENT	0x0001
#define VK_DATA_IN_OFFSET	0x80000000
#define VK_MAX_DATA_LENGTH      1024*1024

/* NK record macros */

#define NK_TYPE_LINKKEY		0x0010
#define NK_TYPE_NORMALKEY	0x0020
#define NK_TYPE_ROOTKEY		0x002c
  /* TODO: Unknown type that shows up in Vista registries */
#define NK_TYPE_UNKNOWN1         0x1020 

#define HBIN_STORE_REF(x, y) { x->hbin = y; y->ref_count++ };
/* if the count == 0; we can clean up */
#define HBIN_REMOVE_REF(x, y){ x->hbin = NULL; y->ref_count-- };


/* HBIN block */
struct regf_hbin;
typedef struct regf_hbin 
{
  struct regf_hbin* prev;
  struct regf_hbin* next;
  uint32 file_off;       /* my offset in the registry file */
  uint32 ref_count;      /* how many active records are pointing to this
                          * block (not used currently) 
			  */
  
  uint32 first_hbin_off; /* offset from first hbin block */
  uint32 block_size;     /* block size of this block 
                          * Should be a multiple of 4096 (0x1000)
			  */
  uint32 next_block;     /* relative offset to next block.  
			  * NOTE: This value may be unreliable!
			  */

  uint8 magic[HBIN_MAGIC_SIZE]; /* "hbin" */
  prs_struct ps;	 /* data */
} REGF_HBIN;


/* Hash List -- list of key offsets and hashed names for consistency */
typedef struct 
{
  uint32 nk_off;
  uint8 keycheck[4];
} REGF_HASH_REC;


typedef struct 
{
  REGF_HBIN* hbin;       /* pointer to HBIN record (in memory) containing 
			  * this nk record 
			  */
  REGF_HASH_REC* hashes;
  uint32 hbin_off;	 /* offset from beginning of this hbin block */
  uint32 cell_size;	 /* ((start_offset - end_offset) & 0xfffffff8) */
  
  uint8 header[REC_HDR_SIZE];
  uint16 num_keys;
} REGF_LF_REC;


/* Key Value */
typedef struct 
{
  uint32 offset;	/* Real offset of this record's cell in the file */
  uint32 cell_size;	/* ((start_offset - end_offset) & 0xfffffff8) */

  REGF_HBIN* hbin;	/* pointer to HBIN record (in memory) containing 
			 * this nk record 
			 */
  uint8* data;
  uint16 name_length;
  char*  valuename;
  uint32 hbin_off;	/* offset from beginning of this hbin block */
  
  uint32 data_size;
  uint32 data_off;      /* offset of data cell (virtual) */
  uint32 type;
  uint8  magic[REC_HDR_SIZE];
  uint16 flag;
  uint16 unknown1;
} REGF_VK_REC;


/* Key Security */
struct _regf_sk_rec;

typedef struct _regf_sk_rec 
{
  struct _regf_sk_rec* next;
  struct _regf_sk_rec* prev;
  REGF_HBIN* hbin;	/* pointer to HBIN record (in memory) containing 
			 * this nk record 
			 */
  SEC_DESC* sec_desc;
  uint32 hbin_off;	/* offset from beginning of this hbin block */
  uint32 cell_size;	/* ((start_offset - end_offset) & 0xfffffff8) */
  uint32 offset;        /* Real file offset of this record */
  
  uint32 sk_off;	/* offset parsed from NK record used as a key
			 * to lookup reference to this SK record 
			 */
  
  uint32 prev_sk_off;
  uint32 next_sk_off;
  uint32 ref_count;
  uint32 desc_size;     /* size of security descriptor */
  uint16 unknown_tag;
  uint8  magic[REC_HDR_SIZE];
} REGF_SK_REC;


/* Key Name */ 
typedef struct 
{
  uint32 offset;	/* Real offset of this record's cell in the file */
  uint32 cell_size;	/* Actual or estimated length of the cell.  
			 * Always in multiples of 8. 
			 */

  /* link in the other records here */
  REGF_VK_REC** values;
  REGF_SK_REC* sec_desc;
  REGF_LF_REC subkeys;
  
  /* header information */
  /* XXX: should we be looking for types other than the root key type? */
  uint16 key_type;      
  uint8  magic[REC_HDR_SIZE];
  NTTIME mtime;
  uint16 name_length;
  uint16 classname_length;
  char* classname;
  char* keyname;
  uint32 parent_off;	/* back pointer in registry hive */
  uint32 classname_off;	
  
  /* max lengths */
  uint32 max_bytes_subkeyname;	    /* max subkey name * 2 */
  uint32 max_bytes_subkeyclassname; /* max subkey classname length (as if) */
  uint32 max_bytes_valuename;	    /* max valuename * 2 */
  uint32 max_bytes_value;           /* max value data size */
  
  /* unknowns */
  uint32 unknown1;
  uint32 unknown2;
  uint32 unknown3;
  uint32 unk_index;		    /* nigel says run time index ? */
  
  /* children */
  uint32 num_subkeys;
  uint32 subkeys_off;	/* hash records that point to NK records */	
  uint32 num_values;
  uint32 values_off;	/* value lists which point to VK records */
  uint32 sk_off;	/* offset to SK record */  
} REGF_NK_REC;



/* REGF block */
typedef struct 
{
  /* run time information */
  int fd;	  /* file descriptor */
  /* For sanity checking (not part of the registry header) */
  uint32 file_length;
  void* mem_ctx;  /* memory context for run-time file access information */
  REGF_HBIN* block_list; /* list of open hbin blocks */

  /* Experimental hbin lists */
  range_list* hbins;
  range_list* unalloc_cells;

  /* file format information */
  REGF_SK_REC* sec_desc_list;	/* list of security descriptors referenced 
				 * by NK records 
				 */
  
  uint8  magic[REGF_MAGIC_SIZE];/* "regf" */
  NTTIME mtime;
  uint32 data_offset;		/* offset to record in the first (or any?) 
				 * hbin block 
				 */
  uint32 last_block;		/* offset to last hbin block in file */

  uint32 checksum;		/* Stored checksum. */
  uint32 computed_checksum;     /* Our own calculation of the checksum.
				 * (XOR of bytes 0x0000 - 0x01FB) 
				 */
  
  /* unknown data structure values */
  uint32 unknown1;
  uint32 unknown2;
  uint32 unknown3;
  uint32 unknown4;
  uint32 unknown5;
  uint32 unknown6;
  uint32 unknown7;
} REGF_FILE;



typedef struct 
{
  REGF_FILE* f;
  void_stack* key_positions;
  REGF_NK_REC* cur_key;
  uint32 cur_subkey;
  uint32 cur_value;
} REGFI_ITERATOR;


typedef struct 
{
  REGF_NK_REC* nk;
  uint32 cur_subkey;
  /* We could store a cur_value here as well, but didn't see 
   * the use in it right now.
   */
} REGFI_ITER_POSITION;


/******************************************************************************/
/* Function Declarations */
/*  Main API */
const char*           regfi_type_val2str(unsigned int val);
int                   regfi_type_str2val(const char* str);

char*                 regfi_get_sacl(SEC_DESC* sec_desc);
char*                 regfi_get_dacl(SEC_DESC* sec_desc);
char*                 regfi_get_owner(SEC_DESC* sec_desc);
char*                 regfi_get_group(SEC_DESC* sec_desc);

REGF_FILE*            regfi_open(const char* filename);
int                   regfi_close(REGF_FILE* r);

REGFI_ITERATOR*       regfi_iterator_new(REGF_FILE* fh);
void                  regfi_iterator_free(REGFI_ITERATOR* i);
bool                  regfi_iterator_down(REGFI_ITERATOR* i);
bool                  regfi_iterator_up(REGFI_ITERATOR* i);
bool                  regfi_iterator_to_root(REGFI_ITERATOR* i);

bool                  regfi_iterator_find_subkey(REGFI_ITERATOR* i, 
						 const char* subkey_name);
bool                  regfi_iterator_walk_path(REGFI_ITERATOR* i, 
					       const char** path);
const REGF_NK_REC*    regfi_iterator_cur_key(REGFI_ITERATOR* i);
const REGF_NK_REC*    regfi_iterator_first_subkey(REGFI_ITERATOR* i);
const REGF_NK_REC*    regfi_iterator_cur_subkey(REGFI_ITERATOR* i);
const REGF_NK_REC*    regfi_iterator_next_subkey(REGFI_ITERATOR* i);

bool                  regfi_iterator_find_value(REGFI_ITERATOR* i, 
						const char* value_name);
const REGF_VK_REC*    regfi_iterator_first_value(REGFI_ITERATOR* i);
const REGF_VK_REC*    regfi_iterator_cur_value(REGFI_ITERATOR* i);
const REGF_VK_REC*    regfi_iterator_next_value(REGFI_ITERATOR* i);

/************************************/
/*  Low-layer data structure access */
/************************************/
REGF_FILE*            regfi_parse_regf(int fd, bool strict);
REGF_HBIN*            regfi_parse_hbin(REGF_FILE* file, uint32 offset, 
				       bool strict, bool save_unalloc);


/* regfi_parse_nk: Parses an NK record.
 *
 * Arguments:
 *   f        -- the registry file structure
 *   offset   -- the offset of the cell (not the record) to be parsed.
 *   max_size -- the maximum size the NK cell could be. (for validation)
 *   strict   -- if true, rejects any malformed records.  Otherwise,
 *               tries to minimally validate integrity.
 * Returns:
 *   A newly allocated NK record structure, or NULL on failure.
 */
REGF_NK_REC*          regfi_parse_nk(REGF_FILE* file, uint32 offset, 
				     uint32 max_size, bool strict);


/* Private Functions */
REGF_NK_REC*          regfi_rootkey(REGF_FILE* file);
void                  regfi_key_free(REGF_NK_REC* nk);
uint32                regfi_read(int fd, uint8* buf, uint32* length);



/****************/
/* Experimental */
/****************/

REGF_VK_REC* regfi_parse_vk(REGF_FILE* file, uint32 offset, 
			    uint32 max_size, bool strict);
uint8* regfi_parse_data(REGF_FILE* file, uint32 offset, 
			uint32 length, bool strict);


#endif	/* _REGFI_H */