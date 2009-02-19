/*
 * Branched from Samba project Subversion repository, version #6903:
 *   http://viewcvs.samba.org/cgi-bin/viewcvs.cgi/trunk/source/include/regfio.h?rev=6903&view=auto
 *
 * Windows NT (and later) registry parsing library
 *
 * Copyright (C) 2005-2009 Timothy D. Morgan
 * Copyright (C) 2005 Gerald (Jerry) Carter
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
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "smb_deps.h"
#include "winsec.h"
#include "void_stack.h"
#include "range_list.h"
#include "lru_cache.h"

/******************************************************************************/

/* regfi library error message types */
#define REGFI_MSG_INFO  0x0001
#define REGFI_MSG_WARN  0x0004
#define REGFI_MSG_ERROR 0x0010

/* Windows is lame */
#ifdef O_BINARY
#define REGFI_OPEN_FLAGS O_RDONLY|O_BINARY
#else
#define REGFI_OPEN_FLAGS O_RDONLY
#endif

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
#define REG_KEY                    0x7FFFFFFF

#define REGFI_REGF_SIZE            0x1000 /* "regf" header block size */
#define REGFI_HBIN_ALLOC           0x1000 /* Minimum allocation unit for HBINs */
#define REGFI_MAX_DEPTH		   512
#define REGFI_OFFSET_NONE          0xffffffff

/* XXX: This is totally arbitrary right now. */
#define REGFI_MAX_SUBKEY_DEPTH     255    

/* Header sizes and magic number lengths for various records */
#define REGFI_REGF_MAGIC_SIZE      4
#define REGFI_HBIN_MAGIC_SIZE      4
#define REGFI_CELL_MAGIC_SIZE      2
#define REGFI_HBIN_HEADER_SIZE     0x20
#define REGFI_NK_MIN_LENGTH        0x4C
#define REGFI_VK_MIN_LENGTH        0x14
#define REGFI_SK_MIN_LENGTH        0x14
#define REGFI_SUBKEY_LIST_MIN_LEN  0x4


/* Constants used for validation */
/* XXX: Can we add clock resolution validation as well as range?  It has
 *      been reported that Windows timestamps are never more than a
 *      certain granularity (250ms?), which could be used to help
 *      eliminate false positives.  Would need to validate this and
 *      perhaps conservatively implement a check.
 */
 /* Minimum time is Jan 1, 1990 00:00:00 */
#define REGFI_MTIME_MIN_HIGH       0x01B41E6D
#define REGFI_MTIME_MIN_LOW        0x26F98000
 /* Maximum time is Jan 1, 2290 00:00:00
  * (We hope no one is using Windows by then...) 
  */
#define REGFI_MTIME_MAX_HIGH       0x03047543
#define REGFI_MTIME_MAX_LOW        0xC80A4000


/* Flags for the vk records */
#define REGFI_VK_FLAG_NAME_PRESENT 0x0001
#define REGFI_VK_DATA_IN_OFFSET    0x80000000
#define REGFI_VK_MAX_DATA_LENGTH   1024*1024


/* NK record types */
/* XXX: This is starting to look like this is a flags field.  
 *      Need to decipher the meaning of each flag.
 */
#define REGFI_NK_TYPE_LINKKEY      0x0010
#define REGFI_NK_TYPE_NORMALKEY    0x0020
 /* XXX: Unknown key type that shows up in Vista registries */
#define REGFI_NK_TYPE_UNKNOWN1     0x1020
 /* XXX: Unknown key types that shows up in W2K3 registries */
#define REGFI_NK_TYPE_UNKNOWN2     0x4020
#define REGFI_NK_TYPE_UNKNOWN3     0x0000  /* XXX: This type seems to have UTF-16 names!!! */
#define REGFI_NK_TYPE_ROOTKEY1     0x002c
 /* XXX: Unknown root key type that shows up in Vista registries */
#define REGFI_NK_TYPE_ROOTKEY2     0x00ac

#if 0
/* Initial hypothesis of NK flags: */
/***********************************/
#define REGFI_NK_FLAG_LINK         0x0010
/* The name will be in ASCII if this next bit is set, otherwise UTF-16LE */
#define REGFI_NK_FLAG_ASCIINAME    0x0020
/* These next two combine to form the "c" on both known root key types */
#define REGFI_NK_FLAG_ROOT1        0x0008
#define REGFI_NK_FLAG_ROOT2        0x0004
/* These next two show up on normal-seeming keys in Vista and W2K3 registries */
#define REGFI_NK_FLAG_UNKNOWN1     0x4000
#define REGFI_NK_FLAG_UNKNOWN2     0x1000
/* This next one shows up on root keys in some Vista "software" registries */
#define REGFI_NK_FLAG_UNKNOWN3     0x0080
#endif


/* HBIN block */
typedef struct _regfi_hbin 
{
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

  uint8 magic[REGFI_HBIN_MAGIC_SIZE]; /* "hbin" */
} REGFI_HBIN;


/* Subkey List -- list of key offsets and hashed names for consistency */
typedef struct 
{
  /* Virtual offset of NK record or additional subkey list, 
   * depending on this list's type. 
   */
  uint32 offset;

  uint32 hash;
} REGFI_SUBKEY_LIST_ELEM;


typedef struct _regfi_subkey_list
{
  /* Real offset of this record's cell in the file */
  uint32 offset;

  uint32 cell_size;
  
  /* Number of immediate children */
  uint32 num_children;  

  /* Total number of keys referenced by this list and it's children */
  uint32 num_keys;      

  REGFI_SUBKEY_LIST_ELEM* elements;
  uint8 magic[REGFI_CELL_MAGIC_SIZE];

  /* Set if the magic indicates this subkey list points to child subkey lists */
  bool recursive_type;  
} REGFI_SUBKEY_LIST;


typedef uint32 REGFI_VALUE_LIST_ELEM;
typedef struct _regfi_value_list
{
  /* Actual number of values referenced by this list.  
   * May differ from parent key's num_values if there were parsing errors. 
   */
  uint32 num_values;

  REGFI_VALUE_LIST_ELEM* elements;
} REGFI_VALUE_LIST;


/* Key Value */
typedef struct 
{
  uint32 offset;	/* Real offset of this record's cell in the file */
  uint32 cell_size;	/* ((start_offset - end_offset) & 0xfffffff8) */

  REGFI_HBIN* hbin;	/* pointer to HBIN record (in memory) containing 
			 * this nk record 
			 */
  uint8* data;
  uint16 name_length;
  char*  valuename;
  uint32 hbin_off;	/* offset from beginning of this hbin block */
  
  uint32 data_size;
  uint32 data_off;      /* offset of data cell (virtual) */
  uint32 type;
  uint8  magic[REGFI_CELL_MAGIC_SIZE];
  uint16 flag;
  uint16 unknown1;
  bool data_in_offset;
} REGFI_VK_REC;


/* Key Security */
struct _regfi_sk_rec;

typedef struct _regfi_sk_rec 
{
  uint32 offset;        /* Real file offset of this record */
  uint32 cell_size;	/* ((start_offset - end_offset) & 0xfffffff8) */

  WINSEC_DESC* sec_desc;
  uint32 hbin_off;	/* offset from beginning of this hbin block */
  
  uint32 prev_sk_off;
  uint32 next_sk_off;
  uint32 ref_count;
  uint32 desc_size;     /* size of security descriptor */
  uint16 unknown_tag;
  uint8  magic[REGFI_CELL_MAGIC_SIZE];
} REGFI_SK_REC;


/* Key Name */
typedef struct
{
  uint32 offset;	/* Real offset of this record's cell in the file */
  uint32 cell_size;	/* Actual or estimated length of the cell.  
			 * Always in multiples of 8. 
			 */

  /* link in the other records here */
  REGFI_VALUE_LIST* values;
  REGFI_SUBKEY_LIST* subkeys;
  
  /* header information */
  uint16 key_type;
  uint8  magic[REGFI_CELL_MAGIC_SIZE];
  NTTIME mtime;
  uint16 name_length;
  uint16 classname_length;
  char* classname;
  char* keyname;
  uint32 parent_off;	            /* pointer to parent key */
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
  uint32 subkeys_off;	/* offset of subkey list that points to NK records */
  uint32 num_values;
  uint32 values_off;	/* value lists which point to VK records */
  uint32 sk_off;	/* offset to SK record */
} REGFI_NK_REC;



/* REGF block */
typedef struct 
{
  /* Run-time information */
  /************************/
  /* file descriptor */
  int fd;

  /* For sanity checking (not part of the registry header) */
  uint32 file_length;

  /* Metadata about hbins */
  range_list* hbins;

  /* SK record cached since they're repeatedly reused */
  lru_cache* sk_cache;

  /* Error/warning/info messages returned by lower layer functions */
  char* last_message;

  /* Mask for error message types that will be stored. */
  uint16 msg_mask;


  /* Data parsed from file header */
  /********************************/
  uint8  magic[REGFI_REGF_MAGIC_SIZE];/* "regf" */
  NTTIME mtime;
  uint32 data_offset;		/* offset to record in the first (or any?) 
				 * hbin block 
				 */
  uint32 last_block;		/* offset to last hbin block in file */

  uint32 checksum;		/* Stored checksum. */
  uint32 computed_checksum;     /* Our own calculation of the checksum.
				 * (XOR of bytes 0x0000 - 0x01FB) 
				 */
  
  /* XXX: Some of these we have some clues about (major/minor version, etc). 
   *      Should verify and update names accordingly. 
   */
  /* unknown data structure values */
  uint32 unknown1;
  uint32 unknown2;
  uint32 unknown3;
  uint32 unknown4;
  uint32 unknown5;
  uint32 unknown6;
  uint32 unknown7;
} REGFI_FILE;


/* XXX: Should move all caching (SK records, HBINs, NKs, etc) to a single
 *      structure, probably REGFI_FILE.  Once key caching is in place, 
 *      convert key_positions stack to store just key offsets rather than
 *      whole keys.
 */
typedef struct 
{
  REGFI_FILE* f;
  void_stack* key_positions;
  REGFI_NK_REC* cur_key;
  uint32 cur_subkey;
  uint32 cur_value;
} REGFI_ITERATOR;


typedef struct 
{
  REGFI_NK_REC* nk;
  uint32 cur_subkey;
  /* We could store a cur_value here as well, but didn't see 
   * the use in it right now.
   */
} REGFI_ITER_POSITION;


/******************************************************************************/
/*                         Main iterator API                                  */
/******************************************************************************/
REGFI_FILE*           regfi_open(const char* filename);
int                   regfi_close(REGFI_FILE* r);

/* regfi_get_messages: Get errors, warnings, and/or verbose information
 *                     relating to processing of the given registry file.
 *
 * Arguments:
 *   file     -- the structure for the registry file
 *
 * Returns:
 *   A newly allocated char* which must be free()d by the caller.
 */
char*                 regfi_get_messages(REGFI_FILE* file);
void                  regfi_set_message_mask(REGFI_FILE* file, uint16 mask);

REGFI_ITERATOR*       regfi_iterator_new(REGFI_FILE* fh);
void                  regfi_iterator_free(REGFI_ITERATOR* i);
bool                  regfi_iterator_down(REGFI_ITERATOR* i);
bool                  regfi_iterator_up(REGFI_ITERATOR* i);
bool                  regfi_iterator_to_root(REGFI_ITERATOR* i);

bool                  regfi_iterator_find_subkey(REGFI_ITERATOR* i, 
						 const char* subkey_name);
bool                  regfi_iterator_walk_path(REGFI_ITERATOR* i, 
					       const char** path);
const REGFI_NK_REC*   regfi_iterator_cur_key(REGFI_ITERATOR* i);
const REGFI_SK_REC*   regfi_iterator_cur_sk(REGFI_ITERATOR* i);
const REGFI_NK_REC*   regfi_iterator_first_subkey(REGFI_ITERATOR* i);
const REGFI_NK_REC*   regfi_iterator_cur_subkey(REGFI_ITERATOR* i);
const REGFI_NK_REC*   regfi_iterator_next_subkey(REGFI_ITERATOR* i);

bool                  regfi_iterator_find_value(REGFI_ITERATOR* i, 
						const char* value_name);
const REGFI_VK_REC*   regfi_iterator_first_value(REGFI_ITERATOR* i);
const REGFI_VK_REC*   regfi_iterator_cur_value(REGFI_ITERATOR* i);
const REGFI_VK_REC*   regfi_iterator_next_value(REGFI_ITERATOR* i);


/********************************************************/
/* Middle-layer structure loading, linking, and caching */
/********************************************************/
REGFI_NK_REC*         regfi_load_key(REGFI_FILE* file, uint32 offset, 
				     bool strict);
REGFI_VK_REC*         regfi_load_value(REGFI_FILE* file, uint32 offset, 
				       bool strict);
REGFI_SUBKEY_LIST*    regfi_load_subkeylist(REGFI_FILE* file, uint32 offset,
					    uint32 num_keys, uint32 max_size,
					    bool strict);
REGFI_VALUE_LIST*     regfi_load_valuelist(REGFI_FILE* file, uint32 offset, 
					   uint32 num_values, uint32 max_size,
					   bool strict);

/* These are cached so return values don't need to be freed. */
const REGFI_SK_REC*   regfi_load_sk(REGFI_FILE* file, uint32 offset,
				    bool strict);
const REGFI_HBIN*     regfi_lookup_hbin(REGFI_FILE* file, uint32 voffset);



/************************************/
/*  Low-layer data structure access */
/************************************/
REGFI_FILE*           regfi_parse_regf(int fd, bool strict);
REGFI_HBIN*           regfi_parse_hbin(REGFI_FILE* file, uint32 offset, 
				       bool strict);


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
REGFI_NK_REC*         regfi_parse_nk(REGFI_FILE* file, uint32 offset, 
				     uint32 max_size, bool strict);

REGFI_SUBKEY_LIST*    regfi_parse_subkeylist(REGFI_FILE* file, uint32 offset,
					     uint32 max_size, bool strict);

REGFI_VK_REC*         regfi_parse_vk(REGFI_FILE* file, uint32 offset, 
				     uint32 max_size, bool strict);

uint8*                regfi_parse_data(REGFI_FILE* file, 
				       uint32 data_type, uint32 offset, 
				       uint32 length, uint32 max_size, 
				       bool data_in_offset, bool strict);

REGFI_SK_REC*         regfi_parse_sk(REGFI_FILE* file, uint32 offset, 
				     uint32 max_size, bool strict);

range_list*           regfi_parse_unalloc_cells(REGFI_FILE* file);

bool                  regfi_parse_cell(int fd, uint32 offset, 
				       uint8* hdr, uint32 hdr_len,
				       uint32* cell_length, bool* unalloc);

char*                 regfi_parse_classname(REGFI_FILE* file, uint32 offset,
					    uint16* name_length, 
					    uint32 max_size, bool strict);


/************************************/
/*    Private Functions             */
/************************************/
REGFI_NK_REC*         regfi_rootkey(REGFI_FILE* file);
void                  regfi_key_free(REGFI_NK_REC* nk);
void                  regfi_subkeylist_free(REGFI_SUBKEY_LIST* list);
uint32                regfi_read(int fd, uint8* buf, uint32* length);

const char*           regfi_type_val2str(unsigned int val);
int                   regfi_type_str2val(const char* str);

char*                 regfi_get_sacl(WINSEC_DESC* sec_desc);
char*                 regfi_get_dacl(WINSEC_DESC* sec_desc);
char*                 regfi_get_owner(WINSEC_DESC* sec_desc);
char*                 regfi_get_group(WINSEC_DESC* sec_desc);

REGFI_SUBKEY_LIST*    regfi_merge_subkeylists(uint16 num_lists, 
					      REGFI_SUBKEY_LIST** lists,
					      bool strict);
REGFI_SUBKEY_LIST*    regfi_load_subkeylist_aux(REGFI_FILE* file, uint32 offset,
						uint32 max_size, bool strict,
						uint8 depth_left);
void                  regfi_add_message(REGFI_FILE* file, uint16 msg_type, 
					const char* fmt, ...);
REGFI_NK_REC*         regfi_copy_nk(const REGFI_NK_REC* nk);
REGFI_VK_REC*         regfi_copy_vk(const REGFI_VK_REC* vk);

#endif	/* _REGFI_H */
