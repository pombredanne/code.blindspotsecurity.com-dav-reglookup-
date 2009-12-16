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
#include <iconv.h>

#include "talloc.h"
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

typedef uint8 REGFI_ENCODING;
/* regfi library supported character encodings */
#define REGFI_ENCODING_ASCII   0
#define REGFI_ENCODING_UTF8    1
#define REGFI_ENCODING_DEFAULT REGFI_ENCODING_ASCII
/* UTF16LE is not supported for output */
#define REGFI_ENCODING_UTF16LE 2

#define REGFI_NUM_ENCODINGS    3

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

#define REGFI_OFFSET_NONE          0xffffffff


/* This maximum depth is described here:
 * http://msdn.microsoft.com/en-us/library/ms724872%28VS.85%29.aspx
 */
#define REGFI_MAX_DEPTH		   512

/* This limit defines the maximum number of levels deep that ri subkey list
 * trees can go.
 */
/* XXX: This is totally arbitrary right now.
 *      The actual limit may need to be discovered by experimentation.
 */
#define REGFI_MAX_SUBKEY_DEPTH     255


/* Header sizes and magic number lengths for various records */
#define REGFI_HBIN_ALLOC           0x1000 /* Minimum allocation unit for HBINs */
#define REGFI_REGF_SIZE            0x1000 /* "regf" header block size */
#define REGFI_REGF_MAGIC_SIZE      4
#define REGFI_REGF_NAME_SIZE       64
#define REGFI_REGF_RESERVED1_SIZE  340
#define REGFI_REGF_RESERVED2_SIZE  3528
#define REGFI_HBIN_MAGIC_SIZE      4
#define REGFI_CELL_MAGIC_SIZE      2
#define REGFI_HBIN_HEADER_SIZE     0x20
#define REGFI_NK_MIN_LENGTH        0x4C
#define REGFI_VK_MIN_LENGTH        0x14
#define REGFI_SK_MIN_LENGTH        0x14
#define REGFI_SUBKEY_LIST_MIN_LEN  0x4
#define REGFI_BIG_DATA_MIN_LENGTH  0xC


/* Constants used for validation */
/* XXX: Can we add clock resolution validation as well as range?  It has
 *      been reported that Windows timestamps are never more than a
 *      certain granularity (250ms?), which could be used to help
 *      eliminate false positives.  Would need to verify this and
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
#define REGFI_VK_FLAG_ASCIINAME    0x0001
#define REGFI_VK_DATA_IN_OFFSET    0x80000000
#define REGFI_VK_MAX_DATA_LENGTH   1024*1024  /* XXX: This is arbitrary */


/* Known key flags */
/*******************/
/* These next two show up on normal-seeming keys in Vista and W2K3 registries */
#define REGFI_NK_FLAG_UNKNOWN1     0x4000
#define REGFI_NK_FLAG_UNKNOWN2     0x1000

/* This next one shows up on root keys in some Vista "software" registries */
#define REGFI_NK_FLAG_UNKNOWN3     0x0080

/* Predefined handle.  Rumor has it that the valuelist count for this key is 
 * where the handle is stored.
 * http://msdn.microsoft.com/en-us/library/ms724836(VS.85).aspx
 */
#define REGFI_NK_FLAG_PREDEF_KEY   0x0040

/* The name will be in ASCII if this next bit is set, otherwise UTF-16LE */
#define REGFI_NK_FLAG_ASCIINAME    0x0020

/* Symlink key.  
 * See: http://www.codeproject.com/KB/system/regsymlink.aspx 
 */
#define REGFI_NK_FLAG_LINK         0x0010

/* This key cannot be deleted */
#define REGFI_NK_FLAG_NO_RM        0x0008

/* Root of a hive */
#define REGFI_NK_FLAG_ROOT         0x0004

/* Mount point of another hive.  NULL/(default) value indicates which hive 
 * and where in the hive it points to. 
 */
#define REGFI_NK_FLAG_HIVE_LINK    0x0002 

/* These keys shouldn't be stored on disk, according to:
 * http://geekswithblogs.net/sdorman/archive/2007/12/24/volatile-registry-keys.aspx
 */
#define REGFI_NK_FLAG_VOLATILE     0x0001

/* Useful for identifying unknown flag types */
#define REGFI_NK_KNOWN_FLAGS       (REGFI_NK_FLAG_PREDEF_KEY\
				    | REGFI_NK_FLAG_ASCIINAME\
				    | REGFI_NK_FLAG_LINK\
				    | REGFI_NK_FLAG_NO_RM\
				    | REGFI_NK_FLAG_ROOT\
				    | REGFI_NK_FLAG_HIVE_LINK\
				    | REGFI_NK_FLAG_VOLATILE\
				    | REGFI_NK_FLAG_UNKNOWN1\
				    | REGFI_NK_FLAG_UNKNOWN2)

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


typedef struct _regfi_classname
{
  /* As converted to requested character encoding. */
  char* interpreted;

  /* Represents raw buffer read from classname cell. */
  uint8* raw;

  /* Length of the raw data. May be shorter than that indicated by parent key.*/
  uint16 size;
} REGFI_CLASSNAME;


typedef struct _regfi_data
{
  uint32 type;

  /* Length of the raw data. */
  uint32 size;

  /* This is always present, representing the raw data cell contents. */
  uint8* raw;

  /* Represents the length of the interpreted value. Meaning is type-specific.*/
  uint32 interpreted_size;

  /* These items represent interpreted versions of the raw attribute above. 
   * Only use the appropriate member according to the type field.  
   * In the event of an unknown type, use only the raw field.
   */
  union _regfi_data_interpreted
  {
    uint8* none; /* */
    uint8* string;
    uint8* expand_string;
    uint8* binary; /* */
    uint32 dword;
    uint32 dword_be;
    uint8* link;
    uint8** multiple_string;
    uint64 qword;

    /* The following are treated as binary currently, but this may change in
     * the future as the formats become better understood.
     */
    uint8* resource_list;
    uint8* full_resource_descriptor;
    uint8* resource_requirements_list;
  } interpreted;
} REGFI_DATA;


/* Value record */
typedef struct 
{
  uint32 offset;	/* Real offset of this record's cell in the file */
  uint32 cell_size;	/* ((start_offset - end_offset) & 0xfffffff8) */

  REGFI_DATA* data;     /* XXX: deprecated */

  char*  valuename;
  uint8* valuename_raw;
  uint16 name_length;
  uint32 hbin_off;	/* offset from beginning of this hbin block */
  
  uint32 data_size;     /* As reported in the VK record.  May be different than
			 * That obtained while parsing the data cell itself. */
  uint32 data_off;      /* Offset of data cell (virtual) */
  uint32 type;
  uint8  magic[REGFI_CELL_MAGIC_SIZE];
  uint16 flags;
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
  uint16 flags;
  uint8  magic[REGFI_CELL_MAGIC_SIZE];
  NTTIME mtime;
  uint16 name_length;
  uint16 classname_length;
  char* keyname;
  uint8* keyname_raw;
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

 /* These sequence numbers should match if
  * the hive was properly synced to disk.
  */
  uint32 sequence1;            
  uint32 sequence2;

  NTTIME mtime;
  uint32 major_version;  /* Set to 1 in all known hives */
  uint32 minor_version;  /* Set to 3 or 5 in all known hives */
  uint32 type;           /* XXX: Unverified.  Set to 0 in all known hives */
  uint32 format;         /* XXX: Unverified.  Set to 1 in all known hives */

  uint32 root_cell;  /* Offset to root cell in the first (or any?) hbin block */
  uint32 last_block; /* Offset to last hbin block in file */

  uint32 cluster;    /* XXX: Unverified. Set to 1 in all known hives */

  /* Matches hive's base file name. Stored in UTF-16LE */
  uint8 file_name[REGFI_REGF_NAME_SIZE];

  WINSEC_UUID* rm_id;       /* XXX: Unverified. */
  WINSEC_UUID* log_id;      /* XXX: Unverified. */
  WINSEC_UUID* tm_id;       /* XXX: Unverified. */
  uint32 flags;             /* XXX: Unverified. */
  uint32 guid_signature;    /* XXX: Unverified. */

  uint32 checksum;          /* Stored checksum from file */
  uint32 computed_checksum; /* Our own calculation of the checksum. 
			     * (XOR of bytes 0x0000 - 0x01FB) */

  WINSEC_UUID* thaw_tm_id;  /* XXX: Unverified. */
  WINSEC_UUID* thaw_rm_id;  /* XXX: Unverified. */
  WINSEC_UUID* thaw_log_id; /* XXX: Unverified. */
  uint32 boot_type;         /* XXX: Unverified. */
  uint32 boot_recover;      /* XXX: Unverified. */

  /* This seems to include random junk.  Possibly unsanitized memory left over
   * from when header block was written.  For instance, chunks of nk records 
   * can be found, though often it's all 0s. */
  uint8 reserved1[REGFI_REGF_RESERVED1_SIZE];

  /* This is likely reserved and unusued currently.  (Should be all 0s.)
   * Included here for easier access in looking for hidden data 
   * or doing research. */
  uint8 reserved2[REGFI_REGF_RESERVED2_SIZE];

} REGFI_FILE;


typedef struct _regfi_iterator
{
  REGFI_FILE* f;
  void_stack* key_positions;
  REGFI_NK_REC* cur_key;
  REGFI_ENCODING string_encoding;
  uint32 cur_subkey;
  uint32 cur_value;
} REGFI_ITERATOR;


typedef struct _regfi_iter_position
{
  REGFI_NK_REC* nk;
  uint32 cur_subkey;
  /* We could store a cur_value here as well, but didn't see 
   * the use in it right now.
   */
} REGFI_ITER_POSITION;


typedef struct _regfi_buffer
{
  uint8* buf;
  uint32_t len;
} REGFI_BUFFER;




/******************************************************************************/
/*                         Main iterator API                                  */
/******************************************************************************/

/* regfi_open: Attempts to open a registry hive and allocate related data
 *             structures.
 *
 * Arguments:
 *   filename -- A string containing the relative or absolute path of the
 *               registry hive to be opened.
 *
 * Returns:
 *   A reference to a newly allocated REGFI_FILE structure, if successful. 
 *   NULL on error.
 */
REGFI_FILE*           regfi_open(const char* filename);


/* regfi_alloc: Parses file headers of an already open registry hive file and 
 *              allocates related structures for further parsing.
 *
 * Arguments:
 *   fd       -- A file descriptor of an already open file.  Must be seekable.
 *
 * Returns:
 *   A reference to a newly allocated REGFI_FILE structure, if successful. 
 *   NULL on error.
 */
REGFI_FILE*           regfi_alloc(int fd);


/* regfi_close: Closes and frees an open registry hive.
 *
 * Arguments:
 *   file     -- The registry structure to close.
 *
 * Returns:
 *   0 on success, -1 on failure with errno set.  
 *   errno codes are similar to those of close(2).
 */
int                   regfi_close(REGFI_FILE* file);


/* regfi_free: Frees a hive's data structures without closing the underlying
 *             file.
 *
 * Arguments:
 *   file     -- The registry structure to free.
 */
void                  regfi_free(REGFI_FILE* file);


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


/* regfi_set_message_mask: Set the verbosity level of errors and warnings
 *                         generated by the library 
 *                         (as accessible via regfi_get_messages).
 *
 * Arguments:
 *   file     -- the structure for the registry file
 *   mask     -- an integer representing the types of messages desired.
 *               Acceptable values are created through bitwise ORs of 
 *               REGFI_MSG_* values.  For instance, if only errors and
 *               informational messages were desired (but not warnings),
 *               then one would specify: REGFI_MSG_ERROR|REGFI_MSG_INFO
 *               New REGFI_FILE structures are created with:
 *                REGFI_MSG_ERROR|REGFI_MSG_WARN
 *               Note that error and warning messages will continue to
 *               accumulate in memory if they are not fetched using
 *               regfi_get_messages and then freed by the caller.
 *               To disable error messages entirely, supply 0, which
 *               will prevent message accumulation.  
 *
 * This may be called at any time and will take effect immediately.
 */
void                  regfi_set_message_mask(REGFI_FILE* file, uint16 mask);


/* regfi_iterator_new: Creates a new iterator for the provided registry file.
 *
 * Arguments:
 *   file            -- The opened registry file the iterator should be
 *                      created for.
 *   output_encoding -- Character encoding that strings should be returned in.
 *                      Only supply the REGFI_ENCODING_* constants, as others 
 *                      will be rejected.
 *                      The following values are currently accepted:
 *                      REGFI_ENCODING_DEFAULT (currently REGFI_ENCODING_ASCII)
 *                      REGFI_ENCODING_ASCII
 *                      REGFI_ENCODING_UTF8
 *
 * Returns:
 *   A newly allocated REGFI_ITERATOR. Must be free()d with regfi_iterator_free.
 */
REGFI_ITERATOR*       regfi_iterator_new(REGFI_FILE* file,
					 REGFI_ENCODING output_encoding);


/* regfi_iterator_free: Frees a registry file iterator previously created by 
 *                      regfi_iterator_new.
 *
 * This does not affect the underlying registry file's allocation status.
 *
 * Arguments:
 *   file            -- the iterator to be freed
 */
void                  regfi_iterator_free(REGFI_ITERATOR* i);


/* regfi_iterator_down: Traverse deeper into the registry tree at the
 *                      current subkey.
 *
 * Arguments:
 *   i            -- the iterator
 *
 * Returns:
 *   true on success, false on failure.  Note that subkey and value indexes
 *   are preserved.  That is, if a regfi_iterator_up call occurs later
 *   (reversing the effect of this call) then the subkey and value referenced
 *   prior to the regfi_iterator_down call will still be referenced.  This 
 *   makes depth-first iteration particularly easy.
 */
bool                  regfi_iterator_down(REGFI_ITERATOR* i);


/* regfi_iterator_up: Traverse up to the current key's parent key.
 *
 * Arguments:
 *   i            -- the iterator
 *
 * Returns:
 *   true on success, false on failure.  Any subkey or value state
 *   associated with the current key is lost.
 */
bool                  regfi_iterator_up(REGFI_ITERATOR* i);


/* regfi_iterator_to_root: Traverse up to the root key of the hive.
 *
 * Arguments:
 *   i            -- the iterator
 *
 * Returns:
 *   true on success, false on failure.
 */
bool                  regfi_iterator_to_root(REGFI_ITERATOR* i);


/* regfi_iterator_walk_path: Traverse down multiple levels in the registry hive.
 *
 * Arguments:
 *   i            -- the iterator
 *   path         -- a list of key names representing the path.  This list must
 *                   contain NUL terminated strings.  The list itself is
 *                   terminated with a NULL pointer.  All path elements must be
 *                   keys; value names are not accepted (even as the last
 *                   element).
 *
 * XXX: This currently only accepts ASCII key names.  Need to look into
 *      accepting other encodings.
 *
 * Returns:
 *   true on success, false on failure.  If any element of path is not found,
 *   false will be returned and the iterator will remain in its original
 *   position.
 */
bool                  regfi_iterator_walk_path(REGFI_ITERATOR* i, 
					       const char** path);


/* regfi_iterator_cur_key: Returns the currently referenced key.
 *
 * Arguments:
 *   i            -- the iterator
 *
 * Returns:
 *   A read-only key structure for the current key, or NULL on failure.
 */
const REGFI_NK_REC*   regfi_iterator_cur_key(REGFI_ITERATOR* i);


/* regfi_iterator_cur_sk: Returns the SK (security) record referenced by the 
 *                        current key.
 *
 * Arguments:
 *   i            -- the iterator
 *
 * Returns:
 *   A read-only SK structure, or NULL on failure.
 */
const REGFI_SK_REC*   regfi_iterator_cur_sk(REGFI_ITERATOR* i);


/* regfi_iterator_first_subkey: Sets the internal subkey index to the first
 *                              subkey referenced by the current key.
 *
 * Arguments:
 *   i            -- the iterator
 *
 * Returns:
 *   A read-only key structure for the newly referenced first subkey, 
 *   or NULL on failure.  Failure may be due to a lack of any subkeys or other
 *   errors.
 */
REGFI_NK_REC*         regfi_iterator_first_subkey(REGFI_ITERATOR* i);


/* regfi_iterator_cur_subkey: Returns the currently indexed subkey.
 *
 * Arguments:
 *   i            -- the iterator
 *
 * Returns:
 *   A newly allocated key structure for the currently referenced subkey,
 *   or NULL on failure.  Newly allocated keys must be freed with 
 *   regfi_free_key.
 */
REGFI_NK_REC*         regfi_iterator_cur_subkey(REGFI_ITERATOR* i);
REGFI_NK_REC*         regfi_iterator_next_subkey(REGFI_ITERATOR* i);
bool                  regfi_iterator_find_subkey(REGFI_ITERATOR* i, 
						 const char* subkey_name);

REGFI_VK_REC*         regfi_iterator_first_value(REGFI_ITERATOR* i);
REGFI_VK_REC*         regfi_iterator_cur_value(REGFI_ITERATOR* i);
REGFI_VK_REC*         regfi_iterator_next_value(REGFI_ITERATOR* i);
bool                  regfi_iterator_find_value(REGFI_ITERATOR* i, 
						const char* value_name);

REGFI_CLASSNAME*      regfi_iterator_fetch_classname(REGFI_ITERATOR* i, 
						     const REGFI_NK_REC* key);
REGFI_DATA*           regfi_iterator_fetch_data(REGFI_ITERATOR* i, 
						const REGFI_VK_REC* value);


/********************************************************/
/* Middle-layer structure loading, linking, and caching */
/********************************************************/
REGFI_NK_REC*         regfi_load_key(REGFI_FILE* file, uint32 offset, 
				     REGFI_ENCODING output_encoding, 
				     bool strict);
REGFI_VK_REC*         regfi_load_value(REGFI_FILE* file, uint32 offset, 
				       REGFI_ENCODING output_encoding, 
				       bool strict);
REGFI_SUBKEY_LIST*    regfi_load_subkeylist(REGFI_FILE* file, uint32 offset,
					    uint32 num_keys, uint32 max_size,
					    bool strict);
REGFI_VALUE_LIST*     regfi_load_valuelist(REGFI_FILE* file, uint32 offset, 
					   uint32 num_values, uint32 max_size,
					   bool strict);

REGFI_BUFFER          regfi_load_data(REGFI_FILE* file, uint32 voffset,
				      uint32 length, bool data_in_offset,
				      bool strict);

REGFI_BUFFER          regfi_load_big_data(REGFI_FILE* file, uint32 offset, 
					  uint32 data_length,uint32 cell_length,
					  range_list* used_ranges,
					  bool strict);
bool                  regfi_interpret_data(REGFI_FILE* file, 
					   REGFI_ENCODING string_encoding,
					   uint32 type, REGFI_DATA* data);
void                  regfi_free_classname(REGFI_CLASSNAME* classname);
void                  regfi_free_data(REGFI_DATA* data);


/* These are cached so return values don't need to be freed. */
const REGFI_SK_REC*   regfi_load_sk(REGFI_FILE* file, uint32 offset,
				    bool strict);
const REGFI_HBIN*     regfi_lookup_hbin(REGFI_FILE* file, uint32 offset);


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

REGFI_SK_REC*         regfi_parse_sk(REGFI_FILE* file, uint32 offset, 
				     uint32 max_size, bool strict);

range_list*           regfi_parse_unalloc_cells(REGFI_FILE* file);

bool                  regfi_parse_cell(int fd, uint32 offset, 
				       uint8* hdr, uint32 hdr_len,
				       uint32* cell_length, bool* unalloc);

uint8*                regfi_parse_classname(REGFI_FILE* file, uint32 offset,
					    uint16* name_length, 
					    uint32 max_size, bool strict);

REGFI_BUFFER          regfi_parse_data(REGFI_FILE* file, uint32 offset,
				       uint32 length, bool strict);

REGFI_BUFFER          regfi_parse_little_data(REGFI_FILE* file, uint32 voffset, 
					      uint32 length, bool strict);


/* Dispose of previously parsed records */
void                  regfi_free_key(REGFI_NK_REC* nk);
void                  regfi_free_value(REGFI_VK_REC* vk);



/************************************/
/*    Private Functions             */
/************************************/
REGFI_NK_REC*         regfi_rootkey(REGFI_FILE* file, 
				    REGFI_ENCODING output_encoding);
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
int32                 regfi_calc_maxsize(REGFI_FILE* file, uint32 offset);
int32                 regfi_conv_charset(const char* input_charset, 
					 const char* output_charset,
					 uint8* input, char* output, 
					 uint32 input_len, uint32 output_max);
REGFI_DATA*           regfi_buffer_to_data(REGFI_BUFFER raw_data);

#endif	/* _REGFI_H */
