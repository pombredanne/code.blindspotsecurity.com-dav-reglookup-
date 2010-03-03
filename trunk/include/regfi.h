/** @file
 * Windows NT (and later) registry parsing library
 *
 * Branched from Samba project Subversion repository, version #6903:
 *   http://viewcvs.samba.org/cgi-bin/viewcvs.cgi/trunk/source/include/regfio.h?rev=6903&view=auto
 *
 * Copyright (C) 2005-2010 Timothy D. Morgan
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

/**
 * @mainpage Home
 *
 * See \ref regfiTopLayer
 */

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

#include "byteorder.h"
#include "talloc.h"
#include "winsec.h"
#include "void_stack.h"
#include "range_list.h"
#include "lru_cache.h"

/******************************************************************************/

/* regfi library error message types */
#define REGFI_MSG_INFO  0x0001
#define REGFI_MSG_WARN  0x0004
#define REGFI_MSG_ERROR 0x0010

typedef uint8_t REGFI_ENCODING;
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

/* This next one shows up in some Vista "software" registries */
/* XXX: This shows up in the following two SOFTWARE keys in Vista:
 *   /Wow6432Node/Microsoft
 *   /Wow6432Node/Microsoft/Cryptography
 *  
 * It comes along with UNKNOWN2 and ASCIINAME for a total flags value of 0x10A0
 */
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
				    | REGFI_NK_FLAG_UNKNOWN2\
                                    | REGFI_NK_FLAG_UNKNOWN3)


#define CHAR_BIT 8
#define TIME_T_MIN ((time_t)0 < (time_t) -1 ? (time_t) 0 \
		    : ~ (time_t) 0 << (sizeof (time_t) * CHAR_BIT - 1))
#define TIME_T_MAX (~ (time_t) 0 - TIME_T_MIN)
#define TIME_FIXUP_CONSTANT (369.0*365.25*24*60*60-(3.0*24*60*60+6.0*60*60))

typedef struct _regfi_nttime
{
  uint32_t low;
  uint32_t high;
} REGFI_NTTIME;


/* HBIN block */
typedef struct _regfi_hbin 
{
  uint32_t file_off;       /* my offset in the registry file */
  uint32_t ref_count;      /* how many active records are pointing to this
                          * block (not used currently) 
			  */
  
  uint32_t first_hbin_off; /* offset from first hbin block */
  uint32_t block_size;     /* block size of this block 
                          * Should be a multiple of 4096 (0x1000)
			  */
  uint32_t next_block;     /* relative offset to next block.  
			  * NOTE: This value may be unreliable!
			  */

  uint8_t magic[REGFI_HBIN_MAGIC_SIZE]; /* "hbin" */
} REGFI_HBIN;


/* Subkey List -- list of key offsets and hashed names for consistency */
typedef struct 
{
  /* Virtual offset of NK record or additional subkey list, 
   * depending on this list's type. 
   */
  uint32_t offset;

  uint32_t hash;
} REGFI_SUBKEY_LIST_ELEM;


typedef struct _regfi_subkey_list
{
  /* Real offset of this record's cell in the file */
  uint32_t offset;

  uint32_t cell_size;
  
  /* Number of immediate children */
  uint32_t num_children;  

  /* Total number of keys referenced by this list and it's children */
  uint32_t num_keys;      

  REGFI_SUBKEY_LIST_ELEM* elements;
  uint8_t magic[REGFI_CELL_MAGIC_SIZE];

  /* Set if the magic indicates this subkey list points to child subkey lists */
  bool recursive_type;  
} REGFI_SUBKEY_LIST;


typedef uint32_t REGFI_VALUE_LIST_ELEM;
typedef struct _regfi_value_list
{
  /* Actual number of values referenced by this list.  
   * May differ from parent key's num_values if there were parsing errors. 
   */
  uint32_t num_values;

  REGFI_VALUE_LIST_ELEM* elements;
} REGFI_VALUE_LIST;


typedef struct _regfi_classname
{
  /* As converted to requested character encoding. */
  char* interpreted;

  /* Represents raw buffer read from classname cell. */
  uint8_t* raw;

  /* Length of the raw data. May be shorter than that indicated by parent key.*/
  uint16_t size;
} REGFI_CLASSNAME;


typedef struct _regfi_data
{
  uint32_t type;

  /* Length of the raw data. */
  uint32_t size;

  /* This is always present, representing the raw data cell contents. */
  uint8_t* raw;

  /* Represents the length of the interpreted value. Meaning is type-specific.*/
  uint32_t interpreted_size;

  /* These items represent interpreted versions of the raw attribute above. 
   * Only use the appropriate member according to the type field.  
   * In the event of an unknown type, use only the raw field.
   */
  union _regfi_data_interpreted
  {
    uint8_t* none; /* */
    uint8_t* string;
    uint8_t* expand_string;
    uint8_t* binary; /* */
    uint32_t dword;
    uint32_t dword_be;
    uint8_t* link;
    uint8_t** multiple_string;
    uint64_t qword;

    /* The following are treated as binary currently, but this may change in
     * the future as the formats become better understood.
     */
    uint8_t* resource_list;
    uint8_t* full_resource_descriptor;
    uint8_t* resource_requirements_list;
  } interpreted;
} REGFI_DATA;


/* Value record */
typedef struct 
{
  uint32_t offset;	/* Real offset of this record's cell in the file */
  uint32_t cell_size;	/* ((start_offset - end_offset) & 0xfffffff8) */

  REGFI_DATA* data;     /* XXX: deprecated */

  char*  valuename;
  uint8_t* valuename_raw;
  uint16_t name_length;
  uint32_t hbin_off;	/* offset from beginning of this hbin block */
  
  uint32_t data_size;     /* As reported in the VK record.  May be different than
			 * That obtained while parsing the data cell itself. */
  uint32_t data_off;      /* Offset of data cell (virtual) */
  uint32_t type;
  uint8_t  magic[REGFI_CELL_MAGIC_SIZE];
  uint16_t flags;
  uint16_t unknown1;
  bool data_in_offset;
} REGFI_VK_REC;


/* Key Security */
struct _regfi_sk_rec;

typedef struct _regfi_sk_rec 
{
  uint32_t offset;        /* Real file offset of this record */
  uint32_t cell_size;	/* ((start_offset - end_offset) & 0xfffffff8) */

  WINSEC_DESC* sec_desc;
  uint32_t hbin_off;	/* offset from beginning of this hbin block */
  
  uint32_t prev_sk_off;
  uint32_t next_sk_off;
  uint32_t ref_count;
  uint32_t desc_size;     /* size of security descriptor */
  uint16_t unknown_tag;
  uint8_t  magic[REGFI_CELL_MAGIC_SIZE];
} REGFI_SK_REC;


/* Key Name */
typedef struct
{
  uint32_t offset;	/* Real offset of this record's cell in the file */
  uint32_t cell_size;	/* Actual or estimated length of the cell.  
			 * Always in multiples of 8. 
			 */

  /* link in the other records here */
  REGFI_VALUE_LIST* values;
  REGFI_SUBKEY_LIST* subkeys;
  
  /* header information */
  uint16_t flags;
  uint8_t  magic[REGFI_CELL_MAGIC_SIZE];
  REGFI_NTTIME mtime;
  uint16_t name_length;
  uint16_t classname_length;
  char* keyname;
  uint8_t* keyname_raw;
  uint32_t parent_off;	            /* pointer to parent key */
  uint32_t classname_off;
  
  /* max lengths */
  uint32_t max_bytes_subkeyname;	    /* max subkey name * 2 */
  uint32_t max_bytes_subkeyclassname; /* max subkey classname length (as if) */
  uint32_t max_bytes_valuename;	    /* max valuename * 2 */
  uint32_t max_bytes_value;           /* max value data size */
  
  /* unknowns */
  uint32_t unknown1;
  uint32_t unknown2;
  uint32_t unknown3;
  uint32_t unk_index;		    /* nigel says run time index ? */
  
  /* children */
  uint32_t num_subkeys;
  uint32_t subkeys_off;	/* offset of subkey list that points to NK records */
  uint32_t num_values;
  uint32_t values_off;	/* value lists which point to VK records */
  uint32_t sk_off;	/* offset to SK record */
} REGFI_NK_REC;



/* REGF block */
typedef struct 
{
  /* Run-time information */
  /************************/
  /* file descriptor */
  int fd;

  /* For sanity checking (not part of the registry header) */
  uint32_t file_length;

  /* Metadata about hbins */
  range_list* hbins;

  /* SK record cached since they're repeatedly reused */
  lru_cache* sk_cache;

  /* Error/warning/info messages returned by lower layer functions */
  char* last_message;

  /* Mask for error message types that will be stored. */
  uint16_t msg_mask;


  /* Data parsed from file header */
  /********************************/
  uint8_t  magic[REGFI_REGF_MAGIC_SIZE];/* "regf" */

 /* These sequence numbers should match if
  * the hive was properly synced to disk.
  */
  uint32_t sequence1;            
  uint32_t sequence2;

  REGFI_NTTIME mtime;
  uint32_t major_version;  /* Set to 1 in all known hives */
  uint32_t minor_version;  /* Set to 3 or 5 in all known hives */
  uint32_t type;           /* XXX: Unverified.  Set to 0 in all known hives */
  uint32_t format;         /* XXX: Unverified.  Set to 1 in all known hives */

  uint32_t root_cell;  /* Offset to root cell in the first (or any?) hbin block */
  uint32_t last_block; /* Offset to last hbin block in file */

  uint32_t cluster;    /* XXX: Unverified. Set to 1 in all known hives */

  /* Matches hive's base file name. Stored in UTF-16LE */
  uint8_t file_name[REGFI_REGF_NAME_SIZE];

  WINSEC_UUID* rm_id;       /* XXX: Unverified. */
  WINSEC_UUID* log_id;      /* XXX: Unverified. */
  WINSEC_UUID* tm_id;       /* XXX: Unverified. */
  uint32_t flags;             /* XXX: Unverified. */
  uint32_t guid_signature;    /* XXX: Unverified. */

  uint32_t checksum;          /* Stored checksum from file */
  uint32_t computed_checksum; /* Our own calculation of the checksum. 
			     * (XOR of bytes 0x0000 - 0x01FB) */

  WINSEC_UUID* thaw_tm_id;  /* XXX: Unverified. */
  WINSEC_UUID* thaw_rm_id;  /* XXX: Unverified. */
  WINSEC_UUID* thaw_log_id; /* XXX: Unverified. */
  uint32_t boot_type;         /* XXX: Unverified. */
  uint32_t boot_recover;      /* XXX: Unverified. */

  /* This seems to include random junk.  Possibly unsanitized memory left over
   * from when header block was written.  For instance, chunks of nk records 
   * can be found, though often it's all 0s. */
  uint8_t reserved1[REGFI_REGF_RESERVED1_SIZE];

  /* This is likely reserved and unusued currently.  (Should be all 0s.)
   * Included here for easier access in looking for hidden data 
   * or doing research. */
  uint8_t reserved2[REGFI_REGF_RESERVED2_SIZE];

} REGFI_FILE;


typedef struct _regfi_iterator
{
  REGFI_FILE* f;
  void_stack* key_positions;
  REGFI_NK_REC* cur_key;
  REGFI_ENCODING string_encoding;
  uint32_t cur_subkey;
  uint32_t cur_value;
} REGFI_ITERATOR;


typedef struct _regfi_iter_position
{
  REGFI_NK_REC* nk;
  uint32_t cur_subkey;
  /* We could store a cur_value here as well, but didn't see 
   * the use in it right now.
   */
} REGFI_ITER_POSITION;


typedef struct _regfi_buffer
{
  uint8_t* buf;
  uint32_t len;
} REGFI_BUFFER;


/******************************************************************************/
/** 
 * @defgroup regfiBase Base Functions: Usable with Any Layer
 *
 * These functions don't fit particularly well in any of the other layers or
 * are intended for use with any of the API layers.
 */
/******************************************************************************/


/** Attempts to open a registry hive and allocate related data structures.
 * 
 * @param filename A string containing the relative or absolute path of the
 *               registry hive to be opened.
 *
 * @return A reference to a newly allocated REGFI_FILE structure, 
 *         if successful;  NULL on error.
 *
 * @ingroup regfiBase
 */
REGFI_FILE*           regfi_open(const char* filename);


/** Parses file headers of an already open registry hive file and 
 *  allocates related structures for further parsing.
 *
 * @param fd A file descriptor of an already open file.  Must be seekable.
 *
 * @return A reference to a newly allocated REGFI_FILE structure, if successful;
 *         NULL on error.
 *
 * @ingroup regfiBase
 */
REGFI_FILE*           regfi_alloc(int fd);


/** Closes and frees an open registry hive.
 *
 * @param file The registry structure to close.
 *
 * @return 0 on success, -1 on failure with errno set.  
 *         errno codes are similar to those of close(2).
 *
 * @ingroup regfiBase
 */
int                   regfi_close(REGFI_FILE* file);


/** Frees a hive's data structures without closing the underlying file.
 *
 * @param file The registry structure to free.
 *
 * @ingroup regfiBase
 */
void                  regfi_free(REGFI_FILE* file);


/** Get errors, warnings, and/or verbose information relating to processing of
 *  the given registry file.
 *
 * @param file the structure for the registry file
 *
 * @return A newly allocated char* which must be free()d by the caller.
 *
 * @ingroup regfiBase
 */
char*                 regfi_get_messages(REGFI_FILE* file);


/** Set the verbosity level of errors and warnings generated by the library
 *  (as accessible via regfi_get_messages).
 *
 * This may be called at any time and will take effect immediately.
 *
 * @param file   the structure for the registry file
 *
 * @param mask   an integer representing the types of messages desired.
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
 * @ingroup regfiBase
 */
void                  regfi_set_message_mask(REGFI_FILE* file, uint16_t mask);


/* Dispose of previously parsed records */

/** Frees a key structure previously returned by one of the API functions
 *
 * XXX: finish documenting
 *
 * @ingroup regfiBase
 */
void                  regfi_free_key(REGFI_NK_REC* nk);


/** Frees a value structure previously returned by one of the API functions
 *
 * XXX: finish documenting
 *
 * @ingroup regfiBase
 */
void                  regfi_free_value(REGFI_VK_REC* vk);



/******************************************************************************/
/** 
 * @defgroup regfiTopLayer Top Layer: Primary regfi Library Interface
 *
 * This top layer of API functions provides an iterator interface which makes
 * traversing registry data structures easy in both single-threaded and 
 * multi-threaded scenarios.
 */
/******************************************************************************/

/** Creates a new iterator for the provided registry file.
 *
 * @param file The opened registry file the iterator should be created for.
 *
 * @param output_encoding Character encoding that strings should be returned in.
 *                        Only supply the REGFI_ENCODING_* constants, as others 
 *                        will be rejected.
 *                        The following values are currently accepted:
 *                        REGFI_ENCODING_DEFAULT (currently REGFI_ENCODING_ASCII)
 *                        REGFI_ENCODING_ASCII
 *                        REGFI_ENCODING_UTF8
 *
 * @return A newly allocated REGFI_ITERATOR. 
 *         Must be free()d with regfi_iterator_free.
 *
 * @ingroup regfiTopLayer
 */
REGFI_ITERATOR*       regfi_iterator_new(REGFI_FILE* file,
					 REGFI_ENCODING output_encoding);


/** Frees a registry file iterator previously created by regfi_iterator_new.
 *
 * This does not affect the underlying registry file's allocation status.
 *
 * @param i the iterator to be freed
 *
 * @ingroup regfiTopLayer
 */
void                  regfi_iterator_free(REGFI_ITERATOR* i);


/** Traverse deeper into the registry tree at the current subkey.
 *
 * @param i the iterator
 *
 * @return  true on success, false on failure.  
 *          Note that subkey and value indexes are preserved.  That is, if a
 *          regfi_iterator_up call occurs later (reversing the effect of this
 *          call) then the subkey and value referenced prior to the
 *          regfi_iterator_down call will still be referenced.  This  makes
 *          depth-first iteration particularly easy.
 *
 * @ingroup regfiTopLayer
 */
bool                  regfi_iterator_down(REGFI_ITERATOR* i);


/** Traverse up to the current key's parent key.
 *
 * @param i the iterator
 *
 * @return  true on success, false on failure.  Any subkey or value state
 *          associated with the current key is lost.
 *
 * @ingroup regfiTopLayer
 */
bool                  regfi_iterator_up(REGFI_ITERATOR* i);


/** Traverse up to the root key of the hive.
 *
 * @param i the iterator
 *
 * @return true on success, false on failure.
 *
 * @ingroup regfiTopLayer
 */
bool                  regfi_iterator_to_root(REGFI_ITERATOR* i);


/** Traverse down multiple levels in the registry hive.
 *
 * XXX: This currently only accepts ASCII key names.  Need to look into
 *      accepting other encodings.
 *
 * @param i    the iterator
 * @param path a list of key names representing the path.  This list must
 *             contain NUL terminated strings.  The list itself is
 *             terminated with a NULL pointer.  All path elements must be
 *             keys; value names are not accepted (even as the last
 *             element).
 *
 * @return true on success, false on failure.  If any element of path is not
 *                 found, false will be returned and the iterator will remain
 *                 in its original position.
 *
 * @ingroup regfiTopLayer
 */
bool regfi_iterator_walk_path(REGFI_ITERATOR* i, const char** path);


/** Returns the currently referenced key.
 *
 * @param i the iterator
 *
 * @return A read-only key structure for the current key, or NULL on failure.
 *
 * @ingroup regfiTopLayer
 */
const REGFI_NK_REC*   regfi_iterator_cur_key(REGFI_ITERATOR* i);


/** Returns the SK (security) record referenced by the current key.
 *
 * @param i the iterator
 *
 * @return A read-only SK structure, or NULL on failure.
 *
 * @ingroup regfiTopLayer
 */
const REGFI_SK_REC*   regfi_iterator_cur_sk(REGFI_ITERATOR* i);


/** Sets the internal subkey index to the first subkey referenced by the current
 *  key and returns that key.
 *
 * @param i the iterator
 *
 * @return A newly allocated key structure for the newly referenced first 
 *         subkey, or NULL on failure.  Failure may be due to a lack of any
 *         subkeys or other errors.  Newly allocated keys must be freed with
 *         regfi_free_key.
 *
 * @ingroup regfiTopLayer
 */
REGFI_NK_REC*         regfi_iterator_first_subkey(REGFI_ITERATOR* i);


/** Returns the currently indexed subkey.
 *
 * @param i the iterator
 *
 * @return A newly allocated key structure for the currently referenced subkey,
 *         or NULL on failure.  Newly allocated keys must be freed with 
 *         regfi_free_key.
 *
 * @ingroup regfiTopLayer
 */
REGFI_NK_REC*         regfi_iterator_cur_subkey(REGFI_ITERATOR* i);


/** Increments the internal subkey index to the next key in the subkey-list and
 *  returns the subkey for that index.
 *
 * @param i the iterator
 *
 * @return A newly allocated key structure for the next subkey or NULL on
 *         failure.  Newly allocated keys must be freed with regfi_free_key.
 *
 * @ingroup regfiTopLayer
 */
REGFI_NK_REC*         regfi_iterator_next_subkey(REGFI_ITERATOR* i);


/** Searches for a subkey with a given name under the current key.
 *
 * @param i           the iterator
 * @param subkey_name subkey name to search for
 *
 * @return True if such a subkey was found, false otherwise.  If a subkey is
 *         found, the current subkey index is set to that subkey.  Otherwise,
 *         the subkey index remains at the same location as before the call.
 *
 * @ingroup regfiTopLayer
 */
bool                  regfi_iterator_find_subkey(REGFI_ITERATOR* i, 
						 const char* subkey_name);

/** Sets the internal value index to the first value referenced by the current
 *  key and returns that value.
 *
 * @param i the iterator
 *
 * @return  A newly allocated value structure for the newly referenced first
 *          value, or NULL on failure.  Failure may be due to a lack of any
 *          values or other errors.  Newly allocated keys must be freed with
 *          regfi_free_value.
 *
 * @ingroup regfiTopLayer
 */
REGFI_VK_REC*         regfi_iterator_first_value(REGFI_ITERATOR* i);


/** Returns the currently indexed value.
 *
 * @param i the iterator
 *
 * @return A newly allocated value structure for the currently referenced value,
 *         or NULL on failure.  Newly allocated values must be freed with 
 *         regfi_free_value.
 *
 * @ingroup regfiTopLayer
 */
REGFI_VK_REC*         regfi_iterator_cur_value(REGFI_ITERATOR* i);


/** Increments the internal value index to the next value in the value-list and
 *  returns the value for that index.
 *
 * @param i the iterator
 *
 * @return  A newly allocated key structure for the next value or NULL on 
 *          failure.  Newly allocated keys must be freed with regfi_free_value.
 *
 * @ingroup regfiTopLayer
 */
REGFI_VK_REC*         regfi_iterator_next_value(REGFI_ITERATOR* i);


/** Searches for a value with a given name under the current key.
 *
 * @param i          the iterator
 * @param value_name value name to search for
 *
 * @return True if such a value was found, false otherwise.  If a value is 
 *         found, the current value index is set to that value.  Otherwise,
 *         the value index remains at the same location as before the call.
 *
 * @ingroup regfiTopLayer
 */
bool                  regfi_iterator_find_value(REGFI_ITERATOR* i, 
						const char* value_name);

/** Retrieves classname for a given key.
 *
 * @param i   the iterator
 * @param key the key whose classname is desired
 *
 * @return Returns a newly allocated classname structure, or NULL on failure.
 *         Classname structures must be freed with regfi_free_classname.
 *
 * @ingroup regfiTopLayer
 */
REGFI_CLASSNAME*      regfi_iterator_fetch_classname(REGFI_ITERATOR* i, 
						     const REGFI_NK_REC* key);


/** Retrieves data for a given value.
 *
 * @param i     the iterator
 * @param value the value whose data is desired
 *
 * @return Returns a newly allocated data structure, or NULL on failure.
 *         Data structures must be freed with regfi_free_data.
 *
 * @ingroup regfiTopLayer
 */
REGFI_DATA*           regfi_iterator_fetch_data(REGFI_ITERATOR* i, 
						const REGFI_VK_REC* value);



/******************************************************************************/
/** 
 * @defgroup regfiMiddleLayer Middle Layer: Logical Data Structure Loading 
 */
/******************************************************************************/

/** Loads a key at a given file offset along with associated data structures.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiMiddleLayer
 */
REGFI_NK_REC*         regfi_load_key(REGFI_FILE* file, uint32_t offset, 
				     REGFI_ENCODING output_encoding, 
				     bool strict);


/** Loads a value at a given file offset alng with associated data structures.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiMiddleLayer
 */
REGFI_VK_REC*         regfi_load_value(REGFI_FILE* file, uint32_t offset, 
				       REGFI_ENCODING output_encoding, 
				       bool strict);


/** Loads a logical subkey list in its entirety which may span multiple records.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiMiddleLayer
 */
REGFI_SUBKEY_LIST*    regfi_load_subkeylist(REGFI_FILE* file, uint32_t offset,
					    uint32_t num_keys, uint32_t max_size,
					    bool strict);


/** Loads a valuelist.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiMiddleLayer
 */
REGFI_VALUE_LIST*     regfi_load_valuelist(REGFI_FILE* file, uint32_t offset, 
					   uint32_t num_values, uint32_t max_size,
					   bool strict);


/** Loads a data record which may be contained in the virtual offset, in a
 *  single cell, or in multiple cells through big data records.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiMiddleLayer
 */
REGFI_BUFFER          regfi_load_data(REGFI_FILE* file, uint32_t voffset,
				      uint32_t length, bool data_in_offset,
				      bool strict);


/** Loads the data associated with a big data record at the specified offset.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiMiddleLayer
 */
REGFI_BUFFER          regfi_load_big_data(REGFI_FILE* file, uint32_t offset, 
					  uint32_t data_length,uint32_t cell_length,
					  range_list* used_ranges,
					  bool strict);


/** Given raw data, attempts to interpret the data based on a specified registry
 *  data type.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiMiddleLayer
 */
bool                  regfi_interpret_data(REGFI_FILE* file, 
					   REGFI_ENCODING string_encoding,
					   uint32_t type, REGFI_DATA* data);


/** Frees the memory associated with a REGFI_CLASSNAME data structure.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiMiddleLayer
 */
void                  regfi_free_classname(REGFI_CLASSNAME* classname);


/** Frees the memory associated with a REGFI_DATA data structure.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiMiddleLayer
 */
void                  regfi_free_data(REGFI_DATA* data);


/* These are cached so return values don't need to be freed. */

/** Loads an "sk" security record at the specified offset.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiMiddleLayer
 */
const REGFI_SK_REC*   regfi_load_sk(REGFI_FILE* file, uint32_t offset,
				    bool strict);


/** Retrieves the HBIN data structure stored at the specified offset.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiMiddleLayer
 */
const REGFI_HBIN*     regfi_lookup_hbin(REGFI_FILE* file, uint32_t offset);



/******************************************************************************/
/**
 * @defgroup regfiBottomLayer Bottom Layer: Direct Data Structure Access 
 */
/******************************************************************************/

REGFI_FILE*           regfi_parse_regf(int fd, bool strict);
REGFI_HBIN*           regfi_parse_hbin(REGFI_FILE* file, uint32_t offset, 
				       bool strict);


/** Parses an NK record at the specified offset
 *
 * @param file     the registry file structure
 * @param offset   the offset of the cell (not the record) to be parsed.
 * @param max_size the maximum size the NK cell could be. (for validation)
 * @param strict   if true, rejects any malformed records.  Otherwise,
 *                 tries to minimally validate integrity.
 *
 * @return A newly allocated NK record structure, or NULL on failure.
 *
 * @ingroup regfiBottomLayer
 */
REGFI_NK_REC*         regfi_parse_nk(REGFI_FILE* file, uint32_t offset,
				     uint32_t max_size, bool strict);


/** Parses a single cell containing a subkey-list record.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiBottomLayer
 */
REGFI_SUBKEY_LIST*    regfi_parse_subkeylist(REGFI_FILE* file, uint32_t offset,
					     uint32_t max_size, bool strict);


/** Parses a VK (value) record at the specified offset
 *
 * XXX: finish documenting
 *
 * @ingroup regfiBottomLayer
 */
REGFI_VK_REC*         regfi_parse_vk(REGFI_FILE* file, uint32_t offset, 
				     uint32_t max_size, bool strict);


/** Parses an SK (security) record at the specified offset
 *
 * XXX: finish documenting
 *
 * @ingroup regfiBottomLayer
 */
REGFI_SK_REC*         regfi_parse_sk(REGFI_FILE* file, uint32_t offset, 
				     uint32_t max_size, bool strict);


/** Retrieves information on all cells in the registry hive which are 
 *  currently in the unallocated status.  
 *
 * The unallocated status is determined based soley on the cell length sign.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiBottomLayer
 */
range_list*           regfi_parse_unalloc_cells(REGFI_FILE* file);


/** Helper function to parse a cell
 *
 * XXX: finish documenting
 *
 * @ingroup regfiBottomLayer
 */
bool                  regfi_parse_cell(int fd, uint32_t offset, 
				       uint8_t* hdr, uint32_t hdr_len,
				       uint32_t* cell_length, bool* unalloc);


/** Parses a classname cell
 *
 * XXX: finish documenting
 *
 * @ingroup regfiBottomLayer
 */
uint8_t*                regfi_parse_classname(REGFI_FILE* file, uint32_t offset,
					    uint16_t* name_length, 
					    uint32_t max_size, bool strict);


/** Parses a single-cell data record
 *
 * XXX: finish documenting
 *
 * @ingroup regfiBottomLayer
 */
REGFI_BUFFER          regfi_parse_data(REGFI_FILE* file, uint32_t offset,
				       uint32_t length, bool strict);


/** Parses a "little data" record which is stored entirely within the 
 *  provided virtual offset.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiBottomLayer
 */
REGFI_BUFFER          regfi_parse_little_data(REGFI_FILE* file, uint32_t voffset, 
					      uint32_t length, bool strict);


/******************************************************************************/
/*    Private Functions                                                       */
/******************************************************************************/
REGFI_NK_REC*         regfi_rootkey(REGFI_FILE* file, 
				    REGFI_ENCODING output_encoding);
void                  regfi_subkeylist_free(REGFI_SUBKEY_LIST* list);
uint32_t                regfi_read(int fd, uint8_t* buf, uint32_t* length);

const char*           regfi_type_val2str(unsigned int val);
int                   regfi_type_str2val(const char* str);

char*                 regfi_get_sacl(WINSEC_DESC* sec_desc);
char*                 regfi_get_dacl(WINSEC_DESC* sec_desc);
char*                 regfi_get_owner(WINSEC_DESC* sec_desc);
char*                 regfi_get_group(WINSEC_DESC* sec_desc);

REGFI_SUBKEY_LIST*    regfi_merge_subkeylists(uint16_t num_lists, 
					      REGFI_SUBKEY_LIST** lists,
					      bool strict);
REGFI_SUBKEY_LIST*    regfi_load_subkeylist_aux(REGFI_FILE* file, uint32_t offset,
						uint32_t max_size, bool strict,
						uint8_t depth_left);
void                  regfi_add_message(REGFI_FILE* file, uint16_t msg_type, 
					const char* fmt, ...);
REGFI_NK_REC*         regfi_copy_nk(const REGFI_NK_REC* nk);
REGFI_VK_REC*         regfi_copy_vk(const REGFI_VK_REC* vk);
int32_t               regfi_calc_maxsize(REGFI_FILE* file, uint32_t offset);
int32_t               regfi_conv_charset(const char* input_charset, 
					 const char* output_charset,
					 uint8_t* input, char* output, 
					 uint32_t input_len, uint32_t output_max);
REGFI_DATA*           regfi_buffer_to_data(REGFI_BUFFER raw_data);

/* XXX: move to base API and document */
void                  regfi_unix2nt_time(REGFI_NTTIME* nt, time_t t);
time_t                regfi_nt2unix_time(const REGFI_NTTIME* nt);


#endif	/* _REGFI_H */
