/*
 * Copyright (C) 2005-2011 Timothy D. Morgan
 * Copyright (C) 2010 Michael Cohen
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

/**
 * @file
 * Windows NT (and later) read-only registry library
 *
 * This library is intended for use in digital forensics investigations, but 
 * is likely useful in other applications.
 *
 * Branched from Samba project Subversion repository, version #6903:
 *   http://viewcvs.samba.org/cgi-bin/viewcvs.cgi/trunk/source/include/regfio.h?rev=6903&view=auto
 *
 * Since then, it has been heavily rewritten, simplified, and improved.
 */

/**
 * @mainpage Home
 *
 * The regfi library is a read-only NT registry library which serves as the main
 * engine behind the reglookup tool.  It is designed with digital forensic 
 * analysis in mind, but it should also be useful in other tools which need to 
 * efficiently traverse and query registry data structures.
 *
 * The library is broken down into four main parts, the 
 * @ref regfiBase "Base Layer", which any code dependent on the library will 
 * likely need to rely on, as well as three main functional layers: 
 * @li @ref regfiIteratorLayer
 * @li @ref regfiGlueLayer
 * @li @ref regfiParseLayer
 *
 * Most users will find that a combination of the Base Layer and the Iterator Layer 
 * will be sufficient for accessing registry hive files.  Those who are willing
 * to dive deep into registry data structures, for instance to recover deleted
 * data structures or to research Windows registry behavior in detail, will 
 * find the Parse Layer to be quite useful.
 */


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
#include <iconv.h>
#include <pthread.h>
#include <talloc.h>

/* regfi headers */
#include "compat.h"
#include "byteorder.h"
#include "winsec.h"
#include "void_stack.h"
#include "range_list.h"
#include "lru_cache.h"

/******************************************************************************/
/* Constants for use while interacting with the library                       */
/******************************************************************************/

/* regfi library error message types */
#define REGFI_LOG_INFO  0x0001
#define REGFI_LOG_WARN  0x0004
#define REGFI_LOG_ERROR 0x0010
#define REGFI_DEFAULT_LOG_MASK REGFI_LOG_ERROR|REGFI_LOG_WARN

/* regfi library supported character encodings */
/* UTF16LE is not supported for output */
typedef enum {
  REGFI_ENCODING_DEFAULT  = 0,
  REGFI_ENCODING_ASCII =   0,
  REGFI_ENCODING_UTF8  =  1,
  REGFI_ENCODING_UTF16LE = 2,
  REGFI_NUM_ENCODINGS  =  3
} REGFI_ENCODING;

/* Registry data types */
typedef enum {
  REG_NONE                   =    0,
  REG_SZ		     =    1,
  REG_EXPAND_SZ              =    2,
  REG_BINARY 	             =    3,
  REG_DWORD	             =    4,
  REG_DWORD_LE	             =    4 , /* DWORD, little endian */
  REG_DWORD_BE	             =    5 , /* DWORD, big endian */
  REG_LINK                   =    6,
  REG_MULTI_SZ  	     =    7,
  REG_RESOURCE_LIST          =    8,
  REG_FULL_RESOURCE_DESCRIPTOR=   9,
  REG_RESOURCE_REQUIREMENTS_LIST= 10,
  REG_QWORD                     = 11, /* 64-bit little endian */
/* XXX: Has MS defined a REG_QWORD_BE? */
/* Not a real type in the registry */
  REG_KEY                 =   0x7FFFFFFF
} REGFI_DATA_TYPE;
#define REGFI_OFFSET_NONE          0xffffffff



/******************************************************************************/
/* Various resource limits and related constants                              */
/******************************************************************************/

/* Flags determining how many records to cache internally */
#define REGFI_CACHE_SK_MAX         64
#define REGFI_CACHE_NK_MAX         1024

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


/******************************************************************************/
/* Symbols for internal use                                                   */
/******************************************************************************/

/* Global thread-local storage key */
pthread_key_t regfi_log_key;

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
#define REGFI_MTIME_MIN            0x01B41E6D00000000L

 /* Maximum time is Jan 1, 2290 00:00:00
  * (We hope no one is using Windows by then...) 
  */
#define REGFI_MTIME_MAX            0x0304754300000000L


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


#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

#define TIME_T_MIN ((time_t)0 < (time_t) -1 ? (time_t) 0 \
		    : ~ (time_t) 0 << (sizeof (time_t) * CHAR_BIT - 1))
#define TIME_T_MAX (~ (time_t) 0 - TIME_T_MIN)
#define REGFI_TIME_FIXUP (369.0*365.25*24*60*60-(3.0*24*60*60+6.0*60*60))



/******************************************************************************/
/* Structures                                                                 */
/******************************************************************************/

typedef uint64_t REGFI_NTTIME;

typedef struct _regfi_log
{
  /* Error/warning/info messages returned by lower layer functions */
  char* messages;

  /* Mask for error message types that will be stored. */
  uint16_t msg_mask;

} REGFI_LOG;


/** HBIN block information
 * @ingroup regfiMiddleLayer
 */
typedef struct _regfi_hbin 
{
  /** Offset of this HBIN in the registry file */
  uint32_t file_off;

  /** Number of active records pointing to this block (not used currently) */
  uint32_t ref_count;

  /** Offset from first hbin block */
  uint32_t first_hbin_off;

  /** Block size of this block Should be a multiple of 4096 (0x1000) */
  uint32_t block_size;

  /** Relative offset to next block.  
   * 
   * @note This value may be unreliable!
   */
  uint32_t next_block;

  /** Magic number for the HBIN (should be "hbin"). */
  uint8_t magic[REGFI_HBIN_MAGIC_SIZE];
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


/** Subkey-list structure
 * @ingroup regfiMiddleLayer
 */
typedef struct _regfi_subkey_list
{
  /* Real offset of this record's cell in the file */
  uint32_t offset;

  uint32_t cell_size;
  
  /* Number of immediate children */
  uint32_t num_children;

  /* Total number of keys referenced by this list and its children */
  uint32_t num_keys;

  REGFI_SUBKEY_LIST_ELEM* elements;
  uint8_t magic[REGFI_CELL_MAGIC_SIZE];

  /* Set if the magic indicates this subkey list points to child subkey lists */
  bool recursive_type;
} REGFI_SUBKEY_LIST;


typedef uint32_t REGFI_VALUE_LIST_ELEM;
/** Value-list structure
 * @ingroup regfiMiddleLayer
 */
typedef struct _regfi_value_list
{
  /* Real offset of this record's cell in the file */
  uint32_t offset;

  uint32_t cell_size;

  /* Actual number of values referenced by this list.  
   * May differ from parent key's num_values if there were parsing errors. 
   */
  uint32_t num_values;

  REGFI_VALUE_LIST_ELEM* elements;
} REGFI_VALUE_LIST;


/** Class name structure (used in storing SysKeys)
 * @ingroup regfiBase
 */
typedef struct _regfi_classname
{
  /** Real offset of this record's cell in the file */
  uint32_t offset;

  /** As converted to requested REGFI_ENCODING */
  char* interpreted;

  /** Represents raw buffer read from classname cell.
   *
   * Length of this item is specified in the size field.
   */
  uint8_t* raw;

  /** Length of the raw data.
   *
   * May be shorter than that indicated by parent key.
   */
  uint16_t size;
} REGFI_CLASSNAME;


/** Data record structure
 * @ingroup regfiBase
 */
typedef struct _regfi_data
{
  /* XXX: this isn't populated yet. Should set it to start of data cell
   *      or big data cell. 
   */
  uint32_t offset;

  /** Data type of this data, as indicated by the referencing VK record. */
  REGFI_DATA_TYPE type;

  /** Length of the raw data. */
  uint32_t size;

  /** This is always present, representing the raw data cell contents. */
  uint8_t* raw;

  /** Represents the length of the interpreted value. Meaning is type-specific. 
   *  Will be 0 if interpretation failed for any reason.
   */
  uint32_t interpreted_size;

  /** These items represent interpreted versions of the REGFI_DATA::raw field.
   *
   * Only use the appropriate member according to the REGFI_DATA::type field.
   * In the event of an unknown type, use only the REGFI_DATA::raw field.
   */
  union _regfi_data_interpreted
  {
    /** REG_NONE 
     *
     * Stored as a raw buffer.  Use REGFI_DATA::interpreted_size to determine
     * length.
     */
    uint8_t* none; 

    /** REG_SZ 
     *
     * Stored as a NUL terminated string.  Converted to the specified
     * REGFI_ENCODING.
     */
    uint8_t* string;

    /** REG_EXPAND_SZ 
     *
     * Stored as a NUL terminated string.  Converted to the specified
     * REGFI_ENCODING.
     */
    uint8_t* expand_string;

    /** REG_BINARY
     *
     * Stored as a raw buffer.  Use REGFI_DATA::interpreted_size to determine
     * length.
     */
    uint8_t* binary;

    /** REG_DWORD */
    uint32_t dword;

    /** REG_DWORD_BE */
    uint32_t dword_be;

    /** REG_LINK
     *
     * Stored as a NUL terminated string.  Converted to the specified
     * REGFI_ENCODING.
     */
    uint8_t* link;

    /** REG_MULTI_SZ 
     *
     * Stored as a list of uint8_t* pointers, terminated with a NULL pointer.
     * Each string element in the list is NUL terminated, and the character set
     * is determined by the specified REGFI_ENCODING.
     */
    uint8_t** multiple_string;

    /** REG_QWORD */
    uint64_t qword;

    /* The following are treated as binary currently, but this may change in
     * the future as the formats become better understood.
     */

    /** REG_RESOURCE_LIST
     *
     * Stored as a raw buffer.  Use REGFI_DATA::interpreted_size to determine
     * length.
     */
    uint8_t* resource_list;

    /** REG_FULL_RESOURCE_DESCRIPTOR
     *
     * Stored as a raw buffer.  Use REGFI_DATA::interpreted_size to determine
     * length.
     */
    uint8_t* full_resource_descriptor;

    /** REG_RESOURCE_REQUIREMENTS_LIST
     *
     * Stored as a raw buffer.  Use REGFI_DATA::interpreted_size to determine
     * length.
     */
    uint8_t* resource_requirements_list;
  } interpreted;
} REGFI_DATA;


/** Value structure
 * @ingroup regfiBase
 */
typedef struct _regfi_vk
{
  /** Real offset of this record's cell in the file */
  uint32_t offset;	

  /** ((start_offset - end_offset) & 0xfffffff8) */
  uint32_t cell_size;

  /** The name of this value converted to desired REGFI_ENCODING.  
   *
   * This conversion typically occurs automatically through REGFI_ITERATOR
   * settings.  String is NUL terminated.
   */
  char* name;

  /** The raw value name
   *
   * Length of the buffer is stored in name_length.
   */
  uint8_t* name_raw;

  /** Length of name_raw */
  uint16_t name_length;

  /** Offset from beginning of this hbin block */
  uint32_t hbin_off;
  
  /** Size of the value's data as reported in the VK record.
   *
   * May be different than that obtained while parsing the data cell itself.
   */
  uint32_t data_size;

  /** Virtual offset of data cell */
  uint32_t data_off;

  /** Value's data type */
  REGFI_DATA_TYPE type;

  /** VK record's magic number (should be "vk") */
  uint8_t  magic[REGFI_CELL_MAGIC_SIZE];

  /** VK record flags */
  uint16_t flags;

  /* XXX: A 2-byte field of unknown purpose stored in the VK record */
  uint16_t unknown1;

  /** Whether or not the data record is stored in the VK record's data_off field. 
   *
   * This information is derived from the high bit of the raw data size field.
   */
  bool     data_in_offset;

  /* XXX: deprecated */
  REGFI_DATA* data;

} REGFI_VK;


/* Key Security */
struct _regfi_sk;

/** Security structure
 * @ingroup regfiBase
 */
typedef struct _regfi_sk 
{
  /** Real file offset of this record */
  uint32_t offset;

  /** ((start_offset - end_offset) & 0xfffffff8) */
  uint32_t cell_size;

  /** The stored Windows security descriptor for this SK record */
  WINSEC_DESC* sec_desc;

  /** Offset of this record from beginning of this hbin block */
  uint32_t hbin_off;
  
  /** Offset of the previous SK record in the linked list of SK records */
  uint32_t prev_sk_off;

  /** Offset of the next SK record in the linked list of SK records */
  uint32_t next_sk_off;

  /** Number of keys referencing this SK record */
  uint32_t ref_count;

  /** Size of security descriptor (sec_desc) */
  uint32_t desc_size;

  /* XXX: A 2-byte field of unknown purpose */
  uint16_t unknown_tag;

  /** The magic number for this record (should be "sk") */
  uint8_t  magic[REGFI_CELL_MAGIC_SIZE];
} REGFI_SK;


/** Key structure
 * @ingroup regfiBase
 */
typedef struct _regfi_nk
{
  /** Real offset of this record's cell in the file */
  uint32_t offset;

  /** Actual or estimated length of the cell.  
   * Always in multiples of 8. 
   */
  uint32_t cell_size;

  /** Preloaded value-list for this key.
   * This element is loaded automatically when using the iterator interface and
   * possibly some lower layer interfaces.
   */
  REGFI_VALUE_LIST* values;


  /** Preloaded subkey-list for this key.
   * This element is loaded automatically when using the iterator interface and
   * possibly some lower layer interfaces.
   */
  REGFI_SUBKEY_LIST* subkeys;
  
  /** Key flags */
  uint16_t flags;

  /** Magic number of key (should be "nk") */
  uint8_t  magic[REGFI_CELL_MAGIC_SIZE];

  /** Key's last modification time */
  REGFI_NTTIME mtime;

  /** Length of name_raw */
  uint16_t name_length;

  /** Length of referenced classname */
  uint16_t classname_length;

  /** The name of this key converted to desired REGFI_ENCODING.  
   *
   * This conversion typically occurs automatically through REGFI_ITERATOR
   * settings.  String is NUL terminated.
   */
  char* name;

  /** The raw key name
   *
   * Length of the buffer is stored in name_length.
   */
  uint8_t* name_raw;

  /** Virtual offset of parent key */
  uint32_t parent_off;

  /** Virtual offset of classname key */
  uint32_t classname_off;
  
  /* XXX: max subkey name * 2 */
  uint32_t max_bytes_subkeyname;

  /* XXX: max subkey classname length (as if) */
  uint32_t max_bytes_subkeyclassname;

  /* XXX: max value name * 2 */
  uint32_t max_bytes_valuename;

  /* XXX: max value data size */
  uint32_t max_bytes_value;
  
  /* XXX: Fields of unknown purpose */
  uint32_t unknown1;
  uint32_t unknown2;
  uint32_t unknown3;
  uint32_t unk_index;		    /* nigel says run time index ? */
  
  /** Number of subkeys */
  uint32_t num_subkeys;

  /** Virtual offset of subkey-list */
  uint32_t subkeys_off;

  /** Number of values for this key */
  uint32_t num_values;

  /** Virtual offset of value-list */
  uint32_t values_off;

  /** Virtual offset of SK record */
  uint32_t sk_off;
} REGFI_NK;


typedef struct _regfi_raw_file
{
  int64_t  (* seek)(); /* (REGFI_RAW_FILE* self, uint64_t offset, int whence) */
  ssize_t  (* read)(); /* (REGFI_RAW_FILE* self, void* buf, size_t count) */

  uint64_t cur_off;
  uint64_t size;
  void*    state;
} REGFI_RAW_FILE;


/** Registry hive file data structure
 *
 * This essential structure stores run-time information about a single open
 * registry hive as well as file header (REGF block) data.  This structure 
 * also stores a list of warnings and error messages generated while parsing
 * the registry hive.  These can be tuned using @ref regfi_log_set_mask.  
 * Messages may be retrieved using @ref regfi_log_get_str.
 *
 * @note If the message mask is set to record any messages, dependent code 
 *       must use @ref regfi_log_get_str periodically to clear the message
 *       queue. Otherwise, this structure will grow in size over time as 
 *       messages queue up.
 *
 * @ingroup regfiBase
 */ 
typedef struct _regfi_file
{
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


  /* Run-time information */
  /************************/
  /* For sanity checking (not part of the registry header) */
  uint32_t file_length;

  /** The encoding that all strings are converted to during interpretation.
   */
  REGFI_ENCODING string_encoding;

  /* Functions for accessing the file */
  REGFI_RAW_FILE* cb;

  /* Mutex for all cb access.  This is done to prevent one thread from moving
   * the file offset while another thread is in the middle of a multi-read
   * parsing transaction */
  pthread_mutex_t cb_lock;

  /* Metadata about hbins */
  range_list* hbins;

  /* Multiple read access allowed, write access is exclusive */
  pthread_rwlock_t hbins_lock;

  /* Small number of SK records cached */
  lru_cache* sk_cache;

  /* Need exclusive access for LRUs, since lookups make changes */
  pthread_mutex_t sk_lock;

  /* Limited number of keys cached */
  lru_cache* nk_cache;

  /* Need exclusive access for LRUs, since lookups make changes */
  pthread_mutex_t nk_lock;

  /* Needed to protect various talloc calls */
  pthread_mutex_t mem_lock;

} REGFI_FILE;


typedef struct _regfi_iter_position
{
  /* key offset */
  uint32_t offset;

  /* Index of the current subkey */
  uint32_t cur_subkey;

  /* Index of the current value */
  uint32_t cur_value;

  /* The number of subkeys of this key */
  uint32_t num_subkeys;

  /* The number of values of this key */
  uint32_t num_values;

} REGFI_ITER_POSITION;


/** Registry hive iterator
 * @ingroup regfiIteratorLayer
 */
typedef struct _regfi_iterator
{
  /** The registry hive this iterator is associated with */
  REGFI_FILE* f;

  /** All current parent keys and associated iterator positions */
  void_stack* key_positions;

  REGFI_ITER_POSITION* cur;
} REGFI_ITERATOR;



/** General purpose buffer with stored length
 * @ingroup regfiBottomLayer
 */
typedef struct _regfi_buffer
{
  uint8_t* buf;
  uint32_t len;
} REGFI_BUFFER;



/******************************************************************************/
/** 
 * @defgroup regfiBase Base Layer: Essential Functions and Data Structures
 *
 * These functions are either necessary for normal use of the regfi API or just
 * don't fit particularly well in any of the other layers.
 */
/******************************************************************************/



/** Returns the current regfi library version
 *
 * @return A string indicating the version.
 *
 * @ingroup regfiBase
 */
_EXPORT()
const char* regfi_version();


/** Parses file headers of an already open registry hive file and 
 *  allocates related structures for further parsing.
 *
 * @param fd A file descriptor of an already open file.  Must be seekable.
 *
 * @param output_encoding Character encoding that strings should be returned in.
 *                        Only supply the REGFI_ENCODING_* constants, as others 
 *                        will be rejected.
 *                        The following values are currently accepted:
 *                        REGFI_ENCODING_DEFAULT (currently REGFI_ENCODING_ASCII)
 *                        REGFI_ENCODING_ASCII
 *                        REGFI_ENCODING_UTF8
 *
 * @return A reference to a newly allocated REGFI_FILE structure, if successful;
 *         NULL on error.  Use regfi_free to free the returned REGFI_FILE.
 *
 * @ingroup regfiBase
 */
_EXPORT()
REGFI_FILE* regfi_alloc(int fd, REGFI_ENCODING output_encoding);


/** Parses file headers returned by supplied callback functions.
 *
 * This interface is useful if you have a registry hive in memory
 * or have some other reason to emulate a real file.
 *
 * @param file_cb A structure defining the callback functions needed to access the file. 
 *
 * @param output_encoding Character encoding that strings should be returned in.
 *                        Only supply the REGFI_ENCODING_* constants, as others 
 *                        will be rejected.
 *                        The following values are currently accepted:
 *                        REGFI_ENCODING_DEFAULT (currently REGFI_ENCODING_ASCII)
 *                        REGFI_ENCODING_ASCII
 *                        REGFI_ENCODING_UTF8
 *
 * @return A reference to a newly allocated REGFI_FILE structure, if successful;
 *         NULL on error.  Use regfi_free to free the returned REGFI_FILE.
 *
 * @ingroup regfiBase
 */
_EXPORT()
REGFI_FILE* regfi_alloc_cb(REGFI_RAW_FILE* file_cb,
			   REGFI_ENCODING output_encoding);


/** Frees a hive's data structures without closing the underlying file.
 *
 * @param file The registry structure to free.
 *
 * @ingroup regfiBase
 */
_EXPORT()
void regfi_free(REGFI_FILE* file);


/** Get errors, warnings, and/or verbose information relating to processing of
 *  the given registry file.
 *
 * @return A newly allocated char* which must be free()d by the caller.
 *
 * @ingroup regfiBase
 */
_EXPORT()
char* regfi_log_get_str();


/** Set the verbosity level of messages generated by the library for the 
 *  current thread.
 *
 * @param mask   An integer representing the types of messages desired.
 *               Acceptable values are created through bitwise ORs of 
 *               REGFI_LOG_* values.  For instance, if only errors and
 *               informational messages were desired (but not warnings),
 *               then one would specify: REGFI_LOG_ERROR|REGFI_LOG_INFO
 *               By default the message mask is: REGFI_LOG_ERROR|REGFI_LOG_WARN.
 *
 * @return       true on success and false on failure.  Failure occurs if 
 *               underlying pthread functions fail.  errno is set in this case.
 *
 * Message masks are set in a thread-specific way.  If one were to set a message
 * mask in one thread and then spawn a new thread, then the new thread will have
 * it's message mask reset to the default.  This function may be called at any 
 * time and will take effect immediately for the current thread.
 *
 * @note When a non-zero message mask is set, messages will
 *       accumulate in memory without limit if they are not fetched using
 *       @ref regfi_log_get_str and subsequently freed by the caller.  It is
 *       recommended that messsages be fetched after each regfi API call in
 *       order to provide the most context.
 *
 * @ingroup regfiBase
 */
_EXPORT()
bool regfi_log_set_mask(uint16_t mask);


/** Fetches a hive's root key.
 *
 * @return Returns the root key or NULL on failure.  Key must be freed using
 *         @ref regfi_free_record.
 *
 * @ingroup regfiBase
 */
_EXPORT()
const REGFI_NK*       regfi_get_rootkey(REGFI_FILE* file);


/** Frees a record previously returned by one of the API functions.
 *
 * @param file The file from which the record originated.  
 *             (This is needed for memory management reasons.)
 * 
 * @param record Any of the following record types: REGFI_NK, REGFI_VK, 
 *        REGFI_SK, REGFI_DATA, and REGFI_CLASSNAME records.
 *
 * @note The "const" in the record data type is a bit misleading and is there just for
 * convenience.  Since records returned previously must not be modified by users
 * of the API due to internal caching, these are returned as const, so this
 * function is const to make passing those records back easy.
 *
 * @ingroup regfiBase
 */
_EXPORT()
void regfi_free_record(REGFI_FILE* file, const void* record);


/** Increments reference count on record
 *
 * Adds an extra internal reference to specified record, making it necessary to
 * call regfi_free_record on it an additional time before it is freed.  This is
 * useful in cases where multiple threads/structures need access to a shared record,
 * without requiring them to be in sync with when it is freed.
 *
 * @param file The file from which the record originated.  
 *             (This is needed for memory management reasons.)
 * 
 * @param record Any of the following record types: REGFI_NK, REGFI_VK, 
 *        REGFI_SK, REGFI_DATA, and REGFI_CLASSNAME records.
 *
 * @return Updated record pointer on success, NULL otherwise
 *
 * @note Be sure to use the returned record for further access to the structure
 *       instead of the previous version of the pointer.  E.g.:
 *       @code 
 *       myKey = (const REGFI_NK*)regfi_reference_record(myFile, myKey);
 *       @endcode
 *
 * @ingroup regfiBase
 */
_EXPORT()
const void* regfi_reference_record(REGFI_FILE* file, const void* record);


/** Retrieves number of subkeys referenced by this key.
 *
 * Number of subkeyss in key structure and subkey list structure could differ,
 * so this provides a standard/sane way of determining the number.
 *
 * @param key  the key whose number of subkeys is desired
 *
 * @return Returns the number of subkeys referenced by this key.
 *
 * @ingroup regfiBase
 */
_EXPORT()
uint32_t regfi_fetch_num_subkeys(const REGFI_NK* key);


/** Retrieves number of values referenced by this key.
 *
 * Number of values in key structure and value list structure could differ,
 * so this provides a standard/sane way of determining the number.
 *
 * @param key  the key whose number of values is desired
 *
 * @return Returns the number of values referenced by this key.
 *
 * @ingroup regfiBase
 */
_EXPORT()
uint32_t regfi_fetch_num_values(const REGFI_NK* key);


/** Retrieves classname for a given key.
 *
 * @param file the file from which key is derived
 * @param key the key whose classname is desired
 *
 * @return Returns a newly allocated classname structure, or NULL on failure.
 *         Classname structures must be freed with @ref regfi_free_record.
 *
 * @ingroup regfiBase
 */
_EXPORT()
const REGFI_CLASSNAME* regfi_fetch_classname(REGFI_FILE* file, 
					     const REGFI_NK* key);


/** Returns the SK (security) record referenced by the supplied key.
 *
 * @param file the file from which key is derived
 * @param key  the key whose SK record is desired
 * 
 * @return A read-only SK structure, or NULL on failure.
 *
 * @ingroup regfiBase
 */
_EXPORT()
const REGFI_SK* regfi_fetch_sk(REGFI_FILE* file, const REGFI_NK* key);


/** Returns the next SK (security) record referenced by the supplied SK record
 *
 * @param file the file from which sk is derived
 * @param sk   the SK record whose next sibling SK record is desired
 * 
 * @return A read-only SK structure, or NULL on failure.
 *
 * @note
 * SK records are included in a circular, doubly-linked list.
 * To iterate over all SK records, be sure to check for the repetition of
 * the SK record you started with to determine when all have been traversed.
 *
 * @ingroup regfiBase
 */
_EXPORT()
const REGFI_SK* regfi_next_sk(REGFI_FILE* file, const REGFI_SK* sk);


/** Returns the previous SK (security) record referenced by the supplied SK record
 *
 * @param file the file from which sk is derived
 * @param sk   the SK record whose previous sibling SK record is desired
 * 
 * @return A read-only SK structure, or NULL on failure.
 *
 * @note
 * SK records are included in a circular, doubly-linked list.
 * To iterate over all SK records, be sure to check for the repetition of
 * the SK record you started with to determine when all have been traversed.
 *
 * @ingroup regfiBase
 */
_EXPORT()
const REGFI_SK* regfi_prev_sk(REGFI_FILE* file, const REGFI_SK* sk);


/** Retrieves data for a given value.
 *
 * @param file the file from which value is derived
 * @param value the value whose data is desired
 *
 * @return Returns a newly allocated data structure, or NULL on failure.
 *         Data structures must be freed with @ref regfi_free_record.
 *
 * @ingroup regfiBase
 */
_EXPORT()
const REGFI_DATA* regfi_fetch_data(REGFI_FILE* file,
				   const REGFI_VK* value);


/** Locates a specific subkey of a given key.
 *
 * @param file  the file from which key is derived
 * @param key   the key whose subkey is desired
 * @param name  name of the desired subkey (case-insensitive)
 * @param index a return value: the index of the desired subkey.
 *              undefined on error
 *
 * @return true if the subkey is found, false if an error occurred or if the
 *         specified name could not be found. If an error occurs, messages
 *         will be written explaining the issue. (See regfi_log_get_str.)
 *
 * @ingroup regfiBase
 */
_EXPORT()
bool regfi_find_subkey(REGFI_FILE* file, const REGFI_NK* key, 
		       const char* name, uint32_t* index);


/** Locates a specific value of a given key.
 *
 * @param file  the file from which key is derived
 * @param key   the key whose value is desired
 * @param name  name of the desired value (case-insensitive)
 * @param index a return value: the index of the desired value.  
 *              undefined on error
 *
 * @return true if the value is found, false if an error occurred or if the
 *         specified name could not be found. If an error occurs, messages
 *         will be written explaining the issue. (See regfi_log_get_str.)
 *
 * @ingroup regfiBase
 */
_EXPORT()
bool regfi_find_value(REGFI_FILE* file, const REGFI_NK* key,
		      const char* name, uint32_t* index);


/** Retrieves a specific subkey of a given key.
 *
 * @param file  the file from which key is derived
 * @param key   the key whose subkey is desired
 * @param index the index of the desired subkey
 *
 * @return the requested subkey or NULL on error.
 *
 * @ingroup regfiBase
 */
_EXPORT()
const REGFI_NK* regfi_get_subkey(REGFI_FILE* file, const REGFI_NK* key, 
				 uint32_t index);


/** Retrieves a specific value of a given key.
 *
 * @param file  the file from which key is derived
 * @param key   the key whose value is desired
 * @param index the index of the desired value
 *
 * @return the requested value or NULL on error.
 *
 * @ingroup regfiBase
 */
_EXPORT()
const REGFI_VK* regfi_get_value(REGFI_FILE* file, const REGFI_NK* key, 
				uint32_t index);



/** Uses a key's parent_off reference to retrieve it's parent.
 *
 * @param file  the file from which key is derived
 * @param key   the key whose parent is desired
 *
 * @return the requested subkey or NULL on error.
 *
 * @ingroup regfiBase
 */
_EXPORT()
const REGFI_NK* regfi_get_parentkey(REGFI_FILE* file, const REGFI_NK* key);


/******************************************************************************/
/** 
 * @defgroup regfiIteratorLayer Iterator Layer: Primary regfi Library Interface
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
 * @return A newly allocated REGFI_ITERATOR. 
 *         Must be free()d with regfi_iterator_free.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
REGFI_ITERATOR* regfi_iterator_new(REGFI_FILE* file);


/** Frees a registry file iterator previously created by regfi_iterator_new.
 *
 * This does not affect the underlying registry file's allocation status.
 *
 * @param i the iterator to be freed
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
void regfi_iterator_free(REGFI_ITERATOR* i);


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
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
bool regfi_iterator_down(REGFI_ITERATOR* i);


/** Traverse up to the current key's parent key.
 *
 * @param i the iterator
 *
 * @return  true on success, false on failure.  Any subkey or value state
 *          associated with the current key is lost.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
bool regfi_iterator_up(REGFI_ITERATOR* i);


/** Traverse up to the root key of the hive.
 *
 * @param i the iterator
 *
 * @return true on success, false on failure.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
bool regfi_iterator_to_root(REGFI_ITERATOR* i);


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
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
bool regfi_iterator_descend(REGFI_ITERATOR* i, const char** path);


/** Returns the currently referenced key.
 *
 * @param i the iterator
 *
 * @return A read-only key structure for the current key, or NULL on failure.
 *         Data structures must be freed with @ref regfi_free_record.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
const REGFI_NK* regfi_iterator_cur_key(REGFI_ITERATOR* i);


/** Sets the internal subkey index to the first subkey referenced by the current
 *  key.
 *
 * @param i the iterator
 *
 * @return True if the current key has any subkeys, false otherwise.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
bool regfi_iterator_first_subkey(REGFI_ITERATOR* i);


/** Returns the currently indexed subkey.
 *
 * @param i the iterator
 *
 * @return A newly allocated key structure for the currently referenced subkey,
 *         or NULL on failure.  Newly allocated keys must be freed with 
 *         @ref regfi_free_record.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
const REGFI_NK* regfi_iterator_cur_subkey(REGFI_ITERATOR* i);


/** Increments the internal subkey index to the next key in the subkey-list.
 *
 * @param i the iterator
 *
 * @return True if another subkey should exist, false otherwise.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
bool regfi_iterator_next_subkey(REGFI_ITERATOR* i);


/** Searches for a subkey with a given name under the current key.
 *
 * @param i     the iterator
 * @param name  subkey name to search for
 *
 * @return True if such a subkey was found, false otherwise.  If a subkey is
 *         found, the current subkey index is set to that subkey.  Otherwise,
 *         the subkey index remains at the same location as before the call.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
bool regfi_iterator_find_subkey(REGFI_ITERATOR* i, const char* name);


/** Sets the internal value index to the first value referenced by the current
 *  key.
 *
 * @param i the iterator
 *
 * @return True if the current key has any values, false otherwise.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
bool regfi_iterator_first_value(REGFI_ITERATOR* i);


/** Returns the currently indexed value.
 *
 * @param i the iterator
 *
 * @return A newly allocated value structure for the currently referenced value,
 *         or NULL on failure.  Newly allocated values must be freed with 
 *         @ref regfi_free_record.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
const REGFI_VK* regfi_iterator_cur_value(REGFI_ITERATOR* i);


/** Increments the internal value index to the next value in the value-list.
 *
 * @param i the iterator
 *
 * @return True if another value should exist, false otherwise.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
bool regfi_iterator_next_value(REGFI_ITERATOR* i);


/** Searches for a value with a given name under the current key.
 *
 * @param i     the iterator
 * @param name  value name to search for
 *
 * @return True if such a value was found, false otherwise.  If a value is 
 *         found, the current value index is set to that value.  Otherwise,
 *         the value index remains at the same location as before the call.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
bool regfi_iterator_find_value(REGFI_ITERATOR* i, const char* name);


/** Returns the current key and all parent keys as a list of NK records
 *
 * @param i     the iterator
 *
 * @return An array of NK record pointers terminated by a NULL pointer.  
 *         This array may be passed directly to regfi_free_record to free
 *         the entire array.
 *
 * @note In order to use an element of the array independently from the 
 *       array (that is, to hold a pointer to an individual NK record while 
 *       freeing the remaining array), callers must first use 
 *       regfi_reference_record on the elements to be kept.
 *
 * @ingroup regfiIteratorLayer
 */
_EXPORT()
const REGFI_NK** regfi_iterator_ancestry(REGFI_ITERATOR* i);


/******************************************************************************/
/** 
 * @defgroup regfiGlueLayer Glue Layer: Logical Data Structure Loading 
 */
/******************************************************************************/

/** Loads a key and associated data structures given a file offset.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiGlueLayer
 */
_EXPORT()
REGFI_NK* regfi_load_key(REGFI_FILE* file, uint32_t offset, 
                         bool strict);


/** Loads a value at a given file offset alng with associated data structures.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiGlueLayer
 */
_EXPORT()
REGFI_VK* regfi_load_value(REGFI_FILE* file, uint32_t offset, 
                           bool strict);


/** Loads a logical subkey list in its entirety which may span multiple records.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiGlueLayer
 */
_EXPORT()
REGFI_SUBKEY_LIST* regfi_load_subkeylist(REGFI_FILE* file, uint32_t offset,
					 uint32_t num_keys, uint32_t max_size,
					 bool strict);


/** Loads a valuelist.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiGlueLayer
 */
_EXPORT()
REGFI_VALUE_LIST* regfi_load_valuelist(REGFI_FILE* file, uint32_t offset, 
				       uint32_t num_values, uint32_t max_size,
				       bool strict);


/** Loads a data record which may be contained in the virtual offset, in a
 *  single cell, or in multiple cells through big data records.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiGlueLayer
 */
_EXPORT()
REGFI_BUFFER regfi_load_data(REGFI_FILE* file, uint32_t voffset,
			     uint32_t length, bool data_in_offset,
			     bool strict);


/** Loads the data associated with a big data record at the specified offset.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiGlueLayer
 */
_EXPORT()
REGFI_BUFFER regfi_load_big_data(REGFI_FILE* file, uint32_t offset, 
				 uint32_t data_length,uint32_t cell_length,
				 range_list* used_ranges,
				 bool strict);


/** Given raw data, attempts to interpret the data based on a specified registry
 *  data type.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiGlueLayer
 */
_EXPORT()
bool regfi_interpret_data(REGFI_FILE* file, 
			  uint32_t type, REGFI_DATA* data);



/* These are cached so return values don't need to be freed. */

/** Loads an "sk" security record at the specified offset.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiGlueLayer
 */
_EXPORT()
const REGFI_SK* regfi_load_sk(REGFI_FILE* file, uint32_t offset,
                              bool strict);




/** Retrieves the HBIN data structure stored at the specified offset.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiGlueLayer
 */
_EXPORT()
const REGFI_HBIN* regfi_lookup_hbin(REGFI_FILE* file, uint32_t offset);



/******************************************************************************/
/**
 * @defgroup regfiParseLayer Parsing Layer: Direct Data Structure Access 
 */
/******************************************************************************/

_EXPORT()
REGFI_FILE* regfi_parse_regf(REGFI_RAW_FILE* file_cb, bool strict);

_EXPORT()
REGFI_HBIN* regfi_parse_hbin(REGFI_FILE* file, uint32_t offset, 
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
 * @ingroup regfiParseLayer
 */
_EXPORT()
REGFI_NK* regfi_parse_nk(REGFI_FILE* file, uint32_t offset,
			     uint32_t max_size, bool strict);


/** Parses a single cell containing a subkey-list record.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiParseLayer
 */
_EXPORT()
REGFI_SUBKEY_LIST* regfi_parse_subkeylist(REGFI_FILE* file, uint32_t offset,
					  uint32_t max_size, bool strict);


/** Parses a VK (value) record at the specified offset
 *
 * XXX: finish documenting
 *
 * @ingroup regfiParseLayer
 */
_EXPORT()
REGFI_VK* regfi_parse_vk(REGFI_FILE* file, uint32_t offset, 
			     uint32_t max_size, bool strict);


/** Parses an SK (security) record at the specified offset
 *
 * XXX: finish documenting
 *
 * @ingroup regfiParseLayer
 */
_EXPORT()
REGFI_SK* regfi_parse_sk(REGFI_FILE* file, uint32_t offset, 
			     uint32_t max_size, bool strict);


/** Retrieves information on all cells in the registry hive which are 
 *  currently in the unallocated status.  
 *
 * The unallocated status is determined based soley on the cell length sign.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiParseLayer
 */
_EXPORT()
range_list* regfi_parse_unalloc_cells(REGFI_FILE* file);


/** Helper function to parse a cell
 *
 * XXX: finish documenting
 *
 * @ingroup regfiParseLayer
 */
_EXPORT()
bool regfi_parse_cell(REGFI_RAW_FILE* file_cb, uint32_t offset,
		      uint8_t* hdr, uint32_t hdr_len,
		      uint32_t* cell_length, bool* unalloc);


/** Parses a classname cell
 *
 * XXX: finish documenting
 *
 * @ingroup regfiParseLayer
 */
_EXPORT()
uint8_t* regfi_parse_classname(REGFI_FILE* file, uint32_t offset,
			       uint16_t* name_length, 
			       uint32_t max_size, bool strict);


/** Parses a single-cell data record
 *
 * XXX: finish documenting
 *
 * @ingroup regfiParseLayer
 */
_EXPORT()
REGFI_BUFFER regfi_parse_data(REGFI_FILE* file, uint32_t offset,
			      uint32_t length, bool strict);


/** Parses a "little data" record which is stored entirely within the 
 *  provided virtual offset.
 *
 * XXX: finish documenting
 *
 * @ingroup regfiParseLayer
 */
_EXPORT()
REGFI_BUFFER regfi_parse_little_data(REGFI_FILE* file, uint32_t voffset, 
				     uint32_t length, bool strict);


/******************************************************************************/
/*    Private (and undocumented) Functions                                    */
/******************************************************************************/
int64_t               regfi_raw_seek(REGFI_RAW_FILE* self, 
				     uint64_t offset, int whence);
ssize_t               regfi_raw_read(REGFI_RAW_FILE* self, 
				     void* buf, size_t count);
_EXPORT()
uint64_t              regfi_seek(REGFI_RAW_FILE* file_cb, 
				 uint64_t offset, int whence);
_EXPORT()
uint32_t              regfi_read(REGFI_RAW_FILE* file_cb, 
				 uint8_t* buf, uint32_t* length);

_EXPORT()
const char*           regfi_type_val2str(unsigned int val);
_EXPORT()
int                   regfi_type_str2val(const char* str);

_EXPORT()
char*                 regfi_get_sacl(WINSEC_DESC* sec_desc);
_EXPORT()
char*                 regfi_get_dacl(WINSEC_DESC* sec_desc);
_EXPORT()
char*                 regfi_get_owner(WINSEC_DESC* sec_desc);
_EXPORT()
char*                 regfi_get_group(WINSEC_DESC* sec_desc);

REGFI_SUBKEY_LIST*    regfi_merge_subkeylists(uint16_t num_lists, 
					      REGFI_SUBKEY_LIST** lists,
					      bool strict);
REGFI_SUBKEY_LIST*    regfi_load_subkeylist_aux(REGFI_FILE* file, uint32_t offset,
						uint32_t max_size, bool strict,
						uint8_t depth_left);
void                  regfi_add_message(REGFI_FILE* file, uint16_t msg_type, 
					const char* fmt, ...);
REGFI_NK*             regfi_copy_nk(const REGFI_NK* nk);
REGFI_VK*             regfi_copy_vk(const REGFI_VK* vk);
_EXPORT()
int32_t               regfi_calc_maxsize(REGFI_FILE* file, uint32_t offset);
REGFI_BUFFER          regfi_conv_charset(const char* input_charset, const char* output_charset,
                                         uint8_t* input, uint32_t input_len);
_EXPORT()
REGFI_DATA*           regfi_buffer_to_data(REGFI_BUFFER raw_data);

/* XXX: move to base API and document */
_EXPORT()
REGFI_NTTIME          regfi_unix2nt_time(time_t t);
_EXPORT()
double                regfi_nt2unix_time(REGFI_NTTIME nt);


_EXPORT()
void regfi_interpret_keyname(REGFI_FILE* file, REGFI_NK* nk, bool strict);
_EXPORT()
void regfi_interpret_valuename(REGFI_FILE* file, REGFI_VK* vk, bool strict);

_EXPORT()
void regfi_init();


#endif	/* _REGFI_H */
