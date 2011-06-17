/*
 * Copyright (C) 2005-2011 Timothy D. Morgan
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
 *
 * Windows NT (and later) read-only registry library
 *
 * See @ref regfi.h for more information.
 *
 * Branched from Samba project Subversion repository, version #7470:
 *   http://viewcvs.samba.org/cgi-bin/viewcvs.cgi/trunk/source/registry/regfio.c?rev=7470&view=auto
 *
 * Since then, it has been heavily rewritten, simplified, and improved.
 */

#include "regfi.h"

/* Library version can be overridden at build time */
#ifndef REGFI_VERSION
#define REGFI_VERSION "trunk"
#endif


/* Registry types mapping */
const unsigned int regfi_num_reg_types = 12;
static const char* regfi_type_names[] =
  {"NONE", "SZ", "EXPAND_SZ", "BINARY", "DWORD", "DWORD_BE", "LINK",
   "MULTI_SZ", "RSRC_LIST", "RSRC_DESC", "RSRC_REQ_LIST", "QWORD"};

const char* regfi_encoding_names[] =
  {"US-ASCII//TRANSLIT", "UTF-8//TRANSLIT", "UTF-16LE//TRANSLIT"};


/* Ensures regfi_init runs only once */
static pthread_once_t regfi_init_once = PTHREAD_ONCE_INIT;


/******************************************************************************
 ******************************************************************************/
const char* regfi_version()
{
  return REGFI_VERSION;
}


/******************************************************************************
 ******************************************************************************/
void regfi_log_free(void* ptr)
{
  REGFI_LOG* log_info = (REGFI_LOG*)ptr;
  
  if(log_info->messages != NULL)
    free(log_info->messages);

  talloc_free(log_info);
}


/******************************************************************************
 ******************************************************************************/
void regfi_init()
{
  int err;
  if((err = pthread_key_create(&regfi_log_key, regfi_log_free)) != 0)
    fprintf(stderr, "ERROR: key_create: %s\n", strerror(err));
  errno = err;
}


/******************************************************************************
 ******************************************************************************/
REGFI_LOG* regfi_log_new()
{
  int err;
  REGFI_LOG* log_info = talloc(NULL, REGFI_LOG);
  if(log_info == NULL)
    return NULL;

  log_info->msg_mask = REGFI_DEFAULT_LOG_MASK;
  log_info->messages = NULL;

  pthread_once(&regfi_init_once, regfi_init);

  if((err = pthread_setspecific(regfi_log_key, log_info)) != 0)
  {
    fprintf(stderr, "ERROR: setspecific: %s\n", strerror(err));
    goto fail;
  }

  return log_info;

 fail:
  talloc_free(log_info);
  errno = err;
  return NULL;
}


/******************************************************************************
 ******************************************************************************/
void regfi_log_add(uint16_t msg_type, const char* fmt, ...)
{
  /* XXX: Switch internal storage over to a linked list or stack.
   *      Then add a regfi_log_get function that returns the list in some
   *      convenient, user-friendly data structure.  regfi_log_get_str should
   *      stick around and will simply smush the list into a big string when 
   *      it's called, rather than having messages smushed when they're first
   *      written to the log.
   */
  uint32_t buf_size, buf_used;
  char* new_msg;
  REGFI_LOG* log_info;
  va_list args;

  log_info = (REGFI_LOG*)pthread_getspecific(regfi_log_key);
  if(log_info == NULL && (log_info = regfi_log_new()) == NULL)
    return;

  if((log_info->msg_mask & msg_type) == 0)
    return;

  if(log_info->messages == NULL)
    buf_used = 0;
  else
    buf_used = strlen(log_info->messages);
  
  buf_size = buf_used+strlen(fmt)+160;
  new_msg = realloc(log_info->messages, buf_size);
  if(new_msg == NULL)
    /* XXX: should we report this? */
    return;
  
  switch (msg_type)
  {
  case REGFI_LOG_INFO:
    strcpy(new_msg+buf_used, "INFO: ");
    buf_used += 6;
    break;
  case REGFI_LOG_WARN:
    strcpy(new_msg+buf_used, "WARN: ");
    buf_used += 6;
    break;
  case REGFI_LOG_ERROR:
    strcpy(new_msg+buf_used, "ERROR: ");
    buf_used += 7;
    break;
  }
  
  va_start(args, fmt);
  vsnprintf(new_msg+buf_used, buf_size-buf_used, fmt, args);
  va_end(args);
  strncat(new_msg, "\n", buf_size-1);
  
  log_info->messages = new_msg;
}


/******************************************************************************
 ******************************************************************************/
char* regfi_log_get_str()
{
  char* ret_val;
  REGFI_LOG* log_info = (REGFI_LOG*)pthread_getspecific(regfi_log_key);
  if(log_info == NULL && (log_info = regfi_log_new()) == NULL)
    return NULL;
  
  ret_val = log_info->messages;
  log_info->messages = NULL;

  return ret_val;
}


/******************************************************************************
 ******************************************************************************/
bool regfi_log_set_mask(uint16_t msg_mask)
{
  REGFI_LOG* log_info = (REGFI_LOG*)pthread_getspecific(regfi_log_key);
  if(log_info == NULL && (log_info = regfi_log_new()) == NULL)
  {
      return false;
  }

  log_info->msg_mask = msg_mask;
  return true;
}


/******************************************************************************
 * Returns NULL for an invalid e
 *****************************************************************************/
static const char* regfi_encoding_int2str(REGFI_ENCODING e)
{
  if(e < REGFI_NUM_ENCODINGS)
    return regfi_encoding_names[e];

  return NULL;
}


/******************************************************************************
 * Returns NULL for an invalid val
 *****************************************************************************/
const char* regfi_type_val2str(unsigned int val)
{
  if(val == REG_KEY)
    return "KEY";
  
  if(val >= regfi_num_reg_types)
    return NULL;
  
  return regfi_type_names[val];
}


/******************************************************************************
 * Returns -1 on error
 *****************************************************************************/
int regfi_type_str2val(const char* str)
{
  int i;

  if(strcmp("KEY", str) == 0)
    return REG_KEY;

  for(i=0; i < regfi_num_reg_types; i++)
    if (strcmp(regfi_type_names[i], str) == 0) 
      return i;

  if(strcmp("DWORD_LE", str) == 0)
    return REG_DWORD_LE;

  return -1;
}


/* Security descriptor formatting functions  */

const char* regfi_ace_type2str(uint8_t type)
{
  static const char* map[7] 
    = {"ALLOW", "DENY", "AUDIT", "ALARM", 
       "ALLOW CPD", "OBJ ALLOW", "OBJ DENY"};
  if(type < 7)
    return map[type];
  else
    /* XXX: would be nice to return the unknown integer value.  
     *      However, as it is a const string, it can't be free()ed later on, 
     *      so that would need to change. 
     */
    return "UNKNOWN";
}


/* XXX: need a better reference on the meaning of each flag. */
/* For more info, see:
 *   http://msdn2.microsoft.com/en-us/library/aa772242.aspx
 */
char* regfi_ace_flags2str(uint8_t flags)
{
  static const char* flag_map[32] = 
    { "OI", /* Object Inherit */
      "CI", /* Container Inherit */
      "NP", /* Non-Propagate */
      "IO", /* Inherit Only */
      "IA", /* Inherited ACE */
      NULL,
      NULL,
      NULL,
    };

  char* ret_val = malloc(35*sizeof(char));
  char* fo = ret_val;
  uint32_t i;
  uint8_t f;

  if(ret_val == NULL)
    return NULL;

  fo[0] = '\0';
  if (!flags)
    return ret_val;

  for(i=0; i < 8; i++)
  {
    f = (1<<i);
    if((flags & f) && (flag_map[i] != NULL))
    {
      strcpy(fo, flag_map[i]);
      fo += strlen(flag_map[i]);
      *(fo++) = ' ';
      flags ^= f;
    }
  }
  
  /* Any remaining unknown flags are added at the end in hex. */
  if(flags != 0)
    sprintf(fo, "0x%.2X ", flags);

  /* Chop off the last space if we've written anything to ret_val */
  if(fo != ret_val)
    fo[-1] = '\0';

  return ret_val;
}


char* regfi_ace_perms2str(uint32_t perms)
{
  uint32_t i, p;
  /* This is more than is needed by a fair margin. */
  char* ret_val = malloc(350*sizeof(char));
  char* r = ret_val;

  /* Each represents one of 32 permissions bits.  NULL is for undefined/reserved bits.
   * For more information, see:
   *   http://msdn2.microsoft.com/en-gb/library/aa374892.aspx
   *   http://msdn2.microsoft.com/en-gb/library/ms724878.aspx
   */
  static const char* perm_map[32] = 
    {/* object-specific permissions (registry keys, in this case) */
      "QRY_VAL",       /* KEY_QUERY_VALUE */
      "SET_VAL",       /* KEY_SET_VALUE */
      "CREATE_KEY",    /* KEY_CREATE_SUB_KEY */
      "ENUM_KEYS",     /* KEY_ENUMERATE_SUB_KEYS */
      "NOTIFY",        /* KEY_NOTIFY */
      "CREATE_LNK",    /* KEY_CREATE_LINK - Reserved for system use. */
      NULL,
      NULL,
      "WOW64_64",      /* KEY_WOW64_64KEY */
      "WOW64_32",      /* KEY_WOW64_32KEY */
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      /* standard access rights */
      "DELETE",        /* DELETE */
      "R_CONT",        /* READ_CONTROL */
      "W_DAC",         /* WRITE_DAC */
      "W_OWNER",       /* WRITE_OWNER */
      "SYNC",          /* SYNCHRONIZE - Shouldn't be set in registries */
      NULL,
      NULL,
      NULL,
      /* other generic */
      "SYS_SEC",       /* ACCESS_SYSTEM_SECURITY */
      "MAX_ALLWD",     /* MAXIMUM_ALLOWED */
      NULL,
      NULL,
      "GEN_A",         /* GENERIC_ALL */
      "GEN_X",         /* GENERIC_EXECUTE */
      "GEN_W",         /* GENERIC_WRITE */
      "GEN_R",         /* GENERIC_READ */
    };


  if(ret_val == NULL)
    return NULL;

  r[0] = '\0';
  for(i=0; i < 32; i++)
  {
    p = (1<<i);
    if((perms & p) && (perm_map[i] != NULL))
    {
      strcpy(r, perm_map[i]);
      r += strlen(perm_map[i]);
      *(r++) = ' ';
      perms ^= p;
    }
  }
  
  /* Any remaining unknown permission bits are added at the end in hex. */
  if(perms != 0)
    sprintf(r, "0x%.8X ", perms);

  /* Chop off the last space if we've written anything to ret_val */
  if(r != ret_val)
    r[-1] = '\0';

  return ret_val;
}


char* regfi_get_acl(WINSEC_ACL* acl)
{
  uint32_t i, extra, size = 0;
  const char* type_str;
  char* flags_str;
  char* perms_str;
  char* sid_str;
  char* ace_delim = "";
  char* ret_val = NULL;
  char* tmp_val = NULL;
  bool failed = false;
  char field_delim = ':';

  for (i = 0; i < acl->num_aces && !failed; i++)
  {
    sid_str = winsec_sid2str(acl->aces[i]->trustee);
    type_str = regfi_ace_type2str(acl->aces[i]->type);
    perms_str = regfi_ace_perms2str(acl->aces[i]->access_mask);
    flags_str = regfi_ace_flags2str(acl->aces[i]->flags);
    
    if(flags_str != NULL && perms_str != NULL 
       && type_str != NULL && sid_str != NULL)
    {
      /* XXX: this is slow */
      extra = strlen(sid_str) + strlen(type_str) 
	+ strlen(perms_str) + strlen(flags_str) + 5;
      tmp_val = realloc(ret_val, size+extra);

      if(tmp_val == NULL)
      {
	free(ret_val);
	ret_val = NULL;
	failed = true;
      }
      else
      {
	ret_val = tmp_val;
	size += sprintf(ret_val+size, "%s%s%c%s%c%s%c%s",
			ace_delim,sid_str,
			field_delim,type_str,
			field_delim,perms_str,
			field_delim,flags_str);
	ace_delim = "|";
      }
    }
    else
      failed = true;

    if(sid_str != NULL)
      free(sid_str);
    if(sid_str != NULL)
      free(perms_str);
    if(sid_str != NULL)
      free(flags_str);
  }

  return ret_val;
}


char* regfi_get_sacl(WINSEC_DESC *sec_desc)
{
  if (sec_desc->sacl)
    return regfi_get_acl(sec_desc->sacl);
  else
    return NULL;
}


char* regfi_get_dacl(WINSEC_DESC *sec_desc)
{
  if (sec_desc->dacl)
    return regfi_get_acl(sec_desc->dacl);
  else
    return NULL;
}


char* regfi_get_owner(WINSEC_DESC *sec_desc)
{
  return winsec_sid2str(sec_desc->owner_sid);
}


char* regfi_get_group(WINSEC_DESC *sec_desc)
{
  return winsec_sid2str(sec_desc->grp_sid);
}


bool regfi_read_lock(REGFI_FILE* file, pthread_rwlock_t* lock, const char* context)
{
  int lock_ret = pthread_rwlock_rdlock(lock);
  if(lock_ret != 0)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Error obtaining read lock in"
		      "%s due to: %s\n", context, strerror(lock_ret));
    return false;
  }

  return true;
}


bool regfi_write_lock(REGFI_FILE* file, pthread_rwlock_t* lock, const char* context)
{
  int lock_ret = pthread_rwlock_wrlock(lock);
  if(lock_ret != 0)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Error obtaining write lock in"
		      "%s due to: %s\n", context, strerror(lock_ret));
    return false;
  }

  return true;
}


bool regfi_rw_unlock(REGFI_FILE* file, pthread_rwlock_t* lock, const char* context)
{
  int lock_ret = pthread_rwlock_unlock(lock);
  if(lock_ret != 0)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Error releasing lock in"
		      "%s due to: %s\n", context, strerror(lock_ret));
    return false;
  }

  return true;
}


bool regfi_lock(REGFI_FILE* file, pthread_mutex_t* lock, const char* context)
{
  int lock_ret = pthread_mutex_lock(lock);
  if(lock_ret != 0)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Error obtaining mutex lock in"
		      "%s due to: %s\n", context, strerror(lock_ret));
    return false;
  }

  return true;
}


bool regfi_unlock(REGFI_FILE* file, pthread_mutex_t* lock, const char* context)
{
  int lock_ret = pthread_mutex_unlock(lock);
  if(lock_ret != 0)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Error releasing mutex lock in"
		      "%s due to: %s\n", context, strerror(lock_ret));
    return false;
  }

  return true;
}


int64_t regfi_raw_seek(REGFI_RAW_FILE* self, uint64_t offset, int whence)
{
  if(sizeof(off_t) == 4 && offset > 2147483647)
  {
    errno = EOVERFLOW;
    return -1;
  }
  return lseek(*(int*)self->state, offset, whence);
}

ssize_t regfi_raw_read(REGFI_RAW_FILE* self, void* buf, size_t count)
{
  return read(*(int*)self->state, buf, count);
}


/*****************************************************************************
 * Convenience function to wrap up the ugly callback stuff
 *****************************************************************************/
uint64_t regfi_seek(REGFI_RAW_FILE* file_cb, uint64_t offset, int whence)
{
  return file_cb->seek(file_cb, offset, whence);
}


/*****************************************************************************
 * This function is just like read(2), except that it continues to
 * re-try reading from the file descriptor if EINTR or EAGAIN is received.  
 * regfi_read will attempt to read length bytes from the file and write them to
 * buf.
 *
 * On success, 0 is returned.  Upon failure, an errno code is returned.
 *
 * The number of bytes successfully read is returned through the length 
 * parameter by reference.  If both the return value and length parameter are 
 * returned as 0, then EOF was encountered immediately
 *****************************************************************************/
uint32_t regfi_read(REGFI_RAW_FILE* file_cb, uint8_t* buf, uint32_t* length)
{
  uint32_t rsize = 0;
  uint32_t rret = 0;

  do
  {
    rret = file_cb->read(file_cb, 
                         buf + rsize, 
                         *length - rsize);
    if(rret > 0)
      rsize += rret;
  }while(*length - rsize > 0 
         && (rret > 0 || (rret == -1 && (errno == EAGAIN || errno == EINTR))));
  
  *length = rsize;
  if (rret == -1 && errno != EINTR && errno != EAGAIN)
    return errno;

  return 0;
}


/*****************************************************************************
 *
 *****************************************************************************/
bool regfi_parse_cell(REGFI_RAW_FILE* file_cb, uint32_t offset, uint8_t* hdr, 
		      uint32_t hdr_len, uint32_t* cell_length, bool* unalloc)
{
  uint32_t length;
  int32_t raw_length;
  uint8_t tmp[4];

  if(regfi_seek(file_cb, offset, SEEK_SET) == -1)
    return false;

  length = 4;
  if((regfi_read(file_cb, tmp, &length) != 0) || length != 4)
    return false;
  raw_length = IVALS(tmp, 0);

  if(raw_length < 0)
  {
    (*cell_length) = raw_length*(-1);
    (*unalloc) = false;
  }
  else
  {
    (*cell_length) = raw_length;
    (*unalloc) = true;
  }

  if(*cell_length - 4 < hdr_len)
    return false;

  if(hdr_len > 0)
  {
    length = hdr_len;
    if((regfi_read(file_cb, hdr, &length) != 0) || length != hdr_len)
      return false;
  }

  return true;
}


/******************************************************************************
 * Given an offset and an hbin, is the offset within that hbin?
 * The offset is a virtual file offset.
 ******************************************************************************/
static bool regfi_offset_in_hbin(const REGFI_HBIN* hbin, uint32_t voffset)
{
  if(!hbin)
    return false;

  if((voffset > hbin->first_hbin_off) 
     && (voffset < (hbin->first_hbin_off + hbin->block_size)))
    return true;
		
  return false;
}



/******************************************************************************
 * Provide a physical offset and receive the correpsonding HBIN
 * block for it.  NULL if one doesn't exist.
 ******************************************************************************/
const REGFI_HBIN* regfi_lookup_hbin(REGFI_FILE* file, uint32_t offset)
{
  return (const REGFI_HBIN*)range_list_find_data(file->hbins, offset);
}


/******************************************************************************
 * Calculate the largest possible cell size given a physical offset.
 * Largest size is based on the HBIN the offset is currently a member of.
 * Returns negative values on error.
 * (Since cells can only be ~2^31 in size, this works out.)
 ******************************************************************************/
int32_t regfi_calc_maxsize(REGFI_FILE* file, uint32_t offset)
{
  const REGFI_HBIN* hbin = regfi_lookup_hbin(file, offset);
  if(hbin == NULL)
    return -1;

  return (hbin->block_size + hbin->file_off) - offset;
}


/******************************************************************************
 ******************************************************************************/
REGFI_SUBKEY_LIST* regfi_load_subkeylist(REGFI_FILE* file, uint32_t offset, 
					 uint32_t num_keys, uint32_t max_size, 
					 bool strict)
{
  REGFI_SUBKEY_LIST* ret_val;

  ret_val = regfi_load_subkeylist_aux(file, offset, max_size, strict, 
				      REGFI_MAX_SUBKEY_DEPTH);
  if(ret_val == NULL)
  {
    regfi_log_add(REGFI_LOG_WARN, "Failed to load subkey list at"
		      " offset 0x%.8X.", offset);
    return NULL;
  }

  if(num_keys != ret_val->num_keys)
  {
    /*  Not sure which should be authoritative, the number from the 
     *  NK record, or the number in the subkey list.  Just emit a warning for
     *  now if they don't match.
     */
    regfi_log_add(REGFI_LOG_WARN, "Number of subkeys listed in parent"
		      " (%d) did not match number found in subkey list/tree (%d)"
		      " while parsing subkey list/tree at offset 0x%.8X.", 
		      num_keys, ret_val->num_keys, offset);
  }

  return ret_val;
}


/******************************************************************************
 ******************************************************************************/
REGFI_SUBKEY_LIST* regfi_load_subkeylist_aux(REGFI_FILE* file, uint32_t offset, 
					     uint32_t max_size, bool strict,
					     uint8_t depth_left)
{
  REGFI_SUBKEY_LIST* ret_val;
  REGFI_SUBKEY_LIST** sublists;
  uint32_t i, num_sublists, off;
  int32_t sublist_maxsize;

  if(depth_left == 0)
  {
    regfi_log_add(REGFI_LOG_WARN, "Maximum depth reached"
		      " while parsing subkey list/tree at offset 0x%.8X.", 
		      offset);
    return NULL;
  }

  ret_val = regfi_parse_subkeylist(file, offset, max_size, strict);
  if(ret_val == NULL)
    return NULL;

  if(ret_val->recursive_type)
  {
    num_sublists = ret_val->num_children;
    sublists = (REGFI_SUBKEY_LIST**)malloc(num_sublists 
					   * sizeof(REGFI_SUBKEY_LIST*));
    for(i=0; i < num_sublists; i++)
    {
      off = ret_val->elements[i].offset + REGFI_REGF_SIZE;

      sublist_maxsize = regfi_calc_maxsize(file, off);
      if(sublist_maxsize < 0)
	sublists[i] = NULL;
      else
	sublists[i] = regfi_load_subkeylist_aux(file, off, sublist_maxsize, 
						strict, depth_left-1);
    }
    talloc_free(ret_val);

    return regfi_merge_subkeylists(num_sublists, sublists, strict);
  }

  return ret_val;
}


/******************************************************************************
 ******************************************************************************/
REGFI_SUBKEY_LIST* regfi_parse_subkeylist(REGFI_FILE* file, uint32_t offset, 
					  uint32_t max_size, bool strict)
{
  REGFI_SUBKEY_LIST* ret_val;
  uint32_t i, cell_length, length, elem_size, read_len;
  uint8_t* elements = NULL;
  uint8_t buf[REGFI_SUBKEY_LIST_MIN_LEN];
  bool unalloc;
  bool recursive_type;

  if(!regfi_lock(file, &file->cb_lock, "regfi_parse_subkeylist"))
     goto fail;

  if(!regfi_parse_cell(file->cb, offset, buf, REGFI_SUBKEY_LIST_MIN_LEN,
		       &cell_length, &unalloc))
  {
    regfi_log_add(REGFI_LOG_WARN, "Could not parse cell while "
		      "parsing subkey-list at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  if(cell_length > max_size)
  {
    regfi_log_add(REGFI_LOG_WARN, "Cell size longer than max_size"
		      " while parsing subkey-list at offset 0x%.8X.", offset);
    if(strict)
      goto fail_locked;
    cell_length = max_size & 0xFFFFFFF8;
  }

  recursive_type = false;
  if(buf[0] == 'r' && buf[1] == 'i')
  {
    recursive_type = true;
    elem_size = sizeof(uint32_t);
  }
  else if(buf[0] == 'l' && buf[1] == 'i')
  {
    elem_size = sizeof(uint32_t);
  }
  else if((buf[0] == 'l') && (buf[1] == 'f' || buf[1] == 'h'))
    elem_size = sizeof(REGFI_SUBKEY_LIST_ELEM);
  else
  {
    regfi_log_add(REGFI_LOG_ERROR, "Unknown magic number"
		      " (0x%.2X, 0x%.2X) encountered while parsing"
		      " subkey-list at offset 0x%.8X.", buf[0], buf[1], offset);
    goto fail_locked;
  }

  ret_val = talloc(NULL, REGFI_SUBKEY_LIST);
  if(ret_val == NULL)
    goto fail_locked;

  ret_val->offset = offset;
  ret_val->cell_size = cell_length;
  ret_val->magic[0] = buf[0];
  ret_val->magic[1] = buf[1];
  ret_val->recursive_type = recursive_type;
  ret_val->num_children = SVAL(buf, 0x2);

  if(!recursive_type)
    ret_val->num_keys = ret_val->num_children;

  length = elem_size*ret_val->num_children;
  if(cell_length - REGFI_SUBKEY_LIST_MIN_LEN - sizeof(uint32_t) < length)
  {
    regfi_log_add(REGFI_LOG_WARN, "Number of elements too large for"
		      " cell while parsing subkey-list at offset 0x%.8X.", 
		      offset);
    if(strict)
      goto fail_locked;
    length = cell_length - REGFI_SUBKEY_LIST_MIN_LEN - sizeof(uint32_t);
  }

  ret_val->elements = talloc_array(ret_val, REGFI_SUBKEY_LIST_ELEM, 
				   ret_val->num_children);
  if(ret_val->elements == NULL)
    goto fail_locked;

  elements = (uint8_t*)malloc(length);
  if(elements == NULL)
    goto fail_locked;

  read_len = length;
  if(regfi_read(file->cb, elements, &read_len) != 0 || read_len!=length)
    goto fail_locked;

  if(!regfi_unlock(file, &file->cb_lock, "regfi_parse_subkeylist"))
     goto fail;

  if(elem_size == sizeof(uint32_t))
  {
    for (i=0; i < ret_val->num_children; i++)
    {
      ret_val->elements[i].offset = IVAL(elements, i*elem_size);
      ret_val->elements[i].hash = 0;
    }
  }
  else
  {
    for (i=0; i < ret_val->num_children; i++)
    {
      ret_val->elements[i].offset = IVAL(elements, i*elem_size);
      ret_val->elements[i].hash = IVAL(elements, i*elem_size+4);
    }
  }
  free(elements);

  return ret_val;

 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_parse_subkeylist");
 fail:
  if(elements != NULL)
    free(elements);
  talloc_free(ret_val);
  return NULL;
}


/*******************************************************************
 *******************************************************************/
REGFI_SUBKEY_LIST* regfi_merge_subkeylists(uint16_t num_lists, 
					   REGFI_SUBKEY_LIST** lists,
					   bool strict)
{
  uint32_t i,j,k;
  REGFI_SUBKEY_LIST* ret_val;

  if(lists == NULL)
    return NULL;
  ret_val = talloc(NULL, REGFI_SUBKEY_LIST);

  if(ret_val == NULL)
    return NULL;
  
  /* Obtain total number of elements */
  ret_val->num_keys = 0;
  for(i=0; i < num_lists; i++)
  {
    if(lists[i] != NULL)
      ret_val->num_keys += lists[i]->num_children;
  }
  ret_val->num_children = ret_val->num_keys;

  if(ret_val->num_keys > 0)
  {
    ret_val->elements = talloc_array(ret_val, REGFI_SUBKEY_LIST_ELEM,
				     ret_val->num_keys);
    k=0;

    if(ret_val->elements != NULL)
    {
      for(i=0; i < num_lists; i++)
      {
	if(lists[i] != NULL)
	{
	  for(j=0; j < lists[i]->num_keys; j++)
	  {
	    ret_val->elements[k].hash = lists[i]->elements[j].hash;
	    ret_val->elements[k++].offset = lists[i]->elements[j].offset;
	  }
	}
      }
    }
  }
  
  for(i=0; i < num_lists; i++)
    talloc_free(lists[i]);
  free(lists);

  return ret_val;
}


/******************************************************************************
 *
 ******************************************************************************/
REGFI_SK* regfi_parse_sk(REGFI_FILE* file, uint32_t offset, uint32_t max_size, 
			     bool strict)
{
  REGFI_SK* ret_val = NULL;
  uint8_t* sec_desc_buf = NULL;
  uint32_t cell_length, length;
  uint8_t sk_header[REGFI_SK_MIN_LENGTH];
  bool unalloc = false;

  if(!regfi_lock(file, &file->cb_lock, "regfi_parse_sk"))
     goto fail;

  if(!regfi_parse_cell(file->cb, offset, sk_header, REGFI_SK_MIN_LENGTH,
		       &cell_length, &unalloc))
  {
    regfi_log_add(REGFI_LOG_WARN, "Could not parse SK record cell"
		      " at offset 0x%.8X.", offset);
    goto fail_locked;
  }
   
  if(sk_header[0] != 's' || sk_header[1] != 'k')
  {
    regfi_log_add(REGFI_LOG_WARN, "Magic number mismatch in parsing"
		      " SK record at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  ret_val = talloc(NULL, REGFI_SK);
  if(ret_val == NULL)
    goto fail_locked;

  ret_val->offset = offset;
  /* XXX: Is there a way to be more conservative (shorter) with 
   *      cell length when cell is unallocated?
   */
  ret_val->cell_size = cell_length;

  if(ret_val->cell_size > max_size)
    ret_val->cell_size = max_size & 0xFFFFFFF8;
  if((ret_val->cell_size < REGFI_SK_MIN_LENGTH) 
     || (strict && (ret_val->cell_size & 0x00000007) != 0))
  {
    regfi_log_add(REGFI_LOG_WARN, "Invalid cell size found while"
		      " parsing SK record at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  ret_val->magic[0] = sk_header[0];
  ret_val->magic[1] = sk_header[1];

  ret_val->unknown_tag = SVAL(sk_header, 0x2);
  ret_val->prev_sk_off = IVAL(sk_header, 0x4);
  ret_val->next_sk_off = IVAL(sk_header, 0x8);
  ret_val->ref_count = IVAL(sk_header, 0xC);
  ret_val->desc_size = IVAL(sk_header, 0x10);

  if((ret_val->prev_sk_off & 0x00000007) != 0
     || (ret_val->next_sk_off & 0x00000007) != 0)
  {
    regfi_log_add(REGFI_LOG_WARN, "SK record's next/previous offsets"
		      " are not a multiple of 8 while parsing SK record at"
		      " offset 0x%.8X.", offset);
    goto fail_locked;
  }

  if(ret_val->desc_size + REGFI_SK_MIN_LENGTH > ret_val->cell_size)
  {
    regfi_log_add(REGFI_LOG_WARN, "Security descriptor too large for"
		      " cell while parsing SK record at offset 0x%.8X.", 
		      offset);
    goto fail_locked;
  }

  sec_desc_buf = (uint8_t*)malloc(ret_val->desc_size);
  if(sec_desc_buf == NULL)
    goto fail_locked;

  length = ret_val->desc_size;
  if(regfi_read(file->cb, sec_desc_buf, &length) != 0 
     || length != ret_val->desc_size)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to read security"
		      " descriptor while parsing SK record at offset 0x%.8X.",
		      offset);
    goto fail_locked;
  }

  if(!regfi_unlock(file, &file->cb_lock, "regfi_parse_sk"))
     goto fail;

  if(!(ret_val->sec_desc = winsec_parse_desc(ret_val, sec_desc_buf, 
						   ret_val->desc_size)))
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to parse security"
		      " descriptor while parsing SK record at offset 0x%.8X.",
		      offset);
    goto fail;
  }

  free(sec_desc_buf);
  return ret_val;

 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_parse_sk");
 fail:
  if(sec_desc_buf != NULL)
    free(sec_desc_buf);
  talloc_free(ret_val);
  return NULL;
}


REGFI_VALUE_LIST* regfi_parse_valuelist(REGFI_FILE* file, uint32_t offset, 
					uint32_t num_values, bool strict)
{
  REGFI_VALUE_LIST* ret_val;
  uint32_t i, cell_length, length, read_len;
  bool unalloc;

  if(!regfi_lock(file, &file->cb_lock, "regfi_parse_valuelist"))
     goto fail;

  if(!regfi_parse_cell(file->cb, offset, NULL, 0, &cell_length, &unalloc))
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to read cell header"
		      " while parsing value list at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  if((cell_length & 0x00000007) != 0)
  {
    regfi_log_add(REGFI_LOG_WARN, "Cell length not a multiple of 8"
		      " while parsing value list at offset 0x%.8X.", offset);
    if(strict)
      goto fail_locked;
    cell_length = cell_length & 0xFFFFFFF8;
  }

  if((num_values * sizeof(uint32_t)) > cell_length-sizeof(uint32_t))
  {
    regfi_log_add(REGFI_LOG_WARN, "Too many values found"
		      " while parsing value list at offset 0x%.8X.", offset);
    if(strict)
      goto fail_locked;
    num_values = cell_length/sizeof(uint32_t) - sizeof(uint32_t);
  }

  read_len = num_values*sizeof(uint32_t);
  ret_val = talloc(NULL, REGFI_VALUE_LIST);
  if(ret_val == NULL)
    goto fail_locked;

  ret_val->elements = (REGFI_VALUE_LIST_ELEM*)talloc_size(ret_val, read_len);
  if(ret_val->elements == NULL)
    goto fail_locked;

  ret_val->offset = offset;
  ret_val->cell_size = cell_length;
  ret_val->num_values = num_values;

  length = read_len;
  if((regfi_read(file->cb, (uint8_t*)ret_val->elements, &length) != 0) 
     || length != read_len)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to read value pointers"
		      " while parsing value list at offset 0x%.8X.", offset);
    goto fail_locked;
  }
  
  if(!regfi_unlock(file, &file->cb_lock, "regfi_parse_valuelist"))
     goto fail;

  for(i=0; i < num_values; i++)
  {
    /* Fix endianness */
    ret_val->elements[i] = IVAL(&ret_val->elements[i], 0);

    /* Validate the first num_values values to ensure they make sense */
    if(strict)
    {
      /* XXX: Need to revisit this file length check when we start dealing 
       *      with partial files. */
      if((ret_val->elements[i] + REGFI_REGF_SIZE > file->file_length)
	 || ((ret_val->elements[i] & 0x00000007) != 0))
      {
	regfi_log_add(REGFI_LOG_WARN, "Invalid value pointer"
			  " (0x%.8X) found while parsing value list at offset"
			  " 0x%.8X.", ret_val->elements[i], offset);
	goto fail;
      }
    }
  }

  return ret_val;

 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_parse_valuelist");
 fail:
  talloc_free(ret_val);
  return NULL;
}

/* XXX: should give this boolean return type to indicate errors */
void regfi_interpret_valuename(REGFI_FILE* file, REGFI_VK* vk, 
			       REGFI_ENCODING output_encoding, bool strict)
{
  /* XXX: Registry value names are supposedly limited to 16383 characters 
   *      according to:
   *      http://msdn.microsoft.com/en-us/library/ms724872%28VS.85%29.aspx
   *      Might want to emit a warning if this is exceeded.  
   *      It is expected that "characters" could be variable width.
   *      Also, it may be useful to use this information to limit false positives
   *      when recovering deleted VK records.
   */
  int32_t tmp_size;
  REGFI_ENCODING from_encoding = (vk->flags & REGFI_VK_FLAG_ASCIINAME)
    ? REGFI_ENCODING_ASCII : REGFI_ENCODING_UTF16LE;

  if(vk->name_length == 0)
    return;

  if(from_encoding == output_encoding)
  {
    vk->name_raw[vk->name_length] = '\0';
    vk->name = (char*)vk->name_raw;
  }
  else
  {
    vk->name = talloc_array(vk, char, vk->name_length+1);
    if(vk->name == NULL)
      return;

    tmp_size = regfi_conv_charset(regfi_encoding_int2str(from_encoding),
				  regfi_encoding_int2str(output_encoding),
				  vk->name_raw, vk->name,
				  vk->name_length, vk->name_length+1);
    if(tmp_size < 0)
    {
      regfi_log_add(REGFI_LOG_WARN, "Error occurred while converting"
			" value name to encoding %s.  Error message: %s",
			regfi_encoding_int2str(output_encoding), 
			strerror(-tmp_size));
      talloc_free(vk->name);
      vk->name = NULL;
    }
  }
}


/******************************************************************************
 ******************************************************************************/
REGFI_VK* regfi_load_value(REGFI_FILE* file, uint32_t offset, 
			   REGFI_ENCODING output_encoding, bool strict)
{
  REGFI_VK* ret_val = NULL;
  int32_t max_size;

  max_size = regfi_calc_maxsize(file, offset);
  if(max_size < 0)
    return NULL;
  
  ret_val = regfi_parse_vk(file, offset, max_size, strict);
  if(ret_val == NULL)
    return NULL;

  regfi_interpret_valuename(file, ret_val, output_encoding, strict);

  return ret_val;
}


/******************************************************************************
 * If !strict, the list may contain NULLs, VK records may point to NULL.
 ******************************************************************************/
REGFI_VALUE_LIST* regfi_load_valuelist(REGFI_FILE* file, uint32_t offset, 
				       uint32_t num_values, uint32_t max_size,
				       bool strict)
{
  uint32_t usable_num_values;

  if((num_values+1) * sizeof(uint32_t) > max_size)
  {
    regfi_log_add(REGFI_LOG_WARN, "Number of values indicated by"
		      " parent key (%d) would cause cell to straddle HBIN"
		      " boundary while loading value list at offset"
		      " 0x%.8X.", num_values, offset);
    if(strict)
      return NULL;
    usable_num_values = max_size/sizeof(uint32_t) - sizeof(uint32_t);
  }
  else
    usable_num_values = num_values;

  return regfi_parse_valuelist(file, offset, usable_num_values, strict);
}


/* XXX: should give this boolean return type to indicate errors */
void regfi_interpret_keyname(REGFI_FILE* file, REGFI_NK* nk, 
			     REGFI_ENCODING output_encoding, bool strict)
{
  /* XXX: Registry key names are supposedly limited to 255 characters according to:
   *      http://msdn.microsoft.com/en-us/library/ms724872%28VS.85%29.aspx
   *      Might want to emit a warning if this is exceeded.  
   *      It is expected that "characters" could be variable width.
   *      Also, it may be useful to use this information to limit false positives
   *      when recovering deleted NK records.
   */
  int32_t tmp_size;
  REGFI_ENCODING from_encoding = (nk->flags & REGFI_NK_FLAG_ASCIINAME) 
    ? REGFI_ENCODING_ASCII : REGFI_ENCODING_UTF16LE;

  if(nk->name_length == 0)
    return;  

  if(from_encoding == output_encoding)
  {
    nk->name_raw[nk->name_length] = '\0';
    nk->name = (char*)nk->name_raw;
  }
  else
  {
    nk->name = talloc_array(nk, char, nk->name_length+1);
    if(nk->name == NULL)
      return;

    memset(nk->name,0,nk->name_length+1);

    tmp_size = regfi_conv_charset(regfi_encoding_int2str(from_encoding),
				  regfi_encoding_int2str(output_encoding),
				  nk->name_raw, nk->name,
				  nk->name_length, nk->name_length+1);
    if(tmp_size < 0)
    {
      regfi_log_add(REGFI_LOG_WARN, "Error occurred while converting"
			" key name to encoding %s.  Error message: %s",
			regfi_encoding_int2str(output_encoding), 
			strerror(-tmp_size));
      talloc_free(nk->name);
      nk->name = NULL;
    }
  }
}


/******************************************************************************
 *
 ******************************************************************************/
REGFI_NK* regfi_load_key(REGFI_FILE* file, uint32_t offset,
			 REGFI_ENCODING output_encoding, bool strict)
{
  REGFI_NK* nk;
  uint32_t off;
  int32_t max_size;

  if(file->nk_cache != NULL)
  {
    /* First, check to see if we have this key in our cache */
    if(!regfi_lock(file, &file->mem_lock, "regfi_load_nk"))
      return NULL;
    regfi_lock(file, &file->nk_lock, "regfi_load_nk");
    
    nk = (REGFI_NK*)lru_cache_find(file->nk_cache, &offset, 4);
    if(nk != NULL)
      nk = talloc_reference(NULL, nk);

    regfi_unlock(file, &file->nk_lock, "regfi_load_nk");
    regfi_unlock(file, &file->mem_lock, "regfi_load_nk");
    if(nk != NULL)
      return nk;
  }

  /* Not cached currently, proceed with loading it */
  max_size = regfi_calc_maxsize(file, offset);
  if (max_size < 0) 
    return NULL;

  /* get the initial nk record */
  if((nk = regfi_parse_nk(file, offset, max_size, true)) == NULL)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Could not load NK record at"
		  " offset 0x%.8X.", offset);
    return NULL;
  }

  regfi_interpret_keyname(file, nk, output_encoding, strict);

  /* get value list */
  if(nk->num_values && (nk->values_off!=REGFI_OFFSET_NONE)) 
  {
    off = nk->values_off + REGFI_REGF_SIZE;
    max_size = regfi_calc_maxsize(file, off);
    if(max_size < 0)
    {
      if(strict)
      {
	talloc_free(nk);
	return NULL;
      }
      else
	nk->values = NULL;
    }
    else
    {
      nk->values = regfi_load_valuelist(file, off, nk->num_values, 
					max_size, true);
      if(nk->values == NULL)
      {
	regfi_log_add(REGFI_LOG_WARN, "Could not load value list"
		      " for NK record at offset 0x%.8X.", offset);
	if(strict)
	{
	  talloc_free(nk);
	  return NULL;
	}
      }
      talloc_reparent(NULL, nk, nk->values);
    }
  }

  /* now get subkey list */
  if(nk->num_subkeys && (nk->subkeys_off != REGFI_OFFSET_NONE)) 
  {
    off = nk->subkeys_off + REGFI_REGF_SIZE;
    max_size = regfi_calc_maxsize(file, off);
    if(max_size < 0) 
    {
      if(strict)
      {
	talloc_free(nk);
	return NULL;
      }
      else
	nk->subkeys = NULL;
    }
    else
    {
      nk->subkeys = regfi_load_subkeylist(file, off, nk->num_subkeys,
					  max_size, true);

      if(nk->subkeys == NULL)
      {
	regfi_log_add(REGFI_LOG_WARN, "Could not load subkey list"
		      " while parsing NK record at offset 0x%.8X.", offset);
	nk->num_subkeys = 0;
      }
      talloc_reparent(NULL, nk, nk->subkeys);
    }
  }

  if(file->nk_cache != NULL)
  {
    /* All is well, so let us cache this key for later */
    if(!regfi_lock(file, &file->mem_lock, "regfi_load_nk"))
      return NULL;
    regfi_lock(file, &file->nk_lock, "regfi_load_nk");
    
    lru_cache_update(file->nk_cache, &offset, 4, nk);
    
    regfi_unlock(file, &file->nk_lock, "regfi_load_nk");
    regfi_unlock(file, &file->mem_lock, "regfi_load_nk");
  }

  return nk;
}


/******************************************************************************
 ******************************************************************************/
const REGFI_SK* regfi_load_sk(REGFI_FILE* file, uint32_t offset, bool strict)
{
  REGFI_SK* ret_val = NULL;
  int32_t max_size;
  void* failure_ptr = NULL;
  
  max_size = regfi_calc_maxsize(file, offset);
  if(max_size < 0)
    return NULL;

  if(file->sk_cache == NULL)
    return regfi_parse_sk(file, offset, max_size, strict);

  if(!regfi_lock(file, &file->mem_lock, "regfi_load_sk"))
    return NULL;
  regfi_lock(file, &file->sk_lock, "regfi_load_sk");

  /* First look if we have already parsed it */
  ret_val = (REGFI_SK*)lru_cache_find(file->sk_cache, &offset, 4);

  /* Bail out if we have previously cached a parse failure at this offset. */
  if(ret_val == (void*)REGFI_OFFSET_NONE)
  {
    ret_val = NULL;
    goto unlock;
  }

  if(ret_val == NULL)
  {
    ret_val = regfi_parse_sk(file, offset, max_size, strict);
    if(ret_val == NULL)
    { /* Cache the parse failure and bail out. */
      failure_ptr = talloc(NULL, uint32_t);
      if(failure_ptr == NULL)
	goto unlock;

      *(uint32_t*)failure_ptr = REGFI_OFFSET_NONE;
      lru_cache_update(file->sk_cache, &offset, 4, failure_ptr);

      /* Let the cache be the only owner of this */
      talloc_unlink(NULL, failure_ptr);
    }
  }
  else
    ret_val = talloc_reference(NULL, ret_val);

 unlock:
  regfi_unlock(file, &file->sk_lock, "regfi_load_sk");
  regfi_unlock(file, &file->mem_lock, "regfi_load_sk");

  return ret_val;
}



/******************************************************************************
 ******************************************************************************/
REGFI_NK* regfi_find_root_nk(REGFI_FILE* file, const REGFI_HBIN* hbin, 
			     REGFI_ENCODING output_encoding)
{
  REGFI_NK* nk = NULL;
  uint32_t cell_length;
  uint32_t cur_offset = hbin->file_off+REGFI_HBIN_HEADER_SIZE;
  uint32_t hbin_end = hbin->file_off+hbin->block_size;
  bool unalloc;

  while(cur_offset < hbin_end)
  {

    if(!regfi_lock(file, &file->cb_lock, "regfi_find_root_nk"))
      return NULL;

    if(!regfi_parse_cell(file->cb, cur_offset, NULL, 0, &cell_length, &unalloc))
    {
      regfi_log_add(REGFI_LOG_WARN, "Could not parse cell at offset"
		    " 0x%.8X while searching for root key.", cur_offset);
      goto error_locked;
    }

    if(!regfi_unlock(file, &file->cb_lock, "regfi_find_root_nk"))
      return NULL;

    if(!unalloc)
    {
      nk = regfi_load_key(file, cur_offset, output_encoding, true);
      if(nk != NULL)
      {
	if(nk->flags & REGFI_NK_FLAG_ROOT)
	  return nk;
      }
    }

    cur_offset += cell_length;
  }

  return NULL;

 error_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_find_root_nk");
  return NULL;
}



/******************************************************************************
 ******************************************************************************/
REGFI_FILE* regfi_alloc(int fd, REGFI_ENCODING output_encoding)
{
  REGFI_FILE* ret_val;
  REGFI_RAW_FILE* file_cb = talloc(NULL, REGFI_RAW_FILE);
  if(file_cb == NULL) 
    return NULL;

  file_cb->state = (void*)talloc(file_cb, int);
  if(file_cb->state == NULL)
    goto fail;
  *(int*)file_cb->state = fd;
  
  file_cb->cur_off = 0;
  file_cb->size = 0;
  file_cb->read = &regfi_raw_read;
  file_cb->seek = &regfi_raw_seek;
  
  ret_val = regfi_alloc_cb(file_cb, output_encoding);
  if(ret_val == NULL)
    goto fail;

  /* In this case, we want file_cb to be freed when ret_val is */
  talloc_reparent(NULL, ret_val, file_cb);
  return ret_val;

 fail:
    talloc_free(file_cb);
    return NULL;
}


/******************************************************************************
 ******************************************************************************/
static int regfi_free_cb(void* f)
{
  REGFI_FILE* file = (REGFI_FILE*)f;

  pthread_mutex_destroy(&file->cb_lock);
  pthread_rwlock_destroy(&file->hbins_lock);
  pthread_mutex_destroy(&file->sk_lock);
  pthread_mutex_destroy(&file->nk_lock);
  pthread_mutex_destroy(&file->mem_lock);

  return 0;
}


/******************************************************************************
 ******************************************************************************/
REGFI_FILE* regfi_alloc_cb(REGFI_RAW_FILE* file_cb, 
			   REGFI_ENCODING output_encoding)
{
  REGFI_FILE* rb;
  REGFI_HBIN* hbin = NULL;
  uint32_t hbin_off, cache_secret;
  int64_t file_length;
  bool rla;

  /* Determine file length.  Must be at least big enough for the header
   * and one hbin.
   */
  file_length = regfi_seek(file_cb, 0, SEEK_END);
  if(file_length < REGFI_REGF_SIZE+REGFI_HBIN_ALLOC)
  {
    regfi_log_add(REGFI_LOG_ERROR, "File length (%d) too short to contain a"
		  " header and at least one HBIN.", file_length);
    return NULL;
  }
  regfi_seek(file_cb, 0, SEEK_SET);

  if(output_encoding != REGFI_ENCODING_UTF8
     && output_encoding != REGFI_ENCODING_ASCII)
  { 
    regfi_log_add(REGFI_LOG_ERROR, "Invalid output_encoding supplied"
		  " in creation of regfi iterator.");
    return NULL;
  }

  /* Read file header */
  if ((rb = regfi_parse_regf(file_cb, false)) == NULL)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to read REGF block.");
    return NULL;
  }
  rb->file_length = file_length;
  rb->cb = file_cb;
  rb->string_encoding = output_encoding;

  if(pthread_mutex_init(&rb->cb_lock, NULL) != 0)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to create cb_lock mutex.");
    goto fail;
  }

  if(pthread_rwlock_init(&rb->hbins_lock, NULL) != 0)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to create hbins_lock rwlock.");
    goto fail;
  }

  if(pthread_mutex_init(&rb->sk_lock, NULL) != 0)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to create sk_lock mutex.");
    goto fail;
  }

  if(pthread_mutex_init(&rb->nk_lock, NULL) != 0)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to create nk_lock mutex.");
    goto fail;
  }

  if(pthread_mutex_init(&rb->mem_lock, NULL) != 0)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to create mem_lock mutex.");
    goto fail;
  }

  rb->hbins = range_list_new();
  if(rb->hbins == NULL)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to create HBIN range_list.");
    goto fail;
  }
  talloc_reparent(NULL, rb, rb->hbins);

  rla = true;
  hbin_off = REGFI_REGF_SIZE;
  hbin = regfi_parse_hbin(rb, hbin_off, true);
  while(hbin && rla)
  {
    rla = range_list_add(rb->hbins, hbin->file_off, hbin->block_size, hbin);
    if(rla)
      talloc_reparent(NULL, rb->hbins, hbin);

    hbin_off = hbin->file_off + hbin->block_size;
    hbin = regfi_parse_hbin(rb, hbin_off, true);
  }

  /* This secret isn't very secret, but we don't need a good one.  This 
   * secret is just designed to prevent someone from trying to blow our
   * caching and make things slow.
   */
  cache_secret = 0x15DEAD05^time(NULL)^(getpid()<<16);

  rb->sk_cache = NULL;
  if(REGFI_CACHE_SK_MAX > 0)
    rb->sk_cache = lru_cache_create_ctx(rb, REGFI_CACHE_SK_MAX, 
                                        cache_secret, true);

  rb->nk_cache = NULL;
  if(REGFI_CACHE_NK_MAX > 0)
    rb->nk_cache = lru_cache_create_ctx(rb, REGFI_CACHE_NK_MAX, 
                                        cache_secret, true);

  /* success */
  talloc_set_destructor(rb, regfi_free_cb);
  return rb;

 fail:
  pthread_mutex_destroy(&rb->cb_lock);
  pthread_rwlock_destroy(&rb->hbins_lock);
  pthread_mutex_destroy(&rb->sk_lock);
  pthread_mutex_destroy(&rb->nk_lock);
  pthread_mutex_destroy(&rb->mem_lock);

  range_list_free(rb->hbins);
  talloc_free(rb);
  return NULL;
}


/******************************************************************************
 ******************************************************************************/
void regfi_free(REGFI_FILE* file)
{
  /* Callback handles cleanup side effects */
  talloc_free(file);
}


/******************************************************************************
 * First checks the offset given by the file header, then checks the
 * rest of the file if that fails.
 ******************************************************************************/
const REGFI_NK* regfi_get_rootkey(REGFI_FILE* file)
{
  REGFI_NK* nk = NULL;
  REGFI_HBIN* hbin;
  uint32_t root_offset, i, num_hbins;
  
  if(!file)
    return NULL;

  root_offset = file->root_cell+REGFI_REGF_SIZE;
  nk = regfi_load_key(file, root_offset, file->string_encoding, true);
  if(nk != NULL)
  {
    if(nk->flags & REGFI_NK_FLAG_ROOT)
      return nk;
  }

  regfi_log_add(REGFI_LOG_WARN, "File header indicated root key at"
		" location 0x%.8X, but no root key found."
		" Searching rest of file...", root_offset);
  
  /* If the file header gives bad info, scan through the file one HBIN
   * block at a time looking for an NK record with a root key type.
   */
  
  if(!regfi_read_lock(file, &file->hbins_lock, "regfi_get_rootkey"))
    return NULL;

  num_hbins = range_list_size(file->hbins);
  for(i=0; i < num_hbins && nk == NULL; i++)
  {
    hbin = (REGFI_HBIN*)range_list_get(file->hbins, i)->data;
    nk = regfi_find_root_nk(file, hbin, file->string_encoding);
  }

  if(!regfi_rw_unlock(file, &file->hbins_lock, "regfi_get_rootkey"))
    return NULL;

  return nk;
}


/******************************************************************************
 *****************************************************************************/
void regfi_free_record(REGFI_FILE* file, const void* record)
{
  if(!regfi_lock(file, &file->mem_lock, "regfi_free_record"))
    return;

  talloc_unlink(NULL, (void*)record);

  regfi_unlock(file, &file->mem_lock, "regfi_free_record");
}


/******************************************************************************
 *****************************************************************************/
const void* regfi_reference_record(REGFI_FILE* file, const void* record)
{
  const void* ret_val = NULL;

  if(!regfi_lock(file, &file->mem_lock, "regfi_reference_record"))
    return ret_val;

  ret_val = talloc_reference(NULL, record);

  regfi_unlock(file, &file->mem_lock, "regfi_reference_record");
  return ret_val;
}


/******************************************************************************
 *****************************************************************************/
uint32_t regfi_fetch_num_subkeys(const REGFI_NK* key)
{
  uint32_t num_in_list = 0;
  if(key == NULL)
    return 0;

  if(key->subkeys != NULL)
    num_in_list = key->subkeys->num_keys;

  if(num_in_list != key->num_subkeys)
  {
    regfi_log_add(REGFI_LOG_INFO, "Key at offset 0x%.8X contains %d keys in its"
		  " subkey list but reports %d should be available.", 
		  key->offset, num_in_list, key->num_subkeys);
    return (num_in_list < key->num_subkeys)?num_in_list:key->num_subkeys;
  }
  
  return num_in_list;
}


/******************************************************************************
 *****************************************************************************/
uint32_t regfi_fetch_num_values(const REGFI_NK* key)
{
  uint32_t num_in_list = 0;
  if(key == NULL)
    return 0;

  if(key->values != NULL)
    num_in_list = key->values->num_values;

  if(num_in_list != key->num_values)
  {
    regfi_log_add(REGFI_LOG_INFO, "Key at offset 0x%.8X contains %d values in"
		  " its value list but reports %d should be available.",
		  key->offset, num_in_list, key->num_values);
    return (num_in_list < key->num_values)?num_in_list:key->num_values;
  }
  
  return num_in_list;
}


/******************************************************************************
 *****************************************************************************/
REGFI_ITERATOR* regfi_iterator_new(REGFI_FILE* file)
{
  REGFI_NK* root;
  REGFI_ITERATOR* ret_val;

  ret_val = talloc(NULL, REGFI_ITERATOR);
  if(ret_val == NULL)
    return NULL;
  
  ret_val->cur = talloc(ret_val, REGFI_ITER_POSITION);
  if(ret_val->cur == NULL)
  {
    talloc_free(ret_val);
    return NULL;
  }

  ret_val->key_positions = void_stack_new(REGFI_MAX_DEPTH);
  if(ret_val->key_positions == NULL)
  {
    talloc_free(ret_val);
    return NULL;
  }
  talloc_reparent(NULL, ret_val, ret_val->key_positions);

  root = (REGFI_NK*)regfi_get_rootkey(file);
  if(root == NULL)
  {
    talloc_free(ret_val);
    return NULL;
  }

  ret_val->cur->offset = root->offset;
  if(root->subkeys_off == REGFI_OFFSET_NONE)
    ret_val->cur->num_subkeys = 0;
  else
    ret_val->cur->num_subkeys = regfi_fetch_num_subkeys(root);
  
  if(root->values_off == REGFI_OFFSET_NONE)
    ret_val->cur->num_values = 0;
  else
    ret_val->cur->num_values = regfi_fetch_num_values(root);

  ret_val->cur->cur_subkey = 0;
  ret_val->cur->cur_value = 0;
  ret_val->f = file;

  regfi_free_record(ret_val->f, root);
  return ret_val;
}


/******************************************************************************
 *****************************************************************************/
void regfi_iterator_free(REGFI_ITERATOR* i)
{
  talloc_unlink(NULL, i);
}


/******************************************************************************
 *****************************************************************************/
/* XXX: some way of indicating reason for failure should be added. */
bool regfi_iterator_down(REGFI_ITERATOR* i)
{
  REGFI_NK* subkey;
  REGFI_ITER_POSITION* pos = talloc(i, REGFI_ITER_POSITION);
  if(pos == NULL)
    return false;

  subkey = (REGFI_NK*)regfi_iterator_cur_subkey(i);
  if(subkey == NULL)
  {
    talloc_free(pos);
    return false;
  }

  if(!void_stack_push(i->key_positions, i->cur))
  {
    talloc_free(pos);
    regfi_free_record(i->f, subkey);
    return false;
  }

  pos->offset = subkey->offset;
  if(subkey->subkeys_off == REGFI_OFFSET_NONE)
    pos->num_subkeys = 0;
  else
    pos->num_subkeys = regfi_fetch_num_subkeys(subkey);

  if(subkey->values_off == REGFI_OFFSET_NONE)
    pos->num_values = 0;
  else
    pos->num_values = regfi_fetch_num_values(subkey);

  pos->cur_subkey = 0;
  pos->cur_value = 0;
  i->cur = pos;

  regfi_free_record(i->f, subkey);
  return true;
}


/******************************************************************************
 *****************************************************************************/
bool regfi_iterator_up(REGFI_ITERATOR* i)
{
  REGFI_ITER_POSITION* pos;

  pos = (REGFI_ITER_POSITION*)void_stack_pop(i->key_positions);
  if(pos == NULL)
    return false;

  if(!regfi_lock(i->f, &i->f->mem_lock, "regfi_iterator_up"))
    return false;
  
  talloc_unlink(i, i->cur);

  regfi_unlock(i->f, &i->f->mem_lock, "regfi_iterator_up");

  i->cur = pos;
  return true;
}


/******************************************************************************
 *****************************************************************************/
bool regfi_iterator_to_root(REGFI_ITERATOR* i)
{
  while(regfi_iterator_up(i))
    continue;

  return true;
}


/******************************************************************************
 *****************************************************************************/
bool regfi_iterator_find_subkey(REGFI_ITERATOR* i, const char* name)
{
  const REGFI_NK* cur_key;
  uint32_t new_index;
  bool ret_val = false;

  cur_key = regfi_iterator_cur_key(i);
  if(cur_key == NULL)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Current key invalid in find_subkey.");
    return ret_val;
  }

  if(regfi_find_subkey(i->f, cur_key, name, &new_index))
  {
    i->cur->cur_subkey = new_index;
    ret_val = true;
  }

  regfi_free_record(i->f, cur_key);
  return ret_val;
}


/******************************************************************************
 *****************************************************************************/
bool regfi_iterator_descend(REGFI_ITERATOR* i, const char** path)
{
  uint32_t x;
  if(path == NULL)
    return false;

  for(x=0; 
      ((path[x] != NULL) && regfi_iterator_find_subkey(i, path[x])
       && regfi_iterator_down(i));
      x++)
  { continue; }

  if(path[x] == NULL)
  {
    return true;
  }

  /* XXX: is this the right number of times? */
  for(; x > 0; x--)
    regfi_iterator_up(i);
  
  return false;
}


/******************************************************************************
 *****************************************************************************/
const REGFI_NK* regfi_iterator_cur_key(REGFI_ITERATOR* i)
{
  const REGFI_NK* ret_val = NULL;

  ret_val = regfi_load_key(i->f, i->cur->offset, i->f->string_encoding, true);
  return ret_val;
}


/******************************************************************************
 *****************************************************************************/
const REGFI_SK* regfi_fetch_sk(REGFI_FILE* file, const REGFI_NK* key)
{
  if(key == NULL || key->sk_off == REGFI_OFFSET_NONE)
    return NULL;

  return regfi_load_sk(file, key->sk_off + REGFI_REGF_SIZE, true);
}


/******************************************************************************
 *****************************************************************************/
const REGFI_SK* regfi_next_sk(REGFI_FILE* file, const REGFI_SK* sk)
{
  if(sk == NULL || sk->next_sk_off == REGFI_OFFSET_NONE)
    return NULL;

  return regfi_load_sk(file, sk->next_sk_off + REGFI_REGF_SIZE, true);
}


/******************************************************************************
 *****************************************************************************/
const REGFI_SK* regfi_prev_sk(REGFI_FILE* file, const REGFI_SK* sk)
{
  if(sk == NULL || sk->prev_sk_off == REGFI_OFFSET_NONE)
    return NULL;

  return regfi_load_sk(file, sk->prev_sk_off + REGFI_REGF_SIZE, true);
}


/******************************************************************************
 *****************************************************************************/
bool regfi_iterator_first_subkey(REGFI_ITERATOR* i)
{
  i->cur->cur_subkey = 0;
  return (i->cur->cur_subkey < i->cur->num_subkeys);
}


/******************************************************************************
 *****************************************************************************/
const REGFI_NK* regfi_iterator_cur_subkey(REGFI_ITERATOR* i)
{
  const REGFI_NK* cur_key;
  const REGFI_NK* ret_val;
  
  cur_key = regfi_iterator_cur_key(i);
  if(cur_key == NULL)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Current key invalid in cur_subkey.");
    return NULL;
  }

  ret_val = regfi_get_subkey(i->f, cur_key, i->cur->cur_subkey);

  regfi_free_record(i->f, cur_key);
  return ret_val;
}


/******************************************************************************
 *****************************************************************************/
bool regfi_iterator_next_subkey(REGFI_ITERATOR* i)
{
  i->cur->cur_subkey++;
  return (i->cur->cur_subkey < i->cur->num_subkeys);
}


/******************************************************************************
 *****************************************************************************/
bool regfi_iterator_find_value(REGFI_ITERATOR* i, const char* name)
{
  const REGFI_NK* cur_key;
  uint32_t new_index;
  bool ret_val = false;

  cur_key = regfi_iterator_cur_key(i);
  if(cur_key == NULL)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Current key invalid in find_value.");
    return ret_val;
  }

  if(regfi_find_value(i->f, cur_key, name, &new_index))
  {
    i->cur->cur_value = new_index;
    ret_val = true;
  }

  regfi_free_record(i->f, cur_key);
  return ret_val;
}


/******************************************************************************
 *****************************************************************************/
bool regfi_iterator_first_value(REGFI_ITERATOR* i)
{
  i->cur->cur_value = 0;
  return (i->cur->cur_value < i->cur->num_values);
}


/******************************************************************************
 *****************************************************************************/
const REGFI_VK* regfi_iterator_cur_value(REGFI_ITERATOR* i)
{
  const REGFI_NK* cur_key;
  const REGFI_VK* ret_val = NULL;

  cur_key = regfi_iterator_cur_key(i);
  if(cur_key == NULL)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Current key invalid in cur_value.");
    return ret_val;
  }

  ret_val = regfi_get_value(i->f, cur_key, i->cur->cur_value);
  
  regfi_free_record(i->f, cur_key);
  return ret_val;
}


/******************************************************************************
 *****************************************************************************/
bool regfi_iterator_next_value(REGFI_ITERATOR* i)
{
  i->cur->cur_value++;
  return (i->cur->cur_value < i->cur->num_values);
}




/******************************************************************************
 *****************************************************************************/
const REGFI_NK** regfi_iterator_ancestry(REGFI_ITERATOR* i)
{
  REGFI_NK** ret_val;
  void_stack_iterator* iter;
  const REGFI_ITER_POSITION* cur;
  uint16_t k, num_keys;

  num_keys = void_stack_size(i->key_positions)+1;
  ret_val = talloc_array(NULL, REGFI_NK*, num_keys+1);
  if(ret_val == NULL)
    return NULL;

  iter = void_stack_iterator_new(i->key_positions);
  if (iter == NULL)
  {
    talloc_free(ret_val);
    return NULL;
  }

  k=0;
  for(cur=void_stack_iterator_next(iter);
      cur != NULL; cur=void_stack_iterator_next(iter))
  { 
    ret_val[k++] = regfi_load_key(i->f, cur->offset, i->f->string_encoding, true); 
  }
  ret_val[k] = regfi_load_key(i->f, i->cur->offset, i->f->string_encoding, true);
  void_stack_iterator_free(iter);

  if(!regfi_lock(i->f, &i->f->mem_lock, "regfi_iterator_ancestry"))
  {
    talloc_free(ret_val);
    return NULL;
  }

  for(k=0; k<num_keys; k++)
    talloc_reparent(NULL, ret_val, ret_val[k]);

  regfi_unlock(i->f, &i->f->mem_lock, "regfi_iterator_ancestry");

  ret_val[k] = NULL;
  return (const REGFI_NK**)ret_val;
}


/******************************************************************************
 *****************************************************************************/
const REGFI_CLASSNAME* regfi_fetch_classname(REGFI_FILE* file,
					     const REGFI_NK* key)
{
  REGFI_CLASSNAME* ret_val;
  uint8_t* raw;
  char* interpreted;
  uint32_t offset;
  int32_t conv_size, max_size;
  uint16_t parse_length;

  if(key->classname_off == REGFI_OFFSET_NONE || key->classname_length == 0)
    return NULL;

  offset = key->classname_off + REGFI_REGF_SIZE;
  max_size = regfi_calc_maxsize(file, offset);
  if(max_size <= 0)
    return NULL;

  parse_length = key->classname_length;
  raw = regfi_parse_classname(file, offset, &parse_length, max_size, true);
  
  if(raw == NULL)
  {
    regfi_log_add(REGFI_LOG_WARN, "Could not parse class"
		  " name at offset 0x%.8X for key record at offset 0x%.8X.",
		  offset, key->offset);
    return NULL;
  }

  ret_val = talloc(NULL, REGFI_CLASSNAME);
  if(ret_val == NULL)
    return NULL;

  ret_val->offset = offset;
  ret_val->raw = raw;
  ret_val->size = parse_length;
  talloc_reparent(NULL, ret_val, raw);

  interpreted = talloc_array(NULL, char, parse_length);

  conv_size = regfi_conv_charset(regfi_encoding_int2str(REGFI_ENCODING_UTF16LE),
				 regfi_encoding_int2str(file->string_encoding),
				 raw, interpreted,
				 parse_length, parse_length);
  if(conv_size < 0)
  {
    regfi_log_add(REGFI_LOG_WARN, "Error occurred while"
		  " converting classname to charset %s.  Error message: %s",
		  file->string_encoding, strerror(-conv_size));
    talloc_free(interpreted);
    ret_val->interpreted = NULL;
  }
  else
  {
    /* XXX: check for NULL return here? */
    interpreted = talloc_realloc(NULL, interpreted, char, conv_size);
    ret_val->interpreted = interpreted;
    talloc_reparent(NULL, ret_val, interpreted);
  }

  return ret_val;
}


/******************************************************************************
 *****************************************************************************/
const REGFI_DATA* regfi_fetch_data(REGFI_FILE* file, 
				   const REGFI_VK* value)
{
  REGFI_DATA* ret_val = NULL;
  REGFI_BUFFER raw_data;

  if(value->data_size != 0)
  {
    raw_data = regfi_load_data(file, value->data_off, value->data_size,
			       value->data_in_offset, true);
    if(raw_data.buf == NULL)
    {
      regfi_log_add(REGFI_LOG_WARN, "Could not parse data record"
		    " while parsing VK record at offset 0x%.8X.",
		    value->offset);
    }
    else
    {
      ret_val = regfi_buffer_to_data(raw_data);

      if(ret_val == NULL)
      {
	regfi_log_add(REGFI_LOG_WARN, "Error occurred in converting"
		      " data buffer to data structure while interpreting "
		      "data for VK record at offset 0x%.8X.",
		      value->offset);
	talloc_free(raw_data.buf);
	return NULL;
      }

      if(!regfi_interpret_data(file, file->string_encoding, 
			       value->type, ret_val))
      {
	regfi_log_add(REGFI_LOG_INFO, "Error occurred while"
		      " interpreting data for VK record at offset 0x%.8X.",
		      value->offset);
      }
    }
  }
  
  return ret_val;
}



/******************************************************************************
 *****************************************************************************/
bool regfi_find_subkey(REGFI_FILE* file, const REGFI_NK* key, 
		       const char* name, uint32_t* index)
{
  const REGFI_NK* cur;
  uint32_t i;
  uint32_t num_subkeys = regfi_fetch_num_subkeys(key);
  bool found = false;

  /* XXX: should we allow "(default)" subkey names? 
   *      Do realistically they exist?
   */
  if(name == NULL)
    return false;

  for(i=0; (i < num_subkeys) && (found == false); i++)
  {
    cur = regfi_get_subkey(file, key, i);
    if(cur == NULL)
      return false;

    /* A NULL name signifies the "(default)" value for a key */
    if(cur->name != NULL && (strcasecmp(cur->name, name) == 0))
    {
      found = true;
      *index = i;
    }

    regfi_free_record(file, cur);
  }

  return found;
}



/******************************************************************************
 *****************************************************************************/
bool regfi_find_value(REGFI_FILE* file, const REGFI_NK* key, 
		      const char* name, uint32_t* index)
{
  const REGFI_VK* cur;
  uint32_t i;
  uint32_t num_values = regfi_fetch_num_values(key);
  bool found = false;

  for(i=0; (i < num_values) && (found == false); i++)
  {
    cur = regfi_get_value(file, key, i);
    if(cur == NULL)
      return false;

    /* A NULL name signifies the "(default)" value for a key */
    if(((name == NULL) && (cur->name == NULL))
       || ((name != NULL) && (cur->name != NULL) 
           && (strcasecmp(cur->name, name) == 0)))
    {
      found = true;
      *index = i;
    }

    regfi_free_record(file, cur);
  }

  return found;
}



/******************************************************************************
 *****************************************************************************/
const REGFI_NK* regfi_get_subkey(REGFI_FILE* file, const REGFI_NK* key, 
				 uint32_t index)
{
  if(index < regfi_fetch_num_subkeys(key))
  {
    return regfi_load_key(file, 
			  key->subkeys->elements[index].offset+REGFI_REGF_SIZE,
			  file->string_encoding, true);
  }

  return NULL;
}


/******************************************************************************
 *****************************************************************************/
const REGFI_VK* regfi_get_value(REGFI_FILE* file, const REGFI_NK* key, 
				uint32_t index)
{
  if(index < regfi_fetch_num_values(key))
  {
    return regfi_load_value(file, 
			    key->values->elements[index]+REGFI_REGF_SIZE,
			    file->string_encoding, true);
  }

  return NULL;  
}



/******************************************************************************
 *****************************************************************************/
const REGFI_NK* regfi_get_parentkey(REGFI_FILE* file, const REGFI_NK* key)
{
  if(key != NULL && key->parent_off != REGFI_OFFSET_NONE)
    return regfi_load_key(file, 
                          key->parent_off+REGFI_REGF_SIZE,
                          file->string_encoding, true);

  return NULL;
}



/******************************************************************************
 *****************************************************************************/
REGFI_DATA* regfi_buffer_to_data(REGFI_BUFFER raw_data)
{
  REGFI_DATA* ret_val;

  if(raw_data.buf == NULL)
    return NULL;

  ret_val = talloc(NULL, REGFI_DATA);
  if(ret_val == NULL)
    return NULL;
  
  talloc_reparent(NULL, ret_val, raw_data.buf);
  ret_val->raw = raw_data.buf;
  ret_val->size = raw_data.len;
  ret_val->interpreted_size = 0;
  ret_val->interpreted.qword = 0;

  return ret_val;
}


/******************************************************************************
 *****************************************************************************/
bool regfi_interpret_data(REGFI_FILE* file, REGFI_ENCODING string_encoding,
			  uint32_t type, REGFI_DATA* data)
{
  uint8_t** tmp_array;
  uint8_t* tmp_str;
  int32_t tmp_size;
  uint32_t i, j, array_size;

  if(data == NULL)
    return false;

  switch (type)
  {
  case REG_SZ:
  case REG_EXPAND_SZ:
  /* REG_LINK is a symbolic link, stored as a unicode string. */
  case REG_LINK:
    tmp_str = talloc_array(NULL, uint8_t, data->size);
    if(tmp_str == NULL)
    {
      data->interpreted.string = NULL;
      data->interpreted_size = 0;
      return false;
    }
      
    tmp_size = regfi_conv_charset(regfi_encoding_int2str(REGFI_ENCODING_UTF16LE),
				  regfi_encoding_int2str(string_encoding),
				  data->raw, (char*)tmp_str, 
				  data->size, data->size);
    if(tmp_size < 0)
    {
      regfi_log_add(REGFI_LOG_INFO, "Error occurred while"
		    " converting data of type %d to %d.  Error message: %s",
		    type, string_encoding, strerror(-tmp_size));
      talloc_free(tmp_str);
      data->interpreted.string = NULL;
      data->interpreted_size = 0;
      return false;
    }

    tmp_str = talloc_realloc(NULL, tmp_str, uint8_t, tmp_size);
    if(tmp_str == NULL)
      return false;
    data->interpreted.string = tmp_str;
    data->interpreted_size = tmp_size;
    talloc_reparent(NULL, data, tmp_str);
    break;

  case REG_DWORD:
    if(data->size < 4)
    {
      data->interpreted.dword = 0;
      data->interpreted_size = 0;
      return false;
    }
    data->interpreted.dword = IVAL(data->raw, 0);
    data->interpreted_size = 4;
    break;

  case REG_DWORD_BE:
    if(data->size < 4)
    {
      data->interpreted.dword_be = 0;
      data->interpreted_size = 0;
      return false;
    }
    data->interpreted.dword_be = RIVAL(data->raw, 0);
    data->interpreted_size = 4;
    break;

  case REG_QWORD:
    if(data->size < 8)
    {
      data->interpreted.qword = 0;
      data->interpreted_size = 0;
      return false;
    }
    data->interpreted.qword = 
      (uint64_t)IVAL(data->raw, 0) + (((uint64_t)IVAL(data->raw, 4))<<32);
    data->interpreted_size = 8;
    break;
    
  case REG_MULTI_SZ:
    tmp_str = talloc_array(NULL, uint8_t, data->size);
    if(tmp_str == NULL)
    {
      data->interpreted.multiple_string = NULL;
      data->interpreted_size = 0;
      return false;
    }

    /* Attempt to convert entire string from UTF-16LE to output encoding,
     * then parse and quote fields individually.
     */
    tmp_size = regfi_conv_charset(regfi_encoding_int2str(REGFI_ENCODING_UTF16LE),
				  regfi_encoding_int2str(string_encoding),
				  data->raw, (char*)tmp_str,
				  data->size, data->size);
    if(tmp_size < 0)
    {
      regfi_log_add(REGFI_LOG_INFO, "Error occurred while"
		    " converting data of type %d to %s.  Error message: %s",
		    type, string_encoding, strerror(-tmp_size));
      talloc_free(tmp_str);
      data->interpreted.multiple_string = NULL;
      data->interpreted_size = 0;
      return false;
    }

    array_size = tmp_size+1;
    tmp_array = talloc_array(NULL, uint8_t*, array_size);
    if(tmp_array == NULL)
    {
      talloc_free(tmp_str);
      data->interpreted.string = NULL;
      data->interpreted_size = 0;
      return false;
    }
    
    tmp_array[0] = tmp_str;
    for(i=0,j=1; i < tmp_size && j < array_size-1; i++)
    {
      if(tmp_str[i] == '\0' && (i+1 < tmp_size) && tmp_str[i+1] != '\0')
	tmp_array[j++] = tmp_str+i+1;
    }
    tmp_array[j] = NULL;
    tmp_array = talloc_realloc(NULL, tmp_array, uint8_t*, j+1);
    data->interpreted.multiple_string = tmp_array;
    /* XXX: how meaningful is this?  should we store number of strings instead? */
    data->interpreted_size = tmp_size;
    talloc_reparent(NULL, tmp_array, tmp_str);
    talloc_reparent(NULL, data, tmp_array);
    break;

  /* XXX: Dont know how to interpret these yet, just treat as binary */
  case REG_NONE:
    data->interpreted.none = data->raw;
    data->interpreted_size = data->size;
    break;

  case REG_RESOURCE_LIST:
    data->interpreted.resource_list = data->raw;
    data->interpreted_size = data->size;
    break;

  case REG_FULL_RESOURCE_DESCRIPTOR:
    data->interpreted.full_resource_descriptor = data->raw;
    data->interpreted_size = data->size;
    break;

  case REG_RESOURCE_REQUIREMENTS_LIST:
    data->interpreted.resource_requirements_list = data->raw;
    data->interpreted_size = data->size;
    break;

  case REG_BINARY:
    data->interpreted.binary = data->raw;
    data->interpreted_size = data->size;
    break;

  default:
    data->interpreted.qword = 0;
    data->interpreted_size = 0;
    return false;
  }

  data->type = type;
  return true;
}


/******************************************************************************
 * Convert from UTF-16LE to specified character set. 
 * On error, returns a negative errno code.
 *****************************************************************************/
int32_t regfi_conv_charset(const char* input_charset, const char* output_charset,
			   uint8_t* input, char* output, 
			   uint32_t input_len, uint32_t output_max)
{
  iconv_t conv_desc;
  char* inbuf = (char*)input;
  char* outbuf = output;
  size_t in_len = (size_t)input_len;
  size_t out_len = (size_t)(output_max-1);
  int ret;

  /* XXX: Consider creating a couple of conversion descriptors earlier,
   *      storing them on an iterator so they don't have to be recreated
   *      each time.
   */

  /* Set up conversion descriptor. */
  conv_desc = iconv_open(output_charset, input_charset);

  ret = iconv(conv_desc, &inbuf, &in_len, &outbuf, &out_len);
  if(ret == -1)
  {
    iconv_close(conv_desc);
    return -errno;
  }
  *outbuf = '\0';

  iconv_close(conv_desc);  
  return output_max-out_len-1;
}



/*******************************************************************
 * Computes the checksum of the registry file header.
 * buffer must be at least the size of a regf header (4096 bytes).
 *******************************************************************/
static uint32_t regfi_compute_header_checksum(uint8_t* buffer)
{
  uint32_t checksum, x;
  int i;

  /* XOR of all bytes 0x0000 - 0x01FB */

  checksum = x = 0;
  
  for ( i=0; i<0x01FB; i+=4 ) {
    x = IVAL(buffer, i );
    checksum ^= x;
  }
  
  return checksum;
}


/*******************************************************************
 *******************************************************************/
REGFI_FILE* regfi_parse_regf(REGFI_RAW_FILE* file_cb, bool strict)
{
  uint8_t file_header[REGFI_REGF_SIZE];
  uint32_t length;
  REGFI_FILE* ret_val;

  ret_val = talloc(NULL, REGFI_FILE);
  if(ret_val == NULL)
    return NULL;

  ret_val->sk_cache = NULL;
  ret_val->hbins = NULL;

  length = REGFI_REGF_SIZE;
  if((regfi_read(file_cb, file_header, &length)) != 0 
     || length != REGFI_REGF_SIZE)
  {
    regfi_log_add(REGFI_LOG_WARN, "Read failed while parsing REGF structure.");
    goto fail;
  }

  ret_val->checksum = IVAL(file_header, 0x1FC);
  ret_val->computed_checksum = regfi_compute_header_checksum(file_header);
  if (strict && (ret_val->checksum != ret_val->computed_checksum))
  {
    regfi_log_add(REGFI_LOG_WARN, "Stored header checksum (%.8X) did not equal"
		  " computed checksum (%.8X).",
		  ret_val->checksum, ret_val->computed_checksum);
    if(strict)
      goto fail;
  }

  memcpy(ret_val->magic, file_header, REGFI_REGF_MAGIC_SIZE);
  if(memcmp(ret_val->magic, "regf", REGFI_REGF_MAGIC_SIZE) != 0)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Magic number mismatch "
		  "(%.2X %.2X %.2X %.2X) while parsing hive header",
		  ret_val->magic[0], ret_val->magic[1], 
		  ret_val->magic[2], ret_val->magic[3]);
    goto fail;
  }

  ret_val->sequence1 = IVAL(file_header, 0x4);
  ret_val->sequence2 = IVAL(file_header, 0x8);
  ret_val->mtime = ((uint64_t)IVAL(file_header, 0x10)) << 32;
  ret_val->mtime |= IVAL(file_header, 0xC);
  ret_val->major_version = IVAL(file_header, 0x14);
  ret_val->minor_version = IVAL(file_header, 0x18);
  ret_val->type = IVAL(file_header, 0x1C);
  ret_val->format = IVAL(file_header, 0x20);
  ret_val->root_cell = IVAL(file_header, 0x24);
  ret_val->last_block = IVAL(file_header, 0x28);
  ret_val->cluster = IVAL(file_header, 0x2C);

  memcpy(ret_val->file_name, file_header+0x30,  REGFI_REGF_NAME_SIZE);

  ret_val->rm_id = winsec_parse_uuid(ret_val, file_header+0x70, 16);
  if(ret_val->rm_id == NULL)
    regfi_log_add(REGFI_LOG_WARN, "Hive header's rm_id failed to parse.");

  ret_val->log_id = winsec_parse_uuid(ret_val, file_header+0x80, 16);
  if(ret_val->log_id == NULL)
    regfi_log_add(REGFI_LOG_WARN, "Hive header's log_id failed to parse.");

  ret_val->flags = IVAL(file_header, 0x90);

  ret_val->tm_id = winsec_parse_uuid(ret_val, file_header+0x94, 16);
  if(ret_val->tm_id == NULL)
    regfi_log_add(REGFI_LOG_WARN, "Hive header's tm_id failed to parse.");

  ret_val->guid_signature = IVAL(file_header, 0xa4);

  memcpy(ret_val->reserved1, file_header+0xa8, REGFI_REGF_RESERVED1_SIZE);
  memcpy(ret_val->reserved2, file_header+0x200, REGFI_REGF_RESERVED2_SIZE);

  ret_val->thaw_tm_id = winsec_parse_uuid(ret_val, file_header+0xFC8, 16);
  ret_val->thaw_rm_id = winsec_parse_uuid(ret_val, file_header+0xFD8, 16);
  ret_val->thaw_log_id = winsec_parse_uuid(ret_val, file_header+0xFE8, 16);
  ret_val->boot_type = IVAL(file_header, 0xFF8);
  ret_val->boot_recover = IVAL(file_header, 0xFFC);

  return ret_val;

 fail:
  talloc_free(ret_val);
  return NULL;
}



/******************************************************************************
 * Given real file offset, read and parse the hbin at that location
 * along with it's associated cells.
 ******************************************************************************/
REGFI_HBIN* regfi_parse_hbin(REGFI_FILE* file, uint32_t offset, bool strict)
{
  REGFI_HBIN* hbin = NULL;
  uint8_t hbin_header[REGFI_HBIN_HEADER_SIZE];
  uint32_t length;
  
  if(offset >= file->file_length)
    goto fail;
  
  if(!regfi_lock(file, &file->cb_lock, "regfi_parse_hbin"))
    goto fail;

  if(regfi_seek(file->cb, offset, SEEK_SET) == -1)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Seek failed"
		  " while parsing hbin at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  length = REGFI_HBIN_HEADER_SIZE;
  if((regfi_read(file->cb, hbin_header, &length) != 0) 
     || length != REGFI_HBIN_HEADER_SIZE)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Read failed"
		  " while parsing hbin at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  if(!regfi_unlock(file, &file->cb_lock, "regfi_parse_hbin"))
    goto fail;

  hbin = talloc(NULL, REGFI_HBIN);
  if(hbin == NULL)
    goto fail;
  hbin->file_off = offset;

  memcpy(hbin->magic, hbin_header, 4);
  if(strict && (memcmp(hbin->magic, "hbin", 4) != 0))
  {
    /* This always seems to happen at the end of a file, so we make it an INFO
     * message, rather than something more serious.
     */
    regfi_log_add(REGFI_LOG_INFO, "Magic number mismatch "
		  "(%.2X %.2X %.2X %.2X) while parsing hbin at offset"
		  " 0x%.8X.", hbin->magic[0], hbin->magic[1], 
		  hbin->magic[2], hbin->magic[3], offset);
    goto fail;
  }

  hbin->first_hbin_off = IVAL(hbin_header, 0x4);
  hbin->block_size = IVAL(hbin_header, 0x8);
  /* this should be the same thing as hbin->block_size, but just in case */
  hbin->next_block = IVAL(hbin_header, 0x1C);


  /* Ensure the block size is a multiple of 0x1000 and doesn't run off 
   * the end of the file. 
   */
  /* XXX: This may need to be relaxed for dealing with 
   *      partial or corrupt files. 
   */
  if((offset + hbin->block_size > file->file_length)
     || (hbin->block_size & 0xFFFFF000) != hbin->block_size)
  {
    regfi_log_add(REGFI_LOG_ERROR, "The hbin offset is not aligned"
		  " or runs off the end of the file"
		  " while parsing hbin at offset 0x%.8X.", offset);
    goto fail;
  }

  return hbin;

 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_parse_hbin");
 fail:
  talloc_free(hbin);
  return NULL;
}


/*******************************************************************
 *******************************************************************/
REGFI_NK* regfi_parse_nk(REGFI_FILE* file, uint32_t offset, 
			 uint32_t max_size, bool strict)
{
  uint8_t nk_header[REGFI_NK_MIN_LENGTH];
  REGFI_NK* ret_val;
  uint32_t length,cell_length;
  bool unalloc = false;

  ret_val = talloc(NULL, REGFI_NK);
  if(ret_val == NULL)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to allocate memory while"
		  " parsing NK record at offset 0x%.8X.", offset);
    goto fail;
  }

  if(!regfi_lock(file, &file->cb_lock, "regfi_parse_nk"))
    goto fail;

  if(!regfi_parse_cell(file->cb, offset, nk_header, REGFI_NK_MIN_LENGTH,
		       &cell_length, &unalloc))
  {
    regfi_log_add(REGFI_LOG_WARN, "Could not parse cell header"
		  " while parsing NK record at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  if((nk_header[0x0] != 'n') || (nk_header[0x1] != 'k'))
  {
    regfi_log_add(REGFI_LOG_WARN, "Magic number mismatch in parsing"
		  " NK record at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  ret_val->values = NULL;
  ret_val->subkeys = NULL;
  ret_val->offset = offset;
  ret_val->cell_size = cell_length;

  if(ret_val->cell_size > max_size)
    ret_val->cell_size = max_size & 0xFFFFFFF8;
  if((ret_val->cell_size < REGFI_NK_MIN_LENGTH) 
     || (strict && (ret_val->cell_size & 0x00000007) != 0))
  {
    regfi_log_add(REGFI_LOG_WARN, "A length check failed while"
		  " parsing NK record at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  ret_val->magic[0] = nk_header[0x0];
  ret_val->magic[1] = nk_header[0x1];
  ret_val->flags = SVAL(nk_header, 0x2);
  
  if((ret_val->flags & ~REGFI_NK_KNOWN_FLAGS) != 0)
  {
    regfi_log_add(REGFI_LOG_WARN, "Unknown key flags (0x%.4X) while"
		  " parsing NK record at offset 0x%.8X.", 
		  (ret_val->flags & ~REGFI_NK_KNOWN_FLAGS), offset);
  }

  ret_val->mtime = ((uint64_t)IVAL(nk_header, 0x8)) << 32;
  ret_val->mtime |= IVAL(nk_header, 0x4);
  /* If the key is unallocated and the MTIME is earlier than Jan 1, 1990
   * or later than Jan 1, 2290, we consider this a bad key.  This helps
   * weed out some false positives during deleted data recovery.
   */
  if(unalloc
     && (ret_val->mtime < REGFI_MTIME_MIN
	 || ret_val->mtime > REGFI_MTIME_MAX))
  { goto fail_locked; }

  ret_val->unknown1 = IVAL(nk_header, 0xC);
  ret_val->parent_off = IVAL(nk_header, 0x10);
  ret_val->num_subkeys = IVAL(nk_header, 0x14);
  ret_val->unknown2 = IVAL(nk_header, 0x18);
  ret_val->subkeys_off = IVAL(nk_header, 0x1C);
  ret_val->unknown3 = IVAL(nk_header, 0x20);
  ret_val->num_values = IVAL(nk_header, 0x24);
  ret_val->values_off = IVAL(nk_header, 0x28);
  ret_val->sk_off = IVAL(nk_header, 0x2C);
  ret_val->classname_off = IVAL(nk_header, 0x30);

  ret_val->max_bytes_subkeyname = IVAL(nk_header, 0x34);
  ret_val->max_bytes_subkeyclassname = IVAL(nk_header, 0x38);
  ret_val->max_bytes_valuename = IVAL(nk_header, 0x3C);
  ret_val->max_bytes_value = IVAL(nk_header, 0x40);
  ret_val->unk_index = IVAL(nk_header, 0x44);

  ret_val->name_length = SVAL(nk_header, 0x48);
  ret_val->classname_length = SVAL(nk_header, 0x4A);
  ret_val->name = NULL;

  if(ret_val->name_length + REGFI_NK_MIN_LENGTH > ret_val->cell_size)
  {
    if(strict)
    {
      regfi_log_add(REGFI_LOG_ERROR, "Contents too large for cell"
		    " while parsing NK record at offset 0x%.8X.", offset);
      goto fail_locked;
    }
    else
      ret_val->name_length = ret_val->cell_size - REGFI_NK_MIN_LENGTH;
  }
  else if (unalloc)
  { /* Truncate cell_size if it's much larger than the apparent total record length. */
    /* Round up to the next multiple of 8 */
    length = (ret_val->name_length + REGFI_NK_MIN_LENGTH) & 0xFFFFFFF8;
    if(length < ret_val->name_length + REGFI_NK_MIN_LENGTH)
      length+=8;

    /* If cell_size is still greater, truncate. */
    if(length < ret_val->cell_size)
      ret_val->cell_size = length;
  }

  /* +1 to length in case we decided to use this directly as a string later */
  ret_val->name_raw = talloc_array(ret_val, uint8_t, ret_val->name_length+1);
  if(ret_val->name_raw == NULL)
    goto fail_locked;

  /* Don't need to seek, should be at the right offset */
  length = ret_val->name_length;
  if((regfi_read(file->cb, (uint8_t*)ret_val->name_raw, &length) != 0)
     || length != ret_val->name_length)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Failed to read key name"
		  " while parsing NK record at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  if(!regfi_unlock(file, &file->cb_lock, "regfi_parse_nk"))
    goto fail;

  return ret_val;

 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_parse_nk");
 fail:
  talloc_free(ret_val);
  return NULL;
}


uint8_t* regfi_parse_classname(REGFI_FILE* file, uint32_t offset, 
			       uint16_t* name_length, uint32_t max_size, bool strict)
{
  uint8_t* ret_val = NULL;
  uint32_t length;
  uint32_t cell_length;
  bool unalloc = false;

  if(*name_length <= 0 || offset == REGFI_OFFSET_NONE  
     || (offset & 0x00000007) != 0)
  { goto fail; }

  if(!regfi_lock(file, &file->cb_lock, "regfi_parse_classname"))
    goto fail;

  if(!regfi_parse_cell(file->cb, offset, NULL, 0, &cell_length, &unalloc))
  {
    regfi_log_add(REGFI_LOG_WARN, "Could not parse cell header"
		  " while parsing class name at offset 0x%.8X.", offset);
    goto fail_locked;
  }
  
  if((cell_length & 0x0000007) != 0)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Cell length not a multiple of 8"
		  " while parsing class name at offset 0x%.8X.", offset);
    goto fail_locked;
  }
  
  if(cell_length > max_size)
  {
    regfi_log_add(REGFI_LOG_WARN, "Cell stretches past hbin "
		  "boundary while parsing class name at offset 0x%.8X.",
		  offset);
    if(strict)
      goto fail_locked;
    cell_length = max_size;
  }
  
  if((cell_length - 4) < *name_length)
  {
    regfi_log_add(REGFI_LOG_WARN, "Class name is larger than"
		  " cell_length while parsing class name at offset"
		  " 0x%.8X.", offset);
    if(strict)
      goto fail_locked;
    *name_length = cell_length - 4;
  }
  
  ret_val = talloc_array(NULL, uint8_t, *name_length);
  if(ret_val != NULL)
  {
    length = *name_length;
    if((regfi_read(file->cb, ret_val, &length) != 0)
       || length != *name_length)
    {
      regfi_log_add(REGFI_LOG_ERROR, "Could not read class name"
		    " while parsing class name at offset 0x%.8X.", offset);
      goto fail_locked;
    }
  }

  if(!regfi_unlock(file, &file->cb_lock, "regfi_parse_classname"))
    goto fail;

  return ret_val;

 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_parse_classname");
 fail:
  talloc_free(ret_val);
  return NULL;
}


/******************************************************************************
*******************************************************************************/
REGFI_VK* regfi_parse_vk(REGFI_FILE* file, uint32_t offset, 
			     uint32_t max_size, bool strict)
{
  REGFI_VK* ret_val;
  uint8_t vk_header[REGFI_VK_MIN_LENGTH];
  uint32_t raw_data_size, length, cell_length;
  bool unalloc = false;

  ret_val = talloc(NULL, REGFI_VK);
  if(ret_val == NULL)
    goto fail;

  if(!regfi_lock(file, &file->cb_lock, "regfi_parse_nk"))
    goto fail;

  if(!regfi_parse_cell(file->cb, offset, vk_header, REGFI_VK_MIN_LENGTH,
		       &cell_length, &unalloc))
  {
    regfi_log_add(REGFI_LOG_WARN, "Could not parse cell header"
		  " while parsing VK record at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  ret_val->offset = offset;
  ret_val->cell_size = cell_length;
  ret_val->name = NULL;
  ret_val->name_raw = NULL;
  
  if(ret_val->cell_size > max_size)
    ret_val->cell_size = max_size & 0xFFFFFFF8;
  if((ret_val->cell_size < REGFI_VK_MIN_LENGTH) 
     || (ret_val->cell_size & 0x00000007) != 0)
  {
    regfi_log_add(REGFI_LOG_WARN, "Invalid cell size encountered"
		  " while parsing VK record at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  ret_val->magic[0] = vk_header[0x0];
  ret_val->magic[1] = vk_header[0x1];
  if((ret_val->magic[0] != 'v') || (ret_val->magic[1] != 'k'))
  {
    /* XXX: This does not account for deleted keys under Win2K which
     *      often have this (and the name length) overwritten with
     *      0xFFFF. 
     */
    regfi_log_add(REGFI_LOG_WARN, "Magic number mismatch"
		  " while parsing VK record at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  ret_val->name_length = SVAL(vk_header, 0x2);
  raw_data_size = IVAL(vk_header, 0x4);
  ret_val->data_size = raw_data_size & ~REGFI_VK_DATA_IN_OFFSET;
  /* The data is typically stored in the offset if the size <= 4, 
   * in which case this flag is set. 
   */
  ret_val->data_in_offset = (bool)(raw_data_size & REGFI_VK_DATA_IN_OFFSET);
  ret_val->data_off = IVAL(vk_header, 0x8);
  ret_val->type = IVAL(vk_header, 0xC);
  ret_val->flags = SVAL(vk_header, 0x10);
  ret_val->unknown1 = SVAL(vk_header, 0x12);

  if(ret_val->name_length > 0)
  {
    if(ret_val->name_length + REGFI_VK_MIN_LENGTH + 4 > ret_val->cell_size)
    {
      regfi_log_add(REGFI_LOG_WARN, "Name too long for remaining cell"
		    " space while parsing VK record at offset 0x%.8X.",
		    offset);
      if(strict)
	goto fail_locked;
      else
	ret_val->name_length = ret_val->cell_size - REGFI_VK_MIN_LENGTH - 4;
    }

    /* Round up to the next multiple of 8 */
    cell_length = (ret_val->name_length + REGFI_VK_MIN_LENGTH + 4) & 0xFFFFFFF8;
    if(cell_length < ret_val->name_length + REGFI_VK_MIN_LENGTH + 4)
      cell_length+=8;

    /* +1 to length in case we decided to use this directly as a string later */
    ret_val->name_raw = talloc_array(ret_val, uint8_t, ret_val->name_length+1);
    if(ret_val->name_raw == NULL)
      goto fail_locked;

    length = ret_val->name_length;
    if((regfi_read(file->cb, (uint8_t*)ret_val->name_raw, &length) != 0)
       || length != ret_val->name_length)
    {
      regfi_log_add(REGFI_LOG_ERROR, "Could not read value name"
		    " while parsing VK record at offset 0x%.8X.", offset);
      goto fail_locked;
    }
  }
  else
    cell_length = REGFI_VK_MIN_LENGTH + 4;

  if(!regfi_unlock(file, &file->cb_lock, "regfi_parse_nk"))
    goto fail;

  if(unalloc)
  {
    /* If cell_size is still greater, truncate. */
    if(cell_length < ret_val->cell_size)
      ret_val->cell_size = cell_length;
  }

  return ret_val;
  
 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_parse_vk");
 fail:
  talloc_free(ret_val);
  return NULL;
}


/******************************************************************************
 *
 ******************************************************************************/
REGFI_BUFFER regfi_load_data(REGFI_FILE* file, uint32_t voffset,
			     uint32_t length, bool data_in_offset,
			     bool strict)
{
  REGFI_BUFFER ret_val;
  uint32_t cell_length, offset;
  int32_t max_size;
  bool unalloc;
  
  /* Microsoft's documentation indicates that "available memory" is 
   * the limit on value sizes for the more recent registry format version.
   * This is not only annoying, but it's probably also incorrect, since clearly
   * value data sizes are limited to 2^31 (high bit used as a flag) and even 
   * with big data records, the apparent max size is:
   *   16344 * 2^16 = 1071104040 (~1GB).
   *
   * We choose to limit it to 1M which was the limit in older versions and 
   * should rarely be exceeded unless the file is corrupt or malicious. 
   * For more info, see:
   *   http://msdn.microsoft.com/en-us/library/ms724872%28VS.85%29.aspx
   */
  /* XXX: add way to skip this check at user discression. */
  if(length > REGFI_VK_MAX_DATA_LENGTH)
  {
    regfi_log_add(REGFI_LOG_WARN, "Value data size %d larger than "
		  "%d, truncating...", length, REGFI_VK_MAX_DATA_LENGTH);
    length = REGFI_VK_MAX_DATA_LENGTH;
  }

  if(data_in_offset)
    return regfi_parse_little_data(file, voffset, length, strict);
  else
  {
    offset = voffset + REGFI_REGF_SIZE;
    max_size = regfi_calc_maxsize(file, offset);
    if(max_size < 0)
    {
      regfi_log_add(REGFI_LOG_WARN, "Could not find HBIN for data"
		    " at offset 0x%.8X.", offset);
      goto fail;
    }
    
    if(!regfi_lock(file, &file->cb_lock, "regfi_load_data"))
      goto fail;

    if(!regfi_parse_cell(file->cb, offset, NULL, 0,
			 &cell_length, &unalloc))
    {
      regfi_log_add(REGFI_LOG_WARN, "Could not parse cell while"
		    " parsing data record at offset 0x%.8X.", offset);
      goto fail_locked;
    }

    if(!regfi_unlock(file, &file->cb_lock, "regfi_load_data"))
      goto fail;

    if((cell_length & 0x00000007) != 0)
    {
      regfi_log_add(REGFI_LOG_WARN, "Cell length not multiple of 8"
		    " while parsing data record at offset 0x%.8X.",
		    offset);
      goto fail;
    }

    if(cell_length > max_size)
    {
      regfi_log_add(REGFI_LOG_WARN, "Cell extends past HBIN boundary"
		    " while parsing data record at offset 0x%.8X.",
		    offset);
      goto fail;
    }

    if(cell_length - 4 < length)
    {
      /* XXX: All big data records thus far have been 16 bytes long.  
       *      Should we check for this precise size instead of just 
       *      relying upon the above check?
       */
      if (file->major_version >= 1 && file->minor_version >= 5)
      {
	/* Attempt to parse a big data record */
	return regfi_load_big_data(file, offset, length, cell_length, 
				   NULL, strict);
      }
      else
      {
	regfi_log_add(REGFI_LOG_WARN, "Data length (0x%.8X) larger than"
		      " remaining cell length (0x%.8X)"
		      " while parsing data record at offset 0x%.8X.", 
		      length, cell_length - 4, offset);
	if(strict)
	  goto fail;
	else
	  length = cell_length - 4;
      }
    }

    ret_val = regfi_parse_data(file, offset, length, strict);
  }

  return ret_val;

 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_load_data");
 fail:
  ret_val.buf = NULL;
  ret_val.len = 0;
  return ret_val;
}


/******************************************************************************
 * Parses the common case data records stored in a single cell.
 ******************************************************************************/
REGFI_BUFFER regfi_parse_data(REGFI_FILE* file, uint32_t offset,
			      uint32_t length, bool strict)
{
  REGFI_BUFFER ret_val;
  uint32_t read_length;

  ret_val.buf = NULL;
  ret_val.len = 0;
  
  if((ret_val.buf = talloc_array(NULL, uint8_t, length)) == NULL)
    goto fail;
  ret_val.len = length;

  if(!regfi_lock(file, &file->cb_lock, "regfi_parse_data"))
    goto fail;

  if(regfi_seek(file->cb, offset+4, SEEK_SET) == -1)
  {
    regfi_log_add(REGFI_LOG_WARN, "Could not seek while "
		  "reading data at offset 0x%.8X.", offset);
    goto fail_locked;
  }
  
  read_length = length;
  if((regfi_read(file->cb, ret_val.buf, &read_length) != 0)
     || read_length != length)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Could not read data block while"
		  " parsing data record at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  if(!regfi_unlock(file, &file->cb_lock, "regfi_parse_data"))
    goto fail;

  return ret_val;

 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_parse_data");
 fail:
  talloc_free(ret_val.buf);
  ret_val.buf = NULL;
  ret_val.buf = 0;
  return ret_val;
}



/******************************************************************************
 *
 ******************************************************************************/
REGFI_BUFFER regfi_parse_little_data(REGFI_FILE* file, uint32_t voffset,
				     uint32_t length, bool strict)
{
  uint8_t i;
  REGFI_BUFFER ret_val;

  ret_val.buf = NULL;
  ret_val.len = 0;

  if(length > 4)
  {
    regfi_log_add(REGFI_LOG_ERROR, "Data in offset but length > 4"
		  " while parsing data record. (voffset=0x%.8X, length=%d)",
		  voffset, length);
    return ret_val;
  }

  if((ret_val.buf = talloc_array(NULL, uint8_t, length)) == NULL)
    return ret_val;
  ret_val.len = length;
  
  for(i = 0; i < length; i++)
    ret_val.buf[i] = (uint8_t)((voffset >> i*8) & 0xFF);

  return ret_val;
}

/******************************************************************************
*******************************************************************************/
REGFI_BUFFER regfi_parse_big_data_header(REGFI_FILE* file, uint32_t offset, 
					 uint32_t max_size, bool strict)
{
  REGFI_BUFFER ret_val;
  uint32_t cell_length;
  bool unalloc;

  /* XXX: do something with unalloc? */
  ret_val.buf = (uint8_t*)talloc_array(NULL, uint8_t, REGFI_BIG_DATA_MIN_LENGTH);
  if(ret_val.buf == NULL)
    goto fail;

  if(REGFI_BIG_DATA_MIN_LENGTH > max_size)
  {
    regfi_log_add(REGFI_LOG_WARN, "Big data header exceeded max_size "
		  "while parsing big data header at offset 0x%.8X.",offset);
    goto fail;
  }

  if(!regfi_lock(file, &file->cb_lock, "regfi_parse_big_data_header"))
    goto fail;


  if(!regfi_parse_cell(file->cb, offset, ret_val.buf, REGFI_BIG_DATA_MIN_LENGTH,
		       &cell_length, &unalloc))
  {
    regfi_log_add(REGFI_LOG_WARN, "Could not parse cell while"
		  " parsing big data header at offset 0x%.8X.", offset);
    goto fail_locked;
  }

  if(!regfi_unlock(file, &file->cb_lock, "regfi_parse_big_data_header"))
    goto fail;

  if((ret_val.buf[0] != 'd') || (ret_val.buf[1] != 'b'))
  {
    regfi_log_add(REGFI_LOG_WARN, "Unknown magic number"
		  " (0x%.2X, 0x%.2X) encountered while parsing"
		  " big data header at offset 0x%.8X.", 
		  ret_val.buf[0], ret_val.buf[1], offset);
    goto fail;
  }

  ret_val.len = REGFI_BIG_DATA_MIN_LENGTH;
  return ret_val;

 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_parse_big_data_header");
 fail:
  talloc_free(ret_val.buf);
  ret_val.buf = NULL;
  ret_val.len = 0;
  return ret_val;
}



/******************************************************************************
 *
 ******************************************************************************/
uint32_t* regfi_parse_big_data_indirect(REGFI_FILE* file, uint32_t offset,
				      uint16_t num_chunks, bool strict)
{
  uint32_t* ret_val;
  uint32_t indirect_length;
  int32_t max_size;
  uint16_t i;
  bool unalloc;

  /* XXX: do something with unalloc? */
  max_size = regfi_calc_maxsize(file, offset);
  if((max_size < 0) || (num_chunks*sizeof(uint32_t) + 4 > max_size))
    return NULL;

  ret_val = (uint32_t*)talloc_array(NULL, uint32_t, num_chunks);
  if(ret_val == NULL)
    goto fail;

  if(!regfi_lock(file, &file->cb_lock, "regfi_parse_big_data_indirect"))
    goto fail;

  if(!regfi_parse_cell(file->cb, offset, (uint8_t*)ret_val,
		       num_chunks*sizeof(uint32_t),
		       &indirect_length, &unalloc))
  {
    regfi_log_add(REGFI_LOG_WARN, "Could not parse cell while"
		  " parsing big data indirect record at offset 0x%.8X.", 
		  offset);
    goto fail_locked;
  }

  if(!regfi_unlock(file, &file->cb_lock, "regfi_parse_big_data_indirect"))
    goto fail;

  /* Convert pointers to proper endianess, verify they are aligned. */
  for(i=0; i<num_chunks; i++)
  {
    ret_val[i] = IVAL(ret_val, i*sizeof(uint32_t));
    if((ret_val[i] & 0x00000007) != 0)
      goto fail;
  }
  
  return ret_val;

 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_parse_big_data_indirect");
 fail:
  talloc_free(ret_val);
  return NULL;
}


/******************************************************************************
 * Arguments:
 *  file       --
 *  offsets    -- list of virtual offsets.
 *  num_chunks -- 
 *  strict     --
 *
 * Returns:
 *  A range_list with physical offsets and complete lengths 
 *  (including cell headers) of associated cells.  
 *  No data in range_list elements.
 ******************************************************************************/
range_list* regfi_parse_big_data_cells(REGFI_FILE* file, uint32_t* offsets,
				       uint16_t num_chunks, bool strict)
{
  uint32_t cell_length, chunk_offset;
  range_list* ret_val;
  uint16_t i;
  bool unalloc;
  
  /* XXX: do something with unalloc? */
  ret_val = range_list_new();
  if(ret_val == NULL)
    goto fail;
  
  for(i=0; i<num_chunks; i++)
  {
    if(!regfi_lock(file, &file->cb_lock, "regfi_parse_big_data_cells"))
      goto fail;

    chunk_offset = offsets[i]+REGFI_REGF_SIZE;
    if(!regfi_parse_cell(file->cb, chunk_offset, NULL, 0,
			 &cell_length, &unalloc))
    {
      regfi_log_add(REGFI_LOG_WARN, "Could not parse cell while"
		    " parsing big data chunk at offset 0x%.8X.", 
		    chunk_offset);
      goto fail_locked;
    }

    if(!regfi_unlock(file, &file->cb_lock, "regfi_parse_big_data_cells"))
      goto fail;

    if(!range_list_add(ret_val, chunk_offset, cell_length, NULL))
      goto fail;
  }

  return ret_val;

 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_parse_big_data_cells");
 fail:
  if(ret_val != NULL)
    range_list_free(ret_val);
  return NULL;
}


/******************************************************************************
*******************************************************************************/
REGFI_BUFFER regfi_load_big_data(REGFI_FILE* file, 
				 uint32_t offset, uint32_t data_length, 
				 uint32_t cell_length, range_list* used_ranges,
				 bool strict)
{
  REGFI_BUFFER ret_val;
  uint16_t num_chunks, i;
  uint32_t read_length, data_left, tmp_len, indirect_offset;
  uint32_t* indirect_ptrs = NULL;
  REGFI_BUFFER bd_header;
  range_list* bd_cells = NULL;
  const range_list_element* cell_info;

  ret_val.buf = NULL;

  /* XXX: Add better error/warning messages */

  bd_header = regfi_parse_big_data_header(file, offset, cell_length, strict);
  if(bd_header.buf == NULL)
    goto fail;

  /* Keep track of used space for use by reglookup-recover */
  if(used_ranges != NULL)
    if(!range_list_add(used_ranges, offset, cell_length, NULL))
      goto fail;

  num_chunks = SVAL(bd_header.buf, 0x2);
  indirect_offset = IVAL(bd_header.buf, 0x4) + REGFI_REGF_SIZE;
  talloc_free(bd_header.buf);

  indirect_ptrs = regfi_parse_big_data_indirect(file, indirect_offset,
						num_chunks, strict);
  if(indirect_ptrs == NULL)
    goto fail;

  if(used_ranges != NULL)
    if(!range_list_add(used_ranges, indirect_offset, num_chunks*4+4, NULL))
      goto fail;
  
  if((ret_val.buf = talloc_array(NULL, uint8_t, data_length)) == NULL)
    goto fail;
  data_left = data_length;

  bd_cells = regfi_parse_big_data_cells(file, indirect_ptrs, num_chunks, strict);
  if(bd_cells == NULL)
    goto fail;

  talloc_free(indirect_ptrs);
  indirect_ptrs = NULL;
  
  for(i=0; (i<num_chunks) && (data_left>0); i++)
  {
    cell_info = range_list_get(bd_cells, i);
    if(cell_info == NULL)
      goto fail;

    /* XXX: This should be "cell_info->length-4" to account for the 4 byte cell
     *      length.  However, it has been observed that some (all?) chunks
     *      have an additional 4 bytes of 0 at the end of their cells that 
     *      isn't part of the data, so we're trimming that off too. 
     *      Perhaps it's just an 8 byte alignment requirement...
     */
    if(cell_info->length - 8 >= data_left)
    {
      if(i+1 != num_chunks)
      {
	regfi_log_add(REGFI_LOG_WARN, "Left over chunks detected "
		      "while constructing big data at offset 0x%.8X "
		      "(chunk offset 0x%.8X).", offset, cell_info->offset);
      }
      read_length = data_left;
    }
    else
      read_length = cell_info->length - 8;


    if(read_length > regfi_calc_maxsize(file, cell_info->offset))
    {
      regfi_log_add(REGFI_LOG_WARN, "A chunk exceeded the maxsize "
		    "while constructing big data at offset 0x%.8X "
		    "(chunk offset 0x%.8X).", offset, cell_info->offset);
      goto fail;
    }

    if(!regfi_lock(file, &file->cb_lock, "regfi_load_big_data"))
      goto fail;

    if(regfi_seek(file->cb, cell_info->offset+sizeof(uint32_t), SEEK_SET) == -1)
    {
      regfi_log_add(REGFI_LOG_WARN, "Could not seek to chunk while "
		    "constructing big data at offset 0x%.8X "
		    "(chunk offset 0x%.8X).", offset, cell_info->offset);
      goto fail_locked;
    }

    tmp_len = read_length;
    if(regfi_read(file->cb, ret_val.buf+(data_length-data_left), 
		  &read_length) != 0 || (read_length != tmp_len))
    {
      regfi_log_add(REGFI_LOG_WARN, "Could not read data chunk while"
		    " constructing big data at offset 0x%.8X"
		    " (chunk offset 0x%.8X).", offset, cell_info->offset);
      goto fail_locked;
    }

    if(!regfi_unlock(file, &file->cb_lock, "regfi_load_big_data"))
      goto fail;

    if(used_ranges != NULL)
      if(!range_list_add(used_ranges, cell_info->offset,cell_info->length,NULL))
	goto fail;

    data_left -= read_length;
  }
  range_list_free(bd_cells);

  ret_val.len = data_length-data_left;
  return ret_val;

 fail_locked:
  regfi_unlock(file, &file->cb_lock, "regfi_load_big_data");
 fail:
  talloc_free(ret_val.buf);
  talloc_free(indirect_ptrs);
  if(bd_cells != NULL)
    range_list_free(bd_cells);
  ret_val.buf = NULL;
  ret_val.len = 0;
  return ret_val;
}


range_list* regfi_parse_unalloc_cells(REGFI_FILE* file)
{
  range_list* ret_val;
  REGFI_HBIN* hbin;
  const range_list_element* hbins_elem;
  uint32_t i, num_hbins, curr_off, cell_len;
  bool is_unalloc;

  ret_val = range_list_new();
  if(ret_val == NULL)
    return NULL;

  if(!regfi_read_lock(file, &file->hbins_lock, "regfi_parse_unalloc_cells"))
  {
    range_list_free(ret_val);
    return NULL;
  }

  num_hbins = range_list_size(file->hbins);
  for(i=0; i<num_hbins; i++)
  {
    hbins_elem = range_list_get(file->hbins, i);
    if(hbins_elem == NULL)
      break;
    hbin = (REGFI_HBIN*)hbins_elem->data;

    curr_off = REGFI_HBIN_HEADER_SIZE;
    while(curr_off < hbin->block_size)
    {
      if(!regfi_lock(file, &file->cb_lock, "regfi_parse_unalloc_cells"))
	break;

      if(!regfi_parse_cell(file->cb, hbin->file_off+curr_off, NULL, 0,
			   &cell_len, &is_unalloc))
      {
	regfi_unlock(file, &file->cb_lock, "regfi_parse_unalloc_cells");
	break;
      }

      if(!regfi_unlock(file, &file->cb_lock, "regfi_parse_unalloc_cells"))
	break;

      if((cell_len == 0) || ((cell_len & 0x00000007) != 0))
      {
	regfi_log_add(REGFI_LOG_ERROR, "Bad cell length encountered"
		      " while parsing unallocated cells at offset 0x%.8X.",
		      hbin->file_off+curr_off);
	break;
      }

      /* for some reason the record_size of the last record in
	 an hbin block can extend past the end of the block
	 even though the record fits within the remaining 
	 space....aaarrrgggghhhhhh */  
      if(curr_off + cell_len >= hbin->block_size)
	cell_len = hbin->block_size - curr_off;
      
      if(is_unalloc)
	range_list_add(ret_val, hbin->file_off+curr_off, 
		       cell_len, NULL);
      
      curr_off = curr_off+cell_len;
    }
  }

  if(!regfi_rw_unlock(file, &file->hbins_lock, "regfi_parse_unalloc_cells"))
  {
    range_list_free(ret_val);
    return NULL;
  }

  return ret_val;
}


/* From lib/time.c */

/****************************************************************************
 Returns an 8 byte filetime from a time_t
 This takes real GMT as input and converts to kludge-GMT
****************************************************************************/
REGFI_NTTIME regfi_unix2nt_time(time_t t)
{
  double d;

  if (t==0)
    return 0L;
  
  if (t == TIME_T_MAX) 
    return 0x7fffffffffffffffL;
  
  if (t == -1) 
    return 0xffffffffffffffffL;
  
  /* this converts GMT to kludge-GMT */
  /* XXX: This was removed due to difficult dependency requirements.  
   *      So far, times appear to be correct without this adjustment, but 
   *      that may be proven wrong with adequate testing. 
   */
  /* t -= TimeDiff(t) - get_serverzone(); */
  
  d = (double)(t) + REGFI_TIME_FIXUP;
  d *= 1.0e7;
  /*
  nt->high = (uint32_t)(d * (1.0/c));
  nt->low  = (uint32_t)(d - ((double)nt->high) * c);
  */

  return (REGFI_NTTIME) d;
}


/****************************************************************************
 Interpret an 8 byte "filetime" structure to a time_t
 It's originally in "100ns units since jan 1st 1601"

 An 8 byte value of 0xffffffffffffffff will be returned as (time_t)0.

 It appears to be kludge-GMT (at least for file listings). This means
 its the GMT you get by taking a localtime and adding the
 serverzone. This is NOT the same as GMT in some cases. This routine
 converts this to real GMT.
****************************************************************************/
double regfi_nt2unix_time(REGFI_NTTIME nt)
{
  double ret_val;
  
  if (nt == 0 || nt == 0xffffffffffffffffL)
    return 0;
  
  ret_val = (double)(nt) * 1.0e-7;
  
  /* now adjust by 369 years to make the secs since 1970 */
  ret_val -= REGFI_TIME_FIXUP;
  
  /* this takes us from kludge-GMT to real GMT */
  /* XXX: This was removed due to difficult dependency requirements.  
   *      So far, times appear to be correct without this adjustment, but 
   *      that may be proven wrong with adequate testing. 
   */
  /*
    ret -= get_serverzone();
    ret += LocTimeDiff(ret);
  */

  return ret_val;
}

/* End of stuff from lib/time.c */
