/*
 * Branched from Samba project Subversion repository, version #7470:
 *   http://viewcvs.samba.org/cgi-bin/viewcvs.cgi/trunk/source/registry/regfio.c?rev=7470&view=auto
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

#include "regfi.h"


/* Registry types mapping */
const unsigned int regfi_num_reg_types = 12;
static const char* regfi_type_names[] =
  {"NONE", "SZ", "EXPAND_SZ", "BINARY", "DWORD", "DWORD_BE", "LINK",
   "MULTI_SZ", "RSRC_LIST", "RSRC_DESC", "RSRC_REQ_LIST", "QWORD"};



/******************************************************************************
 ******************************************************************************/
void regfi_add_message(REGFI_FILE* file, uint16 msg_type, const char* fmt, ...)
{
  /* XXX: This function is not particularly efficient,
   *      but then it is mostly used during errors. 
   */
  uint32 buf_size, buf_used;
  char* new_msg;
  va_list args;

  if((file->msg_mask & msg_type) != 0)
  {
    if(file->last_message == NULL)
      buf_used = 0;
    else
      buf_used = strlen(file->last_message);
    
    buf_size = buf_used+strlen(fmt)+160;
    new_msg = realloc(file->last_message, buf_size);
    if(new_msg == NULL)
      /* XXX: should we report this? */
      return;

    switch (msg_type)
    {
    case REGFI_MSG_INFO:
      strcpy(new_msg+buf_used, "INFO: ");
      buf_used += 6;
      break;
    case REGFI_MSG_WARN:
      strcpy(new_msg+buf_used, "WARN: ");
      buf_used += 6;
      break;
    case REGFI_MSG_ERROR:
      strcpy(new_msg+buf_used, "ERROR: ");
      buf_used += 7;
      break;
    }

    va_start(args, fmt);
    vsnprintf(new_msg+buf_used, buf_size-buf_used, fmt, args);
    va_end(args);
    strncat(new_msg, "\n", buf_size-1);
    
    file->last_message = new_msg;
  }
}


/******************************************************************************
 ******************************************************************************/
char* regfi_get_messages(REGFI_FILE* file)
{
  char* ret_val = file->last_message;
  file->last_message = NULL;

  return ret_val;
}


void regfi_set_message_mask(REGFI_FILE* file, uint16 mask)
{
  file->msg_mask = mask;
}


/* Returns NULL on error */
const char* regfi_type_val2str(unsigned int val)
{
  if(val == REG_KEY)
    return "KEY";
  
  if(val >= regfi_num_reg_types)
    return NULL;
  
  return regfi_type_names[val];
}


/* Returns -1 on error */
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

const char* regfi_ace_type2str(uint8 type)
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
char* regfi_ace_flags2str(uint8 flags)
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
  uint32 i;
  uint8 f;

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


char* regfi_ace_perms2str(uint32 perms)
{
  uint32 i, p;
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


char* regfi_sid2str(WINSEC_DOM_SID* sid)
{
  uint32 i, size = WINSEC_MAX_SUBAUTHS*11 + 24;
  uint32 left = size;
  uint8 comps = sid->num_auths;
  char* ret_val = malloc(size);
  
  if(ret_val == NULL)
    return NULL;

  if(comps > WINSEC_MAX_SUBAUTHS)
    comps = WINSEC_MAX_SUBAUTHS;

  left -= sprintf(ret_val, "S-%u-%u", sid->sid_rev_num, sid->id_auth[5]);

  for (i = 0; i < comps; i++) 
    left -= snprintf(ret_val+(size-left), left, "-%u", sid->sub_auths[i]);

  return ret_val;
}


char* regfi_get_acl(WINSEC_ACL* acl)
{
  uint32 i, extra, size = 0;
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
    sid_str = regfi_sid2str(acl->aces[i]->trustee);
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
  return regfi_sid2str(sec_desc->owner_sid);
}


char* regfi_get_group(WINSEC_DESC *sec_desc)
{
  return regfi_sid2str(sec_desc->grp_sid);
}


/*****************************************************************************
 * This function is just like read(2), except that it continues to
 * re-try reading from the file descriptor if EINTR or EAGAIN is received.  
 * regfi_read will attempt to read length bytes from fd and write them to buf.
 *
 * On success, 0 is returned.  Upon failure, an errno code is returned.
 *
 * The number of bytes successfully read is returned through the length 
 * parameter by reference.  If both the return value and length parameter are 
 * returned as 0, then EOF was encountered immediately
 *****************************************************************************/
uint32 regfi_read(int fd, uint8* buf, uint32* length)
{
  uint32 rsize = 0;
  uint32 rret = 0;

  do
  {
    rret = read(fd, buf + rsize, *length - rsize);
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
bool regfi_parse_cell(int fd, uint32 offset, uint8* hdr, uint32 hdr_len,
		      uint32* cell_length, bool* unalloc)
{
  uint32 length;
  int32 raw_length;
  uint8 tmp[4];

  if(lseek(fd, offset, SEEK_SET) == -1)
    return false;

  length = 4;
  if((regfi_read(fd, tmp, &length) != 0) || length != 4)
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
    if((regfi_read(fd, hdr, &length) != 0) || length != hdr_len)
      return false;
  }

  return true;
}


/*******************************************************************
 * Given an offset and an hbin, is the offset within that hbin?
 * The offset is a virtual file offset.
 *******************************************************************/
static bool regfi_offset_in_hbin(const REGFI_HBIN* hbin, uint32 voffset)
{
  if(!hbin)
    return false;

  if((voffset > hbin->first_hbin_off) 
     && (voffset < (hbin->first_hbin_off + hbin->block_size)))
    return true;
		
  return false;
}



/*******************************************************************
 * Provide a virtual offset and receive the correpsonding HBIN 
 * block for it.  NULL if one doesn't exist.
 *******************************************************************/
const REGFI_HBIN* regfi_lookup_hbin(REGFI_FILE* file, uint32 voffset)
{
  return (const REGFI_HBIN*)range_list_find_data(file->hbins, 
						 voffset+REGFI_REGF_SIZE);
}



/******************************************************************************
 ******************************************************************************/
REGFI_SUBKEY_LIST* regfi_load_subkeylist(REGFI_FILE* file, uint32 offset, 
					 uint32 num_keys, uint32 max_size, 
					 bool strict)
{
  REGFI_SUBKEY_LIST* ret_val;

  ret_val = regfi_load_subkeylist_aux(file, offset, max_size, strict, 
				      REGFI_MAX_SUBKEY_DEPTH);
  if(ret_val == NULL)
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Failed to load subkey list at"
		      " offset 0x%.8X.", offset);
    return NULL;
  }

  if(num_keys != ret_val->num_keys)
  {
    /*  Not sure which should be authoritative, the number from the 
     *  NK record, or the number in the subkey list.  Just emit a warning for
     *  now if they don't match.
     */
    regfi_add_message(file, REGFI_MSG_WARN, "Number of subkeys listed in parent"
		      " (%d) did not match number found in subkey list/tree (%d)"
		      " while parsing subkey list/tree at offset 0x%.8X.", 
		      num_keys, ret_val->num_keys, offset);
  }

  return ret_val;
}


/******************************************************************************
 ******************************************************************************/
REGFI_SUBKEY_LIST* regfi_load_subkeylist_aux(REGFI_FILE* file, uint32 offset, 
					     uint32 max_size, bool strict,
					     uint8 depth_left)
{
  REGFI_SUBKEY_LIST* ret_val;
  REGFI_SUBKEY_LIST** sublists;
  const REGFI_HBIN* sublist_hbin;
  uint32 i, num_sublists, off, max_length;

  if(depth_left == 0)
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Maximum depth reached"
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
      sublist_hbin = regfi_lookup_hbin(file, ret_val->elements[i].offset);
      if(sublist_hbin == NULL)
	sublists[i] = NULL;
      else
      {
	max_length = sublist_hbin->block_size + sublist_hbin->file_off - off;
	sublists[i] = regfi_load_subkeylist_aux(file, off, max_length, strict,
						depth_left-1);
      }
    }
    talloc_free(ret_val);

    return regfi_merge_subkeylists(num_sublists, sublists, strict);
  }

  return ret_val;
}


/******************************************************************************
 ******************************************************************************/
REGFI_SUBKEY_LIST* regfi_parse_subkeylist(REGFI_FILE* file, uint32 offset, 
					  uint32 max_size, bool strict)
{
  REGFI_SUBKEY_LIST* ret_val;
  uint32 i, cell_length, length, elem_size, read_len;
  uint8* elements = NULL;
  uint8 buf[REGFI_SUBKEY_LIST_MIN_LEN];
  bool unalloc;
  bool recursive_type;

  if(!regfi_parse_cell(file->fd, offset, buf, REGFI_SUBKEY_LIST_MIN_LEN, 
		       &cell_length, &unalloc))
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Could not parse cell while "
		      "parsing subkey-list at offset 0x%.8X.", offset);
    return NULL;
  }

  if(cell_length > max_size)
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Cell size longer than max_size"
		      " while parsing subkey-list at offset 0x%.8X.", offset);
    if(strict)
      return NULL;
    cell_length = max_size & 0xFFFFFFF8;
  }

  recursive_type = false;
  if(buf[0] == 'r' && buf[1] == 'i')
  {
    recursive_type = true;
    elem_size = sizeof(uint32);
  }
  else if(buf[0] == 'l' && buf[1] == 'i')
    elem_size = sizeof(uint32);
  else if((buf[0] == 'l') && (buf[1] == 'f' || buf[1] == 'h'))
    elem_size = sizeof(REGFI_SUBKEY_LIST_ELEM);
  else
  {
    regfi_add_message(file, REGFI_MSG_ERROR, "Unknown magic number"
		      " (0x%.2X, 0x%.2X) encountered while parsing"
		      " subkey-list at offset 0x%.8X.", buf[0], buf[1], offset);
    return NULL;
  }

  ret_val = talloc(NULL, REGFI_SUBKEY_LIST);
  if(ret_val == NULL)
    return NULL;

  ret_val->offset = offset;
  ret_val->cell_size = cell_length;
  ret_val->magic[0] = buf[0];
  ret_val->magic[1] = buf[1];
  ret_val->recursive_type = recursive_type;
  ret_val->num_children = SVAL(buf, 0x2);

  if(!recursive_type)
    ret_val->num_keys = ret_val->num_children;

  length = elem_size*ret_val->num_children;
  if(cell_length - REGFI_SUBKEY_LIST_MIN_LEN - sizeof(uint32) < length)
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Number of elements too large for"
		      " cell while parsing subkey-list at offset 0x%.8X.", 
		      offset);
    if(strict)
      goto fail;
    length = cell_length - REGFI_SUBKEY_LIST_MIN_LEN - sizeof(uint32);
  }

  ret_val->elements = talloc_array(ret_val, REGFI_SUBKEY_LIST_ELEM, 
				   ret_val->num_children);
  if(ret_val->elements == NULL)
    goto fail;

  elements = (uint8*)malloc(length);
  if(elements == NULL)
    goto fail;

  read_len = length;
  if(regfi_read(file->fd, elements, &read_len) != 0 || read_len != length)
    goto fail;

  if(elem_size == sizeof(uint32))
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

 fail:
  if(elements != NULL)
    free(elements);
  talloc_free(ret_val);
  return NULL;
}


/*******************************************************************
 *******************************************************************/
REGFI_SUBKEY_LIST* regfi_merge_subkeylists(uint16 num_lists, 
					   REGFI_SUBKEY_LIST** lists,
					   bool strict)
{
  uint32 i,j,k;
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
    regfi_subkeylist_free(lists[i]);
  free(lists);

  return ret_val;
}


/******************************************************************************
 *
 ******************************************************************************/
REGFI_SK_REC* regfi_parse_sk(REGFI_FILE* file, uint32 offset, uint32 max_size, 
			     bool strict)
{
  REGFI_SK_REC* ret_val;
  uint8* sec_desc_buf = NULL;
  uint32 cell_length, length;
  uint8 sk_header[REGFI_SK_MIN_LENGTH];
  bool unalloc = false;

  if(!regfi_parse_cell(file->fd, offset, sk_header, REGFI_SK_MIN_LENGTH,
		       &cell_length, &unalloc))
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Could not parse SK record cell"
		      " at offset 0x%.8X.", offset);
    return NULL;
  }
   
  if(sk_header[0] != 's' || sk_header[1] != 'k')
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Magic number mismatch in parsing"
		      " SK record at offset 0x%.8X.", offset);
    return NULL;
  }

  ret_val = talloc(NULL, REGFI_SK_REC);
  if(ret_val == NULL)
    return NULL;

  ret_val->offset = offset;
  /* XXX: Is there a way to be more conservative (shorter) with 
   *      cell length when cell is unallocated?
   */
  ret_val->cell_size = cell_length;

  if(ret_val->cell_size > max_size)
    ret_val->cell_size = max_size & 0xFFFFFFF8;
  if((ret_val->cell_size < REGFI_SK_MIN_LENGTH) 
     || (strict && ret_val->cell_size != (ret_val->cell_size & 0xFFFFFFF8)))
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Invalid cell size found while"
		      " parsing SK record at offset 0x%.8X.", offset);
    goto fail;
  }

  ret_val->magic[0] = sk_header[0];
  ret_val->magic[1] = sk_header[1];

  ret_val->unknown_tag = SVAL(sk_header, 0x2);
  ret_val->prev_sk_off = IVAL(sk_header, 0x4);
  ret_val->next_sk_off = IVAL(sk_header, 0x8);
  ret_val->ref_count = IVAL(sk_header, 0xC);
  ret_val->desc_size = IVAL(sk_header, 0x10);

  if(ret_val->prev_sk_off != (ret_val->prev_sk_off & 0xFFFFFFF8) 
     || ret_val->next_sk_off != (ret_val->next_sk_off & 0xFFFFFFF8))
  {
    regfi_add_message(file, REGFI_MSG_WARN, "SK record's next/previous offsets"
		      " are not a multiple of 8 while parsing SK record at"
		      " offset 0x%.8X.", offset);
    goto fail;
  }

  if(ret_val->desc_size + REGFI_SK_MIN_LENGTH > ret_val->cell_size)
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Security descriptor too large for"
		      " cell while parsing SK record at offset 0x%.8X.", 
		      offset);
    goto fail;
  }

  sec_desc_buf = (uint8*)malloc(ret_val->desc_size);
  if(sec_desc_buf == NULL)
    goto fail;

  length = ret_val->desc_size;
  if(regfi_read(file->fd, sec_desc_buf, &length) != 0 
     || length != ret_val->desc_size)
  {
    regfi_add_message(file, REGFI_MSG_ERROR, "Failed to read security"
		      " descriptor while parsing SK record at offset 0x%.8X.",
		      offset);
    goto fail;
  }

  if(!(ret_val->sec_desc = winsec_parse_desc(ret_val, sec_desc_buf, 
						   ret_val->desc_size)))
  {
    regfi_add_message(file, REGFI_MSG_ERROR, "Failed to parse security"
		      " descriptor while parsing SK record at offset 0x%.8X.",
		      offset);
    goto fail;
  }

  free(sec_desc_buf);
  return ret_val;

 fail:
  if(sec_desc_buf != NULL)
    free(sec_desc_buf);
  talloc_free(ret_val);
  return NULL;
}


REGFI_VALUE_LIST* regfi_parse_valuelist(REGFI_FILE* file, uint32 offset, 
					uint32 num_values, bool strict)
{
  REGFI_VALUE_LIST* ret_val;
  uint32 i, cell_length, length, read_len;
  bool unalloc;

  if(!regfi_parse_cell(file->fd, offset, NULL, 0, &cell_length, &unalloc))
  {
    regfi_add_message(file, REGFI_MSG_ERROR, "Failed to read cell header"
		      " while parsing value list at offset 0x%.8X.", offset);
    return NULL;
  }

  if(cell_length != (cell_length & 0xFFFFFFF8))
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Cell length not a multiple of 8"
		      " while parsing value list at offset 0x%.8X.", offset);
    if(strict)
      return NULL;
    cell_length = cell_length & 0xFFFFFFF8;
  }

  if((num_values * sizeof(uint32)) > cell_length-sizeof(uint32))
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Too many values found"
		      " while parsing value list at offset 0x%.8X.", offset);
    if(strict)
      return NULL;
    num_values = cell_length/sizeof(uint32) - sizeof(uint32);
  }

  read_len = num_values*sizeof(uint32);
  ret_val = talloc(NULL, REGFI_VALUE_LIST);
  if(ret_val == NULL)
    return NULL;

  ret_val->elements = (REGFI_VALUE_LIST_ELEM*)talloc_size(ret_val, read_len);
  if(ret_val->elements == NULL)
  {
    talloc_free(ret_val);
    return NULL;
  }
  ret_val->num_values = num_values;

  length = read_len;
  if((regfi_read(file->fd, (uint8*)ret_val->elements, &length) != 0) 
     || length != read_len)
  {
    regfi_add_message(file, REGFI_MSG_ERROR, "Failed to read value pointers"
		      " while parsing value list at offset 0x%.8X.", offset);
    talloc_free(ret_val);
    return NULL;
  }
  
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
	 || ((ret_val->elements[i] & 0xFFFFFFF8) != ret_val->elements[i]))
      {
	regfi_add_message(file, REGFI_MSG_WARN, "Invalid value pointer"
			  " (0x%.8X) found while parsing value list at offset"
			  " 0x%.8X.", ret_val->elements[i], offset);
	talloc_free(ret_val);
	return NULL;
      }
    }
  }

  return ret_val;
}



/******************************************************************************
 ******************************************************************************/
REGFI_VK_REC* regfi_load_value(REGFI_FILE* file, uint32 offset, bool strict)
{
  REGFI_VK_REC* ret_val = NULL;
  const REGFI_HBIN* hbin;
  uint32 data_offset, data_maxsize;
  REGFI_BUFFER data;

  hbin = regfi_lookup_hbin(file, offset - REGFI_REGF_SIZE);
  if(!hbin)
    return NULL;
  
  ret_val = regfi_parse_vk(file, offset, 
			   hbin->block_size + hbin->file_off - offset, strict);

  if(ret_val == NULL)
    return NULL;

  if(ret_val->data_size == 0)
    ret_val->data = NULL;
  else
  {
    if(ret_val->data_in_offset)
    {
      data = regfi_parse_data(file, ret_val->type, ret_val->data_off,
			      ret_val->data_size, 4,
			      ret_val->data_in_offset, strict);
      ret_val->data = data.buf;
      ret_val->data_size = data.len;
    }
    else
    {
      hbin = regfi_lookup_hbin(file, ret_val->data_off);
      if(hbin)
      {
	data_offset = ret_val->data_off+REGFI_REGF_SIZE;
	data_maxsize = hbin->block_size + hbin->file_off - data_offset;
	data = regfi_parse_data(file, ret_val->type, data_offset, 
				ret_val->data_size, data_maxsize, 
				ret_val->data_in_offset, strict);
	ret_val->data = data.buf;
	ret_val->data_size = data.len;

      }
      else
      {
	regfi_add_message(file, REGFI_MSG_WARN, "Could not find HBIN for data"
			  " while parsing VK record at offset 0x%.8X.", 
			  ret_val->offset);
	ret_val->data = NULL;
      }
    }

    if(ret_val->data == NULL)
    {
      regfi_add_message(file, REGFI_MSG_WARN, "Could not parse data record"
			" while parsing VK record at offset 0x%.8X.",
			ret_val->offset);
    }
    else
      talloc_steal(ret_val, ret_val->data);
  }

  return ret_val;
}


/******************************************************************************
 * If !strict, the list may contain NULLs, VK records may point to NULL.
 ******************************************************************************/
REGFI_VALUE_LIST* regfi_load_valuelist(REGFI_FILE* file, uint32 offset, 
				       uint32 num_values, uint32 max_size,
				       bool strict)
{
  uint32 usable_num_values;

  if((num_values+1) * sizeof(uint32) > max_size)
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Number of values indicated by"
		      " parent key (%d) would cause cell to straddle HBIN"
		      " boundary while loading value list at offset"
		      " 0x%.8X.", num_values, offset);
    if(strict)
      return NULL;
    usable_num_values = max_size/sizeof(uint32) - sizeof(uint32);
  }
  else
    usable_num_values = num_values;

  return regfi_parse_valuelist(file, offset, usable_num_values, strict);
}



/******************************************************************************
 *
 ******************************************************************************/
REGFI_NK_REC* regfi_load_key(REGFI_FILE* file, uint32 offset, bool strict)
{
  const REGFI_HBIN* hbin;
  const REGFI_HBIN* sub_hbin;
  REGFI_NK_REC* nk;
  uint32 max_length, off;

  hbin = regfi_lookup_hbin(file, offset-REGFI_REGF_SIZE);
  if (hbin == NULL) 
    return NULL;

  /* get the initial nk record */
  max_length = hbin->block_size + hbin->file_off - offset;
  if((nk = regfi_parse_nk(file, offset, max_length, true)) == NULL)
  {
    regfi_add_message(file, REGFI_MSG_ERROR, "Could not load NK record at"
		      " offset 0x%.8X.", offset);
    return NULL;
  }

  /* get value list */
  if(nk->num_values && (nk->values_off!=REGFI_OFFSET_NONE)) 
  {
    sub_hbin = hbin;
    if(!regfi_offset_in_hbin(hbin, nk->values_off)) 
      sub_hbin = regfi_lookup_hbin(file, nk->values_off);
    
    if(sub_hbin == NULL)
    {
      if(strict)
      {
	regfi_free_key(nk);
	return NULL;
      }
      else
	nk->values = NULL;

    }
    else
    {
      off = nk->values_off + REGFI_REGF_SIZE;
      max_length = sub_hbin->block_size + sub_hbin->file_off - off;
      nk->values = regfi_load_valuelist(file, off, nk->num_values, max_length, 
					true);
      if(nk->values == NULL)
      {
	regfi_add_message(file, REGFI_MSG_WARN, "Could not load value list"
			  " for NK record at offset 0x%.8X.", offset);
	if(strict)
	{
	  regfi_free_key(nk);
	  return NULL;
	}
      }
      talloc_steal(nk, nk->values);
    }
  }

  /* now get subkey list */
  if(nk->num_subkeys && (nk->subkeys_off != REGFI_OFFSET_NONE)) 
  {
    sub_hbin = hbin;
    if(!regfi_offset_in_hbin(hbin, nk->subkeys_off))
      sub_hbin = regfi_lookup_hbin(file, nk->subkeys_off);

    if(sub_hbin == NULL) 
    {
      if(strict)
      {
	regfi_free_key(nk);
	return NULL;
      }
      else
	nk->subkeys = NULL;
    }
    else
    {
      off = nk->subkeys_off + REGFI_REGF_SIZE;
      max_length = sub_hbin->block_size + sub_hbin->file_off - off;
      nk->subkeys = regfi_load_subkeylist(file, off, nk->num_subkeys,
					  max_length, true);

      if(nk->subkeys == NULL)
      {
	regfi_add_message(file, REGFI_MSG_WARN, "Could not load subkey list"
			  " while parsing NK record at offset 0x%.8X.", offset);
	nk->num_subkeys = 0;
      }
      talloc_steal(nk, nk->subkeys);
    }
  }

  return nk;
}


/******************************************************************************
 ******************************************************************************/
const REGFI_SK_REC* regfi_load_sk(REGFI_FILE* file, uint32 offset, bool strict)
{
  REGFI_SK_REC* ret_val = NULL;
  const REGFI_HBIN* hbin;
  uint32 max_length;
  void* failure_ptr = NULL;
  
  /* First look if we have already parsed it */
  ret_val = (REGFI_SK_REC*)lru_cache_find(file->sk_cache, &offset, 4);

  /* Bail out if we have previously cached a parse failure at this offset. */
  if(ret_val == (void*)REGFI_OFFSET_NONE)
    return NULL;

  if(ret_val == NULL)
  {
    hbin = regfi_lookup_hbin(file, offset - REGFI_REGF_SIZE);
    if(hbin == NULL)
      return NULL;

    max_length = hbin->block_size + hbin->file_off - offset;
    ret_val = regfi_parse_sk(file, offset, max_length, strict);
    if(ret_val == NULL)
    { /* Cache the parse failure and bail out. */
      failure_ptr = talloc(NULL, uint32_t);
      if(failure_ptr == NULL)
	return NULL;
      *(uint32_t*)failure_ptr = REGFI_OFFSET_NONE;
      lru_cache_update(file->sk_cache, &offset, 4, failure_ptr);
      return NULL;
    }

    lru_cache_update(file->sk_cache, &offset, 4, ret_val);
  }

  return ret_val;
}



/******************************************************************************
 ******************************************************************************/
static bool regfi_find_root_nk(REGFI_FILE* file, uint32 offset,uint32 hbin_size,
			       uint32* root_offset)
{
  uint8 tmp[4];
  int32 record_size;
  uint32 length, hbin_offset = 0;
  REGFI_NK_REC* nk = NULL;
  bool found = false;

  for(record_size=0; !found && (hbin_offset < hbin_size); )
  {
    if(lseek(file->fd, offset+hbin_offset, SEEK_SET) == -1)
      return false;
    
    length = 4;
    if((regfi_read(file->fd, tmp, &length) != 0) || length != 4)
      return false;
    record_size = IVALS(tmp, 0);

    if(record_size < 0)
    {
      record_size = record_size*(-1);
      nk = regfi_parse_nk(file, offset+hbin_offset, hbin_size-hbin_offset, true);
      if(nk != NULL)
      {
	if((nk->key_type == REGFI_NK_TYPE_ROOTKEY1)
	   || (nk->key_type == REGFI_NK_TYPE_ROOTKEY2))
	{
	  found = true;
	  *root_offset = nk->offset;
	}
	regfi_free_key(nk);
      }
    }

    hbin_offset += record_size;
  }

  return found;
}


/*******************************************************************
 * Open the registry file and then read in the REGF block to get the
 * first hbin offset.
 *******************************************************************/
REGFI_FILE* regfi_open(const char* filename)
{
  struct stat sbuf;
  REGFI_FILE* rb;
  REGFI_HBIN* hbin = NULL;
  uint32 hbin_off, file_length, cache_secret;
  int fd;
  bool rla;

  /* open an existing file */
  if ((fd = open(filename, REGFI_OPEN_FLAGS)) == -1)
  {
    /* fprintf(stderr, "regfi_open: failure to open %s (%s)\n", filename, strerror(errno));*/
    return NULL;
  }
  
  /* Determine file length.  Must be at least big enough 
   * for the header and one hbin. 
   */
  if (fstat(fd, &sbuf) == -1)
    return NULL;
  file_length = sbuf.st_size;
  if(file_length < REGFI_REGF_SIZE+REGFI_HBIN_ALLOC)
    return NULL;

  /* read in an existing file */
  if ((rb = regfi_parse_regf(fd, true)) == NULL) 
  {
    /* fprintf(stderr, "regfi_open: Failed to read initial REGF block\n"); */
    close(fd);
    return NULL;
  }
  rb->file_length = file_length;  

  rb->hbins = range_list_new();
  if(rb->hbins == NULL)
  {
    /* fprintf(stderr, "regfi_open: Failed to create HBIN list.\n"); */
    close(fd);
    talloc_free(rb);
    return NULL;
  }
  talloc_steal(rb, rb->hbins);

  rla = true;
  hbin_off = REGFI_REGF_SIZE;
  hbin = regfi_parse_hbin(rb, hbin_off, true);
  while(hbin && rla)
  {
    rla = range_list_add(rb->hbins, hbin->file_off, hbin->block_size, hbin);
    if(rla)
      talloc_steal(rb->hbins, hbin);
    hbin_off = hbin->file_off + hbin->block_size;
    hbin = regfi_parse_hbin(rb, hbin_off, true);
  }

  /* This secret isn't very secret, but we don't need a good one.  This 
   * secret is just designed to prevent someone from trying to blow our
   * caching and make things slow.
   */
  cache_secret = 0x15DEAD05^time(NULL)^(getpid()<<16);

  /* Cache an unlimited number of SK records.  Typically there are very few. */
  rb->sk_cache = lru_cache_create_ctx(rb, 0, cache_secret, true);

  /* Default message mask */
  rb->msg_mask = REGFI_MSG_ERROR|REGFI_MSG_WARN;

  /* success */
  return rb;
}


/******************************************************************************
 ******************************************************************************/
int regfi_close(REGFI_FILE *file)
{
  int fd;

  /* nothing to do if there is no open file */
  if ((file == NULL) || (file->fd == -1))
    return 0;

  fd = file->fd;
  file->fd = -1;

  range_list_free(file->hbins);

  if(file->sk_cache != NULL)
    lru_cache_destroy(file->sk_cache);

  talloc_free(file);
  return close(fd);
}


/******************************************************************************
 * There should be only *one* root key in the registry file based 
 * on my experience.  --jerry
 ******************************************************************************/
REGFI_NK_REC* regfi_rootkey(REGFI_FILE *file)
{
  REGFI_NK_REC* nk = NULL;
  REGFI_HBIN* hbin;
  uint32 root_offset, i, num_hbins;
  
  if(!file)
    return NULL;

  /* Scan through the file one HBIN block at a time looking 
   * for an NK record with a root key type.
   * This is typically the first NK record in the first HBIN
   * block (but we're not assuming that generally).
   */
  num_hbins = range_list_size(file->hbins);
  for(i=0; i < num_hbins; i++)
  {
    hbin = (REGFI_HBIN*)range_list_get(file->hbins, i)->data;
    if(regfi_find_root_nk(file, hbin->file_off+REGFI_HBIN_HEADER_SIZE, 
			  hbin->block_size-REGFI_HBIN_HEADER_SIZE, &root_offset))
    {
      nk = regfi_load_key(file, root_offset, true);
      break;
    }
  }

  return nk;
}


/******************************************************************************
 *****************************************************************************/
void regfi_free_key(REGFI_NK_REC* nk)
{
  regfi_subkeylist_free(nk->subkeys);
  talloc_free(nk);
}


/******************************************************************************
 *****************************************************************************/
void regfi_free_value(REGFI_VK_REC* vk)
{
  talloc_free(vk);
}


/******************************************************************************
 *****************************************************************************/
void regfi_subkeylist_free(REGFI_SUBKEY_LIST* list)
{
  if(list != NULL)
  {
    talloc_free(list);
  }
}


/******************************************************************************
 *****************************************************************************/
REGFI_ITERATOR* regfi_iterator_new(REGFI_FILE* fh)
{
  REGFI_NK_REC* root;
  REGFI_ITERATOR* ret_val = talloc(NULL, REGFI_ITERATOR);
  if(ret_val == NULL)
    return NULL;

  root = regfi_rootkey(fh);
  if(root == NULL)
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
  talloc_steal(ret_val, ret_val->key_positions);

  ret_val->f = fh;
  ret_val->cur_key = root;
  ret_val->cur_subkey = 0;
  ret_val->cur_value = 0;

  return ret_val;
}


/******************************************************************************
 *****************************************************************************/
void regfi_iterator_free(REGFI_ITERATOR* i)
{
  talloc_free(i);
}



/******************************************************************************
 *****************************************************************************/
/* XXX: some way of indicating reason for failure should be added. */
bool regfi_iterator_down(REGFI_ITERATOR* i)
{
  REGFI_NK_REC* subkey;
  REGFI_ITER_POSITION* pos;

  pos = talloc(i->key_positions, REGFI_ITER_POSITION);
  if(pos == NULL)
    return false;

  subkey = (REGFI_NK_REC*)regfi_iterator_cur_subkey(i);
  if(subkey == NULL)
  {
    talloc_free(pos);
    return false;
  }

  pos->nk = i->cur_key;
  pos->cur_subkey = i->cur_subkey;
  if(!void_stack_push(i->key_positions, pos))
  {
    talloc_free(pos);
    regfi_free_key(subkey);
    return false;
  }
  talloc_steal(i, subkey);

  i->cur_key = subkey;
  i->cur_subkey = 0;
  i->cur_value = 0;

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

  regfi_free_key(i->cur_key);
  i->cur_key = pos->nk;
  i->cur_subkey = pos->cur_subkey;
  i->cur_value = 0;
  talloc_free(pos);

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
bool regfi_iterator_find_subkey(REGFI_ITERATOR* i, const char* subkey_name)
{
  REGFI_NK_REC* subkey;
  bool found = false;
  uint32 old_subkey = i->cur_subkey;

  if(subkey_name == NULL)
    return false;

  /* XXX: this alloc/free of each sub key might be a bit excessive */
  subkey = (REGFI_NK_REC*)regfi_iterator_first_subkey(i);
  while((subkey != NULL) && (found == false))
  {
    if(subkey->keyname != NULL 
       && strcasecmp(subkey->keyname, subkey_name) == 0)
      found = true;
    else
    {
      regfi_free_key(subkey);
      subkey = (REGFI_NK_REC*)regfi_iterator_next_subkey(i);
    }
  }

  if(found == false)
  {
    i->cur_subkey = old_subkey;
    return false;
  }

  regfi_free_key(subkey);
  return true;
}


/******************************************************************************
 *****************************************************************************/
bool regfi_iterator_walk_path(REGFI_ITERATOR* i, const char** path)
{
  uint32 x;
  if(path == NULL)
    return false;

  for(x=0; 
      ((path[x] != NULL) && regfi_iterator_find_subkey(i, path[x])
       && regfi_iterator_down(i));
      x++)
  { continue; }

  if(path[x] == NULL)
    return true;
  
  /* XXX: is this the right number of times? */
  for(; x > 0; x--)
    regfi_iterator_up(i);
  
  return false;
}


/******************************************************************************
 *****************************************************************************/
const REGFI_NK_REC* regfi_iterator_cur_key(REGFI_ITERATOR* i)
{
  return i->cur_key;
}


/******************************************************************************
 *****************************************************************************/
const REGFI_SK_REC* regfi_iterator_cur_sk(REGFI_ITERATOR* i)
{
  if(i->cur_key == NULL || i->cur_key->sk_off == REGFI_OFFSET_NONE)
    return NULL;

  return regfi_load_sk(i->f, i->cur_key->sk_off + REGFI_REGF_SIZE, true);
}


/******************************************************************************
 *****************************************************************************/
REGFI_NK_REC* regfi_iterator_first_subkey(REGFI_ITERATOR* i)
{
  i->cur_subkey = 0;
  return regfi_iterator_cur_subkey(i);
}


/******************************************************************************
 *****************************************************************************/
REGFI_NK_REC* regfi_iterator_cur_subkey(REGFI_ITERATOR* i)
{
  uint32 nk_offset;

  /* see if there is anything left to report */
  if (!(i->cur_key) || (i->cur_key->subkeys_off==REGFI_OFFSET_NONE)
      || (i->cur_subkey >= i->cur_key->num_subkeys))
    return NULL;

  nk_offset = i->cur_key->subkeys->elements[i->cur_subkey].offset;

  return regfi_load_key(i->f, nk_offset+REGFI_REGF_SIZE, true);
}


/******************************************************************************
 *****************************************************************************/
/* XXX: some way of indicating reason for failure should be added. */
REGFI_NK_REC* regfi_iterator_next_subkey(REGFI_ITERATOR* i)
{
  REGFI_NK_REC* subkey;

  i->cur_subkey++;
  subkey = regfi_iterator_cur_subkey(i);

  if(subkey == NULL)
    i->cur_subkey--;

  return subkey;
}


/******************************************************************************
 *****************************************************************************/
bool regfi_iterator_find_value(REGFI_ITERATOR* i, const char* value_name)
{
  REGFI_VK_REC* cur;
  bool found = false;

  /* XXX: cur->valuename can be NULL in the registry.  
   *      Should we allow for a way to search for that? 
   */
  if(value_name == NULL)
    return false;

  cur = regfi_iterator_first_value(i);
  while((cur != NULL) && (found == false))
  {
    if((cur->valuename != NULL)
       && (strcasecmp(cur->valuename, value_name) == 0))
      found = true;
    else
    {
      regfi_free_value(cur);
      cur = regfi_iterator_next_value(i);
    }
  }

  return found;
}


/******************************************************************************
 *****************************************************************************/
REGFI_VK_REC* regfi_iterator_first_value(REGFI_ITERATOR* i)
{
  i->cur_value = 0;
  return regfi_iterator_cur_value(i);
}


/******************************************************************************
 *****************************************************************************/
REGFI_VK_REC* regfi_iterator_cur_value(REGFI_ITERATOR* i)
{
  REGFI_VK_REC* ret_val = NULL;
  uint32 voffset;

  if(i->cur_key->values != NULL && i->cur_key->values->elements != NULL)
  {
    if(i->cur_value < i->cur_key->values->num_values)
    {
      voffset = i->cur_key->values->elements[i->cur_value];
      ret_val = regfi_load_value(i->f, voffset+REGFI_REGF_SIZE, true);
    }
  }

  return ret_val;
}


/******************************************************************************
 *****************************************************************************/
REGFI_VK_REC* regfi_iterator_next_value(REGFI_ITERATOR* i)
{
  REGFI_VK_REC* ret_val;

  i->cur_value++;
  ret_val = regfi_iterator_cur_value(i);
  if(ret_val == NULL)
    i->cur_value--;

  return ret_val;
}


/*******************************************************************
 * Computes the checksum of the registry file header.
 * buffer must be at least the size of an regf header (4096 bytes).
 *******************************************************************/
static uint32 regfi_compute_header_checksum(uint8* buffer)
{
  uint32 checksum, x;
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
 * XXX: Add way to return more detailed error information.
 *******************************************************************/
REGFI_FILE* regfi_parse_regf(int fd, bool strict)
{
  uint8 file_header[REGFI_REGF_SIZE];
  uint32 length;
  REGFI_FILE* ret_val;

  ret_val = talloc(NULL, REGFI_FILE);
  if(ret_val == NULL)
    return NULL;

  ret_val->fd = fd;
  ret_val->sk_cache = NULL;
  ret_val->last_message = NULL;
  ret_val->hbins = NULL;
  
  length = REGFI_REGF_SIZE;
  if((regfi_read(fd, file_header, &length)) != 0 || length != REGFI_REGF_SIZE)
    goto fail;
  
  ret_val->checksum = IVAL(file_header, 0x1FC);
  ret_val->computed_checksum = regfi_compute_header_checksum(file_header);
  if (strict && (ret_val->checksum != ret_val->computed_checksum))
    goto fail;

  memcpy(ret_val->magic, file_header, REGFI_REGF_MAGIC_SIZE);
  if(memcmp(ret_val->magic, "regf", REGFI_REGF_MAGIC_SIZE) != 0)
  {
    if(strict)
      goto fail;
    regfi_add_message(ret_val, REGFI_MSG_WARN, "Magic number mismatch "
		      "(%.2X %.2X %.2X %.2X) while parsing hive header",
		      ret_val->magic[0], ret_val->magic[1], 
		      ret_val->magic[2], ret_val->magic[3]);
  }
  ret_val->sequence1 = IVAL(file_header, 0x4);
  ret_val->sequence2 = IVAL(file_header, 0x8);
  ret_val->mtime.low = IVAL(file_header, 0xC);
  ret_val->mtime.high = IVAL(file_header, 0x10);
  ret_val->major_version = IVAL(file_header, 0x14);
  ret_val->minor_version = IVAL(file_header, 0x18);
  ret_val->type = IVAL(file_header, 0x1C);
  ret_val->format = IVAL(file_header, 0x20);
  ret_val->root_cell = IVAL(file_header, 0x24);
  ret_val->last_block = IVAL(file_header, 0x28);

  ret_val->cluster = IVAL(file_header, 0x2C);

  memcpy(ret_val->file_name, file_header+0x30,  REGFI_REGF_NAME_SIZE);

  /* XXX: Should we add a warning if these uuid parsers fail?  Can they? */
  ret_val->rm_id = winsec_parse_uuid(ret_val, file_header+0x70, 16);
  ret_val->log_id = winsec_parse_uuid(ret_val, file_header+0x80, 16);
  ret_val->flags = IVAL(file_header, 0x90);
  ret_val->tm_id = winsec_parse_uuid(ret_val, file_header+0x94, 16);
  ret_val->guid_signature = IVAL(file_header, 0xa4);

  memcpy(ret_val->reserved1, file_header+0xa8, REGFI_REGF_RESERVED1_SIZE);
  memcpy(ret_val->reserved2, file_header+0x200, REGFI_REGF_RESERVED2_SIZE);

  ret_val->thaw_tm_id = winsec_parse_uuid(ret_val, file_header+0xFC8, 16);
  ret_val->thaw_rm_id = winsec_parse_uuid(ret_val, file_header+0xFD8, 16);
  ret_val->thaw_log_id = winsec_parse_uuid(ret_val, file_header+0xFE8, 16);
  ret_val->boot_type = IVAL(file_header, 0x90);
  ret_val->boot_recover = IVAL(file_header, 0x90);

  return ret_val;

 fail:
  talloc_free(ret_val);
  return NULL;
}



/******************************************************************************
 * Given real file offset, read and parse the hbin at that location
 * along with it's associated cells.
 ******************************************************************************/
REGFI_HBIN* regfi_parse_hbin(REGFI_FILE* file, uint32 offset, bool strict)
{
  REGFI_HBIN *hbin;
  uint8 hbin_header[REGFI_HBIN_HEADER_SIZE];
  uint32 length;
  
  if(offset >= file->file_length)
    return NULL;

  if(lseek(file->fd, offset, SEEK_SET) == -1)
  {
    regfi_add_message(file, REGFI_MSG_ERROR, "Seek failed"
		      " while parsing hbin at offset 0x%.8X.", offset);
    return NULL;
  }

  length = REGFI_HBIN_HEADER_SIZE;
  if((regfi_read(file->fd, hbin_header, &length) != 0) 
     || length != REGFI_HBIN_HEADER_SIZE)
    return NULL;

  if(lseek(file->fd, offset, SEEK_SET) == -1)
  {
    regfi_add_message(file, REGFI_MSG_ERROR, "Seek failed"
		      " while parsing hbin at offset 0x%.8X.", offset);
    return NULL;
  }

  hbin = talloc(NULL, REGFI_HBIN);
  if(hbin == NULL)
    return NULL;
  hbin->file_off = offset;

  memcpy(hbin->magic, hbin_header, 4);
  if(strict && (memcmp(hbin->magic, "hbin", 4) != 0))
  {
    regfi_add_message(file, REGFI_MSG_INFO, "Magic number mismatch "
		      "(%.2X %.2X %.2X %.2X) while parsing hbin at offset"
		      " 0x%.8X.", hbin->magic[0], hbin->magic[1], 
		      hbin->magic[2], hbin->magic[3], offset);
    talloc_free(hbin);
    return NULL;
  }

  hbin->first_hbin_off = IVAL(hbin_header, 0x4);
  hbin->block_size = IVAL(hbin_header, 0x8);
  /* this should be the same thing as hbin->block_size but just in case */
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
    regfi_add_message(file, REGFI_MSG_ERROR, "The hbin offset is not aligned"
		      " or runs off the end of the file"
		      " while parsing hbin at offset 0x%.8X.", offset);
    talloc_free(hbin);
    return NULL;
  }

  return hbin;
}


/*******************************************************************
 *******************************************************************/
REGFI_NK_REC* regfi_parse_nk(REGFI_FILE* file, uint32 offset, 
			    uint32 max_size, bool strict)
{
  uint8 nk_header[REGFI_NK_MIN_LENGTH];
  const REGFI_HBIN *hbin;
  REGFI_NK_REC* ret_val;
  uint32 length,cell_length;
  uint32 class_offset, class_maxsize;
  bool unalloc = false;

  if(!regfi_parse_cell(file->fd, offset, nk_header, REGFI_NK_MIN_LENGTH,
		       &cell_length, &unalloc))
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Could not parse cell header"
		      " while parsing NK record at offset 0x%.8X.", offset);
    return NULL;
  }

  /* A bit of validation before bothering to allocate memory */
  if((nk_header[0x0] != 'n') || (nk_header[0x1] != 'k'))
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Magic number mismatch in parsing"
		      " NK record at offset 0x%.8X.", offset);
    return NULL;
  }

  ret_val = talloc(NULL, REGFI_NK_REC);
  if(ret_val == NULL)
  {
    regfi_add_message(file, REGFI_MSG_ERROR, "Failed to allocate memory while"
		      " parsing NK record at offset 0x%.8X.", offset);
    return NULL;
  }

  ret_val->values = NULL;
  ret_val->subkeys = NULL;
  ret_val->offset = offset;
  ret_val->cell_size = cell_length;

  if(ret_val->cell_size > max_size)
    ret_val->cell_size = max_size & 0xFFFFFFF8;
  if((ret_val->cell_size < REGFI_NK_MIN_LENGTH) 
     || (strict && ret_val->cell_size != (ret_val->cell_size & 0xFFFFFFF8)))
  {
    regfi_add_message(file, REGFI_MSG_WARN, "A length check failed while"
		      " parsing NK record at offset 0x%.8X.", offset);
    talloc_free(ret_val);
    return NULL;
  }

  ret_val->magic[0] = nk_header[0x0];
  ret_val->magic[1] = nk_header[0x1];
  ret_val->key_type = SVAL(nk_header, 0x2);
  if((ret_val->key_type != REGFI_NK_TYPE_NORMALKEY)
     && (ret_val->key_type != REGFI_NK_TYPE_ROOTKEY1) 
     && (ret_val->key_type != REGFI_NK_TYPE_ROOTKEY2)
     && (ret_val->key_type != REGFI_NK_TYPE_LINKKEY)
     && (ret_val->key_type != REGFI_NK_TYPE_UNKNOWN1)
     && (ret_val->key_type != REGFI_NK_TYPE_UNKNOWN2)
     && (ret_val->key_type != REGFI_NK_TYPE_UNKNOWN3))
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Unknown key type (0x%.4X) while"
		      " parsing NK record at offset 0x%.8X.", 
		      ret_val->key_type, offset);
  }

  ret_val->mtime.low = IVAL(nk_header, 0x4);
  ret_val->mtime.high = IVAL(nk_header, 0x8);
  /* If the key is unallocated and the MTIME is earlier than Jan 1, 1990
   * or later than Jan 1, 2290, we consider this a bad key.  This helps
   * weed out some false positives during deleted data recovery.
   */
  if(unalloc
     && ((ret_val->mtime.high < REGFI_MTIME_MIN_HIGH 
	  && ret_val->mtime.low < REGFI_MTIME_MIN_LOW)
	 || (ret_val->mtime.high > REGFI_MTIME_MAX_HIGH 
	     && ret_val->mtime.low > REGFI_MTIME_MAX_LOW)))
    return NULL;

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


  if(ret_val->name_length + REGFI_NK_MIN_LENGTH > ret_val->cell_size)
  {
    if(strict)
    {
      regfi_add_message(file, REGFI_MSG_ERROR, "Contents too large for cell"
			" while parsing NK record at offset 0x%.8X.", offset);
      talloc_free(ret_val);
      return NULL;
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

  ret_val->keyname = talloc_array(ret_val, char, ret_val->name_length+1);
  if(ret_val->keyname == NULL)
  {
    talloc_free(ret_val);
    return NULL;
  }

  /* Don't need to seek, should be at the right offset */
  length = ret_val->name_length;
  if((regfi_read(file->fd, (uint8*)ret_val->keyname, &length) != 0)
     || length != ret_val->name_length)
  {
    regfi_add_message(file, REGFI_MSG_ERROR, "Failed to read key name"
		      " while parsing NK record at offset 0x%.8X.", offset);
    talloc_free(ret_val);
    return NULL;
  }
  ret_val->keyname[ret_val->name_length] = '\0';

  /* XXX: This linking should be moved up to regfi_load_key */
  if(ret_val->classname_off != REGFI_OFFSET_NONE)
  {
    hbin = regfi_lookup_hbin(file, ret_val->classname_off);
    if(hbin)
    {
      class_offset = ret_val->classname_off+REGFI_REGF_SIZE;
      class_maxsize = hbin->block_size + hbin->file_off - class_offset;
      ret_val->classname
	= regfi_parse_classname(file, class_offset, &ret_val->classname_length, 
				class_maxsize, strict);
    }
    else
    {
      ret_val->classname = NULL;
      regfi_add_message(file, REGFI_MSG_WARN, "Could not find hbin for class"
			" name while parsing NK record at offset 0x%.8X.", 
			offset);
    }

    if(ret_val->classname == NULL)
    {
      regfi_add_message(file, REGFI_MSG_WARN, "Could not parse class"
			" name while parsing NK record at offset 0x%.8X.", 
			offset);
    }
    else
      talloc_steal(ret_val, ret_val->classname);
  }

  return ret_val;
}


char* regfi_parse_classname(REGFI_FILE* file, uint32 offset, 
			    uint16* name_length, uint32 max_size, bool strict)
{
  char* ret_val = NULL;
  uint32 length;
  uint32 cell_length;
  bool unalloc = false;

  if(*name_length > 0 && offset != REGFI_OFFSET_NONE 
     && offset == (offset & 0xFFFFFFF8))
  {
    if(!regfi_parse_cell(file->fd, offset, NULL, 0, &cell_length, &unalloc))
    {
      regfi_add_message(file, REGFI_MSG_WARN, "Could not parse cell header"
			" while parsing class name at offset 0x%.8X.", offset);
	return NULL;
    }

    if((cell_length & 0xFFFFFFF8) != cell_length)
    {
      regfi_add_message(file, REGFI_MSG_ERROR, "Cell length not a multiple of 8"
			" while parsing class name at offset 0x%.8X.", offset);
      return NULL;
    }

    if(cell_length > max_size)
    {
      regfi_add_message(file, REGFI_MSG_WARN, "Cell stretches past hbin "
			"boundary while parsing class name at offset 0x%.8X.",
			offset);
      if(strict)
	return NULL;
      cell_length = max_size;
    }

    if((cell_length - 4) < *name_length)
    {
      regfi_add_message(file, REGFI_MSG_WARN, "Class name is larger than"
			" cell_length while parsing class name at offset"
			" 0x%.8X.", offset);
      if(strict)
	return NULL;
      *name_length = cell_length - 4;
    }
    
    ret_val = talloc_array(NULL, char, *name_length);
    if(ret_val != NULL)
    {
      length = *name_length;
      if((regfi_read(file->fd, (uint8*)ret_val, &length) != 0)
	 || length != *name_length)
      {
	regfi_add_message(file, REGFI_MSG_ERROR, "Could not read class name"
			  " while parsing class name at offset 0x%.8X.", offset);
	talloc_free(ret_val);
	return NULL;
      }
    }
  }

  return ret_val;
}


/*******************************************************************
 *******************************************************************/
REGFI_VK_REC* regfi_parse_vk(REGFI_FILE* file, uint32 offset, 
			     uint32 max_size, bool strict)
{
  REGFI_VK_REC* ret_val;
  uint8 vk_header[REGFI_VK_MIN_LENGTH];
  uint32 raw_data_size, length, cell_length;
  bool unalloc = false;

  if(!regfi_parse_cell(file->fd, offset, vk_header, REGFI_VK_MIN_LENGTH,
		       &cell_length, &unalloc))
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Could not parse cell header"
		      " while parsing VK record at offset 0x%.8X.", offset);
    return NULL;
  }

  ret_val = talloc(NULL, REGFI_VK_REC);
  if(ret_val == NULL)
    return NULL;

  ret_val->offset = offset;
  ret_val->cell_size = cell_length;
  ret_val->data = NULL;
  ret_val->valuename = NULL;
  
  if(ret_val->cell_size > max_size)
    ret_val->cell_size = max_size & 0xFFFFFFF8;
  if((ret_val->cell_size < REGFI_VK_MIN_LENGTH) 
     || ret_val->cell_size != (ret_val->cell_size & 0xFFFFFFF8))
  {
    regfi_add_message(file, REGFI_MSG_WARN, "Invalid cell size encountered"
		      " while parsing VK record at offset 0x%.8X.", offset);
    talloc_free(ret_val);
    return NULL;
  }

  ret_val->magic[0] = vk_header[0x0];
  ret_val->magic[1] = vk_header[0x1];
  if((ret_val->magic[0] != 'v') || (ret_val->magic[1] != 'k'))
  {
    /* XXX: This does not account for deleted keys under Win2K which
     *      often have this (and the name length) overwritten with
     *      0xFFFF. 
     */
    regfi_add_message(file, REGFI_MSG_WARN, "Magic number mismatch"
		      " while parsing VK record at offset 0x%.8X.", offset);
    talloc_free(ret_val);
    return NULL;
  }

  ret_val->name_length = SVAL(vk_header, 0x2);
  raw_data_size = IVAL(vk_header, 0x4);
  ret_val->data_size = raw_data_size & ~REGFI_VK_DATA_IN_OFFSET;
  ret_val->data_in_offset = (bool)(raw_data_size & REGFI_VK_DATA_IN_OFFSET);
  ret_val->data_off = IVAL(vk_header, 0x8);
  ret_val->type = IVAL(vk_header, 0xC);
  ret_val->flag = SVAL(vk_header, 0x10);
  ret_val->unknown1 = SVAL(vk_header, 0x12);

  if(ret_val->flag & REGFI_VK_FLAG_NAME_PRESENT)
  {
    if(ret_val->name_length + REGFI_VK_MIN_LENGTH + 4 > ret_val->cell_size)
    {
      regfi_add_message(file, REGFI_MSG_WARN, "Name too long for remaining cell"
			" space while parsing VK record at offset 0x%.8X.",
			offset);
      if(strict)
      {
	talloc_free(ret_val);
	return NULL;
      }
      else
	ret_val->name_length = ret_val->cell_size - REGFI_VK_MIN_LENGTH - 4;
    }

    /* Round up to the next multiple of 8 */
    cell_length = (ret_val->name_length + REGFI_VK_MIN_LENGTH + 4) & 0xFFFFFFF8;
    if(cell_length < ret_val->name_length + REGFI_VK_MIN_LENGTH + 4)
      cell_length+=8;

    ret_val->valuename = talloc_array(ret_val, char, ret_val->name_length+1);
    if(ret_val->valuename == NULL)
    {
      talloc_free(ret_val);
      return NULL;
    }

    length = ret_val->name_length;
    if((regfi_read(file->fd, (uint8*)ret_val->valuename, &length) != 0)
       || length != ret_val->name_length)
    {
      regfi_add_message(file, REGFI_MSG_ERROR, "Could not read value name"
			" while parsing VK record at offset 0x%.8X.", offset);
      talloc_free(ret_val);
      return NULL;
    }
    ret_val->valuename[ret_val->name_length] = '\0';

  }
  else
    cell_length = REGFI_VK_MIN_LENGTH + 4;

  if(unalloc)
  {
    /* If cell_size is still greater, truncate. */
    if(cell_length < ret_val->cell_size)
      ret_val->cell_size = cell_length;
  }

  return ret_val;
}


REGFI_BUFFER regfi_parse_data(REGFI_FILE* file, 
			      uint32 data_type, uint32 offset,
			      uint32 length, uint32 max_size, 
			      bool data_in_offset, bool strict)
{
  REGFI_BUFFER ret_val;
  uint32 read_length, cell_length;
  uint8 i;
  bool unalloc;
  
  /* The data is typically stored in the offset if the size <= 4 */
  if(data_in_offset)
  {
    if(length > 4)
    {
      regfi_add_message(file, REGFI_MSG_ERROR, "Data in offset but length > 4"
			" while parsing data record at offset 0x%.8X.", 
			offset);
      goto fail;
    }

    if((ret_val.buf = talloc_array(NULL, uint8_t, length)) == NULL)
      goto fail;
    ret_val.len = length;

    for(i = 0; i < length; i++)
      ret_val.buf[i] = (uint8)((offset >> i*8) & 0xFF);
  }
  else
  {
    if(!regfi_parse_cell(file->fd, offset, NULL, 0,
			 &cell_length, &unalloc))
    {
      regfi_add_message(file, REGFI_MSG_WARN, "Could not parse cell while"
			" parsing data record at offset 0x%.8X.", offset);
      goto fail;
    }

    if((cell_length & 0xFFFFFFF8) != cell_length)
    {
      regfi_add_message(file, REGFI_MSG_WARN, "Cell length not multiple of 8"
			" while parsing data record at offset 0x%.8X.",
			offset);
      goto fail;
    }

    if(cell_length > max_size)
    {
      regfi_add_message(file, REGFI_MSG_WARN, "Cell extends past HBIN boundary"
			" while parsing data record at offset 0x%.8X.",
			offset);
      if(strict)
	goto fail;
      else
	cell_length = max_size;
    }

    if(cell_length - 4 < length)
    {
      /* XXX: This strict condition has been triggered in multiple registries.
       *      Not sure the cause, but the data length values are very large,
       *      such as 53392.  For now, we're truncating the size and returning 
       *      what we can, since this issue is so common.
       */
      regfi_add_message(file, REGFI_MSG_WARN, "Data length (0x%.8X) larger than"
			" remaining cell length (0x%.8X)"
			" while parsing data record at offset 0x%.8X.", 
			length, cell_length - 4, offset);
      /*
      if(strict)
        goto fail;
      else
      */
      length = cell_length - 4;
    }

    if((ret_val.buf = talloc_array(NULL, uint8_t, length)) == NULL)
      goto fail;
    ret_val.len = length;

    read_length = length;
    if((regfi_read(file->fd, ret_val.buf, &read_length) != 0)
       || read_length != length)
    {
      regfi_add_message(file, REGFI_MSG_ERROR, "Could not read data block while"
			" parsing data record at offset 0x%.8X.", offset);
      talloc_free(ret_val.buf);
      goto fail;
    }
  }

  return ret_val;

 fail:
  ret_val.buf = NULL;
  ret_val.len = 0;
  return ret_val;
}


range_list* regfi_parse_unalloc_cells(REGFI_FILE* file)
{
  range_list* ret_val;
  REGFI_HBIN* hbin;
  const range_list_element* hbins_elem;
  uint32 i, num_hbins, curr_off, cell_len;
  bool is_unalloc;

  ret_val = range_list_new();
  if(ret_val == NULL)
    return NULL;

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
      if(!regfi_parse_cell(file->fd, hbin->file_off+curr_off, NULL, 0,
			   &cell_len, &is_unalloc))
	break;
      
      if((cell_len == 0) || ((cell_len & 0xFFFFFFF8) != cell_len))
      {
	regfi_add_message(file, REGFI_MSG_ERROR, "Bad cell length encountered"
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

  return ret_val;
}
