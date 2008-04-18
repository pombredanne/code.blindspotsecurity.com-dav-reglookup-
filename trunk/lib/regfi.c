/*
 * Branched from Samba project Subversion repository, version #7470:
 *   http://viewcvs.samba.org/cgi-bin/viewcvs.cgi/trunk/source/registry/regfio.c?rev=7470&view=auto
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

#include "../include/regfi.h"


/* Registry types mapping */
const unsigned int regfi_num_reg_types = 12;
static const char* regfi_type_names[] =
  {"NONE", "SZ", "EXPAND_SZ", "BINARY", "DWORD", "DWORD_BE", "LINK",
   "MULTI_SZ", "RSRC_LIST", "RSRC_DESC", "RSRC_REQ_LIST", "QWORD"};


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


/* Security descriptor parsing functions  */

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

  /* XXX: what was this old VI flag for??
     XXX: Is this check right?  0xF == 1|2|4|8, which makes it redundant...
  if (flags == 0xF) {
    if (some) strcat(flg_output, " ");
    some = 1;
    strcat(flg_output, "VI");
  }
  */

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


char* regfi_sid2str(DOM_SID* sid)
{
  uint32 i, size = MAXSUBAUTHS*11 + 24;
  uint32 left = size;
  uint8 comps = sid->num_auths;
  char* ret_val = malloc(size);
  
  if(ret_val == NULL)
    return NULL;

  if(comps > MAXSUBAUTHS)
    comps = MAXSUBAUTHS;

  left -= sprintf(ret_val, "S-%u-%u", sid->sid_rev_num, sid->id_auth[5]);

  for (i = 0; i < comps; i++) 
    left -= snprintf(ret_val+(size-left), left, "-%u", sid->sub_auths[i]);

  return ret_val;
}


char* regfi_get_acl(SEC_ACL* acl)
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
    sid_str = regfi_sid2str(&acl->ace[i].trustee);
    type_str = regfi_ace_type2str(acl->ace[i].type);
    perms_str = regfi_ace_perms2str(acl->ace[i].info.mask);
    flags_str = regfi_ace_flags2str(acl->ace[i].flags);
    
    if(flags_str != NULL && perms_str != NULL 
       && type_str != NULL && sid_str != NULL)
    {
      /* XXX: this is slow */
      extra = strlen(sid_str) + strlen(type_str) 
	+ strlen(perms_str) + strlen(flags_str)+5;
      tmp_val = realloc(ret_val, size+extra);

      if(tmp_val == NULL)
      {
	free(ret_val);
	failed = true;
      }
      else
      {
	ret_val = tmp_val;
	size += snprintf(ret_val+size, extra, "%s%s%c%s%c%s%c%s",
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


char* regfi_get_sacl(SEC_DESC *sec_desc)
{
  if (sec_desc->sacl)
    return regfi_get_acl(sec_desc->sacl);
  else
    return NULL;
}


char* regfi_get_dacl(SEC_DESC *sec_desc)
{
  if (sec_desc->dacl)
    return regfi_get_acl(sec_desc->dacl);
  else
    return NULL;
}


char* regfi_get_owner(SEC_DESC *sec_desc)
{
  return regfi_sid2str(sec_desc->owner_sid);
}


char* regfi_get_group(SEC_DESC *sec_desc)
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
static bool regfi_parse_cell(int fd, uint32 offset, uint8* hdr, uint32 hdr_len,
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
static bool regfi_offset_in_hbin(REGF_HBIN* hbin, uint32 offset)
{
  if(!hbin)
    return false;

  if((offset > hbin->first_hbin_off) 
     && (offset < (hbin->first_hbin_off + hbin->block_size)))
    return true;
		
  return false;
}



/*******************************************************************
 * Given a virtual offset, and receive the correpsonding HBIN 
 * block for it.  NULL if one doesn't exist.
 *******************************************************************/
static REGF_HBIN* regfi_lookup_hbin(REGF_FILE* file, uint32 offset)
{
  return (REGF_HBIN*)range_list_find_data(file->hbins, offset+REGF_BLOCKSIZE);
}



/*******************************************************************
 TODO: not currently validating against max_size
 *******************************************************************/
REGF_HASH_LIST* regfi_load_hashlist(REGF_FILE* file, uint32 offset, 
				    uint32 num_keys, uint32 max_size, 
				    bool strict)
{
  REGF_HASH_LIST* ret_val;
  uint32 i, cell_length, length;
  uint8* hashes;
  uint8 buf[REGFI_HASH_LIST_MIN_LENGTH];
  bool unalloc;

  if(!regfi_parse_cell(file->fd, offset, buf, REGFI_HASH_LIST_MIN_LENGTH, 
		       &cell_length, &unalloc))
    return NULL;

  ret_val = (REGF_HASH_LIST*)zalloc(sizeof(REGF_HASH_LIST));
  if(ret_val == NULL)
    return NULL;

  ret_val->offset = offset;
  ret_val->cell_size = cell_length;

  if((buf[0] != 'l' || buf[1] != 'f') && (buf[0] != 'l' || buf[1] != 'h')
     && (buf[0] != 'r' || buf[1] != 'i'))
  {
    /*printf("DEBUG: lf->header=%c%c\n", buf[0], buf[1]);*/
    free(ret_val);
    return NULL;
  }

  if(buf[0] == 'r' && buf[1] == 'i')
  {
    fprintf(stderr, "WARNING: ignoring encountered \"ri\" record.\n");
    free(ret_val);
    return NULL;
  }

  ret_val->magic[0] = buf[0];
  ret_val->magic[1] = buf[1];

  ret_val->num_keys = SVAL(buf, 0x2);
  if(num_keys != ret_val->num_keys)
  {
    if(strict)
    {
      free(ret_val);
      return NULL;
    }
    /* TODO: Not sure which should be authoritative, the number from the 
     *       NK record, or the number in the hash list.  Go with the larger
     *       of the two to ensure all keys are found.  Note the length checks
     *       on the cell later ensure that there won't be any critical errors.
     */
    if(num_keys < ret_val->num_keys)
      num_keys = ret_val->num_keys;
    else
      ret_val->num_keys = num_keys;
  }

  if(cell_length - REGFI_HASH_LIST_MIN_LENGTH - sizeof(uint32) 
     < ret_val->num_keys*sizeof(REGF_HASH_LIST_ELEM))
    return NULL;

  length = sizeof(REGF_HASH_LIST_ELEM)*ret_val->num_keys;
  ret_val->hashes = (REGF_HASH_LIST_ELEM*)zalloc(length);
  if(ret_val->hashes == NULL)
  {
    free(ret_val);
    return NULL;
  }

  hashes = (uint8*)zalloc(length);
  if(hashes == NULL)
  {
    free(ret_val->hashes);
    free(ret_val);
    return NULL;
  }

  if(regfi_read(file->fd, hashes, &length) != 0
     || length != sizeof(REGF_HASH_LIST_ELEM)*ret_val->num_keys)
  {
    free(ret_val->hashes);
    free(ret_val);
    return NULL;
  }

  for (i=0; i < ret_val->num_keys; i++)
  {
    ret_val->hashes[i].nk_off = IVAL(hashes, i*sizeof(REGF_HASH_LIST_ELEM));
    ret_val->hashes[i].hash = IVAL(hashes, i*sizeof(REGF_HASH_LIST_ELEM)+4);
  }
  free(hashes);

  return ret_val;
}



/*******************************************************************
 *******************************************************************/
REGF_SK_REC* regfi_parse_sk(REGF_FILE* file, uint32 offset, uint32 max_size, bool strict)
{
  REGF_SK_REC* ret_val;
  uint32 cell_length, length;
  prs_struct ps;
  uint8 sk_header[REGFI_SK_MIN_LENGTH];
  bool unalloc = false;


  if(!regfi_parse_cell(file->fd, offset, sk_header, REGFI_SK_MIN_LENGTH,
		       &cell_length, &unalloc))
    return NULL;
   
  if(sk_header[0] != 's' || sk_header[1] != 'k')
    return NULL;
  
  ret_val = (REGF_SK_REC*)zalloc(sizeof(REGF_SK_REC));
  if(ret_val == NULL)
    return NULL;

  ret_val->offset = offset;
  ret_val->cell_size = cell_length;

  if(ret_val->cell_size > max_size)
    ret_val->cell_size = max_size & 0xFFFFFFF8;
  if((ret_val->cell_size < REGFI_SK_MIN_LENGTH) 
     || (strict && ret_val->cell_size != (ret_val->cell_size & 0xFFFFFFF8)))
  {
    free(ret_val);
    return NULL;
  }


  ret_val->magic[0] = sk_header[0];
  ret_val->magic[1] = sk_header[1];

  ret_val->unknown_tag = SVAL(sk_header, 0x2);
  ret_val->prev_sk_off = IVAL(sk_header, 0x4);
  ret_val->next_sk_off = IVAL(sk_header, 0x8);
  ret_val->ref_count = IVAL(sk_header, 0xC);
  ret_val->desc_size = IVAL(sk_header, 0x10);

  if(ret_val->desc_size + REGFI_SK_MIN_LENGTH > ret_val->cell_size)
  {
    free(ret_val);
    return NULL;
  }

  /* TODO: need to get rid of this, but currently the security descriptor
   * code depends on the ps structure.
   */
  if(!prs_init(&ps, ret_val->desc_size, NULL, UNMARSHALL))
  {
    free(ret_val);
    return NULL;
  }

  length = ret_val->desc_size;
  if(regfi_read(file->fd, (uint8*)ps.data_p, &length) != 0 
     || length != ret_val->desc_size)
  {
    free(ret_val);
    return NULL;
  }

  if (!sec_io_desc("sec_desc", &ret_val->sec_desc, &ps, 0))
  {
    free(ret_val);
    return NULL;
  }

  free(ps.data_p);

  return ret_val;
}



/******************************************************************************
 TODO: not currently validating against max_size.
 ******************************************************************************/
REGF_VK_REC** regfi_load_valuelist(REGF_FILE* file, uint32 offset, 
				   uint32 num_values, uint32 max_size, 
				   bool strict)
{
  REGF_VK_REC** ret_val;
  REGF_HBIN* sub_hbin;
  uint8* buf;
  uint32 i, cell_length, vk_raw_offset, vk_offset, vk_max_length, buf_len;
  bool unalloc;

  buf_len = sizeof(uint8) * 4 * num_values;
  buf = (uint8*)zalloc(buf_len);
  if(buf == NULL)
    return NULL; 

  if(!regfi_parse_cell(file->fd, offset, buf, buf_len, &cell_length, &unalloc))
  {
    free(buf);
    return NULL;
  }

  ret_val = (REGF_VK_REC**)zalloc(sizeof(REGF_VK_REC*) * num_values);
  if(ret_val == NULL)
  {
    free(buf);
    return NULL;
  }
  
  for (i=0; i < num_values; i++) 
  {
    vk_raw_offset = IVAL(buf, i*4);
    
    sub_hbin = regfi_lookup_hbin(file, vk_raw_offset);
    if (!sub_hbin)
    {
      free(buf);
      free(ret_val);
      return NULL;
    }
    
    vk_offset =  vk_raw_offset + REGF_BLOCKSIZE;
    vk_max_length = sub_hbin->block_size - vk_offset + sizeof(uint32);
    ret_val[i] = regfi_parse_vk(file, vk_offset, vk_max_length, true);
    if(ret_val[i] == NULL)
    {
      free(buf);
      free(ret_val);
      return NULL;     
    }
  }

  free(buf);
  return ret_val;
}


/*******************************************************************
 *******************************************************************/
static REGF_SK_REC* find_sk_record_by_offset( REGF_FILE *file, uint32 offset )
{
  REGF_SK_REC *p_sk;
  
  for ( p_sk=file->sec_desc_list; p_sk; p_sk=p_sk->next ) {
    if ( p_sk->sk_off == offset ) 
      return p_sk;
  }
  
  return NULL;
}


/*******************************************************************
 *******************************************************************/
static REGF_SK_REC* find_sk_record_by_sec_desc( REGF_FILE *file, SEC_DESC *sd )
{
  REGF_SK_REC *p;

  for ( p=file->sec_desc_list; p; p=p->next ) {
    if ( sec_desc_equal( p->sec_desc, sd ) )
      return p;
  }

  /* failure */

  return NULL;
}


/*******************************************************************
 * TODO: Need to add full key and SK record caching using a 
 *       custom cache structure.
 *******************************************************************/
REGF_NK_REC* regfi_load_key(REGF_FILE *file, uint32 offset, bool strict)
{
  REGF_HBIN* hbin;
  REGF_HBIN* sub_hbin;
  REGF_NK_REC* nk;
  uint32 max_length, off;

  hbin = regfi_lookup_hbin(file, offset-REGF_BLOCKSIZE);
  if (hbin == NULL) 
    return NULL;

  /* get the initial nk record */
  max_length = hbin->block_size + hbin->file_off - offset;
  if ((nk = regfi_parse_nk(file, offset, max_length, true)) == NULL)
    return NULL;

  /* fill in values */
  if(nk->num_values && (nk->values_off!=REGF_OFFSET_NONE)) 
  {
    sub_hbin = hbin;
    if(!regfi_offset_in_hbin(hbin, nk->values_off)) 
      sub_hbin = regfi_lookup_hbin(file, nk->values_off);
    
    if(sub_hbin == NULL)
    {
      if(strict)
      {
	free(nk);
	return NULL;
      }
      else
	nk->values = NULL;
    }
    else
    {
      off = nk->values_off + REGF_BLOCKSIZE;
      max_length = sub_hbin->block_size + sub_hbin->file_off - off;
      nk->values = regfi_load_valuelist(file, off, nk->num_values, max_length, 
					true);
      if(strict && nk->values == NULL)
      {
	free(nk);
	return NULL;
      }
    }
  }

  /* now get subkeys */
  if(nk->num_subkeys && (nk->subkeys_off != REGF_OFFSET_NONE)) 
  {
    sub_hbin = hbin;
    if(!regfi_offset_in_hbin(hbin, nk->subkeys_off))
      sub_hbin = regfi_lookup_hbin(file, nk->subkeys_off);

    if (sub_hbin == NULL) 
    {
      if(strict)
      {
	free(nk);
	/* TODO: need convenient way to free nk->values deeply in all cases. */
	return NULL;
      }
      else
	nk->subkeys = NULL;
    }
    else
    {
      off = nk->subkeys_off + REGF_BLOCKSIZE;
      max_length = sub_hbin->block_size + sub_hbin->file_off - off;
      nk->subkeys = regfi_load_hashlist(file, off, nk->num_subkeys, 
					max_length, true);
      if(nk->subkeys == NULL)
      {
	/* TODO: temporary hack to get around 'ri' records */
	nk->num_subkeys = 0;
      }
    }
  }

  /* get the security descriptor.  First look if we have already parsed it */
  if((nk->sk_off!=REGF_OFFSET_NONE)
     && !(nk->sec_desc = find_sk_record_by_offset( file, nk->sk_off )))
  {
    sub_hbin = hbin;
    if(!regfi_offset_in_hbin(hbin, nk->sk_off))
      sub_hbin = regfi_lookup_hbin(file, nk->sk_off);

    if(sub_hbin == NULL)
    {
      free(nk);
      /* TODO: need convenient way to free nk->values and nk->subkeys deeply 
       *       in all cases. 
       */
      return NULL;
    }

    off = nk->sk_off + REGF_BLOCKSIZE;
    max_length = sub_hbin->block_size + sub_hbin->file_off - off;
    nk->sec_desc = regfi_parse_sk(file, off, max_length, true);
    if(strict && nk->sec_desc == NULL)
    {
      free(nk);
      /* TODO: need convenient way to free nk->values and nk->subkeys deeply 
       *       in all cases. 
       */
      return NULL;
    }
    nk->sec_desc->sk_off = nk->sk_off;
    
    /* add to the list of security descriptors (ref_count has been read from the files) */
    /* XXX: this kind of caching needs to be re-evaluated */
    DLIST_ADD( file->sec_desc_list, nk->sec_desc );
  }
  
  return nk;
}


/******************************************************************************

 ******************************************************************************/
static bool regfi_find_root_nk(REGF_FILE* file, uint32 offset, uint32 hbin_size,
			       uint32* root_offset)
{
  uint8 tmp[4];
  int32 record_size;
  uint32 length, hbin_offset = 0;
  REGF_NK_REC* nk = NULL;
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
	if(nk->key_type == NK_TYPE_ROOTKEY)
	{
	  found = true;
	  *root_offset = nk->offset;
	}
	free(nk);
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
REGF_FILE* regfi_open(const char* filename, uint32 flags)
{
  REGF_FILE* rb;
  REGF_HBIN* hbin = NULL;
  uint32 hbin_off;
  int fd;
  bool rla, save_unalloc = false;

  if(flags & REGFI_FLAG_SAVE_UNALLOC)
    save_unalloc = true;

  /* open an existing file */
  if ((fd = open(filename, O_RDONLY)) == -1) 
  {
    /* DEBUG(0,("regfi_open: failure to open %s (%s)\n", filename, strerror(errno)));*/
    return NULL;
  }
  
  /* read in an existing file */
  if ((rb = regfi_parse_regf(fd, true)) == NULL) 
  {
    /* DEBUG(0,("regfi_open: Failed to read initial REGF block\n"));*/
    close(fd);
    return NULL;
  }
  
  rb->hbins = range_list_new();
  rb->unalloc_cells = range_list_new();
  if((rb->hbins == NULL) || (rb->unalloc_cells == NULL))
  {
    range_list_free(rb->hbins);
    range_list_free(rb->unalloc_cells);
    close(fd);
    free(rb);
    return NULL;
  }

  rla = true;
  hbin_off = REGF_BLOCKSIZE;
  hbin = regfi_parse_hbin(rb, hbin_off, true, save_unalloc);
  while(hbin && rla)
  {
    hbin_off = hbin->file_off + hbin->block_size;
    rla = range_list_add(rb->hbins, hbin->file_off, hbin->block_size, hbin);
    hbin = regfi_parse_hbin(rb, hbin_off, true, save_unalloc);
  }

  /* success */
  return rb;
}


/*******************************************************************
 *******************************************************************/
int regfi_close( REGF_FILE *file )
{
  int fd;
  uint32 i;

  /* nothing to do if there is no open file */
  if ((file == NULL) || (file->fd == -1))
    return 0;

  fd = file->fd;
  file->fd = -1;
  for(i=0; i < range_list_size(file->hbins); i++)
    free(range_list_get(file->hbins, i)->data);
  range_list_free(file->hbins);

  for(i=0; i < range_list_size(file->unalloc_cells); i++)
    free(range_list_get(file->unalloc_cells, i)->data);
  range_list_free(file->unalloc_cells);

  free(file);

  return close(fd);
}


/******************************************************************************
 * There should be only *one* root key in the registry file based 
 * on my experience.  --jerry
 *****************************************************************************/
REGF_NK_REC* regfi_rootkey(REGF_FILE *file)
{
  REGF_NK_REC* nk = NULL;
  REGF_HBIN*   hbin;
  uint32       root_offset, i, num_hbins;
  
  if(!file)
    return NULL;

  /* Scan through the file one HBIN block at a time looking 
     for an NK record with a type == 0x002c.
     Normally this is the first nk record in the first hbin 
     block (but I'm not assuming that for now) */

  num_hbins = range_list_size(file->hbins);
  for(i=0; i < num_hbins; i++)
  {
    hbin = (REGF_HBIN*)range_list_get(file->hbins, i)->data;
    if(regfi_find_root_nk(file, hbin->file_off+HBIN_HEADER_REC_SIZE, 
			  hbin->block_size-HBIN_HEADER_REC_SIZE, &root_offset))
    {
      nk = regfi_load_key(file, root_offset, true);
      break;
    }
  }

  return nk;
}


/******************************************************************************
 *****************************************************************************/
void regfi_key_free(REGF_NK_REC* nk)
{
  uint32 i;
  
  if((nk->values != NULL) && (nk->values_off!=REGF_OFFSET_NONE))
  {
    for(i=0; i < nk->num_values; i++)
    {
      if(nk->values[i]->valuename != NULL)
	free(nk->values[i]->valuename);
      if(nk->values[i]->data != NULL)
	free(nk->values[i]->data);
      free(nk->values[i]);
    }
    free(nk->values);
  }

  if(nk->keyname != NULL)
    free(nk->keyname);
  if(nk->classname != NULL)
    free(nk->classname);

  /* XXX: not freeing hbin because these are cached.  This needs to be reviewed. */
  /* XXX: not freeing sec_desc because these are cached.  This needs to be reviewed. */
  free(nk);
}


/******************************************************************************
 *****************************************************************************/
REGFI_ITERATOR* regfi_iterator_new(REGF_FILE* fh)
{
  REGF_NK_REC* root;
  REGFI_ITERATOR* ret_val = (REGFI_ITERATOR*)malloc(sizeof(REGFI_ITERATOR));
  if(ret_val == NULL)
    return NULL;

  root = regfi_rootkey(fh);
  if(root == NULL)
  {
    free(ret_val);
    return NULL;
  }

  ret_val->key_positions = void_stack_new(REGF_MAX_DEPTH);
  if(ret_val->key_positions == NULL)
  {
    free(ret_val);
    free(root);
    return NULL;
  }

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
  REGFI_ITER_POSITION* cur;

  if(i->cur_key != NULL)
    regfi_key_free(i->cur_key);

  while((cur = (REGFI_ITER_POSITION*)void_stack_pop(i->key_positions)) != NULL)
  {
    regfi_key_free(cur->nk);
    free(cur);
  }
  
  free(i);
}



/******************************************************************************
 *****************************************************************************/
/* XXX: some way of indicating reason for failure should be added. */
bool regfi_iterator_down(REGFI_ITERATOR* i)
{
  REGF_NK_REC* subkey;
  REGFI_ITER_POSITION* pos;

  pos = (REGFI_ITER_POSITION*)malloc(sizeof(REGFI_ITER_POSITION));
  if(pos == NULL)
    return false;

  subkey = (REGF_NK_REC*)regfi_iterator_cur_subkey(i);
  if(subkey == NULL)
  {
    free(pos);
    return false;
  }

  pos->nk = i->cur_key;
  pos->cur_subkey = i->cur_subkey;
  if(!void_stack_push(i->key_positions, pos))
  {
    free(pos);
    regfi_key_free(subkey);
    return false;
  }

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

  regfi_key_free(i->cur_key);
  i->cur_key = pos->nk;
  i->cur_subkey = pos->cur_subkey;
  i->cur_value = 0;
  free(pos);

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
  REGF_NK_REC* subkey;
  bool found = false;
  uint32 old_subkey = i->cur_subkey;
  
  if(subkey_name == NULL)
    return false;

  /* XXX: this alloc/free of each sub key might be a bit excessive */
  subkey = (REGF_NK_REC*)regfi_iterator_first_subkey(i);
  while((subkey != NULL) && (found == false))
  {
    if(subkey->keyname != NULL 
       && strcasecmp(subkey->keyname, subkey_name) == 0)
      found = true;
    else
    {
      regfi_key_free(subkey);
      subkey = (REGF_NK_REC*)regfi_iterator_next_subkey(i);
    }
  }

  if(found == false)
  {
    i->cur_subkey = old_subkey;
    return false;
  }

  regfi_key_free(subkey);
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
const REGF_NK_REC* regfi_iterator_cur_key(REGFI_ITERATOR* i)
{
  return i->cur_key;
}


/******************************************************************************
 *****************************************************************************/
const REGF_NK_REC* regfi_iterator_first_subkey(REGFI_ITERATOR* i)
{
  i->cur_subkey = 0;
  return regfi_iterator_cur_subkey(i);
}


/******************************************************************************
 *****************************************************************************/
const REGF_NK_REC* regfi_iterator_cur_subkey(REGFI_ITERATOR* i)
{
  uint32 nk_offset;

  /* see if there is anything left to report */
  if (!(i->cur_key) || (i->cur_key->subkeys_off==REGF_OFFSET_NONE)
      || (i->cur_subkey >= i->cur_key->num_subkeys))
    return NULL;

  nk_offset = i->cur_key->subkeys->hashes[i->cur_subkey].nk_off;
  
  return regfi_load_key(i->f, nk_offset+REGF_BLOCKSIZE, true);
}


/******************************************************************************
 *****************************************************************************/
/* XXX: some way of indicating reason for failure should be added. */
const REGF_NK_REC* regfi_iterator_next_subkey(REGFI_ITERATOR* i)
{
  const REGF_NK_REC* subkey;

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
  const REGF_VK_REC* cur;
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
      cur = regfi_iterator_next_value(i);
  }

  return found;
}


/******************************************************************************
 *****************************************************************************/
const REGF_VK_REC* regfi_iterator_first_value(REGFI_ITERATOR* i)
{
  i->cur_value = 0;
  return regfi_iterator_cur_value(i);
}


/******************************************************************************
 *****************************************************************************/
const REGF_VK_REC* regfi_iterator_cur_value(REGFI_ITERATOR* i)
{
  REGF_VK_REC* ret_val = NULL;
  if(i->cur_value < i->cur_key->num_values)
    ret_val = i->cur_key->values[i->cur_value];

  return ret_val;
}


/******************************************************************************
 *****************************************************************************/
const REGF_VK_REC* regfi_iterator_next_value(REGFI_ITERATOR* i)
{
  const REGF_VK_REC* ret_val;

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
 * TODO: add way to return more detailed error information.
 *******************************************************************/
REGF_FILE* regfi_parse_regf(int fd, bool strict)
{
  uint8 file_header[REGF_BLOCKSIZE];
  uint32 length;
  uint32 file_length;
  struct stat sbuf;
  REGF_FILE* ret_val;

  /* Determine file length.  Must be at least big enough 
   * for the header and one hbin. 
   */
  if (fstat(fd, &sbuf) == -1)
    return NULL;
  file_length = sbuf.st_size;
  if(file_length < REGF_BLOCKSIZE+REGF_ALLOC_BLOCK)
    return NULL;

  ret_val = (REGF_FILE*)zalloc(sizeof(REGF_FILE));
  if(ret_val == NULL)
    return NULL;

  ret_val->fd = fd;
  ret_val->file_length = file_length;

  length = REGF_BLOCKSIZE;
  if((regfi_read(fd, file_header, &length)) != 0 
     || length != REGF_BLOCKSIZE)
  {
    free(ret_val);
    return NULL;
  }

  ret_val->checksum = IVAL(file_header, 0x1FC);
  ret_val->computed_checksum = regfi_compute_header_checksum(file_header);
  if (strict && (ret_val->checksum != ret_val->computed_checksum))
  {
    free(ret_val);
    return NULL;
  }

  memcpy(ret_val->magic, file_header, 4);
  if(strict && (memcmp(ret_val->magic, "regf", 4) != 0))
  {
    free(ret_val);
    return NULL;
  }
  
  ret_val->unknown1 = IVAL(file_header, 0x4);
  ret_val->unknown2 = IVAL(file_header, 0x8);

  ret_val->mtime.low = IVAL(file_header, 0xC);
  ret_val->mtime.high = IVAL(file_header, 0x10);

  ret_val->unknown3 = IVAL(file_header, 0x14);
  ret_val->unknown4 = IVAL(file_header, 0x18);
  ret_val->unknown5 = IVAL(file_header, 0x1C);
  ret_val->unknown6 = IVAL(file_header, 0x20);
  
  ret_val->data_offset = IVAL(file_header, 0x24);
  ret_val->last_block = IVAL(file_header, 0x28);

  ret_val->unknown7 = IVAL(file_header, 0x2C);

  return ret_val;
}



/*******************************************************************
 * Given real file offset, read and parse the hbin at that location
 * along with it's associated cells.  If save_unalloc is true, a list
 * of unallocated cell offsets will be stored in TODO.
 *******************************************************************/
/* TODO: Need a way to return types of errors.  Also need to free 
 *       the hbin/ps when an error occurs.
 */
REGF_HBIN* regfi_parse_hbin(REGF_FILE* file, uint32 offset, 
			    bool strict, bool save_unalloc)
{
  REGF_HBIN *hbin;
  uint8 hbin_header[HBIN_HEADER_REC_SIZE];
  uint32 length, curr_off;
  uint32 cell_len;
  bool is_unalloc;
  
  if(offset >= file->file_length)
    return NULL;

  if(lseek(file->fd, offset, SEEK_SET) == -1)
    return NULL;

  length = HBIN_HEADER_REC_SIZE;
  if((regfi_read(file->fd, hbin_header, &length) != 0) 
     || length != HBIN_HEADER_REC_SIZE)
    return NULL;


  if(lseek(file->fd, offset, SEEK_SET) == -1)
    return NULL;

  if(!(hbin = (REGF_HBIN*)zalloc(sizeof(REGF_HBIN)))) 
    return NULL;
  hbin->file_off = offset;

  memcpy(hbin->magic, hbin_header, 4);
  if(strict && (memcmp(hbin->magic, "hbin", 4) != 0))
  {
    free(hbin);
    return NULL;
  }

  hbin->first_hbin_off = IVAL(hbin_header, 0x4);
  hbin->block_size = IVAL(hbin_header, 0x8);
  /* this should be the same thing as hbin->block_size but just in case */
  hbin->next_block = IVAL(hbin_header, 0x1C);


  /* Ensure the block size is a multiple of 0x1000 and doesn't run off 
   * the end of the file. 
   */
  /* TODO: This may need to be relaxed for dealing with 
   *       partial or corrupt files. */
  if((offset + hbin->block_size > file->file_length)
     || (hbin->block_size & 0xFFFFF000) != hbin->block_size)
  {
    free(hbin);
    return NULL;
  }

  if(save_unalloc)
  {
    curr_off = HBIN_HEADER_REC_SIZE;
    while(curr_off < hbin->block_size)
    {
      if(!regfi_parse_cell(file->fd, hbin->file_off+curr_off, NULL, 0,
			   &cell_len, &is_unalloc))
	break;

      if((cell_len == 0) || ((cell_len & 0xFFFFFFFC) != cell_len))
	/* TODO: should report an error here. */
	break;

      /* for some reason the record_size of the last record in
	 an hbin block can extend past the end of the block
	 even though the record fits within the remaining 
	 space....aaarrrgggghhhhhh */  
      if(curr_off + cell_len >= hbin->block_size)
	cell_len = hbin->block_size - curr_off;

      if(is_unalloc)
	range_list_add(file->unalloc_cells, hbin->file_off+curr_off, 
	  cell_len, NULL);

      curr_off = curr_off+cell_len;
    }
  }

  return hbin;
}



REGF_NK_REC* regfi_parse_nk(REGF_FILE* file, uint32 offset, 
			    uint32 max_size, bool strict)
{
  uint8 nk_header[REGFI_NK_MIN_LENGTH];
  REGF_NK_REC* ret_val;
  uint32 length;
  uint32 cell_length;
  bool unalloc = false;

  if(!regfi_parse_cell(file->fd, offset, nk_header, REGFI_NK_MIN_LENGTH,
		       &cell_length, &unalloc))
     return NULL;
 
  /* A bit of validation before bothering to allocate memory */
  if((nk_header[0x0] != 'n') || (nk_header[0x1] != 'k'))
  {
    /* TODO: deal with subkey-lists that reference other subkey-lists. */
printf("DEBUG: magic check failed! \"%c%c\"\n", nk_header[0x0], nk_header[0x1]);
    return NULL;
  }

  ret_val = (REGF_NK_REC*)zalloc(sizeof(REGF_NK_REC));
  if(ret_val == NULL)
    return NULL;

  ret_val->offset = offset;
  ret_val->cell_size = cell_length;

  if(ret_val->cell_size > max_size)
    ret_val->cell_size = max_size & 0xFFFFFFF8;
  if((ret_val->cell_size < REGFI_NK_MIN_LENGTH) 
     || (strict && ret_val->cell_size != (ret_val->cell_size & 0xFFFFFFF8)))
  {
    free(ret_val);
    return NULL;
  }

  ret_val->magic[0] = nk_header[0x0];
  ret_val->magic[1] = nk_header[0x1];
  ret_val->key_type = SVAL(nk_header, 0x2);
  if((ret_val->key_type != NK_TYPE_NORMALKEY)
     && (ret_val->key_type != NK_TYPE_ROOTKEY) 
     && (ret_val->key_type != NK_TYPE_LINKKEY)
     && (ret_val->key_type != NK_TYPE_UNKNOWN1))
  {
    free(ret_val);
    return NULL;
  }

  ret_val->mtime.low = IVAL(nk_header, 0x4);
  ret_val->mtime.high = IVAL(nk_header, 0x8);
  
  ret_val->unknown1 = IVAL(nk_header, 0xC);
  ret_val->parent_off = IVAL(nk_header, 0x10);
  ret_val->num_subkeys = IVAL(nk_header, 0x14);
  ret_val->unknown2 = IVAL(nk_header, 0x18);
  ret_val->subkeys_off = IVAL(nk_header, 0x1C);
  ret_val->unknown3 = IVAL(nk_header, 0x20);
  ret_val->num_values = IVAL(nk_header, 0x24);
  ret_val->values_off = IVAL(nk_header, 0x28);
  ret_val->sk_off = IVAL(nk_header, 0x2C);
  /* TODO: currently we do nothing with class names.  Need to investigate. */
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
      free(ret_val);
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

  ret_val->keyname = (char*)zalloc(sizeof(char)*(ret_val->name_length+1));
  if(ret_val->keyname == NULL)
  {
    free(ret_val);
    return NULL;
  }

  /* Don't need to seek, should be at the right offset */
  length = ret_val->name_length;
  if((regfi_read(file->fd, (uint8*)ret_val->keyname, &length) != 0)
     || length != ret_val->name_length)
  {
    free(ret_val->keyname);
    free(ret_val);
    return NULL;
  }
  ret_val->keyname[ret_val->name_length] = '\0';

  return ret_val;
}



/*******************************************************************
 *******************************************************************/
REGF_VK_REC* regfi_parse_vk(REGF_FILE* file, uint32 offset, 
			    uint32 max_size, bool strict)
{
  REGF_VK_REC* ret_val;
  uint8 vk_header[REGFI_VK_MIN_LENGTH];
  uint32 raw_data_size, length, cell_length;
  bool unalloc = false;

  if(!regfi_parse_cell(file->fd, offset, vk_header, REGFI_VK_MIN_LENGTH,
		       &cell_length, &unalloc))
    return NULL;
   
  ret_val = (REGF_VK_REC*)zalloc(sizeof(REGF_VK_REC));
  if(ret_val == NULL)
    return NULL;

  ret_val->offset = offset;
  ret_val->cell_size = cell_length;

  if(ret_val->cell_size > max_size)
    ret_val->cell_size = max_size & 0xFFFFFFF8;
  if((ret_val->cell_size < REGFI_VK_MIN_LENGTH) 
     || (strict && ret_val->cell_size != (ret_val->cell_size & 0xFFFFFFF8)))
  {
    free(ret_val);
    return NULL;
  }

  ret_val->magic[0] = vk_header[0x0];
  ret_val->magic[1] = vk_header[0x1];
  if((ret_val->magic[0] != 'v') || (ret_val->magic[1] != 'k'))
  {
    free(ret_val);
    return NULL;
  }

  ret_val->name_length = SVAL(vk_header, 0x2);
  raw_data_size = IVAL(vk_header, 0x4);
  ret_val->data_size = raw_data_size & ~VK_DATA_IN_OFFSET;
  ret_val->data_off = IVAL(vk_header, 0x8);
  ret_val->type = IVAL(vk_header, 0xC);
  ret_val->flag = SVAL(vk_header, 0x10);
  ret_val->unknown1 = SVAL(vk_header, 0x12);

  if(ret_val->flag & VK_FLAG_NAME_PRESENT)
  {
    if(ret_val->name_length + REGFI_VK_MIN_LENGTH > ret_val->cell_size)
    {
      if(strict)
      {
	free(ret_val);
	return NULL;
      }
      else
	ret_val->name_length = ret_val->cell_size - REGFI_VK_MIN_LENGTH;
    }

    /* Round up to the next multiple of 8 */
    length = (ret_val->name_length + REGFI_NK_MIN_LENGTH) & 0xFFFFFFF8;
    if(length < ret_val->name_length + REGFI_NK_MIN_LENGTH)
      length+=8;

    ret_val->valuename = (char*)zalloc(sizeof(char)*(ret_val->name_length+1));
    if(ret_val->valuename == NULL)
    {
      free(ret_val);
      return NULL;
    }
    
    /* Don't need to seek, should be at the right offset */
    length = ret_val->name_length;
    if((regfi_read(file->fd, (uint8*)ret_val->valuename, &length) != 0)
       || length != ret_val->name_length)
    {
      free(ret_val->valuename);
      free(ret_val);
      return NULL;
    }
    ret_val->valuename[ret_val->name_length] = '\0';
  }
  else
    length = REGFI_VK_MIN_LENGTH;

  if(unalloc)
  {
    /* If cell_size is still greater, truncate. */
    if(length < ret_val->cell_size)
      ret_val->cell_size = length;
  }

  if(ret_val->data_size == 0)
    ret_val->data = NULL;
  else
  {
    ret_val->data = regfi_parse_data(file, ret_val->data_off+REGF_BLOCKSIZE,
				     raw_data_size, strict);
    if(strict && (ret_val->data == NULL))
    {
      free(ret_val->valuename);
      free(ret_val);
      return NULL;
    }
  }

  return ret_val;
}


uint8* regfi_parse_data(REGF_FILE* file, uint32 offset, uint32 length, bool strict)
{
  uint8* ret_val;
  uint32 read_length, cell_length;
  uint8 i;
  bool unalloc;

  /* The data is stored in the offset if the size <= 4 */
  if (length & VK_DATA_IN_OFFSET)
  {
    length = length & ~VK_DATA_IN_OFFSET;
    if(length > 4)
      return NULL;

    if((ret_val = (uint8*)zalloc(sizeof(uint8)*length)) == NULL)
      return NULL;

    offset = offset - REGF_BLOCKSIZE;
    for(i = 0; i < length; i++)
      ret_val[i] = (uint8)((offset >> i*8) & 0xFF);
  }
  else
  {
    if(!regfi_parse_cell(file->fd, offset, NULL, 0,
			 &cell_length, &unalloc))
      return NULL;
    
    if(cell_length < 8 || ((cell_length & 0xFFFFFFF8) != cell_length))
      return NULL;

    if(cell_length - 4 < length)
    {
      if(strict)
	return NULL;
      else
	length = cell_length - 4;
    }

    /* TODO: There is currently no check to ensure the data 
     *       cell doesn't cross HBIN boundary.
     */

    if((ret_val = (uint8*)zalloc(sizeof(uint8)*length)) == NULL)
      return NULL;

    read_length = length;
    if((regfi_read(file->fd, ret_val, &read_length) != 0) 
       || read_length != length)
    {
      free(ret_val);
      return NULL;
    }
  }

  return ret_val;
}
