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

  if(hdr_len > 0)
  {
    length = hdr_len;
    if((regfi_read(fd, hdr, &length) != 0) || length != hdr_len)
      return false;
  }

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

  return true;
}


/*******************************************************************
 Input a random offset and receive the correpsonding HBIN 
 block for it
*******************************************************************/
static bool hbin_contains_offset( REGF_HBIN *hbin, uint32 offset )
{
  if ( !hbin )
    return false;
	
  if ( (offset > hbin->first_hbin_off) && (offset < (hbin->first_hbin_off+hbin->block_size)) )
    return true;
		
  return false;
}


/*******************************************************************
 Input a randon offset and receive the correpsonding HBIN 
 block for it
*******************************************************************/
static REGF_HBIN* lookup_hbin_block( REGF_FILE *file, uint32 offset )
{
  REGF_HBIN *hbin = NULL;
  uint32 block_off;

  /* start with the open list */

  for ( hbin=file->block_list; hbin; hbin=hbin->next ) {
    /* DEBUG(10,("lookup_hbin_block: address = 0x%x [0x%x]\n", hbin->file_off, (uint32)hbin ));*/
    if ( hbin_contains_offset( hbin, offset ) )
      return hbin;
  }
	
  if ( !hbin ) {
    /* start at the beginning */

    block_off = REGF_BLOCKSIZE;
    do {
      /* cleanup before the next round */
      if ( hbin )
      {
	if(hbin->ps.is_dynamic)
	  SAFE_FREE(hbin->ps.data_p);
	hbin->ps.is_dynamic = false;
	hbin->ps.buffer_size = 0;
	hbin->ps.data_offset = 0;
      }

      hbin = regfi_parse_hbin(file, block_off, true, false);

      if ( hbin ) 
	block_off = hbin->file_off + hbin->block_size;

    } while ( hbin && !hbin_contains_offset( hbin, offset ) );
  }

  if ( hbin )
    /* XXX: this kind of caching needs to be re-evaluated */
    DLIST_ADD( file->block_list, hbin );

  return hbin;
}


/*******************************************************************
 *******************************************************************/
static bool prs_hash_rec( const char *desc, prs_struct *ps, int depth, REGF_HASH_REC *hash )
{
  depth++;

  if ( !prs_uint32( "nk_off", ps, depth, &hash->nk_off ))
    return false;
  if ( !prs_uint8s("keycheck", ps, depth, hash->keycheck, sizeof( hash->keycheck )) )
    return false;
	
  return true;
}


/*******************************************************************
 *******************************************************************/
static bool hbin_prs_lf_records(const char *desc, REGF_HBIN *hbin, 
				int depth, REGF_NK_REC *nk)
{
  int i;
  REGF_LF_REC *lf = &nk->subkeys;
  uint32 data_size, start_off, end_off;

  depth++;

  /* check if we have anything to do first */
	
  if ( nk->num_subkeys == 0 )
    return true;

  /* move to the LF record */

  if ( !prs_set_offset( &hbin->ps, nk->subkeys_off + HBIN_MAGIC_SIZE - hbin->first_hbin_off ) )
    return false;

  /* backup and get the data_size */
	
  if ( !prs_set_offset( &hbin->ps, hbin->ps.data_offset-sizeof(uint32)) )
    return false;
  start_off = hbin->ps.data_offset;
  if ( !prs_uint32( "cell_size", &hbin->ps, depth, &lf->cell_size ))
    return false;

  if(!prs_uint8s("header", &hbin->ps, depth, 
		 lf->header, sizeof(lf->header)))
    return false;

  /*fprintf(stdout, "DEBUG: lf->header=%c%c\n", lf->header[0], lf->header[1]);*/

  if ( !prs_uint16( "num_keys", &hbin->ps, depth, &lf->num_keys))
    return false;

  if ( hbin->ps.io ) {
    if ( !(lf->hashes = (REGF_HASH_REC*)zcalloc(sizeof(REGF_HASH_REC), lf->num_keys )) )
      return false;
  }

  for ( i=0; i<lf->num_keys; i++ ) {
    if ( !prs_hash_rec( "hash_rec", &hbin->ps, depth, &lf->hashes[i] ) )
      return false;
  }

  end_off = hbin->ps.data_offset;

  /* data_size must be divisible by 8 and large enough to hold the original record */

  data_size = ((start_off - end_off) & 0xfffffff8 );
  /*  if ( data_size > lf->cell_size )*/
    /*DEBUG(10,("Encountered reused record (0x%x < 0x%x)\n", data_size, lf->cell_size));*/

  return true;
}


/*******************************************************************
 *******************************************************************/
static bool hbin_prs_sk_rec( const char *desc, REGF_HBIN *hbin, int depth, REGF_SK_REC *sk )
{
  prs_struct *ps = &hbin->ps;
  uint16 tag = 0xFFFF;
  uint32 data_size, start_off, end_off;


  depth++;

  if ( !prs_set_offset( &hbin->ps, sk->sk_off + HBIN_MAGIC_SIZE - hbin->first_hbin_off ) )
    return false;

  /* backup and get the data_size */
	
  if ( !prs_set_offset( &hbin->ps, hbin->ps.data_offset-sizeof(uint32)) )
    return false;
  start_off = hbin->ps.data_offset;
  if ( !prs_uint32( "cell_size", &hbin->ps, depth, &sk->cell_size ))
    return false;

  if (!prs_uint8s("header", ps, depth, sk->header, sizeof(sk->header)))
    return false;
  if ( !prs_uint16( "tag", ps, depth, &tag))
    return false;

  if ( !prs_uint32( "prev_sk_off", ps, depth, &sk->prev_sk_off))
    return false;
  if ( !prs_uint32( "next_sk_off", ps, depth, &sk->next_sk_off))
    return false;
  if ( !prs_uint32( "ref_count", ps, depth, &sk->ref_count))
    return false;
  if ( !prs_uint32( "size", ps, depth, &sk->size))
    return false;

  if ( !sec_io_desc( "sec_desc", &sk->sec_desc, ps, depth )) 
    return false;

  end_off = hbin->ps.data_offset;

  /* data_size must be divisible by 8 and large enough to hold the original record */

  data_size = ((start_off - end_off) & 0xfffffff8 );
  /*  if ( data_size > sk->cell_size )*/
    /*DEBUG(10,("Encountered reused record (0x%x < 0x%x)\n", data_size, sk->cell_size));*/

  return true;
}



/*******************************************************************
 read a VK record which is contained in the HBIN block stored 
 in the prs_struct *ps.
*******************************************************************/
static bool hbin_prs_vk_records(const char* desc, REGF_HBIN* hbin, 
				int depth, REGF_NK_REC* nk, REGF_FILE* file)
{
  int i;
  uint32 record_size, vk_raw_offset, vk_offset, vk_max_length;
  REGF_HBIN* sub_hbin;

  depth++;
  
  /* check if we have anything to do first */
  if(nk->num_values == 0)
    return true;
  	
  if(hbin->ps.io)
  {
    if (!(nk->values = (REGF_VK_REC**)zcalloc(sizeof(REGF_VK_REC*), 
					      nk->num_values )))
      return false;
  }
  
  /* convert the offset to something relative to this HBIN block */
  if (!prs_set_offset(&hbin->ps, 
		      nk->values_off
		      + HBIN_MAGIC_SIZE
		      - hbin->first_hbin_off
		      - sizeof(uint32)))
  { return false; }

  if ( !hbin->ps.io ) 
  { 
    record_size = ( ( nk->num_values * sizeof(uint32) ) & 0xfffffff8 ) + 8;
    record_size = (record_size - 1) ^ 0xFFFFFFFF;
  }

  if ( !prs_uint32( "record_size", &hbin->ps, depth, &record_size ) )
    return false;
  	
  for ( i=0; i<nk->num_values; i++ ) 
  {
    if ( !prs_uint32( "vk_off", &hbin->ps, depth, &vk_raw_offset) )
      return false;
    
    if(hbin_contains_offset(hbin, vk_raw_offset))
      sub_hbin = hbin;
    else
    {
      sub_hbin = lookup_hbin_block( file, vk_raw_offset );
      if (!sub_hbin)
	return false;
    }
  	
    vk_offset =  vk_raw_offset + REGF_BLOCKSIZE;
    vk_max_length = sub_hbin->block_size - vk_offset + sizeof(uint32);
    if((nk->values[i] = regfi_parse_vk(file, vk_offset, vk_max_length, true))
	== NULL)
      return false;
  }

  return true;
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
 *******************************************************************/
static REGF_NK_REC* hbin_prs_key(REGF_FILE *file, REGF_HBIN *hbin)
{
  REGF_HBIN* sub_hbin;
  REGF_NK_REC* nk;
  uint32 nk_cell_offset;
  uint32 nk_max_length;
  int depth = 0;

  depth++;

  /* get the initial nk record */
  nk_cell_offset = hbin->file_off + hbin->ps.data_offset - sizeof(uint32);
  nk_max_length = hbin->block_size - hbin->ps.data_offset + sizeof(uint32);
  if ((nk = regfi_parse_nk(file, nk_cell_offset, nk_max_length, true)) == NULL)
  {
fprintf(stderr, "DEBUG: regfi_parse_nk returned NULL!\n");
    return NULL;
  }

  /* fill in values */
  if ( nk->num_values && (nk->values_off!=REGF_OFFSET_NONE) ) 
  {
    sub_hbin = hbin;
    if ( !hbin_contains_offset( hbin, nk->values_off ) ) 
    {
      sub_hbin = lookup_hbin_block( file, nk->values_off );
      if ( !sub_hbin ) 
      {
	/*DEBUG(0,("hbin_prs_key: Failed to find HBIN block containing value_list_offset [0x%x]\n", 
	  nk->values_off));*/
	return NULL;
      }
    }
		
    if(!hbin_prs_vk_records("vk_rec", sub_hbin, depth, nk, file))
      return NULL;
  }
		
  /* now get subkeys */
  if ( nk->num_subkeys && (nk->subkeys_off!=REGF_OFFSET_NONE) ) 
  {
    sub_hbin = hbin;
    if ( !hbin_contains_offset( hbin, nk->subkeys_off ) ) 
    {
      sub_hbin = lookup_hbin_block( file, nk->subkeys_off );
      if ( !sub_hbin ) 
      {
	/*DEBUG(0,("hbin_prs_key: Failed to find HBIN block containing subkey_offset [0x%x]\n", 
	  nk->subkeys_off));*/
	return NULL;
      }
    }
		
    if (!hbin_prs_lf_records("lf_rec", sub_hbin, depth, nk))
      return NULL;
  }

  /* get the to the security descriptor.  First look if we have already parsed it */
	
  if ((nk->sk_off!=REGF_OFFSET_NONE) 
      && !(nk->sec_desc = find_sk_record_by_offset( file, nk->sk_off )))
  {
    sub_hbin = hbin;
    if (!hbin_contains_offset(hbin, nk->sk_off))
    {
      sub_hbin = lookup_hbin_block( file, nk->sk_off );
      if ( !sub_hbin ) 
      {
	free(nk);
	/*DEBUG(0,("hbin_prs_key: Failed to find HBIN block containing sk_offset [0x%x]\n", 
	  nk->subkeys_off));*/
	return NULL;
      }
    }
    
    if ( !(nk->sec_desc = (REGF_SK_REC*)zalloc(sizeof(REGF_SK_REC) )) )
      return NULL;
    nk->sec_desc->sk_off = nk->sk_off;
    if ( !hbin_prs_sk_rec( "sk_rec", sub_hbin, depth, nk->sec_desc ))
      return NULL;
			
    /* add to the list of security descriptors (ref_count has been read from the files) */

    nk->sec_desc->sk_off = nk->sk_off;
    /* XXX: this kind of caching needs to be re-evaluated */
    DLIST_ADD( file->sec_desc_list, nk->sec_desc );
  }
  
  return nk;
}


/*******************************************************************
 *******************************************************************/
static bool next_record( REGF_HBIN *hbin, const char *hdr, bool *eob )
{
  uint8 header[REC_HDR_SIZE] = "";
  uint32 record_size;
  uint32 curr_off, block_size;
  bool found = false;
  prs_struct *ps = &hbin->ps;
	
  curr_off = ps->data_offset;
  if ( curr_off == 0 )
    prs_set_offset( ps, HBIN_HEADER_REC_SIZE+4 );

  /* assume that the current offset is at the reacord header 
     and we need to backup to read the record size */
  curr_off -= sizeof(uint32);

  block_size = ps->buffer_size;
  record_size = 0;
  while ( !found ) 
  {
    curr_off = curr_off+record_size;
    if ( curr_off >= block_size ) 
      break;

    if ( !prs_set_offset( &hbin->ps, curr_off) )
      return false;

    if ( !prs_uint32( "record_size", ps, 0, &record_size ) )
      return false;
    if ( !prs_uint8s("header", ps, 0, header, REC_HDR_SIZE ) )
      return false;

    if ( record_size & 0x80000000 ) {
      /* absolute_value(record_size) */
      record_size = (record_size ^ 0xffffffff) + 1;
    }

    if ( memcmp( header, hdr, REC_HDR_SIZE ) == 0 ) {
      found = true;
      curr_off += sizeof(uint32);
    }
  } 

  /* mark prs_struct as done ( at end ) if no more SK records */
  /* mark end-of-block as true */	
  if ( !found )
  {
    prs_set_offset( &hbin->ps, hbin->ps.buffer_size );
    *eob = true;
    return false;
  }

  if (!prs_set_offset(ps, curr_off))
    return false;

  return true;
}


/*******************************************************************
 *******************************************************************/
static REGF_NK_REC* next_nk_record(REGF_FILE *file, REGF_HBIN *hbin, bool *eob)
{
  REGF_NK_REC* ret_val;
  if(next_record(hbin, "nk", eob)
     && (ret_val = hbin_prs_key(file, hbin)) != NULL)
    return ret_val;

fprintf(stderr, "ACK!");
  return NULL;
}


/*******************************************************************
 * Open the registry file and then read in the REGF block to get the
 * first hbin offset.
 *******************************************************************/
REGF_FILE* regfi_open(const char* filename)
{
  REGF_FILE* rb;
  int fd;
  int flags = O_RDONLY;

  /* open an existing file */
  if ((fd = open(filename, flags)) == -1) 
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
    close(fd);
    free(rb);
    return NULL;
  }

  /* success */
  return rb;
}


/*******************************************************************
 *******************************************************************/
int regfi_close( REGF_FILE *file )
{
  int fd;

  /* nothing to do if there is no open file */
  if ((file == NULL) || (file->fd == -1))
    return 0;

  fd = file->fd;
  file->fd = -1;
  range_list_free(file->hbins);
  range_list_free(file->unalloc_cells);
  free(file);

  return close( fd );
}


/******************************************************************************
 * There should be only *one* root key in the registry file based 
 * on my experience.  --jerry
 *****************************************************************************/
REGF_NK_REC* regfi_rootkey( REGF_FILE *file )
{
  REGF_NK_REC *nk;
  REGF_HBIN   *hbin;
  uint32      offset = REGF_BLOCKSIZE;
  bool        found = false;
  bool        eob;
  
  if(!file)
    return NULL;

  /* scan through the file on HBIN block at a time looking 
     for an NK record with a type == 0x002c.
     Normally this is the first nk record in the first hbin 
     block (but I'm not assuming that for now) */
	
  while((hbin = regfi_parse_hbin(file, offset, true, false))) 
  {
    eob = false;

    while(!eob) 
    {
      if((nk = next_nk_record(file, hbin, &eob)) != NULL) 
      {
	if ( nk->key_type == NK_TYPE_ROOTKEY ) 
	{
	  found = true;
	  break;
	}
      }
      if(hbin->ps.is_dynamic)
	SAFE_FREE(hbin->ps.data_p);
      hbin->ps.is_dynamic = false;
      hbin->ps.buffer_size = 0;
      hbin->ps.data_offset = 0;
    }
		
    if(found) 
      break;

    offset += hbin->block_size;
  }
  
  if (!found) {
    /*DEBUG(0,("regfi_rootkey: corrupt registry file ?  No root key record located\n"));*/
    return NULL;
  }

  /* XXX: this kind of caching needs to be re-evaluated */
  DLIST_ADD( file->block_list, hbin );

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
  REGF_NK_REC* subkey;
  REGF_HBIN* hbin;
  uint32 nk_offset;

  /* see if there is anything left to report */
  if (!(i->cur_key) || (i->cur_key->subkeys_off==REGF_OFFSET_NONE)
      || (i->cur_subkey >= i->cur_key->num_subkeys))
    return NULL;

  nk_offset = i->cur_key->subkeys.hashes[i->cur_subkey].nk_off;

  /* find the HBIN block which should contain the nk record */
  hbin = lookup_hbin_block(i->f, nk_offset);
  if(!hbin)
  {
    /* XXX: should print out some kind of error message every time here */
    /*DEBUG(0,("hbin_prs_key: Failed to find HBIN block containing offset [0x%x]\n", 
      i->cur_key->subkeys.hashes[i->cur_subkey].nk_off));*/
    return NULL;
  }
  
  if(!prs_set_offset(&hbin->ps, 
		     HBIN_MAGIC_SIZE + nk_offset - hbin->first_hbin_off))
    return NULL;
		
  if((subkey = hbin_prs_key(i->f, hbin)) == NULL)
    return NULL;

  return subkey;
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



/****************/
/* Experimental */
/****************/
/*
typedef struct {
  uint32 offset;
  uint32 size;
} REGFI_CELL_INFO;

typedef struct {
  uint32 count
  REGFI_CELL_INFO** cells;
} REGFI_CELL_LIST;
*/


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
  uint32 ret, length;
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
  if((ret = regfi_read(fd, file_header, &length)) != 0 
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
  int32 cell_len;
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

  /* TODO: need to get rid of this, but currently lots depends on the 
   * ps structure. 
   */
  if(!prs_init(&hbin->ps, hbin->block_size, file->mem_ctx, UNMARSHALL))
  {
    free(hbin);
    return NULL;
  }
  length = hbin->block_size;
  if((regfi_read(file->fd, (uint8*)hbin->ps.data_p, &length) != 0) 
     || length != hbin->block_size)
  {
    free(hbin);
    return NULL;
  }


  if(save_unalloc)
  {
    cell_len = 0;
    curr_off = HBIN_HEADER_REC_SIZE;
    while ( curr_off < hbin->block_size ) 
    {
      is_unalloc = false;
      cell_len = IVALS(hbin->ps.data_p, curr_off);
      if(cell_len > 0)
	is_unalloc = true;
      else
	cell_len = -1*cell_len;

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

  /* TODO: need to get rid of this, but currently lots depends on the 
   * ps structure. 
   */
  if(!prs_set_offset(&hbin->ps, file->data_offset+HBIN_MAGIC_SIZE))
    return NULL;

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
    /*fprintf(stderr, "DEBUG: magic check failed! \"%c%c\"\n", nk_header[0x0], nk_header[0x1]);*/
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
  bool unalloc;

  /* The data is stored in the offset if the size <= 4 */
  if (length & VK_DATA_IN_OFFSET)   
  {
    length = length & ~VK_DATA_IN_OFFSET;
    if(length > 4)
      return NULL;

    if((ret_val = (uint8*)zalloc(sizeof(uint8)*length)) == NULL)
      return NULL;
    memcpy(ret_val, &offset, length);
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
