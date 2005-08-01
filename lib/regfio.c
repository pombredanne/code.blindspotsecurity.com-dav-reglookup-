/*
 * Branched from Samba project Subversion repository, version #7470:
 *   http://websvn.samba.org/cgi-bin/viewcvs.cgi/trunk/source/registry/regfio.c
 *
 * Unix SMB/CIFS implementation.
 * Windows NT registry I/O library
 *
 * Copyright (C) 2005 Timothy D. Morgan
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

#include "../include/regfio.h"



/*******************************************************************
 *
 * TODO : Right now this code basically ignores classnames.
 *
 ******************************************************************/

/* Registry types mapping */
const VAL_STR reg_type_names[] = 
{
  { REG_SZ,                        "SZ"           },
  { REG_EXPAND_SZ,                 "EXPAND_SZ"    },
  { REG_BINARY,                    "BINARY"       },
  { REG_DWORD,                     "DWORD"        },
  { REG_DWORD_BE,                  "DWORD_BE"     },
  { REG_LINK,                      "LINK"         },
  { REG_MULTI_SZ,                  "MULTI_SZ"     },
  { REG_RESOURCE_LIST,             "RSRC_LIST"    },
  { REG_FULL_RESOURCE_DESCRIPTOR,  "RSRC_DESC"    },
  { REG_RESOURCE_REQUIREMENTS_LIST,"RSRC_REQ_LIST"},
  { REG_KEY,                       "KEY"          },
  { 0,                             NULL           },
};


/* Returns NULL on error */
const char* regfio_type_val2str(unsigned int val)
{
  int i;

  for(i=0; reg_type_names[i].val && reg_type_names[i].str; i++)
    if (reg_type_names[i].val == val) 
      return reg_type_names[i].str;

  return NULL;
}


/* Returns 0 on error */
int regfio_type_str2val(const char* str)
{
  int i;

  for(i=0; reg_type_names[i].val && reg_type_names[i].str; i++) 
    if (strcmp(reg_type_names[i].str, str) == 0) 
      return reg_type_names[i].val;

  return 0;
}


/*******************************************************************
 *******************************************************************/
static int read_block( REGF_FILE *file, prs_struct *ps, uint32 file_offset, 
		       uint32 block_size )
{
  int bytes_read, returned;
  char *buffer;
  SMB_STRUCT_STAT sbuf;

  /* check for end of file */

  if ( fstat( file->fd, &sbuf ) ) {
    /*DEBUG(0,("read_block: stat() failed! (%s)\n", strerror(errno)));*/
    return -1;
  }

  if ( (size_t)file_offset >= sbuf.st_size )
    return -1;
	
  /* if block_size == 0, we are parsnig HBIN records and need 
     to read some of the header to get the block_size from there */
	   
  if ( block_size == 0 ) {
    uint8 hdr[0x20];

    if ( lseek( file->fd, file_offset, SEEK_SET ) == -1 ) {
      /*DEBUG(0,("read_block: lseek() failed! (%s)\n", strerror(errno) ));*/
      return -1;
    }

    returned = read( file->fd, hdr, 0x20 );
    if ( (returned == -1) || (returned < 0x20) ) {
      /*DEBUG(0,("read_block: failed to read in HBIN header. Is the file corrupt?\n"));*/
      return -1;
    }

    /* make sure this is an hbin header */

    if ( strncmp( hdr, "hbin", HBIN_HDR_SIZE ) != 0 ) {
      /*DEBUG(0,("read_block: invalid block header!\n"));*/
      return -1;
    }

    block_size = IVAL( hdr, 0x08 );
  }

  /*DEBUG(10,("read_block: block_size == 0x%x\n", block_size ));*/

  /* set the offset, initialize the buffer, and read the block from disk */

  if ( lseek( file->fd, file_offset, SEEK_SET ) == -1 ) {
    /*DEBUG(0,("read_block: lseek() failed! (%s)\n", strerror(errno) ));*/
    return -1;
  }
	
  prs_init( ps, block_size, file->mem_ctx, UNMARSHALL );
  buffer = ps->data_p;
  bytes_read = returned = 0;

  while ( bytes_read < block_size ) 
  {
    if((returned = 
	read(file->fd, buffer+bytes_read, block_size-bytes_read)) == -1)
    {
      /*DEBUG(0,("read_block: read() failed (%s)\n", strerror(errno) ));*/
      return false;
    }
    if ((returned == 0) && (bytes_read < block_size)) 
    {
      /*DEBUG(0,("read_block: not a vald registry file ?\n" ));*/
      return false;
    }	

    bytes_read += returned;
  }
	
  return bytes_read;
}


/*******************************************************************
 *******************************************************************/
static bool prs_regf_block( const char *desc, prs_struct *ps, int depth, REGF_FILE *file )
{
  depth++;
	
  if ( !prs_uint8s( true, "header", ps, depth, file->header, sizeof( file->header )) )
    return false;
	
  /* yes, these values are always identical so store them only once */
	
  if ( !prs_uint32( "unknown1", ps, depth, &file->unknown1 ))
    return false;
  if ( !prs_uint32( "unknown1 (again)", ps, depth, &file->unknown1 ))
    return false;

  /* get the modtime */
	
  if ( !prs_set_offset( ps, 0x0c ) )
    return false;
  if ( !smb_io_time( "modtime", &file->mtime, ps, depth ) )
    return false;

  /* constants */
	
  if ( !prs_uint32( "unknown2", ps, depth, &file->unknown2 ))
    return false;
  if ( !prs_uint32( "unknown3", ps, depth, &file->unknown3 ))
    return false;
  if ( !prs_uint32( "unknown4", ps, depth, &file->unknown4 ))
    return false;
  if ( !prs_uint32( "unknown5", ps, depth, &file->unknown5 ))
    return false;

  /* get file offsets */
	
  if ( !prs_set_offset( ps, 0x24 ) )
    return false;
  if ( !prs_uint32( "data_offset", ps, depth, &file->data_offset ))
    return false;
  if ( !prs_uint32( "last_block", ps, depth, &file->last_block ))
    return false;
		
  /* one more constant */
	
  if ( !prs_uint32( "unknown6", ps, depth, &file->unknown6 ))
    return false;
		
  /* get the checksum */
	
  if ( !prs_set_offset( ps, 0x01fc ) )
    return false;
  if ( !prs_uint32( "checksum", ps, depth, &file->checksum ))
    return false;
	
  return true;
}


/*******************************************************************
 *******************************************************************/
static bool prs_hbin_block( const char *desc, prs_struct *ps, int depth, REGF_HBIN *hbin )
{
  uint32 block_size2;

  depth++;
	
  if ( !prs_uint8s( true, "header", ps, depth, hbin->header, sizeof( hbin->header )) )
    return false;

  if ( !prs_uint32( "first_hbin_off", ps, depth, &hbin->first_hbin_off ))
    return false;

  /* The dosreg.cpp comments say that the block size is at 0x1c.
     According to a WINXP NTUSER.dat file, this is wrong.  The block_size
     is at 0x08 */

  if ( !prs_uint32( "block_size", ps, depth, &hbin->block_size ))
    return false;

  block_size2 = hbin->block_size;
  prs_set_offset( ps, 0x1c );
  if ( !prs_uint32( "block_size2", ps, depth, &block_size2 ))
    return false;

  if ( !ps->io )
    hbin->dirty = true;
	

  return true;
}


/*******************************************************************
 *******************************************************************/
static bool prs_nk_rec( const char *desc, prs_struct *ps, 
			int depth, REGF_NK_REC *nk )
{
  uint16 class_length, name_length;
  uint32 start;
  uint32 data_size, start_off, end_off;
  uint32 unknown_off = REGF_OFFSET_NONE;

  nk->hbin_off = ps->data_offset;
  start = nk->hbin_off;
	
  depth++;
	
  /* back up and get the data_size */	
  if ( !prs_set_offset( ps, ps->data_offset-sizeof(uint32)) )
    return false;
  start_off = ps->data_offset;
  if ( !prs_uint32( "rec_size", ps, depth, &nk->rec_size ))
    return false;
	
  if (!prs_uint8s(true, "header", ps, depth, nk->header, sizeof(nk->header)))
    return false;
		
  if ( !prs_uint16( "key_type", ps, depth, &nk->key_type ))
    return false;
  if ( !smb_io_time( "mtime", &nk->mtime, ps, depth ))
    return false;
		
  if ( !prs_set_offset( ps, start+0x0010 ) )
    return false;
  if ( !prs_uint32( "parent_off", ps, depth, &nk->parent_off ))
    return false;
  if ( !prs_uint32( "num_subkeys", ps, depth, &nk->num_subkeys ))
    return false;
		
  if ( !prs_set_offset( ps, start+0x001c ) )
    return false;
  if ( !prs_uint32( "subkeys_off", ps, depth, &nk->subkeys_off ))
    return false;
  if ( !prs_uint32( "unknown_off", ps, depth, &unknown_off) )
    return false;
		
  if ( !prs_set_offset( ps, start+0x0024 ) )
    return false;
  if ( !prs_uint32( "num_values", ps, depth, &nk->num_values ))
    return false;
  if ( !prs_uint32( "values_off", ps, depth, &nk->values_off ))
    return false;
  if ( !prs_uint32( "sk_off", ps, depth, &nk->sk_off ))
    return false;
  if ( !prs_uint32( "classname_off", ps, depth, &nk->classname_off ))
    return false;

  if (!prs_uint32("max_bytes_subkeyname", ps, depth, &nk->max_bytes_subkeyname))
    return false;
  if ( !prs_uint32( "max_bytes_subkeyclassname", ps, 
		    depth, &nk->max_bytes_subkeyclassname))
  { return false; }
  if ( !prs_uint32( "max_bytes_valuename", ps, depth, &nk->max_bytes_valuename))
    return false;
  if ( !prs_uint32( "max_bytes_value", ps, depth, &nk->max_bytes_value))
    return false;
  if ( !prs_uint32( "unknown index", ps, depth, &nk->unk_index))
    return false;

  name_length = nk->keyname ? strlen(nk->keyname) : 0 ;
  class_length = nk->classname ? strlen(nk->classname) : 0 ;
  if ( !prs_uint16( "name_length", ps, depth, &name_length ))
    return false;
  if ( !prs_uint16( "class_length", ps, depth, &class_length ))
    return false;	
		
  if ( class_length ) 
  {
    ;;
  }
	
  if ( name_length ) 
  {
    if(ps->io && !(nk->keyname = (char*)zcalloc(sizeof(char), name_length+1)))
	return false;

    if ( !prs_uint8s( true, "name", ps, depth, nk->keyname, name_length) )
      return false;

    if ( ps->io ) 
      nk->keyname[name_length] = '\0';
  }

  end_off = ps->data_offset;

  /* data_size must be divisible by 8 and large enough to hold 
     the original record */

  data_size = ((start_off - end_off) & 0xfffffff8 );
  /*if ( data_size > nk->rec_size )
      DEBUG(10,("Encountered reused record (0x%x < 0x%x)\n", data_size, nk->rec_size));*/

  if ( !ps->io )
    nk->hbin->dirty = true;
  
  nk->subkey_index = 0;
  return true;
}


/*******************************************************************
 *******************************************************************/
static uint32 regf_block_checksum( prs_struct *ps )
{
  char *buffer = ps->data_p;
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
 *******************************************************************/
static bool read_regf_block( REGF_FILE *file )
{
  prs_struct ps;
  uint32 checksum;
	
  /* grab the first block from the file */
		
  if ( read_block( file, &ps, 0, REGF_BLOCKSIZE ) == -1 )
    return false;
	
  /* parse the block and verify the checksum */
	
  if ( !prs_regf_block( "regf_header", &ps, 0, file ) )
    return false;	
		
  checksum = regf_block_checksum( &ps );
	
  if(ps.is_dynamic)
    SAFE_FREE(ps.data_p);
  ps.is_dynamic = false;
  ps.buffer_size = 0;
  ps.data_offset = 0;

  if ( file->checksum !=  checksum ) {
    /*DEBUG(0,("read_regf_block: invalid checksum\n" ));*/
    return false;
  }

  return true;
}


/*******************************************************************
 *******************************************************************/
static REGF_HBIN* read_hbin_block( REGF_FILE *file, off_t offset )
{
  REGF_HBIN *hbin;
  uint32 record_size, curr_off, block_size, header;
	
  if ( !(hbin = (REGF_HBIN*)zalloc(sizeof(REGF_HBIN))) ) 
    return NULL;
  hbin->file_off = offset;
  hbin->free_off = -1;
		
  if ( read_block( file, &hbin->ps, offset, 0 ) == -1 )
    return NULL;
	
  if ( !prs_hbin_block( "hbin", &hbin->ps, 0, hbin ) )
    return NULL;	

  /* this should be the same thing as hbin->block_size but just in case */

  block_size = hbin->ps.buffer_size;

  /* Find the available free space offset.  Always at the end,
     so walk the record list and stop when you get to the end.
     The end is defined by a record header of 0xffffffff.  The 
     previous 4 bytes contains the amount of free space remaining 
     in the hbin block. */

  /* remember that the record_size is in the 4 bytes preceeding the record itself */

  if ( !prs_set_offset( &hbin->ps, file->data_offset+HBIN_HDR_SIZE-sizeof(uint32) ) )
    return false;

  record_size = 0;
  curr_off = hbin->ps.data_offset;
  while ( header != 0xffffffff ) {
    /* not done yet so reset the current offset to the 
       next record_size field */

    curr_off = curr_off+record_size;

    /* for some reason the record_size of the last record in
       an hbin block can extend past the end of the block
       even though the record fits within the remaining 
       space....aaarrrgggghhhhhh */

    if ( curr_off >= block_size ) {
      record_size = -1;
      curr_off = -1;
      break;
    }

    if ( !prs_set_offset( &hbin->ps, curr_off) )
      return false;

    if ( !prs_uint32( "rec_size", &hbin->ps, 0, &record_size ) )
      return false;
    if ( !prs_uint32( "header", &hbin->ps, 0, &header ) )
      return false;
		
    assert( record_size != 0 );

    if ( record_size & 0x80000000 ) {
      /* absolute_value(record_size) */
      record_size = (record_size ^ 0xffffffff) + 1;
    }
  }

  /* save the free space offset */

  if ( header == 0xffffffff ) {

    /* account for the fact that the curr_off is 4 bytes behind the actual 
       record header */

    hbin->free_off = curr_off + sizeof(uint32);
    hbin->free_size = record_size;
  }

  /*DEBUG(10,("read_hbin_block: free space offset == 0x%x\n", hbin->free_off));*/

  if ( !prs_set_offset( &hbin->ps, file->data_offset+HBIN_HDR_SIZE )  )
    return false;
	
  return hbin;
}


/*******************************************************************
 Input a randon offset and receive the correpsonding HBIN 
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

      hbin = read_hbin_block( file, block_off );

      if ( hbin ) 
	block_off = hbin->file_off + hbin->block_size;

    } while ( hbin && !hbin_contains_offset( hbin, offset ) );
  }

  if ( hbin )
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
  if ( !prs_uint8s( true, "keycheck", ps, depth, hash->keycheck, sizeof( hash->keycheck )) )
    return false;
	
  return true;
}


/*******************************************************************
 *******************************************************************/
static bool hbin_prs_lf_records( const char *desc, REGF_HBIN *hbin, int depth, REGF_NK_REC *nk )
{
  int i;
  REGF_LF_REC *lf = &nk->subkeys;
  uint32 data_size, start_off, end_off;

  depth++;

  /* check if we have anything to do first */
	
  if ( nk->num_subkeys == 0 )
    return true;

  /* move to the LF record */

  if ( !prs_set_offset( &hbin->ps, nk->subkeys_off + HBIN_HDR_SIZE - hbin->first_hbin_off ) )
    return false;

  /* backup and get the data_size */
	
  if ( !prs_set_offset( &hbin->ps, hbin->ps.data_offset-sizeof(uint32)) )
    return false;
  start_off = hbin->ps.data_offset;
  if ( !prs_uint32( "rec_size", &hbin->ps, depth, &lf->rec_size ))
    return false;

  if ( !prs_uint8s( true, "header", &hbin->ps, depth, lf->header, sizeof( lf->header )) )
    return false;
		
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
  /*  if ( data_size > lf->rec_size )*/
    /*DEBUG(10,("Encountered reused record (0x%x < 0x%x)\n", data_size, lf->rec_size));*/

  if ( !hbin->ps.io )
    hbin->dirty = true;

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

  if ( !prs_set_offset( &hbin->ps, sk->sk_off + HBIN_HDR_SIZE - hbin->first_hbin_off ) )
    return false;

  /* backup and get the data_size */
	
  if ( !prs_set_offset( &hbin->ps, hbin->ps.data_offset-sizeof(uint32)) )
    return false;
  start_off = hbin->ps.data_offset;
  if ( !prs_uint32( "rec_size", &hbin->ps, depth, &sk->rec_size ))
    return false;

  if ( !prs_uint8s( true, "header", ps, depth, sk->header, sizeof( sk->header )) )
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
  /*  if ( data_size > sk->rec_size )*/
    /*DEBUG(10,("Encountered reused record (0x%x < 0x%x)\n", data_size, sk->rec_size));*/

  if ( !hbin->ps.io )
    hbin->dirty = true;

  return true;
}


/*******************************************************************
 *******************************************************************/
static bool hbin_prs_vk_rec( const char *desc, REGF_HBIN *hbin, int depth, 
			     REGF_VK_REC *vk, REGF_FILE *file )
{
  uint32 offset;
  uint16 name_length;
  prs_struct *ps = &hbin->ps;
  uint32 data_size, start_off, end_off;

  depth++;

  /* backup and get the data_size */
	
  if ( !prs_set_offset( &hbin->ps, hbin->ps.data_offset-sizeof(uint32)) )
    return false;
  start_off = hbin->ps.data_offset;
  if ( !prs_uint32( "rec_size", &hbin->ps, depth, &vk->rec_size ))
    return false;

  if ( !prs_uint8s( true, "header", ps, depth, vk->header, sizeof( vk->header )) )
    return false;

  if ( !hbin->ps.io )
    name_length = strlen(vk->valuename);

  if ( !prs_uint16( "name_length", ps, depth, &name_length ))
    return false;
  if ( !prs_uint32( "data_size", ps, depth, &vk->data_size ))
    return false;
  if ( !prs_uint32( "data_off", ps, depth, &vk->data_off ))
    return false;
  if ( !prs_uint32( "type", ps, depth, &vk->type))
    return false;
  if ( !prs_uint16( "flag", ps, depth, &vk->flag))
    return false;

  offset = ps->data_offset;
  offset += 2;	/* skip 2 bytes */
  prs_set_offset( ps, offset );

  /* get the name */

  if ( vk->flag&VK_FLAG_NAME_PRESENT ) {

    if ( hbin->ps.io ) {
      if ( !(vk->valuename = (char*)zcalloc(sizeof(char), name_length+1 )))
	return false;
    }
    if ( !prs_uint8s( true, "name", ps, depth, vk->valuename, name_length ) )
      return false;
  }

  end_off = hbin->ps.data_offset;

  /* get the data if necessary */

  if ( vk->data_size != 0 ) 
  {
    bool charmode = false;

    if ( (vk->type == REG_SZ) || (vk->type == REG_MULTI_SZ) )
      charmode = true;

    /* the data is stored in the offset if the size <= 4 */
    if ( !(vk->data_size & VK_DATA_IN_OFFSET) ) 
    {
      REGF_HBIN *hblock = hbin;
      uint32 data_rec_size;

      if ( hbin->ps.io ) 
      {
	if ( !(vk->data = (uint8*)zcalloc(sizeof(uint8), vk->data_size) ) )
	  return false;
      }

      /* this data can be in another hbin */
      if ( !hbin_contains_offset( hbin, vk->data_off ) ) 
      {
	if ( !(hblock = lookup_hbin_block( file, vk->data_off )) )
	  return false;
      }
      if (!(prs_set_offset(&hblock->ps, 
			   (vk->data_off
			    + HBIN_HDR_SIZE
			    - hblock->first_hbin_off)
			   - sizeof(uint32))))
      {	return false; }

      if ( !hblock->ps.io ) 
      {
	data_rec_size = ( (vk->data_size+sizeof(uint32)) & 0xfffffff8 ) + 8;
	data_rec_size = ( data_rec_size - 1 ) ^ 0xFFFFFFFF;
      }
      if ( !prs_uint32( "data_rec_size", &hblock->ps, depth, &data_rec_size ))
	return false;
      if(!prs_uint8s(charmode, "data", &hblock->ps, depth, 
		     vk->data, vk->data_size))
	return false;

      if ( !hblock->ps.io )
	hblock->dirty = true;
    }
    else 
    {
      if(!(vk->data = zcalloc(sizeof(uint8), 4)))
	return false;
      SIVAL( vk->data, 0, vk->data_off );
    }
		
  }

  /* data_size must be divisible by 8 and large enough to hold the original record */

  data_size = ((start_off - end_off ) & 0xfffffff8 );
  /*if ( data_size !=  vk->rec_size )
    DEBUG(10,("prs_vk_rec: data_size check failed (0x%x < 0x%x)\n", data_size, vk->rec_size));*/

  if ( !hbin->ps.io )
    hbin->dirty = true;

  return true;
}


/*******************************************************************
 read a VK record which is contained in the HBIN block stored 
 in the prs_struct *ps.
*******************************************************************/
static bool hbin_prs_vk_records(const char *desc, REGF_HBIN *hbin, 
				int depth, REGF_NK_REC *nk, REGF_FILE *file)
{
  int i;
  uint32 record_size;

  depth++;
	
  /* check if we have anything to do first */
  if(nk->num_values == 0)
    return true;
		
  if(hbin->ps.io)
  {
    if (!(nk->values = (REGF_VK_REC*)zcalloc(sizeof(REGF_VK_REC), 
					      nk->num_values )))
      return false;
  }
	
  /* convert the offset to something relative to this HBIN block */
  if (!prs_set_offset(&hbin->ps, 
		      nk->values_off
		      + HBIN_HDR_SIZE
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
    if ( !prs_uint32( "vk_off", &hbin->ps, depth, &nk->values[i].rec_off ) )
      return false;
  }

  for ( i=0; i<nk->num_values; i++ ) 
  {
    REGF_HBIN *sub_hbin = hbin;
    uint32 new_offset;
	
    if ( !hbin_contains_offset( hbin, nk->values[i].rec_off ) ) 
    {
      sub_hbin = lookup_hbin_block( file, nk->values[i].rec_off );
      if ( !sub_hbin ) 
      {
	/*DEBUG(0,("hbin_prs_vk_records: Failed to find HBIN block containing offset [0x%x]\n", 
	  nk->values[i].hbin_off));*/
	return false;
      }
    }
		
    new_offset = nk->values[i].rec_off 
      + HBIN_HDR_SIZE 
      - sub_hbin->first_hbin_off;

    if (!prs_set_offset(&sub_hbin->ps, new_offset))
      return false;
    if (!hbin_prs_vk_rec("vk_rec", sub_hbin, depth, &nk->values[i], file))
      return false;
  }

  if ( !hbin->ps.io )
    hbin->dirty = true;

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
static bool hbin_prs_key( REGF_FILE *file, REGF_HBIN *hbin, REGF_NK_REC *nk )
{
  int depth = 0;
  REGF_HBIN *sub_hbin;
	
  depth++;

  /* get the initial nk record */
  if (!prs_nk_rec("nk_rec", &hbin->ps, depth, nk))
    return false;

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
	return false;
      }
    }
		
    if(!hbin_prs_vk_records("vk_rec", sub_hbin, depth, nk, file))
      return false;
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
	return false;
      }
    }
		
    if (!hbin_prs_lf_records("lf_rec", sub_hbin, depth, nk))
      return false;
  }

  /* get the to the security descriptor.  First look if we have already parsed it */
	
  if ((nk->sk_off!=REGF_OFFSET_NONE) 
      && !(nk->sec_desc = find_sk_record_by_offset( file, nk->sk_off )))
  {
    sub_hbin = hbin;
    if (!hbin_contains_offset(hbin, nk->sk_off))
    {
      sub_hbin = lookup_hbin_block( file, nk->sk_off );
      if ( !sub_hbin ) {
	/*DEBUG(0,("hbin_prs_key: Failed to find HBIN block containing sk_offset [0x%x]\n", 
	  nk->subkeys_off));*/
	return false;
      }
    }
		
    if ( !(nk->sec_desc = (REGF_SK_REC*)zalloc(sizeof(REGF_SK_REC) )) )
      return false;
    nk->sec_desc->sk_off = nk->sk_off;
    if ( !hbin_prs_sk_rec( "sk_rec", sub_hbin, depth, nk->sec_desc ))
      return false;
			
    /* add to the list of security descriptors (ref_count has been read from the files) */

    nk->sec_desc->sk_off = nk->sk_off;
    DLIST_ADD( file->sec_desc_list, nk->sec_desc );
  }
		
  return true;
}


/*******************************************************************
 *******************************************************************/
static bool next_record( REGF_HBIN *hbin, const char *hdr, bool *eob )
{
  char header[REC_HDR_SIZE] = "";
  uint32 record_size;
  uint32 curr_off, block_size;
  bool found = false;
  prs_struct *ps = &hbin->ps;
	
  curr_off = ps->data_offset;
  if ( curr_off == 0 )
    prs_set_offset( ps, HBIN_HEADER_REC_SIZE );

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
    if ( !prs_uint8s( true, "header", ps, 0, header, REC_HDR_SIZE ) )
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
static bool next_nk_record(REGF_FILE *file, REGF_HBIN *hbin, 
			   REGF_NK_REC *nk, bool *eob)
{
  if (next_record(hbin, "nk", eob) 
      && hbin_prs_key(file, hbin, nk))
    return true;
	
  return false;
}


/*******************************************************************
 Open the registry file and then read in the REGF block to get the 
 first hbin offset.
*******************************************************************/
REGF_FILE* regfio_open( const char *filename )
{
  REGF_FILE *rb;
  int flags = O_RDONLY;

  if ( !(rb = (REGF_FILE*)malloc(sizeof(REGF_FILE))) ) {
    /* DEBUG(0,("ERROR allocating memory\n")); */
    return NULL;
  }
  memset(rb, 0, sizeof(REGF_FILE));
  rb->fd = -1;
	
  /*	if ( !(rb->mem_ctx = talloc_init( "read_regf_block" )) ) 
    {
    regfio_close( rb );
    return NULL;
    }
  */
  rb->open_flags = flags;
	
  /* open and existing file */

  if ( (rb->fd = open(filename, flags)) == -1 ) {
    /* DEBUG(0,("regfio_open: failure to open %s (%s)\n", filename, strerror(errno)));*/
    regfio_close( rb );
    return NULL;
  }
	
  /* read in an existing file */
	
  if ( !read_regf_block( rb ) ) {
    /* DEBUG(0,("regfio_open: Failed to read initial REGF block\n"));*/
    regfio_close( rb );
    return NULL;
  }
	
  /* success */
	
  return rb;
}


/*******************************************************************
 *******************************************************************/
static void regfio_mem_free( REGF_FILE *file )
{
  /* free any zalloc()'d memory */
	
  /*	if ( file && file->mem_ctx )
    free(file->mem_ctx);
  */
}


/*******************************************************************
 *******************************************************************/
int regfio_close( REGF_FILE *file )
{
  int fd;

  regfio_mem_free( file );

  /* nothing to do if there is no open file */

  if ( !file || (file->fd == -1) )
    return 0;
		
  fd = file->fd;
  file->fd = -1;
  SAFE_FREE( file );

  return close( fd );
}


/*******************************************************************
 There should be only *one* root key in the registry file based 
 on my experience.  --jerry
*******************************************************************/
REGF_NK_REC* regfio_rootkey( REGF_FILE *file )
{
  REGF_NK_REC *nk;
  REGF_HBIN   *hbin;
  uint32      offset = REGF_BLOCKSIZE;
  bool        found = false;
  bool        eob;
	
  if ( !file )
    return NULL;
		
  if ( !(nk = (REGF_NK_REC*)zalloc(sizeof(REGF_NK_REC) )) ) {
    /*DEBUG(0,("regfio_rootkey: zalloc() failed!\n"));*/
    return NULL;
  }
	
  /* scan through the file on HBIN block at a time looking 
     for an NK record with a type == 0x002c.
     Normally this is the first nk record in the first hbin 
     block (but I'm not assuming that for now) */
	
  while ( (hbin = read_hbin_block( file, offset )) ) {
    eob = false;

    while ( !eob) {
      if ( next_nk_record( file, hbin, nk, &eob ) ) {
	if ( nk->key_type == NK_TYPE_ROOTKEY ) {
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
		
    if ( found ) 
      break;

    offset += hbin->block_size;
  }
	
  if ( !found ) {
    /*DEBUG(0,("regfio_rootkey: corrupt registry file ?  No root key record located\n"));*/
    return NULL;
  }

  DLIST_ADD( file->block_list, hbin );

  return nk;		
}


/* XXX: An interator struct should be used instead, and this function
 *   should operate on it, so the state of iteration isn't stored in the
 * REGF_NK_REC struct itself.
 */
/*******************************************************************
 This acts as an interator over the subkeys defined for a given 
 NK record.  Remember that offsets are from the *first* HBIN block.
*******************************************************************/
REGF_NK_REC* regfio_fetch_subkey( REGF_FILE *file, REGF_NK_REC *nk )
{
  REGF_NK_REC *subkey;
  REGF_HBIN   *hbin;
  uint32      nk_offset;

  /* see if there is anything left to report */
  if (!nk || (nk->subkeys_off==REGF_OFFSET_NONE) 
      || (nk->subkey_index >= nk->num_subkeys))
    return NULL;

  /* find the HBIN block which should contain the nk record */
  if(!(hbin 
       = lookup_hbin_block(file, nk->subkeys.hashes[nk->subkey_index].nk_off )))
  {
    /*DEBUG(0,("hbin_prs_key: Failed to find HBIN block containing offset [0x%x]\n", 
      nk->subkeys.hashes[nk->subkey_index].nk_off));*/
    return NULL;
  }
	
  nk_offset = nk->subkeys.hashes[nk->subkey_index].nk_off;
  if(!prs_set_offset(&hbin->ps, 
		     (HBIN_HDR_SIZE + nk_offset - hbin->first_hbin_off)))
    return NULL;
		
  nk->subkey_index++;
  if(!(subkey = (REGF_NK_REC*)zalloc(sizeof(REGF_NK_REC))))
    return NULL;

  if(!hbin_prs_key(file, hbin, subkey))
    return NULL;

  return subkey;
}
