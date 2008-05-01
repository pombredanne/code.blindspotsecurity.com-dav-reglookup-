/*
 * Copyright (C) 2008 Timothy D. Morgan
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
 * $Id: $
 */

#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>

#include "../include/regfi.h"
#include "../include/range_list.h"
#include "../include/lru_cache.h"


/* Globals, influenced by command line parameters */
bool print_verbose = false;
bool print_security = false;
bool print_header = true;
bool print_leftover = false;
bool print_parsedraw = false;
char* registry_file = NULL;


#include "common.c"

/* Output format:
 *   real_offset,min_length,record_type,parent_path,name,data_type,mtime,num_values,value,data_length,raw_data
 */

void regfi_print_nk(REGF_NK_REC* nk)
{
  printf("Found key at offset 0x%.8X:\n", nk->offset);
  printf("  keyname: \"%s\"\n", nk->keyname);
  printf("  parent_off (virtual): 0x%.8X\n", nk->parent_off);
  printf("  cell_size: %d\n", nk->cell_size);
  printf("  key_type: 0x%.4X\n", nk->key_type);
  printf("  magic: %c%c\n", nk->magic[0], nk->magic[1]);
  printf("  mtime: 0x%.8X 0x%.8X\n", nk->mtime.low, nk->mtime.high);
  printf("  name_length: %d\n", nk->name_length);
  printf("  classname_length: %d\n", nk->classname_length);
  printf("  classname_off (virtual): 0x%.8X\n", nk->classname_off);
  printf("  max_bytes_subkeyname: %d\n", nk->max_bytes_subkeyname);
  printf("  max_bytes_subkeyclassname: %d\n", nk->max_bytes_subkeyclassname);
  printf("  max_bytes_valuename: %d\n", nk->max_bytes_valuename);
  printf("  max_bytes_value: %d\n", nk->max_bytes_value);
  printf("  unknown1: 0x%.8X\n", nk->unknown1);
  printf("  unknown2: 0x%.8X\n", nk->unknown2);
  printf("  unknown3: 0x%.8X\n", nk->unknown3);
  printf("  unk_index: 0x%.8X\n", nk->unk_index);
  printf("  num_subkeys: %d\n", nk->num_subkeys);
  printf("  subkeys_off (virtual): 0x%.8X\n", nk->subkeys_off);
  printf("  num_values: %d\n", nk->num_values);
  printf("  values_off (virtual): 0x%.8X\n", nk->values_off);
  printf("  sk_off (virtual): 0x%.8X\n", nk->sk_off);
  printf("\n");
}


char* getQuotedData(int fd, uint32 offset, uint32 length)
{
  uint8* buf;
  char* quoted_buf;
  uint32 len;

  if((lseek(fd, offset, SEEK_SET)) == -1)
    return NULL;

  buf = (uint8*)malloc(length);
  if(buf == NULL)
    return NULL;

  len = length;
  if((regfi_read(fd, buf, &length) != 0) || length != len)
  {
    free(buf);
    return NULL;
  }

  quoted_buf = quote_buffer(buf, length, common_special_chars);
  free(buf);

  return quoted_buf;
}


void printKey(REGF_FILE* f, REGF_NK_REC* nk, const char* prefix)
{
  char mtime[20];
  time_t tmp_time[1];
  struct tm* tmp_time_s = NULL;
  char* quoted_name = NULL;
  char* quoted_raw = "";

  *tmp_time = nt_time_to_unix(&nk->mtime);
  tmp_time_s = gmtime(tmp_time);
  strftime(mtime, sizeof(mtime), "%Y-%m-%d %H:%M:%S", tmp_time_s);

  quoted_name = quote_string(nk->keyname, key_special_chars);
  if (quoted_name == NULL)
  {
    quoted_name = malloc(1*sizeof(char));
    if(quoted_name == NULL)
      bailOut(EX_OSERR, "ERROR: Could not allocate sufficient memory.\n");
    quoted_name[0] = '\0';

    fprintf(stderr, "WARNING: NULL key name in NK record at offset %.8X.\n",
	    nk->offset);
  }

  if(print_parsedraw)
    quoted_raw = getQuotedData(f->fd, nk->offset, nk->cell_size);

  printf("%.8X,%.8X,KEY,%s,%s,%s,%d,,,,,,,,%s\n", nk->offset, nk->cell_size,
	 prefix, quoted_name, mtime, nk->num_values, quoted_raw);
  
  if(print_parsedraw)
    free(quoted_raw);
}


void printValue(REGF_FILE* f, const REGF_VK_REC* vk, const char* prefix)
{
  char* quoted_value = NULL;
  char* quoted_name = NULL;
  char* quoted_raw = "";
  char* conv_error = NULL;
  const char* str_type = NULL;
  uint32 size = vk->data_size;

  /* Microsoft's documentation indicates that "available memory" is 
   * the limit on value sizes.  Annoying.  We limit it to 1M which 
   * should rarely be exceeded, unless the file is corrupt or 
   * malicious. For more info, see:
   *   http://msdn2.microsoft.com/en-us/library/ms724872.aspx
   */
  /* TODO: should probably do something different here for this tool.*/
  if(size > VK_MAX_DATA_LENGTH)
  {
    fprintf(stderr, "WARNING: value data size %d larger than "
	    "%d, truncating...\n", size, VK_MAX_DATA_LENGTH);
    size = VK_MAX_DATA_LENGTH;
  }
  
  quoted_name = quote_string(vk->valuename, key_special_chars);
  if (quoted_name == NULL)
  { /* Value names are NULL when we're looking at the "(default)" value.
     * Currently we just return a 0-length string to try an eliminate 
     * ambiguity with a literal "(default)" value.  The data type of a line
     * in the output allows one to differentiate between the parent key and
     * this value.
     */
    quoted_name = malloc(1*sizeof(char));
    if(quoted_name == NULL)
      bailOut(EX_OSERR, "ERROR: Could not allocate sufficient memory.\n");
    quoted_name[0] = '\0';
  }

  quoted_value = data_to_ascii(vk->data, size, vk->type, &conv_error);
  if(quoted_value == NULL)
  {
    quoted_value = malloc(1*sizeof(char));
    if(quoted_value == NULL)
      bailOut(EX_OSERR, "ERROR: Could not allocate sufficient memory.\n");
    quoted_value[0] = '\0';

    if(conv_error == NULL)
      fprintf(stderr, "WARNING: Could not quote value for '%s/%s'.  "
	      "Memory allocation failure likely.\n", prefix, quoted_name);
    else if(print_verbose)
      fprintf(stderr, "WARNING: Could not quote value for '%s/%s'.  "
	      "Returned error: %s\n", prefix, quoted_name, conv_error);
  }
  /* XXX: should these always be printed? */
  else if(conv_error != NULL && print_verbose)
    fprintf(stderr, "VERBOSE: While quoting value for '%s/%s', "
	    "warning returned: %s\n", prefix, quoted_name, conv_error);


  if(print_parsedraw)
    quoted_raw = getQuotedData(f->fd, vk->offset, vk->cell_size);

  str_type = regfi_type_val2str(vk->type);
  if(str_type == NULL)
    printf("%.8X,%.8X,VALUE,%s,%s,,,0x%.8X,%s,%d,,,,,%s\n", 
	   vk->offset, vk->cell_size, prefix, quoted_name, 
	   vk->type, quoted_value, vk->data_size, quoted_raw);
  else
    printf("%.8X,%.8X,VALUE,%s,%s,,,%s,%s,%d,,,,,%s\n", 
	   vk->offset, vk->cell_size, prefix, quoted_name, 
	   str_type, quoted_value, vk->data_size, quoted_raw);

  if(print_parsedraw)
    free(quoted_raw);
  if(quoted_value != NULL)
    free(quoted_value);
  if(quoted_name != NULL)
    free(quoted_name);
  if(conv_error != NULL)
    free(conv_error);
}


void printSK(REGF_FILE* f, REGF_SK_REC* sk)
{
  char* quoted_raw = NULL;
  char* empty_str = "";
  char* owner = regfi_get_owner(sk->sec_desc);
  char* group = regfi_get_group(sk->sec_desc);
  char* sacl = regfi_get_sacl(sk->sec_desc);
  char* dacl = regfi_get_dacl(sk->sec_desc);

  if(print_parsedraw)
    quoted_raw = getQuotedData(f->fd, sk->offset, sk->cell_size);

  if(owner == NULL)
    owner = empty_str;
  if(group == NULL)
    group = empty_str;
  if(sacl == NULL)
    sacl = empty_str;
  if(dacl == NULL)
    dacl = empty_str;

  printf("%.8X,%.8X,SK,,,,,,,,%s,%s,%s,%s,%s\n", sk->offset, sk->cell_size,
	 owner, group, sacl, dacl, quoted_raw);
  
  if(owner != empty_str)
    free(owner);
  if(group != empty_str)
    free(group);
  if(sacl != empty_str)
    free(sacl);
  if(dacl != empty_str)
    free(dacl);

  if(print_parsedraw)
    free(quoted_raw);
}


int printCell(REGF_FILE* f, uint32 offset)
{
  char* quoted_buf;
  uint32 cell_length;
  bool unalloc;

  if(!regfi_parse_cell(f->fd, offset, NULL, 0, &cell_length, &unalloc))
    return 1;

  quoted_buf = getQuotedData(f->fd, offset, cell_length);
  if(quoted_buf == NULL)
    return 2;

  printf("%.8X,%.8X,RAW,,,,,,,,,,,,%s\n", offset, cell_length, quoted_buf);

  free(quoted_buf);
  return 0;
}


/*
void dump_cell(int fd, uint32 offset)
{
  uint8* buf;
  uint32 length, j;
  int32 cell_length;

  if((lseek(fd, offset, SEEK_SET)) == -1)
    exit(8);
  
  length = 4;
  regfi_read(fd, (void*)&cell_length, &length);
  if(cell_length < 0)
    cell_length *= -1;

  buf = (uint8*)malloc(cell_length);
  if(buf == NULL)
    exit(9);
  if((lseek(fd, offset, SEEK_SET)) == -1)
    exit(8);

  length = cell_length;
  regfi_read(fd, buf, &length);
  for(j=0; j < length; j++)
  {
    printf("%.2X", buf[j]);
    if(j%4 == 3)
      printf(" ");
  }
  printf("\n");
  free(buf);
}
*/

static void usage(void)
{
  fprintf(stderr, "Usage: reglookup-recover [options] <REGISTRY_FILE>\n");
  fprintf(stderr, "Version: %s\n", REGLOOKUP_VERSION);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "\t-v\t sets verbose mode.\n");
  fprintf(stderr, "\t-h\t enables header row. (default)\n");
  fprintf(stderr, "\t-H\t disables header row.\n");
  fprintf(stderr, "\t-l\t enables leftover(raw) cell output.\n");
  fprintf(stderr, "\t-L\t disables leftover(raw) cell output. (default)\n");
  fprintf(stderr, "\t-r\t enables raw cell output for parsed cells.\n");
  fprintf(stderr, "\t-R\t disables raw cell output for parsed cells. (default)\n");
  fprintf(stderr, "\n");
}


bool removeRange(range_list* rl, uint32 rm_idx, uint32 offset, uint32 length)
{
  const range_list_element* cur_elem = range_list_get(rl, rm_idx);
  
  if(cur_elem == NULL)
  {
    printf("removeRange: cur_elem == NULL.  rm_idx=%d\n", rm_idx);
    return false;
  }

  if(offset > cur_elem->offset)
  {
    if(!range_list_split_element(rl, rm_idx, offset))
    {
      printf("removeRange: first split failed\n");
      return false;
    }
    rm_idx++;
  }
  
  if(offset+length < cur_elem->offset+cur_elem->length)
  {
    if(!range_list_split_element(rl, rm_idx, offset+length))
    {
      printf("removeRange: second split failed\n");
      return false;
    }
  }
  
  if(!range_list_remove(rl, rm_idx))
  {
    printf("removeRange: remove failed\n");
    return false;
  }

  return true;
}


int extractKeys(REGF_FILE* f, 
		range_list* unalloc_cells, 
		range_list* unalloc_keys)
{
  const range_list_element* cur_elem;
  REGF_NK_REC* key;
  uint32 i, j;

  for(i=0; i < range_list_size(unalloc_cells); i++)
  {
    cur_elem = range_list_get(unalloc_cells, i);
    for(j=0; j <= cur_elem->length; j+=8)
    {
      key = regfi_parse_nk(f, cur_elem->offset+j, 
			       cur_elem->length-j, false);
      if(key != NULL)
      {
	if(!range_list_add(unalloc_keys, key->offset, 
			   key->cell_size, key))
	{
	  fprintf(stderr, "ERROR: Couldn't add key to unalloc_keys.\n");
	  return 20;
	}
	
	if(!removeRange(unalloc_cells, i, key->offset, key->cell_size))
	  return 30;
      }
    }
  }

  return 0;
}


int extractValueLists(REGF_FILE* f,
		      range_list* unalloc_cells,
		      range_list* unalloc_keys)
{
  REGF_NK_REC* nk;
  REGF_HBIN* hbin;
  const range_list_element* cur_elem;
  uint32 i, j, num_keys, off, values_length, max_length;
  int32 idx;

  num_keys=range_list_size(unalloc_keys);
  for(i=0; i<num_keys; i++)
  {
    cur_elem = range_list_get(unalloc_keys, i);
    if(cur_elem == NULL)
      return 10;
    nk = cur_elem->data;

    if(nk->num_values && (nk->values_off!=REGF_OFFSET_NONE))
    {
      hbin = regfi_lookup_hbin(f, nk->values_off);
      
      if(hbin != NULL)
      {
	off = nk->values_off + REGF_BLOCKSIZE;
	max_length = hbin->block_size + hbin->file_off - off;
	/* TODO: This is kind of a hack.  We parse all value-lists, VK records, 
	 *       and data records without regard for current allocation status.  
	 *       On the off chance that such a record correctly parsed but is 
	 *       actually a reallocated structure used by something else, we 
	 *       simply prune it after the fact.  Would be faster to check this
	 *       up front somehow. 
	 */
	nk->values = regfi_load_valuelist(f, off, nk->num_values, max_length,
					  false);

	if(nk->values != NULL)
	{
	  idx = range_list_find(unalloc_cells, off);
	  if(idx < 0)
	  { /* We've parsed a values-list which isn't in the unallocated list,
	     * so prune it. 
	     */
	    for(j=0; j<nk->num_values; j++)
	    {
	      if(nk->values[j] != NULL)
	      {
		if(nk->values[j]->data != NULL)
		  free(nk->values[j]->data);
		free(nk->values[j]);
		free(nk->values);
		nk->values = NULL;
	      }
	    }
	  }
	  else
	  { /* Values-list was recovered.  Remove from unalloc_cells and 
	     * inspect values. 
	     */
	    values_length = (nk->num_values+1)*sizeof(uint32);
	    if(values_length != (values_length & 0xFFFFFFF8))
	      values_length = (values_length & 0xFFFFFFF8) + 8;
	    if(!removeRange(unalloc_cells, idx, off, values_length))
	      return 20;

	    for(j=0; j < nk->num_values; j++)
	    {
	      if(nk->values[j] != NULL)
	      {
		idx = range_list_find(unalloc_cells, nk->values[j]->offset);
		if(idx < 0)
		{ /* We've parsed a value which isn't in the unallocated list,
		   * so prune it.
		   */
		  if(nk->values[j]->data != NULL)
		    free(nk->values[j]->data);
		  free(nk->values[j]);
		  nk->values[j] = NULL;
		}
		else
		{
		  /* A VK record was recovered.  Remove from unalloc_cells
		   * and inspect data.
		   */
		  if(!removeRange(unalloc_cells, idx, nk->values[j]->offset,
				  nk->values[j]->cell_size))
		    return 21;

		  /* Don't bother pruning or removing from unalloc_cells if 
		   * there is no data, if it is stored the offset.
		   */
		  if(nk->values[j]->data != NULL && !nk->values[j]->data_in_offset)
		  {
		    off = nk->values[j]->data_off+REGF_BLOCKSIZE;
		    idx = range_list_find(unalloc_cells, off);
		    if(idx < 0)
		    { /* We've parsed a data cell which isn't in the unallocated 
		       * list, so prune it.
		       */
		      free(nk->values[j]->data);
		      nk->values[j]->data = NULL;
		    }
		    else
		    { /*A data record was recovered. Remove from unalloc_cells.*/
		      if(!removeRange(unalloc_cells, idx, off,
				      nk->values[j]->data_size))
			return 22;
		    }
		  }
		}
	      }
	    }
	  }
	}
      }
    }
  }

  return 0;
}



int extractValues(REGF_FILE* f, 
		  range_list* unalloc_cells, 
		  range_list* unalloc_values)
{
  const range_list_element* cur_elem;
  REGF_VK_REC* vk;
  uint32 i, j;

  for(i=0; i < range_list_size(unalloc_cells); i++)
  {
    cur_elem = range_list_get(unalloc_cells, i);
    for(j=0; j <= cur_elem->length; j+=8)
    {
      vk = regfi_parse_vk(f, cur_elem->offset+j, 
			   cur_elem->length-j, false);
      if(vk != NULL)
      {
	if(!range_list_add(unalloc_values, vk->offset,
			   vk->cell_size, vk))
	{
	  fprintf(stderr, "ERROR: Couldn't add value to unalloc_values.\n");
	  return 20;
	}
	
	if(!removeRange(unalloc_cells, i, vk->offset, vk->cell_size))
	  return 30;
      }
    }
  }

  return 0;
}


int extractSKs(REGF_FILE* f, 
	       range_list* unalloc_cells,
	       range_list* unalloc_sks)
{
  const range_list_element* cur_elem;
  REGF_SK_REC* sk;
  uint32 i, j;

  for(i=0; i < range_list_size(unalloc_cells); i++)
  {
    cur_elem = range_list_get(unalloc_cells, i);
    for(j=0; j <= cur_elem->length; j+=8)
    {
      sk = regfi_parse_sk(f, cur_elem->offset+j, 
			  cur_elem->length-j, false);
      if(sk != NULL)
      {
	if(!range_list_add(unalloc_sks, sk->offset,
			   sk->cell_size, sk))
	{
	  fprintf(stderr, "ERROR: Couldn't add sk to unalloc_sks.\n");
	  return 20;
	}
	
	if(!removeRange(unalloc_cells, i, sk->offset, sk->cell_size))
	  return 30;
      }
    }
  }

  return 0;
}


int main(int argc, char** argv)
{ 
  REGF_FILE* f;
  const range_list_element* cur_elem;
  range_list* unalloc_cells;
  range_list* unalloc_keys;
  range_list* unalloc_values;
  range_list* unalloc_sks;
  REGF_NK_REC* tmp_key;
  REGF_VK_REC* tmp_value;
  uint32 argi, arge, i, j, ret;
  /* uint32 test_offset;*/
  
  /* Process command line arguments */
  if(argc < 2)
  {
    usage();
    bailOut(EX_USAGE, "ERROR: Requires at least one argument.\n");
  }
  
  arge = argc-1;
  for(argi = 1; argi < arge; argi++)
  {
    if (strcmp("-v", argv[argi]) == 0)
      print_verbose = true;
    else if (strcmp("-h", argv[argi]) == 0)
      print_header = true;
    else if (strcmp("-H", argv[argi]) == 0)
      print_header = false;
    else if (strcmp("-l", argv[argi]) == 0)
      print_leftover = true;
    else if (strcmp("-L", argv[argi]) == 0)
      print_leftover = false;
    else if (strcmp("-r", argv[argi]) == 0)
      print_parsedraw = true;
    else if (strcmp("-R", argv[argi]) == 0)
      print_parsedraw = false;
    else
    {
      usage();
      fprintf(stderr, "ERROR: Unrecognized option: %s\n", argv[argi]);
      bailOut(EX_USAGE, "");
    }
  }
  /*test_offset = strtol(argv[argi++], NULL, 16);*/

  if((registry_file = strdup(argv[argi])) == NULL)
    bailOut(EX_OSERR, "ERROR: Memory allocation problem.\n");

  f = regfi_open(registry_file);
  if(f == NULL)
  {
    fprintf(stderr, "ERROR: Couldn't open registry file: %s\n", registry_file);
    bailOut(EX_NOINPUT, "");
  }

  if(print_header)
    printf("OFFSET,REC_LENGTH,REC_TYPE,PATH,NAME,"
	   "NK_MTIME,NK_NVAL,VK_TYPE,VK_VALUE,VK_DATA_LEN,"
	   "SK_OWNER,SK_GROUP,SK_SACL,SK_DACL,RAW_CELL\n");
  
/*
 * 1. Build a set of all empty cells.  May need to keep these in a
 *    sorted list based on offset.  May also need to have them in a hash
 *    table. 
 *
 * 2. Scour all cells for NK records (regardless of signature offset),
 *    caching those records separately when they successfully parsed.
 *
 * 3. Follow each NK record's parent pointers up until a non-deleted key
 *    is found.  Associate this full path with the NK records somehow.
 *
 * 4. Follow each NK record's pointers to Value-Lists and attempt to
 *    recover VK/data records from remaining cells.  Associate good VK
 *    records with their full paths.
 *
 * 5. For each remaining cell or partial cell, attempt to identify the
 *    record type and parse it.
 *
 * At each step, claimed cells are removed from the global cell
 * list/hash.  If only part of a cell is claimed, it is removed from
 * the list and the remaining fragments are re-added.
 */

  unalloc_cells = regfi_parse_unalloc_cells(f);
  if(unalloc_cells == NULL)
  {
    fprintf(stderr, "ERROR: Could not obtain list of unallocated cells.\n");
    return 1;
  }

  unalloc_keys = range_list_new();
  if(unalloc_keys == NULL)
    return 10;

  unalloc_values = range_list_new();
  if(unalloc_values == NULL)
    return 10;

  unalloc_sks = range_list_new();
  if(unalloc_sks == NULL)
    return 10;

  ret = extractKeys(f, unalloc_cells, unalloc_keys);
  if(ret != 0)
  {
    fprintf(stderr, "ERROR: extractKeys() failed with %d.\n", ret);
    return ret;
  }

  ret = extractValueLists(f, unalloc_cells, unalloc_keys);
  if(ret != 0)
  {
    fprintf(stderr, "ERROR: extractValueLists() failed with %d.\n", ret);
    return ret;
  }

  /* Carve any orphan values and associated data */
  ret = extractValues(f, unalloc_cells, unalloc_values);
  if(ret != 0)
  {
    fprintf(stderr, "ERROR: extractValues() failed with %d.\n", ret);
    return ret;
  }

  /* TODO: Carve SKs */
  /* Carve any SK records */
  ret = extractSKs(f, unalloc_cells, unalloc_sks);
  if(ret != 0)
  {
    fprintf(stderr, "ERROR: extractSKs() failed with %d.\n", ret);
    return ret;
  }


  for(i=0; i < range_list_size(unalloc_keys); i++)
  {
    cur_elem = range_list_get(unalloc_keys, i);
    tmp_key = (REGF_NK_REC*)cur_elem->data;

    printKey(f, tmp_key, "");

    for(j=0; j < tmp_key->num_values; j++)
    {
      tmp_value = tmp_key->values[j];
      if(tmp_value != NULL)
	printValue(f, tmp_value, tmp_key->keyname);
    }
  }

  /* Print out orphaned values */
  for(i=0; i < range_list_size(unalloc_values); i++)
  {
    cur_elem = range_list_get(unalloc_values, i);
    tmp_value = (REGF_VK_REC*)cur_elem->data; 

    printValue(f, tmp_value, "");
  }
  
  if(print_leftover)
  {
    for(i=0; i < range_list_size(unalloc_cells); i++)
    {
      cur_elem = range_list_get(unalloc_cells, i);
      printf("0x%X,%d,", cur_elem->offset, cur_elem->length);
      
      printCell(f, cur_elem->offset);
    }
  }

  /*
  printf("Analyzing test_offset...\n");
  if((tmp_key = regfi_parse_nk(f, test_offset, 4096, false)) != NULL)
    regfi_print_nk(tmp_key);
  else
    dump_cell(f->fd, test_offset);
  */

  return 0;
}