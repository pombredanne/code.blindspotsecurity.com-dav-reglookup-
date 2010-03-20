/*
 * This program attempts to recover deleted data structures in a registry hive.
 *
 * Copyright (C) 2008-2010 Timothy D. Morgan
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

#include <stdio.h>
#include <stdlib.h>

#include "talloc.h"
#include "regfi.h"
#include "range_list.h"
#include "lru_cache.h"


/* Globals, influenced by command line parameters */
bool print_verbose = false;
bool print_security = false;
bool print_header = true;
bool print_leftover = false;
bool print_parsedraw = false;
const char* registry_file = NULL;

#include "common.c"


char* getQuotedData(REGFI_RAW_FILE* file_cb, uint32_t offset, uint32_t length)
{
  uint8_t* buf;
  char* quoted_buf;
  uint32_t len;

  if((regfi_seek(file_cb, offset, SEEK_SET)) == -1)
    return NULL;

  buf = (uint8_t*)malloc(length);
  if(buf == NULL)
    return NULL;

  len = length;
  if((regfi_read(file_cb, buf, &length) != 0) || length != len)
  {
    free(buf);
    return NULL;
  }

  quoted_buf = quote_buffer(buf, length, common_special_chars);
  free(buf);

  return quoted_buf;
}

/* XXX: Somewhere in here, need to start looking for and handling classnames */
void printKey(REGFI_FILE* f, REGFI_NK_REC* nk, const char* prefix)
{
  char mtime[24];
  char* quoted_name = NULL;
  char* quoted_raw = "";

  formatTime(&nk->mtime, mtime);
  
  /* XXX: Add command line option to choose output encoding */
  regfi_interpret_keyname(f, nk, REGFI_ENCODING_ASCII, true);

  quoted_name = get_quoted_keyname(nk);
  if (quoted_name == NULL)
  {
    quoted_name = malloc(1*sizeof(char));
    if(quoted_name == NULL)
      bailOut(REGLOOKUP_EXIT_OSERR, 
	      "ERROR: Could not allocate sufficient memory.\n");
    quoted_name[0] = '\0';

    fprintf(stderr, "WARN: NULL key name in NK record at offset %.8X.\n",
	    nk->offset);
  }

  if(print_parsedraw)
    quoted_raw = getQuotedData(f->cb, nk->offset, nk->cell_size);

  printf("%.8X,%.8X,KEY,%s,%s,%s,%d,,,,,,,,%s\n", nk->offset, nk->cell_size,
	 prefix, quoted_name, mtime, nk->num_values, quoted_raw);
  
  if(print_parsedraw)
    free(quoted_raw);
  free(quoted_name);
}


void printValue(REGFI_FILE* f, REGFI_VK_REC* vk, const char* prefix)
{
  char* quoted_value = NULL;
  char* quoted_name = NULL;
  char* quoted_raw = "";
  char* conv_error = NULL;
  const char* str_type = NULL;

  /* XXX: Add command line option to choose output encoding */
  regfi_interpret_valuename(f, vk, REGFI_ENCODING_ASCII, true);
  
  quoted_name = get_quoted_valuename(vk);
  if (quoted_name == NULL)
  { /* Value names are NULL when we're looking at the "(default)" value.
     * Currently we just return a 0-length string to try an eliminate 
     * ambiguity with a literal "(default)" value.  The data type of a line
     * in the output allows one to differentiate between the parent key and
     * this value.
     */
    quoted_name = strdup("");
    if(quoted_name == NULL)
      bailOut(REGLOOKUP_EXIT_OSERR, "ERROR: Could not allocate sufficient memory.\n");
  }

  /* XXX: Add command line option to choose output encoding */
  if(vk->data != NULL 
     && !regfi_interpret_data(f, REGFI_ENCODING_ASCII, vk->type, vk->data))
  {
    fprintf(stderr, "WARN: Error occurred while interpreting data for VK record"
	    " at offset 0x%.8X.\n", vk->offset);
  }
  printMsgs(f);

  quoted_value = data_to_ascii(vk->data, &conv_error);
  if(quoted_value == NULL)
  {
    quoted_value = malloc(1*sizeof(char));
    if(quoted_value == NULL)
      bailOut(REGLOOKUP_EXIT_OSERR, "ERROR: Could not allocate sufficient memory.\n");
    quoted_value[0] = '\0';

    if(conv_error == NULL)
      fprintf(stderr, "WARN: Could not quote value for '%s/%s'.  "
	      "Memory allocation failure likely.\n", prefix, quoted_name);
    else if(print_verbose)
      fprintf(stderr, "WARN: Could not quote value for '%s/%s'.  "
	      "Returned error: %s\n", prefix, quoted_name, conv_error);
  }
  /* XXX: should these always be printed? */
  else if(conv_error != NULL && print_verbose)
    fprintf(stderr, "INFO: While quoting value for '%s/%s', "
	    "warning returned: %s\n", prefix, quoted_name, conv_error);


  if(print_parsedraw)
    quoted_raw = getQuotedData(f->cb, vk->offset, vk->cell_size);

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


void printSK(REGFI_FILE* f, REGFI_SK_REC* sk)
{
  char* quoted_raw = NULL;
  char* empty_str = "";
  char* owner = regfi_get_owner(sk->sec_desc);
  char* group = regfi_get_group(sk->sec_desc);
  char* sacl = regfi_get_sacl(sk->sec_desc);
  char* dacl = regfi_get_dacl(sk->sec_desc);

  if(print_parsedraw)
    quoted_raw = getQuotedData(f->cb, sk->offset, sk->cell_size);

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


int printCell(REGFI_FILE* f, uint32_t offset)
{
  char* quoted_buf;
  uint32_t cell_length;
  bool unalloc;

  if(!regfi_parse_cell(f->cb, offset, NULL, 0, &cell_length, &unalloc))
    return 1;

  quoted_buf = getQuotedData(f->cb, offset, cell_length);
  if(quoted_buf == NULL)
    return 2;

  printf("%.8X,%.8X,RAW,,,,,,,,,,,,%s\n", offset, cell_length, quoted_buf);

  free(quoted_buf);
  return 0;
}


/* This function returns a properly quoted parent path or partial parent 
 * path for a given key.  Returns NULL on error, "" if no path was available.
 * Paths returned must be free()d.
 */
/* XXX: This is not terribly efficient, as it may reparse many keys 
 *      repeatedly.  Should try to add caching.
 */
char* getParentPath(REGFI_FILE* f, REGFI_NK_REC* nk)
{
  void_stack* path_stack = void_stack_new(REGFI_MAX_DEPTH);
  REGFI_NK_REC* cur_ancestor;
  char* ret_val;
  uint32_t virt_offset, i, stack_size, ret_val_size, ret_val_used, offset;
  int32_t max_size;
  REGFI_BUFFER* path_element;
  
  /* The path_stack size limit should guarantee that we don't recurse forever. */
  virt_offset = nk->parent_off;
  ret_val_size = 1; /* NUL */
  while(virt_offset != REGFI_OFFSET_NONE)
  {
    offset = virt_offset+REGFI_REGF_SIZE;
    max_size = regfi_calc_maxsize(f, offset);
    if(max_size < 0)
      virt_offset = REGFI_OFFSET_NONE;
    else
    {
      cur_ancestor = regfi_parse_nk(f, offset, max_size, true);
      printMsgs(f);

      if(cur_ancestor == NULL)
	virt_offset = REGFI_OFFSET_NONE;
      else
      {
	if(cur_ancestor->flags & REGFI_NK_FLAG_ROOT)
	  virt_offset = REGFI_OFFSET_NONE;
	else
	  virt_offset = cur_ancestor->parent_off;
	
	path_element = talloc(path_stack, REGFI_BUFFER);
	if(path_element != NULL)
	{
	  /* XXX: Add command line option to choose output encoding */
	  regfi_interpret_keyname(f, cur_ancestor, REGFI_ENCODING_ASCII, true);
	  
	  path_element->buf = (uint8_t*)get_quoted_keyname(cur_ancestor);
	}
 
	if(path_element == NULL || path_element->buf == NULL 
	   || !void_stack_push(path_stack, path_element))
	{
	  /* XXX: Need to add a warning here */
	  regfi_free_record(cur_ancestor);
	  void_stack_free(path_stack);
	  return NULL;
	}

	/* Path element and preceeding delimiter
	 * Note that this integer can't overflow since key name lengths are
	 * 16 bits and the max depth is 512.
	 */
	path_element->len = strlen((char*)path_element->buf);
	ret_val_size += path_element->len + 1;

	regfi_free_record(cur_ancestor);
      }
    }
  }
  
  stack_size = void_stack_size(path_stack);
  ret_val_used = 0;
  ret_val = malloc(ret_val_size);
  if(ret_val == NULL)
  {
    void_stack_free(path_stack);
    return NULL;
  }
  ret_val[0] = '\0';

  for(i=0; i<stack_size; i++)
  {
    path_element = void_stack_pop(path_stack);
    snprintf(ret_val+ret_val_used, ret_val_size-ret_val_used, 
	     "/%s", path_element->buf);
    ret_val_used += path_element->len + 1;
    free(path_element->buf);
    talloc_free(path_element);
  }
  void_stack_free(path_stack);

  return ret_val;
}


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


bool removeRange(range_list* rl, uint32_t offset, uint32_t length)
{
  int32_t rm_idx;
  const range_list_element* cur_elem;

  rm_idx = range_list_find(rl, offset);
  if(rm_idx < 0)
  {
    fprintf(stderr, "DEBUG: removeRange: rm_idx < 0; (%d)\n", rm_idx);
    return false;
  }

  cur_elem = range_list_get(rl, rm_idx);
  if(cur_elem == NULL)
  {
    fprintf(stderr, "DEBUG: removeRange: cur_elem == NULL.  rm_idx=%d\n", rm_idx);
    return false;
  }

  if(offset > cur_elem->offset)
  {
    if(!range_list_split_element(rl, rm_idx, offset))
    {
      fprintf(stderr, "DEBUG: removeRange: first split failed\n");
      return false;
    }
    rm_idx++;
    cur_elem = range_list_get(rl, rm_idx);
    if(cur_elem == NULL)
    {
      fprintf(stderr, 
	      "DEBUG: removeRange: cur_elem == NULL after first split.  rm_idx=%d\n",
	      rm_idx);
      return false;
    }
  }
  
  if(offset+length < cur_elem->offset+cur_elem->length)
  {
    if(!range_list_split_element(rl, rm_idx, offset+length))
    {
      fprintf(stderr, "DEBUG: removeRange: second split failed\n");
      return false;
    }
  }
  
  if(!range_list_remove(rl, rm_idx))
  {
    fprintf(stderr, "DEBUG: removeRange: remove failed\n");
    return false;
  }

  return true;
}


int extractVKs(REGFI_FILE* f,
	       range_list* unalloc_cells,
	       range_list* unalloc_values)
{
  const range_list_element* cur_elem;
  REGFI_VK_REC* vk;
  uint32_t i, j;

  for(i=0; i < range_list_size(unalloc_cells); i++)
  {
    printMsgs(f);
    cur_elem = range_list_get(unalloc_cells, i);
    for(j=0; j <= cur_elem->length; j+=8)
    {
      vk = regfi_parse_vk(f, cur_elem->offset+j, 
			   cur_elem->length-j, false);
      printMsgs(f);

      if(vk != NULL)
      {
	if(!range_list_add(unalloc_values, vk->offset,
			   vk->cell_size, vk))
	{
	  fprintf(stderr, "ERROR: Couldn't add value to unalloc_values.\n");
	  return 20;
	}
	j+=vk->cell_size-8;
      }
    }
  }

  /* Remove value ranges from the unalloc_cells before we continue. */
  for(i=0; i<range_list_size(unalloc_values); i++)
  {
    cur_elem = range_list_get(unalloc_values, i);
    if(!removeRange(unalloc_cells, cur_elem->offset, cur_elem->length))
      return 30;
  }

  return 0;
}


int extractDataCells(REGFI_FILE* file,
		     range_list* unalloc_cells,
		     range_list* unalloc_values)
{
  const range_list_element* cur_elem;
  REGFI_VK_REC* vk;
  range_list* bd_cells;
  REGFI_BUFFER data;
  uint32_t i, j, offset, cell_length, length;
  int32_t max_size;
  bool unalloc;

  bd_cells = range_list_new();
  if(bd_cells == NULL)
    return 10;

  data.buf = NULL;
  data.len = 0;
  for(i=0; i<range_list_size(unalloc_values); i++)
  {
    cur_elem = range_list_get(unalloc_values, i);
    vk = (REGFI_VK_REC*)cur_elem->data;
    if(vk == NULL)
      return 11;

    length = vk->data_size;
    vk->data = NULL;
    if(vk->data_size != 0)
    {
      offset = vk->data_off+REGFI_REGF_SIZE;

      if(vk->data_in_offset)
	data = regfi_parse_little_data(file, vk->data_off, 
				       length, false);
      else
      {
	max_size = regfi_calc_maxsize(file, offset);
	if(max_size >= 0 
	   && regfi_parse_cell(file->cb, offset, NULL, 0,
			       &cell_length, &unalloc)
	   && (cell_length & 0x00000007) == 0
	   && cell_length <= max_size)
	{
	  if(cell_length - 4 < length)
	  {
	    /* Multi-cell "big data" */

	    /* XXX: All big data records thus far have been 16 bytes long.  
	     *      Should we check for this precise size instead of just 
	     *      relying upon the above check?
	     */
	    if (file->major_version >= 1 && file->minor_version >= 5)
	    {
	      /* Attempt to parse a big data record */
	      data = regfi_load_big_data(file, offset, length, 
					 cell_length, bd_cells, false);

	      /* XXX: if this turns out NULL, should fall back to truncating cell */
	      if(data.buf != NULL)
	      {
		for(j=0; j<range_list_size(bd_cells); j++)
		{
		  cur_elem = range_list_get(bd_cells, j);
		  if(cur_elem == NULL)
		    return 20;
		  if(!range_list_has_range(unalloc_cells,
					   cur_elem->offset, 
					   cur_elem->length))
		  {
		    fprintf(stderr, 
			    "WARN: Successfully parsed big data at offset"
			    " 0x%.8X was rejected because some substructure"
			    " (offset=0x%.8X) is allocated or used in other"
			    " recovered structures.\n",
			    offset, cur_elem->offset);
		    talloc_free(data.buf);
		    data.buf = NULL;
		    data.len = 0;
		    break;
		  }
		}
		
		if(data.buf != NULL)
		{
		  for(j=0; j<range_list_size(bd_cells); j++)
		  {
		    cur_elem = range_list_get(bd_cells, j);
		    if(cur_elem == NULL)
		      return 21;
		    
		    if(!removeRange(unalloc_cells, 
				    cur_elem->offset,
				    cur_elem->length))
		    { return 22; }
		  }
		}
	      }

	    }
	    else
	    {
	      fprintf(stderr, 
		      "WARN: Data length (0x%.8X)"
		      " larger than remaining cell length (0x%.8X)"
		      " while parsing data record at offset 0x%.8X."
		      " Truncating...\n",
		      length, cell_length - 4, offset);
	       length = cell_length - 4;
	    }
	  }
	  
	  /* Typical 1-cell data */
	  if(range_list_has_range(unalloc_cells, offset, length))
	  {
	    data = regfi_parse_data(file, offset, length, false);
	    if(data.buf != NULL)
	      if(!removeRange(unalloc_cells, offset, length))
		return 30;
	  }
	}
      }
      /* XXX: Need to come up with a different way to link these so the
       *      vk->data item can be removed from the structure.
       */
      vk->data = regfi_buffer_to_data(data);
      talloc_steal(vk, vk->data);
    }
  }

  range_list_free(bd_cells);
  return 0;
}


/* NOTE: unalloc_keys should be an empty range_list. */
int extractKeys(REGFI_FILE* f, 
		range_list* unalloc_cells, 
		range_list* unalloc_keys)
{
  const range_list_element* cur_elem;
  REGFI_NK_REC* key;
  uint32_t i, j;
  int error_code = 0;

  for(i=0; i < range_list_size(unalloc_cells); i++)
  {
    printMsgs(f);
    cur_elem = range_list_get(unalloc_cells, i);
    for(j=0; cur_elem->length > REGFI_NK_MIN_LENGTH 
	  && j <= cur_elem->length-REGFI_NK_MIN_LENGTH; j+=8)
    {
      key = regfi_parse_nk(f, cur_elem->offset+j,
			   cur_elem->length-j, false);
      printMsgs(f);

      if(key != NULL)
      {
	if(!range_list_add(unalloc_keys, key->offset, 
			   key->cell_size, key))
	{
	  fprintf(stderr, "ERROR: Couldn't add key to unalloc_keys.\n");
	  error_code = 20;
	  goto fail;
	}
	talloc_steal(unalloc_keys, key);
	j+=key->cell_size-8;
      }
    }
  }

  for(i=0; i<range_list_size(unalloc_keys); i++)
  {
    cur_elem = range_list_get(unalloc_keys, i);
    if(!removeRange(unalloc_cells, cur_elem->offset, cur_elem->length))
    {
      error_code = 30;
      goto fail;
    }
  }

  return 0;

 fail:
  regfi_free_record(key);
  return error_code;
}

int extractValueLists(REGFI_FILE* f,
		      range_list* unalloc_cells,
		      range_list* unalloc_keys,
		      range_list* unalloc_linked_values)
{
  REGFI_NK_REC* nk;
  REGFI_VK_REC* vk;
  const range_list_element* cur_elem;
  uint32_t i, j, num_keys, off, values_length;
  int32_t max_size;

  num_keys=range_list_size(unalloc_keys);
  for(i=0; i<num_keys; i++)
  {
    cur_elem = range_list_get(unalloc_keys, i);
    if(cur_elem == NULL)
      return 10;
    nk = cur_elem->data;

    if(nk->num_values && (nk->values_off!=REGFI_OFFSET_NONE))
    {
      off = nk->values_off + REGFI_REGF_SIZE;
      max_size = regfi_calc_maxsize(f, off);
      if(max_size >= 0)
      {
	nk->values = regfi_load_valuelist(f, off, nk->num_values, 
					  max_size, false);
	if(nk->values != NULL && nk->values->elements != NULL)
	{
	  /* Number of elements in the value list may be shorter than advertised 
	   * by NK record due to cell truncation.  We'll consider this valid and 
	   * only throw out the whole value list if it bleeds into an already 
	   * parsed structure.
	   */
	  values_length = (nk->values->num_values+1)*sizeof(uint32_t);
	  if(values_length != (values_length & 0xFFFFFFF8))
	    values_length = (values_length & 0xFFFFFFF8) + 8;

	  if(!range_list_has_range(unalloc_cells, off, values_length))
	  { /* We've parsed a values-list which isn't in the unallocated list,
	     * so prune it.
	     */
	    talloc_free(nk->values);
	    nk->values = NULL;
	  }
	  else
	  { /* Values-list was recovered.  Remove from unalloc_cells and 
	     * inspect values. 
	     */
	    if(!removeRange(unalloc_cells, off, values_length))
	      return 20;

	    for(j=0; j < nk->values->num_values; j++)
	    {
	      /* Don't bother to restrict cell length here, since we'll
	       * check our unalloc_cells range_list later. 
	       */
	      vk = regfi_parse_vk(f, nk->values->elements[j]+REGFI_REGF_SIZE,
				  0x7FFFFFFF, false);
	      printMsgs(f);
	      
	      if(vk != NULL)
	      {
		if(range_list_has_range(unalloc_cells, 
					vk->offset, vk->cell_size))
		{
		  if(!range_list_add(unalloc_linked_values, vk->offset,
				     vk->cell_size, vk))
		  {
		    talloc_free(vk);
		    return 30;
		  }

		  if(!removeRange(unalloc_cells, vk->offset, vk->cell_size))
		    return 40;
		}
		else
		  talloc_free(vk);
	      }
	    }
	  }
	}
      }
    }
  }

  return 0;
}



/* NOTE: unalloc_sks should be an empty range_list. */
int extractSKs(REGFI_FILE* f, 
	       range_list* unalloc_cells,
	       range_list* unalloc_sks)
{
  const range_list_element* cur_elem;
  REGFI_SK_REC* sk;
  uint32_t i, j;

  for(i=0; i < range_list_size(unalloc_cells); i++)
  {
    printMsgs(f);
    cur_elem = range_list_get(unalloc_cells, i);
    for(j=0; j <= cur_elem->length; j+=8)
    {
      sk = regfi_parse_sk(f, cur_elem->offset+j, 
			  cur_elem->length-j, false);
      printMsgs(f);

      if(sk != NULL)
      {
	if(!range_list_add(unalloc_sks, sk->offset,
			   sk->cell_size, sk))
	{
	  fprintf(stderr, "ERROR: Couldn't add sk to unalloc_sks.\n");
	  return 20;
	}
	talloc_steal(unalloc_sks, sk);
	j+=sk->cell_size-8;
      }
    }
  }

  for(i=0; i<range_list_size(unalloc_sks); i++)
  {
    cur_elem = range_list_get(unalloc_sks, i);
    if(!removeRange(unalloc_cells, cur_elem->offset, cur_elem->length))
      return 30;
  }

  return 0;
}


int main(int argc, char** argv)
{ 
  REGFI_FILE* f;
  const range_list_element* cur_elem;
  range_list* unalloc_cells;
  range_list* unalloc_keys;
  range_list* unalloc_linked_values;
  range_list* unalloc_values;
  range_list* unalloc_sks;
  char** parent_paths;
  char* tmp_name;
  char* tmp_path;
  REGFI_NK_REC* tmp_key;
  REGFI_VK_REC* tmp_value;
  uint32_t argi, arge, i, j, ret, num_unalloc_keys;
  int fd;

  /* Process command line arguments */
  if(argc < 2)
  {
    usage();
    bailOut(REGLOOKUP_EXIT_USAGE, "ERROR: Requires at least one argument.\n");
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
      bailOut(REGLOOKUP_EXIT_USAGE, "");
    }
  }
  registry_file = argv[argi];

  fd = openHive(registry_file);
  if(fd < 0)
  {
    fprintf(stderr, "ERROR: Couldn't open registry file: %s\n", registry_file);
    bailOut(REGLOOKUP_EXIT_NOINPUT, "");
  }

  if(print_verbose)
    regfi_log_start(REGFI_LOG_ERROR|REGFI_LOG_WARN|REGFI_LOG_INFO);
  else
    regfi_log_start(REGFI_LOG_ERROR);

  f = regfi_alloc(fd);
  if(f == NULL)
  {
    close(fd);
    bailOut(REGLOOKUP_EXIT_NOINPUT, "ERROR: Failed to create REGFI_FILE structure.\n");
  }

  if(print_header)
    printf("OFFSET,REC_LENGTH,REC_TYPE,PATH,NAME,"
	   "NK_MTIME,NK_NVAL,VK_TYPE,VK_VALUE,VK_DATA_LEN,"
	   "SK_OWNER,SK_GROUP,SK_SACL,SK_DACL,RAW_CELL\n");

  unalloc_cells = regfi_parse_unalloc_cells(f);
  if(unalloc_cells == NULL)
  {
    fprintf(stderr, "ERROR: Could not obtain list of unallocated cells.\n");
    return 1;
  }

  unalloc_keys = range_list_new();
  if(unalloc_keys == NULL)
    return 10;

  unalloc_linked_values = range_list_new();
  if(unalloc_linked_values == NULL)
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

  ret = extractValueLists(f, unalloc_cells, unalloc_keys,unalloc_linked_values);
  if(ret != 0)
  {
    fprintf(stderr, "ERROR: extractValueLists() failed with %d.\n", ret);
    return ret;
  }

  /* Carve any orphan values */
  ret = extractVKs(f, unalloc_cells, unalloc_values);
  if(ret != 0)
  {
    fprintf(stderr, "ERROR: extractVKs() failed with %d.\n", ret);
    return ret;
  }

  /* Carve any data associated with VK records */
  ret = extractDataCells(f, unalloc_cells, unalloc_linked_values);
  if(ret != 0)
  {
    fprintf(stderr, "ERROR: extractDataCells() failed with %d.\n", ret);
    return ret;
  }
  ret = extractDataCells(f, unalloc_cells, unalloc_values);
  if(ret != 0)
  {
    fprintf(stderr, "ERROR: extractDataCells() failed with %d.\n", ret);
    return ret;
  }
  
  /* Carve any SK records */
  ret = extractSKs(f, unalloc_cells, unalloc_sks);
  if(ret != 0)
  {
    fprintf(stderr, "ERROR: extractSKs() failed with %d.\n", ret);
    return ret;
  }

  /* Now that we're done carving, associate recovered keys with parents, 
   * if at all possible.
   */
  num_unalloc_keys = range_list_size(unalloc_keys);
  parent_paths = (char**)malloc(sizeof(char*)*num_unalloc_keys);
  if(parent_paths == NULL)
    return 10;

  for(i=0; i < num_unalloc_keys; i++)
  {
    cur_elem = range_list_get(unalloc_keys, i);
    tmp_key = (REGFI_NK_REC*)cur_elem->data;

    if(tmp_key == NULL)
      return 20;
    
    parent_paths[i] = getParentPath(f, tmp_key);
    if(parent_paths[i] == NULL)
      return 20;
  }
  
  /* Now start the output */
  for(i=0; i < num_unalloc_keys; i++)
  {
    cur_elem = range_list_get(unalloc_keys, i);
    tmp_key = (REGFI_NK_REC*)cur_elem->data;

    printKey(f, tmp_key, parent_paths[i]);
    if(tmp_key->num_values > 0 && tmp_key->values != NULL)
    {
      /* XXX: Add command line option to choose output encoding */
      regfi_interpret_keyname(f, tmp_key, REGFI_ENCODING_ASCII, true);

      tmp_name = get_quoted_keyname(tmp_key);
      tmp_path = (char*)malloc(strlen(parent_paths[i])+strlen(tmp_name)+2);
      if(tmp_path == NULL)
      {
	free(tmp_name);
	return 10;
      }

      sprintf(tmp_path, "%s/%s", parent_paths[i], tmp_name);
      for(j=0; j < tmp_key->values->num_values; j++)
      {
	tmp_value = 
	  (REGFI_VK_REC*)range_list_find_data(unalloc_linked_values, 
					      tmp_key->values->elements[j]
					      + REGFI_REGF_SIZE);
	if(tmp_value != NULL)
	  printValue(f, tmp_value, tmp_path);
      }
      free(tmp_path);
      free(tmp_name);
      free(parent_paths[i]);
    }
  }
  free(parent_paths);

  /* Print out orphaned values */
  for(i=0; i < range_list_size(unalloc_values); i++)
  {
    cur_elem = range_list_get(unalloc_values, i);
    tmp_value = (REGFI_VK_REC*)cur_elem->data; 

    printValue(f, tmp_value, "");
  }
  
  if(print_leftover)
  {
    for(i=0; i < range_list_size(unalloc_cells); i++)
    {
      cur_elem = range_list_get(unalloc_cells, i);
      printCell(f, cur_elem->offset);
    }
  }

  range_list_free(unalloc_cells);
  range_list_free(unalloc_keys);
  range_list_free(unalloc_linked_values);
  range_list_free(unalloc_values);
  range_list_free(unalloc_sks);

  regfi_free(f);
  regfi_log_stop();
  close(fd);

  return 0;
}
