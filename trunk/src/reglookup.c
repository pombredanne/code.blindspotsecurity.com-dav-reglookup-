/*
 * A utility to read a Windows NT/2K/XP/2K3 registry file, using 
 * Gerald Carter''s regfio interface.
 *
 * Copyright (C) 2005-2006 Timothy D. Morgan
 * Copyright (C) 2002 Richard Sharpe, rsharpe@richardsharpe.com
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


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <iconv.h>
#include "../include/regfio.h"
#include "../include/void_stack.h"

/* Globals, influenced by command line parameters */
bool print_verbose = false;
bool print_security = false;
bool print_header = true;
bool path_filter_enabled = false;
bool type_filter_enabled = false;
char* path_filter = NULL;
int type_filter;
char* registry_file = NULL;

/* Other globals */
const char* key_special_chars = ",\"\\/";
const char* subfield_special_chars = ",\"\\|";
const char* common_special_chars = ",\"\\";

iconv_t conv_desc;


void bailOut(int code, char* message)
{
  fprintf(stderr, message);
  exit(code);
}


/* Returns a newly malloc()ed string which contains original buffer,
 * except for non-printable or special characters are quoted in hex
 * with the syntax '\xQQ' where QQ is the hex ascii value of the quoted
 * character.  A null terminator is added, since only ascii, not binary,
 * is returned.
 */
static char* quote_buffer(const unsigned char* str, 
			  unsigned int len, const char* special)
{
  unsigned int i, added_len;
  unsigned int num_written = 0;

  unsigned int buf_len = sizeof(char)*(len+1);
  char* ret_val = malloc(buf_len);
  char* tmp_buf;

  if(ret_val == NULL)
    return NULL;

  for(i=0; i<len; i++)
  {
    if(buf_len <= (num_written+5))
    {
      /* Expand the buffer by the memory consumption rate seen so far 
       * times the amount of input left to process.  The expansion is bounded 
       * below by a minimum safety increase, and above by the maximum possible 
       * output string length.  This should minimize both the number of 
       * reallocs() and the amount of wasted memory.
       */
      added_len = (len-i)*num_written/(i+1);
      if((buf_len+added_len) > (len*4+1))
	buf_len = len*4+1;
      else
      {
	if (added_len < 5)
	  buf_len += 5;
	else
	  buf_len += added_len;
      }

      tmp_buf = realloc(ret_val, buf_len);
      if(tmp_buf == NULL)
      {
	free(ret_val);
	return NULL;
      }
      ret_val = tmp_buf;
    }
    
    if(str[i] < 32 || str[i] > 126 || strchr(special, str[i]) != NULL)
    {
      num_written += snprintf(ret_val + num_written, buf_len - num_written,
			      "\\x%.2X", str[i]);
    }
    else
      ret_val[num_written++] = str[i];
  }
  ret_val[num_written] = '\0';

  return ret_val;
}


/* Returns a newly malloc()ed string which contains original string, 
 * except for non-printable or special characters are quoted in hex
 * with the syntax '\xQQ' where QQ is the hex ascii value of the quoted
 * character.
 */
static char* quote_string(const char* str, const char* special)
{
  unsigned int len;

  if(str == NULL)
    return NULL;

  len = strlen(str);
  return quote_buffer((const unsigned char*)str, len, special);
}


/*
 * Convert from UTF-16LE to ASCII.  Accepts a Unicode buffer, uni, and
 * it's length, uni_max.  Writes ASCII to the buffer ascii, whose size
 * is ascii_max.  Writes at most (ascii_max-1) bytes to ascii, and null
 * terminates the string.  Returns the length of the string stored in
 * ascii.  On error, returns a negative errno code.
 */
static int uni_to_ascii(unsigned char* uni, char* ascii, 
			unsigned int uni_max, unsigned int ascii_max)
{
  char* inbuf = (char*)uni;
  char* outbuf = ascii;
  size_t in_len = (size_t)uni_max;
  size_t out_len = (size_t)(ascii_max-1);
  int ret;

  /* Set up conversion descriptor. */
  conv_desc = iconv_open("US-ASCII", "UTF-16LE");

  ret = iconv(conv_desc, &inbuf, &in_len, &outbuf, &out_len);
  if(ret == -1)
  {
    iconv_close(conv_desc);
    return -errno;
  }
  *outbuf = '\0';

  iconv_close(conv_desc);  
  return strlen(ascii);
}


/*
 * Convert a data value to a string for display.  Returns NULL on error,
 * and the string to display if there is no error, or a non-fatal
 * error.  On any error (fatal or non-fatal) occurs, (*error_msg) will
 * be set to a newly allocated string, containing an error message.  If
 * a memory allocation failure occurs while generating the error
 * message, both the return value and (*error_msg) will be NULL.  It
 * is the responsibility of the caller to free both a non-NULL return
 * value, and a non-NULL (*error_msg).
 */
static char* data_to_ascii(unsigned char *datap, int len, int type, 
			   char** error_msg)
{
  char* asciip;
  char* ascii;
  unsigned char* cur_str;
  char* cur_ascii;
  char* cur_quoted;
  char* tmp_err;
  const char* str_type;
  unsigned int i;
  unsigned int cur_str_len;
  unsigned int ascii_max, cur_str_max;
  unsigned int str_rem, cur_str_rem, alen;
  int ret_err;
  unsigned short num_nulls;

  *error_msg = NULL;

  switch (type) 
  {
  case REG_SZ:
  case REG_EXPAND_SZ:
    /* REG_LINK is a symbolic link, stored as a unicode string. */
  case REG_LINK:
    ascii_max = sizeof(char)*(len+1);
    ascii = malloc(ascii_max);
    if(ascii == NULL)
      return NULL;
    
    /* Sometimes values have binary stored in them.  If the unicode
     * conversion fails, just quote it raw.
     */
    ret_err = uni_to_ascii(datap, ascii, len, ascii_max);
    if(ret_err < 0)
    {
      tmp_err = strerror(-ret_err);
      str_type = regfio_type_val2str(type);
      *error_msg = (char*)malloc(65+strlen(str_type)+strlen(tmp_err)+1);
      if(*error_msg == NULL)
      {
	free(ascii);
	return NULL;
      }
      sprintf(*error_msg, "Unicode conversion failed on %s field; "
	       "printing as binary.  Error: %s", str_type, tmp_err);
      
      cur_quoted = quote_buffer(datap, len, common_special_chars);
    }
    else
      cur_quoted = quote_string(ascii, common_special_chars);
    free(ascii);
    if(cur_quoted == NULL)
    {
      *error_msg = (char*)malloc(27+1);
      if(*error_msg != NULL)
	strcpy(*error_msg, "Buffer could not be quoted.");
    }
    return cur_quoted;
    break;

  case REG_DWORD:
    ascii_max = sizeof(char)*11;
    ascii = malloc(ascii_max);
    if(ascii == NULL)
      return NULL;

    snprintf(ascii, ascii_max, "0x%.2X%.2X%.2X%.2X", 
	     datap[0], datap[1], datap[2], datap[3]);
    return ascii;
    break;

  case REG_DWORD_BE:
    ascii_max = sizeof(char)*11;
    ascii = malloc(ascii_max);
    if(ascii == NULL)
      return NULL;

    snprintf(ascii, ascii_max, "0x%.2X%.2X%.2X%.2X", 
	     datap[3], datap[2], datap[1], datap[0]);
    return ascii;
    break;

  /* XXX: this MULTI_SZ parser is pretty inefficient.  Should be
   *      redone with fewer malloc calls and better string concatenation. 
   */
  case REG_MULTI_SZ:
    ascii_max = sizeof(char)*(len*4+1);
    cur_str_max = sizeof(char)*(len+1);
    cur_str = malloc(cur_str_max);
    cur_ascii = malloc(cur_str_max);
    ascii = malloc(ascii_max);
    if(ascii == NULL || cur_str == NULL || cur_ascii == NULL)
      return NULL;

    /* Reads until it reaches 4 consecutive NULLs, 
     * which is two nulls in unicode, or until it reaches len, or until we
     * run out of buffer.  The latter should never happen, but we shouldn't
     * trust our file to have the right lengths/delimiters.
     */
    asciip = ascii;
    num_nulls = 0;
    str_rem = ascii_max;
    cur_str_rem = cur_str_max;
    cur_str_len = 0;

    for(i=0; (i < len) && str_rem > 0; i++)
    {
      *(cur_str+cur_str_len) = *(datap+i);
      if(*(cur_str+cur_str_len) == 0)
	num_nulls++;
      else
	num_nulls = 0;
      cur_str_len++;

      if(num_nulls == 2)
      {
	ret_err = uni_to_ascii(cur_str, cur_ascii, cur_str_len-1, cur_str_max);
	if(ret_err < 0)
	{
	  /* XXX: should every sub-field error be enumerated? */
	  if(*error_msg == NULL)
	  {
	    tmp_err = strerror(-ret_err);
	    *error_msg = (char*)malloc(90+strlen(tmp_err)+1);
	    if(*error_msg == NULL)
	    {
	      free(cur_str);
	      free(cur_ascii);
	      free(ascii);
	      return NULL;
	    }
	    sprintf(*error_msg, "Unicode conversion failed on at least one "
		    "MULTI_SZ sub-field; printing as binary.  Error: %s",
		    tmp_err);
	  }
	  cur_quoted = quote_buffer(cur_str, cur_str_len-1, 
				    subfield_special_chars);
	}
	else
	  cur_quoted = quote_string(cur_ascii, subfield_special_chars);

	alen = snprintf(asciip, str_rem, "%s", cur_quoted);
	asciip += alen;
	str_rem -= alen;
	free(cur_quoted);

	if(*(datap+i+1) == 0 && *(datap+i+2) == 0)
	  break;
	else
	{
	  if(str_rem > 0)
	  {
	    asciip[0] = '|';
	    asciip[1] = '\0';
	    asciip++;
	    str_rem--;
	  }
	  memset(cur_str, 0, cur_str_max);
	  cur_str_len = 0;
	  num_nulls = 0;
	  /* To eliminate leading nulls in subsequent strings. */
	  i++;
	}
      }
    }
    *asciip = 0;
    free(cur_str);
    free(cur_ascii);
    return ascii;
    break;

  /* XXX: Dont know what to do with these yet, just print as binary... */
  case REG_NONE:
  case REG_RESOURCE_LIST:
  case REG_FULL_RESOURCE_DESCRIPTOR:
  case REG_RESOURCE_REQUIREMENTS_LIST:

  case REG_BINARY:
    return quote_buffer(datap, len, common_special_chars);
    break;
  }


  /* Invalid type */
  *error_msg = (char*)malloc(33+11+1);
  if(*error_msg != NULL)
    sprintf(*error_msg, "Unrecognized registry data type: %d", type);

  return NULL;
}


void_stack* path2Stack(const char* s)
{
  void_stack* ret_val;
  void_stack* rev_ret = void_stack_new(1024);
  const char* cur = s;
  char* next = NULL;
  char* copy;

  if (rev_ret == NULL)
    return NULL;
  if (s == NULL)
    return rev_ret;
  
  while((next = strchr(cur, '/')) != NULL)
  {
    if ((next-cur) > 0)
    {
      copy = (char*)malloc((next-cur+1)*sizeof(char));
      if(copy == NULL)
	bailOut(2, "ERROR: Memory allocation problem.\n");
	  
      memcpy(copy, cur, next-cur);
      copy[next-cur] = '\0';
      void_stack_push(rev_ret, copy);
    }
    cur = next+1;
  }
  if(strlen(cur) > 0)
  {
    copy = strdup(cur);
    void_stack_push(rev_ret, copy);
  }

  ret_val = void_stack_copy_reverse(rev_ret);
  void_stack_destroy(rev_ret);

  return ret_val;
}

/* Returns a quoted path from an nk_stack */
char* stack2Path(void_stack* nk_stack)
{
  const REGF_NK_REC* cur;
  uint32 buf_left = 127;
  uint32 buf_len = buf_left+1;
  uint32 name_len = 0;
  uint32 grow_amt;
  char* buf; 
  char* new_buf;
  char* name;
  void_stack_iterator* iter;
  
  buf = (char*)malloc((buf_len)*sizeof(char));
  if (buf == NULL)
    return NULL;
  buf[0] = '\0';

  iter = void_stack_iterator_new(nk_stack);
  if (iter == NULL)
  {
    free(buf);
    return NULL;
  }

  /* skip root element */
  cur = void_stack_iterator_next(iter);

  while((cur = void_stack_iterator_next(iter)) != NULL)
  {
    buf[buf_len-buf_left-1] = '/';
    buf_left -= 1;
    name = quote_string(cur->keyname, key_special_chars);
    name_len = strlen(name);
    if(name_len+1 > buf_left)
    {
      grow_amt = (uint32)(buf_len/2);
      buf_len += name_len+1+grow_amt-buf_left;
      if((new_buf = realloc(buf, buf_len)) == NULL)
      {
	free(buf);
	free(iter);
	return NULL;
      }
      buf = new_buf;
      buf_left = grow_amt + name_len + 1;
    }
    strncpy(buf+(buf_len-buf_left-1), name, name_len);
    buf_left -= name_len;
    buf[buf_len-buf_left-1] = '\0';
    free(name);
  }

  return buf;
}


void printValue(REGF_VK_REC* vk, char* prefix)
{
  uint32 size;
  uint8 tmp_buf[4];
  char* quoted_value = NULL;
  char* quoted_name = NULL;
  char* conv_error = NULL;

  /* Thanks Microsoft for making this process so straight-forward!!! */
  size = (vk->data_size & ~VK_DATA_IN_OFFSET);
  if(vk->data_size & VK_DATA_IN_OFFSET)
  {
    tmp_buf[0] = (uint8)((vk->data_off >> 3) & 0xFF);
    tmp_buf[1] = (uint8)((vk->data_off >> 2) & 0xFF);
    tmp_buf[2] = (uint8)((vk->data_off >> 1) & 0xFF);
    tmp_buf[3] = (uint8)(vk->data_off & 0xFF);
    if(size > 4)
      size = 4;
    quoted_value = data_to_ascii(tmp_buf, 4, vk->type, &conv_error);
  }
  else
  {
    /* XXX: This is a safety hack.  No data fields have yet been found
     * larger, but length limits are probably better got from fields
     * in the registry itself, within reason.
     */
    if(size > 16384)
    {
      fprintf(stderr, "WARNING: key size %d larger than "
	      "16384, truncating...\n", size);
      size = 16384;
    }

    quoted_value = data_to_ascii(vk->data, vk->data_size, 
				 vk->type, &conv_error);
  }
  
  /* XXX: Sometimes value names can be NULL in registry.  Need to
   *      figure out why and when, and generate the appropriate output
   *      for that condition.
   */
  quoted_name = quote_string(vk->valuename, common_special_chars);

  if(quoted_value == NULL)
  {
    if(conv_error == NULL)
      fprintf(stderr, "WARNING: Could not quote value for '%s/%s'.  "
	      "Memory allocation failure likely.\n", prefix, quoted_name);
    else
      fprintf(stderr, "WARNING: Could not quote value for '%s/%s'.  "
	      "Returned error: %s\n", prefix, quoted_name, conv_error);
  }
  /* XXX: should these always be printed? */
  else if(conv_error != NULL && print_verbose)
      fprintf(stderr, "VERBOSE: While quoting value for '%s/%s', "
	      "warning returned: %s\n", prefix, quoted_name, conv_error);

  if(print_security)
    printf("%s/%s,%s,%s,,,,,\n", prefix, quoted_name,
	   regfio_type_val2str(vk->type), quoted_value);
  else
    printf("%s/%s,%s,%s,\n", prefix, quoted_name,
	   regfio_type_val2str(vk->type), quoted_value);
  
  if(quoted_value != NULL)
    free(quoted_value);
  if(quoted_name != NULL)
    free(quoted_name);
  if(conv_error != NULL)
    free(conv_error);
}


void printValueList(REGF_NK_REC* nk, char* prefix)
{
  uint32 i;
  
  for(i=0; i < nk->num_values; i++)
    if(!type_filter_enabled || (nk->values[i].type == type_filter))
      printValue(nk->values+i, prefix);
}


void printKey(REGF_NK_REC* k, char* full_path)
{
  static char empty_str[1] = "";
  char* owner = NULL;
  char* group = NULL;
  char* sacl = NULL;
  char* dacl = NULL;
  char mtime[20];
  time_t tmp_time[1];
  struct tm* tmp_time_s = NULL;

  *tmp_time = nt_time_to_unix(&k->mtime);
  tmp_time_s = gmtime(tmp_time);
  strftime(mtime, sizeof(mtime), "%Y-%m-%d %H:%M:%S", tmp_time_s);

  if(print_security)
  {
    owner = regfio_get_owner(k->sec_desc->sec_desc);
    group = regfio_get_group(k->sec_desc->sec_desc);
    sacl = regfio_get_sacl(k->sec_desc->sec_desc);
    dacl = regfio_get_dacl(k->sec_desc->sec_desc);
    if(owner == NULL)
      owner = empty_str;
    if(group == NULL)
      group = empty_str;
    if(sacl == NULL)
      sacl = empty_str;
    if(dacl == NULL)
      dacl = empty_str;

    printf("%s,KEY,,%s,%s,%s,%s,%s\n", full_path, mtime, 
	   owner, group, sacl, dacl);

    if(owner != empty_str)
      free(owner);
    if(group != empty_str)
      free(group);
    if(sacl != empty_str)
      free(sacl);
    if(dacl != empty_str)
      free(dacl);
  }
  else
    printf("%s,KEY,,%s\n", full_path, mtime);
}


void printKeyTree(REGF_FILE* f, void_stack* nk_stack, const char* prefix)
{
  REGF_NK_REC* cur = NULL;
  REGF_NK_REC* sub = NULL;
  char* path = NULL;
  char* val_path = NULL;
  uint32 val_path_len = 0;
  uint32 path_len = 0;
  uint32 prefix_len = strlen(prefix);
  int key_type = regfio_type_str2val("KEY");
  
  if((cur = (REGF_NK_REC*)void_stack_cur(nk_stack)) != NULL)
  {
    cur->subkey_index = 0;
    path = stack2Path(nk_stack);

    if(print_verbose)
    {
      if(prefix[0] == '\0')
	fprintf(stderr, "VERBOSE: Printing key tree under path: /\n");
      else
	fprintf(stderr, "VERBOSE: Printing key tree under path: %s\n",
		prefix);
    }

    path_len = strlen(path);
    val_path_len = prefix_len+path_len;
    val_path = (char*)malloc(val_path_len+1+1);
    if(val_path == NULL)
      bailOut(2, "ERROR: Could not allocate val_path.\n");

    strcpy(val_path, prefix);
    strcpy(val_path+prefix_len, path);
    if(val_path[0] == '\0')
    {
      val_path[0] = '/';
      val_path[1] = '\0';
    }
    if(!type_filter_enabled || (key_type == type_filter))
      printKey(cur, val_path);
    if(!type_filter_enabled || (key_type != type_filter))
      printValueList(cur, val_path);
    
    while((cur = (REGF_NK_REC*)void_stack_cur(nk_stack)) != NULL)
    {
      if((sub = regfio_fetch_subkey(f, cur)) == NULL)
      {
	sub = void_stack_pop(nk_stack);
	/* XXX: This is just a shallow free.  Need to write deep free
	 * routines to replace the Samba code for this. 
	 */ 
	if(sub != NULL)
	  free(sub);
      }
      else
      {
	sub->subkey_index = 0;
	void_stack_push(nk_stack, sub);
	path = stack2Path(nk_stack);
	if(path != NULL)
	{
	  path_len = strlen(path);
	  if(val_path_len < prefix_len+path_len)
	  {
	    val_path_len = prefix_len+path_len;
	    val_path = (char*)realloc(val_path, val_path_len+1);
	    if(val_path == NULL)
	      bailOut(2, "ERROR: Could not reallocate val_path.\n");
	  }
	  strcpy(val_path, prefix);
	  strcpy(val_path+prefix_len, path);
	  if(!type_filter_enabled || (key_type == type_filter))
	    printKey(sub, val_path);
	  if(!type_filter_enabled || (key_type != type_filter))
	    printValueList(sub, val_path);
	}
      }
    }
  }
  if(val_path != NULL)
    free(val_path);
  if(print_verbose)
    fprintf(stderr, "VERBOSE: Finished printing key tree.\n");
}


/*
 * Returns 0 if path was found.
 * Returns 1 if path was not found.
 * Returns less than 0 on other error.
 */
int retrievePath(REGF_FILE* f, void_stack* nk_stack,
		 void_stack* path_stack)
{
  REGF_NK_REC* sub = NULL; 
  REGF_NK_REC* cur = NULL;
  void_stack* sub_nk_stack;
  char* prefix;
  char* cur_str = NULL;
  char* path = NULL;
  char* name;
  uint16 path_depth;
  uint32 i, prefix_len;
  bool found_cur = true;
  if(path_stack == NULL)
    return -1;

  path_depth = void_stack_size(path_stack);
  if(path_depth < 1)
    return -2;

  if(void_stack_size(nk_stack) < 1)
    return -3;
  cur = (REGF_NK_REC*)void_stack_cur(nk_stack);

  if(print_verbose)
    fprintf(stderr, "VERBOSE: Beginning retrieval of specified path: %s\n", 
	    path_filter);

  while(void_stack_size(path_stack) > 1)
  {
    /* Search key records only */
    cur_str = (char*)void_stack_pop(path_stack);

    found_cur = false;
    while(!found_cur &&
	  (sub = regfio_fetch_subkey(f, cur)) != NULL)
    {
      if(strcasecmp(sub->keyname, cur_str) == 0)
      {
	cur = sub;
	void_stack_push(nk_stack, sub);
	found_cur = true;
      }
    }
    if(print_verbose && !found_cur)
      fprintf(stderr, "VERBOSE: Could not find KEY '%s' in specified path.\n", 
	      cur_str);

    free(cur_str);
    if(!found_cur)
      return 1;
  }

  /* Last round, search value and key records */
  cur_str = (char*)void_stack_pop(path_stack);

  if(print_verbose)
    fprintf(stderr, "VERBOSE: Searching values for last component"
	            " of specified path.\n");

  for(i=0; (i < cur->num_values); i++)
  {
    /* XXX: Not sure when/why this can be NULL, but it's happened. */
    if(sub->values[i].valuename != NULL 
       && strcasecmp(sub->values[i].valuename, cur_str) == 0)
    {
      path = stack2Path(nk_stack);

      if(print_verbose)
	fprintf(stderr, "VERBOSE: Found final path element as value.\n");

      if(!type_filter_enabled || (sub->values[i].type == type_filter))
        printValue(&sub->values[i], path);
      if(path != NULL)
	free(path);

      return 0;
    }
  }

  if(print_verbose)
    fprintf(stderr, "VERBOSE: Searching keys for last component"
	            " of specified path.\n");

  while((sub = regfio_fetch_subkey(f, cur)) != NULL)
  {
    if(strcasecmp(sub->keyname, cur_str) == 0)
    {
      sub_nk_stack = void_stack_new(1024);
      void_stack_push(sub_nk_stack, sub);
      prefix = stack2Path(nk_stack);
      prefix_len = strlen(prefix);
      prefix = realloc(prefix, prefix_len+strlen(sub->keyname)+2);
      if(prefix == NULL)
	return -1;
      name = quote_string(sub->keyname, key_special_chars);
      strcat(prefix, "/");
      strcat(prefix, name);
      free(name);

      if(print_verbose)
	fprintf(stderr, "VERBOSE: Found final path element as key.\n");

      printKeyTree(f, sub_nk_stack, prefix);

      return 0;
    }
  }

  if(print_verbose)
    fprintf(stderr, "VERBOSE: Could not find last element of path.\n");

  return 1;
}


static void usage(void)
{
  fprintf(stderr, "Usage: reglookup [-v] [-s]"
	  " [-p <PATH_FILTER>] [-t <TYPE_FILTER>]"
	  " <REGISTRY_FILE>\n");
  fprintf(stderr, "Version: 0.3.0\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "\t-v\t sets verbose mode.\n");
  fprintf(stderr, "\t-h\t enables header row. (default)\n");
  fprintf(stderr, "\t-H\t disables header row.\n");
  fprintf(stderr, "\t-s\t enables security descriptor output.\n");
  fprintf(stderr, "\t-S\t disables security descriptor output. (default)\n");
  fprintf(stderr, "\t-p\t restrict output to elements below this path.\n");
  fprintf(stderr, "\t-t\t restrict results to this specific data type.\n");
  fprintf(stderr, "\n");
}


int main(int argc, char** argv)
{
  void_stack* nk_stack;
  void_stack* path_stack;
  REGF_FILE* f;
  REGF_NK_REC* root;
  int retr_path_ret;
  uint32 argi, arge;

  /* Process command line arguments */
  if(argc < 2)
  {
    usage();
    bailOut(1, "ERROR: Requires at least one argument.\n");
  }
  
  arge = argc-1;
  for(argi = 1; argi < arge; argi++)
  {
    if (strcmp("-p", argv[argi]) == 0)
    {
      if(++argi >= arge)
      {
	usage();
	bailOut(1, "ERROR: '-p' option requires parameter.\n");
      }
      if((path_filter = strdup(argv[argi])) == NULL)
	bailOut(2, "ERROR: Memory allocation problem.\n");

      path_filter_enabled = true;
    }
    else if (strcmp("-t", argv[argi]) == 0)
    {
      if(++argi >= arge)
      {
	usage();
	bailOut(1, "ERROR: '-t' option requires parameter.\n");
      }
      if((type_filter = regfio_type_str2val(argv[argi])) < 0)
      {
	fprintf(stderr, "ERROR: Invalid type specified: %s.\n", argv[argi]);
	bailOut(1, "");
      }
      type_filter_enabled = true;
    }
    else if (strcmp("-h", argv[argi]) == 0)
      print_header = true;
    else if (strcmp("-H", argv[argi]) == 0)
      print_header = false;
    else if (strcmp("-s", argv[argi]) == 0)
      print_security = true;
    else if (strcmp("-S", argv[argi]) == 0)
      print_security = false;
    else if (strcmp("-v", argv[argi]) == 0)
      print_verbose = true;
    else
    {
      usage();
      fprintf(stderr, "ERROR: Unrecognized option: %s\n", argv[argi]);
      bailOut(1, "");
    }
  }
  if((registry_file = strdup(argv[argi])) == NULL)
    bailOut(2, "ERROR: Memory allocation problem.\n");

  f = regfio_open(registry_file);
  if(f == NULL)
  {
    fprintf(stderr, "ERROR: Couldn't open registry file: %s\n", registry_file);
    bailOut(3, "");
  }

  root = regfio_rootkey(f);
  nk_stack = void_stack_new(1024);

  if(void_stack_push(nk_stack, root))
  {
    if(print_header)
    {
      if(print_security)
	printf("PATH,TYPE,VALUE,MTIME,OWNER,GROUP,SACL,DACL\n");
      else
	printf("PATH,TYPE,VALUE,MTIME\n");
    }

    path_stack = path2Stack(path_filter);
    if(void_stack_size(path_stack) < 1)
      printKeyTree(f, nk_stack, "");
    else
    {
      retr_path_ret = retrievePath(f, nk_stack, path_stack);
      if(retr_path_ret == 1)
	fprintf(stderr, "WARNING: specified path not found.\n");
      else if(retr_path_ret != 0)
	bailOut(4, "ERROR:\n");
    }
  }
  else
    bailOut(2, "ERROR: Memory allocation problem.\n");

  void_stack_destroy_deep(nk_stack);
  regfio_close(f);

  return 0;
}
