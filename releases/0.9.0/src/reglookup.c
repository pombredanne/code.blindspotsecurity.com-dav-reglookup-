/*
 * A utility to read a Windows NT/2K/XP/2K3 registry file, using 
 * Gerald Carter''s regfio interface.
 *
 * Copyright (C) 2005-2008 Timothy D. Morgan
 * Copyright (C) 2002 Richard Sharpe, rsharpe@richardsharpe.com
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


#include <stdlib.h>
#include <sysexits.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "../include/regfi.h"
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
REGF_FILE* f;


/* XXX: A hack to share some functions with reglookup-recover.c.
 *      Should move these into a properly library at some point.
 */
#include "common.c"


void printValue(const REGF_VK_REC* vk, char* prefix)
{
  char* quoted_value = NULL;
  char* quoted_name = NULL;
  char* conv_error = NULL;
  const char* str_type = NULL;
  uint32 size = vk->data_size;

  /* Microsoft's documentation indicates that "available memory" is 
   * the limit on value sizes.  Annoying.  We limit it to 1M which 
   * should rarely be exceeded, unless the file is corrupt or 
   * malicious. For more info, see:
   *   http://msdn2.microsoft.com/en-us/library/ms724872.aspx
   */
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

  str_type = regfi_type_val2str(vk->type);
  if(print_security)
  {
    if(str_type == NULL)
      printf("%s/%s,0x%.8X,%s,,,,,\n", prefix, quoted_name,
	     vk->type, quoted_value);
    else
      printf("%s/%s,%s,%s,,,,,\n", prefix, quoted_name,
	     str_type, quoted_value);
  }
  else
  {
    if(str_type == NULL)
      printf("%s/%s,0x%.8X,%s,\n", prefix, quoted_name,
	     vk->type, quoted_value);
    else
      printf("%s/%s,%s,%s,\n", prefix, quoted_name,
	     str_type, quoted_value);
  }

  if(quoted_value != NULL)
    free(quoted_value);
  if(quoted_name != NULL)
    free(quoted_name);
  if(conv_error != NULL)
    free(conv_error);
}



/* XXX: Each chunk must be unquoted after it is split out. 
 *      Quoting syntax may need to be standardized and pushed into the API 
 *      to deal with this issue and others.
 */
char** splitPath(const char* s)
{
  char** ret_val;
  const char* cur = s;
  char* next = NULL;
  char* copy;
  uint32 ret_cur = 0;

  ret_val = (char**)malloc((REGF_MAX_DEPTH+1+1)*sizeof(char**));
  if (ret_val == NULL)
    return NULL;
  ret_val[0] = NULL;

  /* We return a well-formed, 0-length, path even when input is icky. */
  if (s == NULL)
    return ret_val;
  
  while((next = strchr(cur, '/')) != NULL)
  {
    if ((next-cur) > 0)
    {
      copy = (char*)malloc((next-cur+1)*sizeof(char));
      if(copy == NULL)
	bailOut(EX_OSERR, "ERROR: Memory allocation problem.\n");
	  
      memcpy(copy, cur, next-cur);
      copy[next-cur] = '\0';
      ret_val[ret_cur++] = copy;
      if(ret_cur < (REGF_MAX_DEPTH+1+1))
	ret_val[ret_cur] = NULL;
      else
	bailOut(EX_DATAERR, "ERROR: Registry maximum depth exceeded.\n");
    }
    cur = next+1;
  }

  /* Grab last element, if path doesn't end in '/'. */
  if(strlen(cur) > 0)
  {
    copy = strdup(cur);
    ret_val[ret_cur++] = copy;
    if(ret_cur < (REGF_MAX_DEPTH+1+1))
      ret_val[ret_cur] = NULL;
    else
      bailOut(EX_DATAERR, "ERROR: Registry maximum depth exceeded.\n");
  }

  return ret_val;
}


void freePath(char** path)
{
  uint32 i;

  if(path == NULL)
    return;

  for(i=0; path[i] != NULL; i++)
    free(path[i]);

  free(path);
}


/* Returns a quoted path from an iterator's stack */
/* XXX: Some way should be found to integrate this into regfi's API 
 *      The problem is that the escaping is sorta reglookup-specific.
 */
char* iter2Path(REGFI_ITERATOR* i)
{
  const REGFI_ITER_POSITION* cur;
  uint32 buf_left = 127;
  uint32 buf_len = buf_left+1;
  uint32 name_len = 0;
  uint32 grow_amt;
  char* buf;
  char* new_buf;
  char* name;
  const char* cur_name;
  void_stack_iterator* iter;
  
  buf = (char*)malloc((buf_len)*sizeof(char));
  if (buf == NULL)
    return NULL;
  buf[0] = '\0';

  iter = void_stack_iterator_new(i->key_positions);
  if (iter == NULL)
  {
    free(buf);
    return NULL;
  }

  /* skip root element */
  if(void_stack_size(i->key_positions) < 1)
  {
    buf[0] = '/';
    buf[1] = '\0';
    return buf;
  }
  cur = void_stack_iterator_next(iter);

  do
  {
    cur = void_stack_iterator_next(iter);
    if (cur == NULL)
      cur_name = i->cur_key->keyname;
    else
      cur_name = cur->nk->keyname;

    buf[buf_len-buf_left-1] = '/';
    buf_left -= 1;
    name = quote_string(cur_name, key_special_chars);
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
  } while(cur != NULL);

  return buf;
}


void printValueList(REGFI_ITERATOR* i, char* prefix)
{
  const REGF_VK_REC* value;

  value = regfi_iterator_first_value(i);
  while(value != NULL)
  {
    if(!type_filter_enabled || (value->type == type_filter))
      printValue(value, prefix);
    value = regfi_iterator_next_value(i);
  }
}


void printKey(REGFI_ITERATOR* i, char* full_path)
{
  static char empty_str[1] = "";
  char* owner = NULL;
  char* group = NULL;
  char* sacl = NULL;
  char* dacl = NULL;
  char mtime[20];
  time_t tmp_time[1];
  struct tm* tmp_time_s = NULL;
  const REGF_SK_REC* sk;
  const REGF_NK_REC* k = regfi_iterator_cur_key(i);

  *tmp_time = nt_time_to_unix(&k->mtime);
  tmp_time_s = gmtime(tmp_time);
  strftime(mtime, sizeof(mtime), "%Y-%m-%d %H:%M:%S", tmp_time_s);

  if(print_security && (sk=regfi_iterator_cur_sk(i)))
  {
    owner = regfi_get_owner(sk->sec_desc);
    group = regfi_get_group(sk->sec_desc);
    sacl = regfi_get_sacl(sk->sec_desc);
    dacl = regfi_get_dacl(sk->sec_desc);
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


void printKeyTree(REGFI_ITERATOR* iter)
{
  const REGF_NK_REC* root = NULL;
  const REGF_NK_REC* cur = NULL;
  const REGF_NK_REC* sub = NULL;
  char* path = NULL;
  int key_type = regfi_type_str2val("KEY");
  bool print_this = true;

  root = cur = regfi_iterator_cur_key(iter);
  sub = regfi_iterator_first_subkey(iter);
  
  if(root == NULL)
    bailOut(EX_DATAERR, "ERROR: root cannot be NULL.\n");
  
  do
  {
    if(print_this)
    {
      path = iter2Path(iter);
      if(path == NULL)
	bailOut(EX_OSERR, "ERROR: Could not construct iterator's path.\n");
      
      if(!type_filter_enabled || (key_type == type_filter))
	printKey(iter, path);
      if(!type_filter_enabled || (key_type != type_filter))
	printValueList(iter, path);
      
      free(path);
    }
    
    if(sub == NULL)
    {
      if(cur != root)
      {
	/* We're done with this sub-tree, going up and hitting other branches. */
	if(!regfi_iterator_up(iter))
	  bailOut(EX_DATAERR, "ERROR: could not traverse iterator upward.\n");
	
	cur = regfi_iterator_cur_key(iter);
	if(cur == NULL)
	  bailOut(EX_DATAERR, "ERROR: unexpected NULL for key.\n");
	
	sub = regfi_iterator_next_subkey(iter);
      }
      print_this = false;
    }
    else
    { /* We have unexplored sub-keys.  
       * Let's move down and print this first sub-tree out. 
       */
      if(!regfi_iterator_down(iter))
	bailOut(EX_DATAERR, "ERROR: could not traverse iterator downward.\n");

      cur = sub;
      sub = regfi_iterator_first_subkey(iter);
      print_this = true;
    }
  } while(!((cur == root) && (sub == NULL)));

  if(print_verbose)
    fprintf(stderr, "VERBOSE: Finished printing key tree.\n");
}


/* XXX: what if there is BOTH a value AND a key with that name?? */
/*
 * Returns 0 if path was not found.
 * Returns 1 if path was found as value.
 * Returns 2 if path was found as key.
 * Returns less than 0 on other error.
 */
int retrievePath(REGFI_ITERATOR* iter, char** path)
{
  const REGF_VK_REC* value;
  char* tmp_path_joined;
  const char** tmp_path;
  uint32 i;
  
  if(path == NULL)
    return -1;

  /* One extra for any value at the end, and one more for NULL */
  tmp_path = (const char**)malloc(sizeof(const char**)*(REGF_MAX_DEPTH+1+1));
  if(tmp_path == NULL)
    return -2;

  /* Strip any potential value name at end of path */
  for(i=0; 
      (path[i] != NULL) && (path[i+1] != NULL) 
	&& (i < REGF_MAX_DEPTH+1+1);
      i++)
    tmp_path[i] = path[i];

  tmp_path[i] = NULL;

  if(print_verbose)
    fprintf(stderr, "VERBOSE: Attempting to retrieve specified path: %s\n",
	    path_filter);

  /* Special check for '/' path filter */
  if(path[0] == NULL)
  {
    if(print_verbose)
      fprintf(stderr, "VERBOSE: Found final path element as root key.\n");
    return 2;
  }

  if(!regfi_iterator_walk_path(iter, tmp_path))
  {
    free(tmp_path);
    return 0;
  }

  if(regfi_iterator_find_value(iter, path[i]))
  {
    if(print_verbose)
      fprintf(stderr, "VERBOSE: Found final path element as value.\n");

    value = regfi_iterator_cur_value(iter);
    tmp_path_joined = iter2Path(iter);

    if((value == NULL) || (tmp_path_joined == NULL))
      bailOut(EX_OSERR, "ERROR: Unexpected error before printValue.\n");

    if(!type_filter_enabled || (value->type == type_filter))
      printValue(value, tmp_path_joined);

    free(tmp_path);
    free(tmp_path_joined);
    return 1;
  }
  else if(regfi_iterator_find_subkey(iter, path[i]))
  {
    if(print_verbose)
      fprintf(stderr, "VERBOSE: Found final path element as key.\n");

    if(!regfi_iterator_down(iter))
      bailOut(EX_DATAERR, "ERROR: Unexpected error on traversing path filter key.\n");

    return 2;
  }

  if(print_verbose)
    fprintf(stderr, "VERBOSE: Could not find last element of path.\n");

  return 0;
}


static void usage(void)
{
  fprintf(stderr, "Usage: reglookup [-v] [-s]"
	  " [-p <PATH_FILTER>] [-t <TYPE_FILTER>]"
	  " <REGISTRY_FILE>\n");
  fprintf(stderr, "Version: %s\n", REGLOOKUP_VERSION);
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
  char** path = NULL;
  REGFI_ITERATOR* iter;
  int retr_path_ret;
  uint32 argi, arge;

  /* Process command line arguments */
  if(argc < 2)
  {
    usage();
    bailOut(EX_USAGE, "ERROR: Requires at least one argument.\n");
  }
  
  arge = argc-1;
  for(argi = 1; argi < arge; argi++)
  {
    if (strcmp("-p", argv[argi]) == 0)
    {
      if(++argi >= arge)
      {
	usage();
	bailOut(EX_USAGE, "ERROR: '-p' option requires parameter.\n");
      }
      if((path_filter = strdup(argv[argi])) == NULL)
	bailOut(EX_OSERR, "ERROR: Memory allocation problem.\n");

      path_filter_enabled = true;
    }
    else if (strcmp("-t", argv[argi]) == 0)
    {
      if(++argi >= arge)
      {
	usage();
	bailOut(EX_USAGE, "ERROR: '-t' option requires parameter.\n");
      }
      if((type_filter = regfi_type_str2val(argv[argi])) < 0)
      {
	fprintf(stderr, "ERROR: Invalid type specified: %s.\n", argv[argi]);
	bailOut(EX_USAGE, "");
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
      bailOut(EX_USAGE, "");
    }
  }
  if((registry_file = strdup(argv[argi])) == NULL)
    bailOut(EX_OSERR, "ERROR: Memory allocation problem.\n");

  f = regfi_open(registry_file);
  if(f == NULL)
  {
    fprintf(stderr, "ERROR: Couldn't open registry file: %s\n", registry_file);
    bailOut(EX_NOINPUT, "");
  }

  iter = regfi_iterator_new(f);
  if(iter == NULL)
    bailOut(EX_OSERR, "ERROR: Couldn't create registry iterator.\n");

  if(print_header)
  {
    if(print_security)
      printf("PATH,TYPE,VALUE,MTIME,OWNER,GROUP,SACL,DACL\n");
    else
      printf("PATH,TYPE,VALUE,MTIME\n");
  }

  if(path_filter_enabled && path_filter != NULL)
    path = splitPath(path_filter);

  if(path != NULL)
  {
    retr_path_ret = retrievePath(iter, path);
    freePath(path);

    if(retr_path_ret == 0)
      fprintf(stderr, "WARNING: specified path not found.\n");
    else if (retr_path_ret == 2)
      printKeyTree(iter);
    else if(retr_path_ret < 0)
    {
      fprintf(stderr, "ERROR: retrievePath() returned %d.\n", 
	      retr_path_ret);
      bailOut(EX_DATAERR,"ERROR: Unknown error occurred in retrieving path.\n");
    }
  }
  else
    printKeyTree(iter);

  regfi_iterator_free(iter);
  regfi_close(f);

  return 0;
}