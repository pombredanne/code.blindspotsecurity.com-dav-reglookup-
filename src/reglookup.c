/*
 * A utility to read a Windows NT and later registry files.
 *
 * Copyright (C) 2005-2010 Timothy D. Morgan
 * Copyright (C) 2010 Tobias Mueller (portions of '-i' code)
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
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "regfi.h"
#include "void_stack.h"

/* Globals, influenced by command line parameters */
bool print_value_mtime = false;
bool print_verbose = false;
bool print_security = false;
bool print_header = true;
bool path_filter_enabled = false;
bool type_filter_enabled = false;
char* path_filter = NULL;
int type_filter;
const char* registry_file = NULL;

/* Other globals */
REGFI_FILE* f;


/* XXX: A hack to share some functions with reglookup-recover.c.
 *      Should move these into a proper library at some point.
 */
#include "common.c"


static bool keysEqual(const REGFI_NK* x, const REGFI_NK* y)
{
  return (x != NULL && y != NULL && x->offset == y->offset);
}

void printValue(REGFI_ITERATOR* iter, const REGFI_VK* vk, char* prefix)
{
  const REGFI_NK* cur_key;
  const REGFI_DATA* data;
  char* quoted_value = NULL;
  char* quoted_name = NULL;
  char* conv_error = NULL;
  const char* str_type = NULL;
  char mtime[20];
  time_t tmp_time[1];
  struct tm* tmp_time_s = NULL;

  quoted_name = get_quoted_valuename(vk);
  if (quoted_name == NULL)
  { /* Value names are NULL when we're looking at the "(default)" value.
     * Currently we just return a 0-length string to try an eliminate 
     * ambiguity with a literal "(default)" value.  The data type of a line
     * in the output allows one to differentiate between the parent key and
     * this value.
     */
    quoted_name = malloc(1*sizeof(char));
    if(quoted_name == NULL)
      bailOut(REGLOOKUP_EXIT_OSERR, "ERROR: Could not allocate sufficient memory.\n");
    quoted_name[0] = '\0';
  }
  
  data = regfi_fetch_data(iter->f, vk);

  printMsgs(iter->f);
  if(data != NULL)
  {
    quoted_value = data_to_ascii(data, &conv_error);
    if(quoted_value == NULL)
    {
      if(conv_error == NULL)
	fprintf(stderr, "WARN: Could not quote value for '%s/%s'.  "
		"Memory allocation failure likely.\n", prefix, quoted_name);
      else
	fprintf(stderr, "WARN: Could not quote value for '%s/%s'.  "
		"Returned error: %s\n", prefix, quoted_name, conv_error);
    }
    else if(conv_error != NULL)
      fprintf(stderr, "WARN: While quoting value for '%s/%s', "
	      "warning returned: %s\n", prefix, quoted_name, conv_error);
    regfi_free_record(iter->f, data);
  }

  if(print_value_mtime)
  {
    cur_key = regfi_iterator_cur_key(iter);
    *tmp_time = regfi_nt2unix_time(cur_key->mtime);
    tmp_time_s = gmtime(tmp_time);
    strftime(mtime, sizeof(mtime), "%Y-%m-%d %H:%M:%S", tmp_time_s);
    regfi_free_record(iter->f, cur_key);
  }
  else
    mtime[0] = '\0';

  str_type = regfi_type_val2str(vk->type);
  if(print_security)
  {
    if(str_type == NULL)
      printf("%s/%s,0x%.8X,%s,%s,,,,\n", prefix, quoted_name,
	     vk->type, quoted_value, mtime);
    else
      printf("%s/%s,%s,%s,%s,,,,\n", prefix, quoted_name,
	     str_type, quoted_value, mtime);
  }
  else
  {
    if(str_type == NULL)
      printf("%s/%s,0x%.8X,%s,%s\n", prefix, quoted_name,
	     vk->type, quoted_value, mtime);
    else
      printf("%s/%s,%s,%s,%s\n", prefix, quoted_name,
	     str_type, quoted_value, mtime);
  }

  if(quoted_value != NULL)
    free(quoted_value);
  if(quoted_name != NULL)
    free(quoted_name);
  if(conv_error != NULL)
    free(conv_error);
}


char** splitPath(const char* s)
{
  char** ret_val;
  const char* cur = s;
  char* next = NULL;
  char* copy;
  uint32_t ret_cur = 0;

  ret_val = (char**)malloc((REGFI_MAX_DEPTH+1+1)*sizeof(char**));
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
	bailOut(REGLOOKUP_EXIT_OSERR, "ERROR: Memory allocation problem.\n");
	  
      memcpy(copy, cur, next-cur);
      copy[next-cur] = '\0';
      ret_val[ret_cur++] = copy;
      if(ret_cur < (REGFI_MAX_DEPTH+1+1))
	ret_val[ret_cur] = NULL;
      else
	bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: Registry maximum depth exceeded.\n");
    }
    cur = next+1;
  }

  /* Grab last element, if path doesn't end in '/'. */
  if(strlen(cur) > 0)
  {
    copy = strdup(cur);
    ret_val[ret_cur++] = copy;
    if(ret_cur < (REGFI_MAX_DEPTH+1+1))
      ret_val[ret_cur] = NULL;
    else
      bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: Registry maximum depth exceeded.\n");
  }

  return ret_val;
}


void freePath(char** path)
{
  uint32_t i;

  if(path == NULL)
    return;

  for(i=0; path[i] != NULL; i++)
    free(path[i]);

  free(path);
}


/* Returns a quoted path of the current iterator's position */
char* iter2Path(REGFI_ITERATOR* i)
{
  const REGFI_NK** path;
  uint32_t k;
  uint32_t buf_left = 127;
  uint32_t buf_len = buf_left+1;
  uint32_t name_len = 0;
  uint32_t grow_amt;
  char* buf;
  char* new_buf;
  char* name;
  
  buf = (char*)malloc((buf_len)*sizeof(char));
  if (buf == NULL)
    return NULL;
  buf[0] = '\0';

  path = regfi_iterator_cur_path(i);
  if(path == NULL)
  {
    free(buf);
    return NULL;
  }

  for(k=0; path[k] != NULL; k++)
  {
    /* skip root element's name */
    if(k == 0)
    {
      buf[0] = '/';
      buf[1] = '\0';
    }
    else
    {
      name = get_quoted_keyname(path[k]);

      buf[buf_len-buf_left-1] = '/';
      buf_left -= 1;
      name_len = strlen(name);
      if(name_len+1 > buf_left)
      {
        grow_amt = (uint32_t)(buf_len/2);
        buf_len += name_len+1+grow_amt-buf_left;
        if((new_buf = realloc(buf, buf_len)) == NULL)
        {
          regfi_free_record(i->f, path);
          free(name);
          free(buf);
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
  }

  regfi_free_record(i->f, path);
  return buf;
}


void printValueList(REGFI_ITERATOR* iter, char* prefix)
{
  const REGFI_VK* value;

  regfi_iterator_first_value(iter);
  while((value = regfi_iterator_cur_value(iter)) != NULL)
  {
    if(!type_filter_enabled || (value->type == type_filter))
      printValue(iter, value, prefix);
    regfi_free_record(iter->f, value);
    regfi_iterator_next_value(iter);
    printMsgs(iter->f);
  }
}


void printKey(REGFI_ITERATOR* iter, char* full_path)
{
  static char empty_str[1] = "";
  char* owner = NULL;
  char* group = NULL;
  char* sacl = NULL;
  char* dacl = NULL;
  char mtime[24];
  char* quoted_classname;
  const REGFI_SK* sk;
  const REGFI_NK* key = regfi_iterator_cur_key(iter);
  const REGFI_CLASSNAME* classname;

  formatTime(key->mtime, mtime);

  if(print_security && (sk=regfi_fetch_sk(iter->f, key)))
  {
    owner = regfi_get_owner(sk->sec_desc);
    group = regfi_get_group(sk->sec_desc);
    sacl = regfi_get_sacl(sk->sec_desc);
    dacl = regfi_get_dacl(sk->sec_desc);
    regfi_free_record(iter->f, sk);

    if(owner == NULL)
      owner = empty_str;
    if(group == NULL)
      group = empty_str;
    if(sacl == NULL)
      sacl = empty_str;
    if(dacl == NULL)
      dacl = empty_str;

    classname = regfi_fetch_classname(iter->f, key);
    printMsgs(iter->f);
    if(classname != NULL)
    {
      if(classname->interpreted == NULL)
      {
	fprintf(stderr, "WARN: Could not convert class name"
		" charset for key '%s'.  Quoting raw...\n", full_path);
	quoted_classname = quote_buffer(classname->raw, classname->size,
					key_special_chars);
      }
      else
	quoted_classname = quote_string(classname->interpreted, 
					key_special_chars);

      if(quoted_classname == NULL)
      {
	fprintf(stderr, "ERROR: Could not quote classname"
		" for key '%s' due to unknown error.\n", full_path);
	quoted_classname = empty_str;
      }
    }
    else
      quoted_classname = empty_str;
    regfi_free_record(iter->f, classname);

    printMsgs(iter->f);
    printf("%s,KEY,,%s,%s,%s,%s,%s,%s\n", full_path, mtime, 
	   owner, group, sacl, dacl, quoted_classname);

    if(owner != empty_str)
      free(owner);
    if(group != empty_str)
      free(group);
    if(sacl != empty_str)
      free(sacl);
    if(dacl != empty_str)
      free(dacl);
    if(quoted_classname != empty_str)
      free(quoted_classname);
  }
  else
    printf("%s,KEY,,%s\n", full_path, mtime);

  regfi_free_record(iter->f, key);
}


void printKeyTree(REGFI_ITERATOR* iter)
{
  const REGFI_NK* root = NULL;
  const REGFI_NK* cur = NULL;
  const REGFI_NK* sub = NULL;
  char* path = NULL;
  int key_type = regfi_type_str2val("KEY");
  bool print_this = true;

  root = regfi_iterator_cur_key(iter);
  regfi_reference_record(iter->f, root);
  cur = root;
  regfi_iterator_first_subkey(iter);
  sub = regfi_iterator_cur_subkey(iter);
  printMsgs(iter->f);

  if(root == NULL)
    bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: root cannot be NULL.\n");
  
  do
  {
    if(print_this)
    {
      path = iter2Path(iter);
      if(path == NULL)
	bailOut(REGLOOKUP_EXIT_OSERR, "ERROR: Could not construct iterator's path.\n");

      if(!type_filter_enabled || (key_type == type_filter))
	printKey(iter, path);
      if(!type_filter_enabled || (key_type != type_filter))
	printValueList(iter, path);
      
      free(path);
    }
    
    if(sub == NULL)
    {
      if(!keysEqual(cur, root))
      {
        regfi_free_record(iter->f, cur);
        cur = NULL;
	/* We're done with this sub-tree, going up and hitting other branches. */
	if(!regfi_iterator_up(iter))
	{
	  printMsgs(iter->f);
	  bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: could not traverse iterator upward.\n");
	}

	cur = regfi_iterator_cur_key(iter);
	if(cur == NULL)
	{
	  printMsgs(iter->f);
	  bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: unexpected NULL for key.\n");
	}
	
	regfi_iterator_next_subkey(iter);
	sub = regfi_iterator_cur_subkey(iter);
      }
      print_this = false;
    }
    else
    { /* We have unexplored sub-keys.  
       * Let's move down and print this first sub-tree out. 
       */
      regfi_free_record(iter->f, cur);
      cur = NULL;
      if(!regfi_iterator_down(iter))
      {
	printMsgs(iter->f);
	bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: could not traverse iterator downward.\n");
      }

      cur = regfi_iterator_cur_key(iter);
      regfi_free_record(iter->f, sub);
      regfi_iterator_first_subkey(iter);
      sub = regfi_iterator_cur_subkey(iter);
      print_this = true;
    }
    printMsgs(iter->f);
  } while(!(keysEqual(cur, root) && (sub == NULL)));
  if(cur != NULL)
    regfi_free_record(iter->f, cur);
  regfi_free_record(iter->f, root);

  if(print_verbose)
    fprintf(stderr, "INFO: Finished printing key tree.\n");
}


/* XXX: What if there is BOTH a value AND a key with that name?? 
 *      What if there are multiple keys/values with the same name?? 
 */
/*
 * Returns 0 if path was not found.
 * Returns 1 if path was found as value.
 * Returns 2 if path was found as key.
 * Returns less than 0 on other error.
 */
int retrievePath(REGFI_ITERATOR* iter, char** path)
{
  const REGFI_VK* value;
  char* tmp_path_joined;
  const char** tmp_path;
  uint32_t i;
  
  if(path == NULL)
    return -1;

  /* One extra for any value at the end, and one more for NULL */
  tmp_path = (const char**)malloc(sizeof(const char**)*(REGFI_MAX_DEPTH+1+1));
  if(tmp_path == NULL)
    return -2;

  /* Strip any potential value name at end of path */
  for(i=0; 
      (path[i] != NULL) && (path[i+1] != NULL) && (i < REGFI_MAX_DEPTH+1);
      i++)
  { tmp_path[i] = path[i]; }
  tmp_path[i] = NULL;

  if(print_verbose)
    fprintf(stderr, "INFO: Attempting to retrieve specified path: %s\n",
	    path_filter);

  /* Special check for '/' path filter */
  if(path[0] == NULL)
  {
    if(print_verbose)
      fprintf(stderr, "INFO: Found final path element as root key.\n");
    free(tmp_path);
    return 2;
  }

  if(!regfi_iterator_walk_path(iter, tmp_path))
  {
    printMsgs(iter->f);
    free(tmp_path);
    return 0;
  }

  if(regfi_iterator_find_value(iter, path[i]))
  {
    if(print_verbose)
      fprintf(stderr, "INFO: Found final path element as value.\n");

    value = regfi_iterator_cur_value(iter);
    printMsgs(iter->f);
    tmp_path_joined = iter2Path(iter);

    if((value == NULL) || (tmp_path_joined == NULL))
      bailOut(REGLOOKUP_EXIT_OSERR, "ERROR: Unexpected error before printValue.\n");

    if(!type_filter_enabled || (value->type == type_filter))
      printValue(iter, value, tmp_path_joined);

    regfi_free_record(iter->f, value);
    free(tmp_path);
    free(tmp_path_joined);
    return 1;
  }
  else if(regfi_iterator_find_subkey(iter, path[i]))
  {
    printMsgs(iter->f);
    if(print_verbose)
      fprintf(stderr, "INFO: Found final path element as key.\n");

    if(!regfi_iterator_down(iter))
    {
      printMsgs(iter->f);
      bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: Unexpected error on traversing path filter key.\n");
    }

    return 2;
  }
  printMsgs(iter->f);

  if(print_verbose)
    fprintf(stderr, "INFO: Could not find last element of path.\n");

  return 0;
}


static void usage(void)
{
  fprintf(stderr, "Usage: reglookup [-v] [-s]"
	  " [-p <PATH_FILTER>] [-t <TYPE_FILTER>]"
	  " <REGISTRY_FILE>\n");
  fprintf(stderr, "Version: %s\n", regfi_version());
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "\t-v\t sets verbose mode.\n");
  fprintf(stderr, "\t-h\t enables header row. (default)\n");
  fprintf(stderr, "\t-H\t disables header row.\n");
  fprintf(stderr, "\t-s\t enables security descriptor output.\n");
  fprintf(stderr, "\t-S\t disables security descriptor output. (default)\n");
  fprintf(stderr, "\t-p\t restrict output to elements below this path.\n");
  fprintf(stderr, "\t-t\t restrict results to this specific data type.\n");
  fprintf(stderr, "\t-i\t includes parent key modification times with child values.\n");
  fprintf(stderr, "\n");
}


int main(int argc, char** argv)
{
  char** path = NULL;
  REGFI_ITERATOR* iter;
  int retr_path_ret, fd;
  uint32_t argi, arge;

  /* Process command line arguments */
  if(argc < 2)
  {
    usage();
    bailOut(REGLOOKUP_EXIT_USAGE, "ERROR: Requires at least one argument.\n");
  }
  
  arge = argc-1;
  for(argi = 1; argi < arge; argi++)
  {
    if (strcmp("-p", argv[argi]) == 0)
    {
      if(++argi >= arge)
      {
	usage();
	bailOut(REGLOOKUP_EXIT_USAGE, "ERROR: '-p' option requires parameter.\n");
      }
      if((path_filter = strdup(argv[argi])) == NULL)
	bailOut(REGLOOKUP_EXIT_OSERR, "ERROR: Memory allocation problem.\n");

      path_filter_enabled = true;
    }
    else if (strcmp("-t", argv[argi]) == 0)
    {
      if(++argi >= arge)
      {
	usage();
	bailOut(REGLOOKUP_EXIT_USAGE, "ERROR: '-t' option requires parameter.\n");
      }
      if((type_filter = regfi_type_str2val(argv[argi])) < 0)
      {
	fprintf(stderr, "ERROR: Invalid type specified: %s.\n", argv[argi]);
	bailOut(REGLOOKUP_EXIT_USAGE, "");
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
    else if (strcmp("-i", argv[argi]) == 0)
      print_value_mtime = true;
    else
    {
      usage();
      fprintf(stderr, "ERROR: Unrecognized option: %s\n", argv[argi]);
      bailOut(REGLOOKUP_EXIT_USAGE, "");
    }
  }
  registry_file = argv[argi];

  if(print_verbose)
    regfi_log_set_mask(REGFI_LOG_INFO|REGFI_LOG_WARN|REGFI_LOG_ERROR);

  fd = openHive(registry_file);
  if(fd < 0)
  {
    fprintf(stderr, "ERROR: Couldn't open registry file: %s\n", registry_file);
    bailOut(REGLOOKUP_EXIT_NOINPUT, "");
  }
    
  /* XXX: add command line option to choose output encoding */
  f = regfi_alloc(fd, REGFI_ENCODING_ASCII);
  if(f == NULL)
  {
    close(fd);
    bailOut(REGLOOKUP_EXIT_NOINPUT, "ERROR: Failed to create REGFI_FILE structure.\n");
  }

  iter = regfi_iterator_new(f);
  if(iter == NULL)
  {
    printMsgs(f);
    bailOut(REGLOOKUP_EXIT_OSERR, "ERROR: Couldn't create registry iterator.\n");
  }

  if(print_header)
  {
    if(print_security)
      printf("PATH,TYPE,VALUE,MTIME,OWNER,GROUP,SACL,DACL,CLASS\n");
    else
      printf("PATH,TYPE,VALUE,MTIME\n");
  }

  if(path_filter_enabled && path_filter != NULL)
    path = splitPath(path_filter);

  if(path != NULL)
  {
    retr_path_ret = retrievePath(iter, path);
    printMsgs(iter->f);
    freePath(path);

    if(retr_path_ret == 0)
      fprintf(stderr, "WARN: Specified path '%s' not found.\n", path_filter);
    else if (retr_path_ret == 2)
      printKeyTree(iter);
    else if(retr_path_ret < 0)
    {
      fprintf(stderr, "ERROR: retrievePath() returned %d.\n", 
	      retr_path_ret);
      bailOut(REGLOOKUP_EXIT_DATAERR,
	      "ERROR: Unknown error occurred in retrieving path.\n");
    }
  }
  else
    printKeyTree(iter);

  regfi_iterator_free(iter);
  regfi_free(f);
  close(fd);

  return 0;
}
