/*
 * A utility to test functionality of Gerald Carter''s regfio interface.
 *
 * Copyright (C) 2005 Timothy D. Morgan
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
#include "../include/regfio.h"
#include "../include/void_stack.h"


/* Globals, influenced by command line parameters */
bool print_verbose = false;
bool print_security = false;
bool path_filter_enabled = false;
bool type_filter_enabled = false;
char* path_filter = NULL;
int type_filter;
char* registry_file = NULL;


void bailOut(int code, char* message)
{
  fprintf(stderr, message);
  exit(code);
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


char* stack2Path(void_stack* nk_stack)
{
  const REGF_NK_REC* cur;
  uint32 buf_left = 127;
  uint32 buf_len = buf_left+1;
  uint32 name_len = 0;
  uint32 grow_amt;
  char* buf; 
  char* new_buf;
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
    name_len = strlen(cur->keyname);
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
    strncpy(buf+(buf_len-buf_left-1), cur->keyname, name_len);
    buf_left -= name_len;
    buf[buf_len-buf_left-1] = '\0';
  }

  return buf;
}


void printValue(REGF_VK_REC* vk, char* prefix)
{
  if(!type_filter_enabled || (vk->type == type_filter))
    printf("%s/%s:%s=\n", prefix, vk->valuename, type_val2str(vk->type));
}


void printValueList(REGF_NK_REC* nk, char* prefix)
{
  uint32 i;
  
  for(i=0; i < nk->num_values; i++)
    printValue(&nk->values[i], prefix);
}


/* XXX: this function is god-awful.  Needs to be re-designed. */
void printKeyTree(REGF_FILE* f, void_stack* nk_stack, char* prefix)
{
  REGF_NK_REC* cur;
  REGF_NK_REC* sub;
  char* path;
  char* val_path;
  int key_type = type_str2val("KEY");

  if((cur = (REGF_NK_REC*)void_stack_cur(nk_stack)) != NULL)
  {
    cur->subkey_index = 0;
    path = stack2Path(nk_stack);
    
    if(strlen(path) > 0)
      if(!type_filter_enabled || (key_type == type_filter))
	printf("%s%s:KEY\n", prefix, path);
    if(!type_filter_enabled || (key_type != type_filter))
      printValueList(cur, path);
    while((cur = (REGF_NK_REC*)void_stack_cur(nk_stack)) != NULL)
    {
      if((sub = regfio_fetch_subkey(f, cur)) != NULL)
      {
	sub->subkey_index = 0;
	void_stack_push(nk_stack, sub);
	path = stack2Path(nk_stack);
	if(path != NULL)
	{
	  val_path = (char*)malloc(strlen(prefix)+strlen(path)+1);
	  sprintf(val_path, "%s%s", prefix, path);
	  if(!type_filter_enabled || (key_type == type_filter))
	    printf("%s:KEY\n", val_path);
	  if(!type_filter_enabled || (key_type != type_filter))
	    printValueList(sub, val_path);
	  free(val_path);
	  free(path);
	}
      }
      else
      {
	cur = void_stack_pop(nk_stack);
	/* XXX: This is just a shallow free.  Need to write deep free
	 * routines to replace the Samba code for this. 
	 */ 
	if(cur != NULL)
	  free(cur);
      }
    }
  }
}


/*
 * Returns 0 if path was found.
 * Returns 1 if path was not found.
 * Returns less than 0 on other error.
 */
int retrievePath(REGF_FILE* f, void_stack* nk_stack,
		 void_stack* path_stack)
{
  REGF_NK_REC* sub; 
  REGF_NK_REC* cur;
  void_stack* sub_nk_stack;
  char* prefix;
  char* cur_str = NULL;
  bool found_cur = true;
  uint32 i;
  uint16 path_depth;
  if(path_stack == NULL)
    return -1;

  path_depth = void_stack_size(path_stack);
  if(path_depth < 1)
    return -2;

  if(void_stack_size(nk_stack) < 1)
    return -3;
  cur = (REGF_NK_REC*)void_stack_cur(nk_stack);

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
    free(cur_str);

    if(!found_cur)
      return 1;
  }

  /* Last round, search value and key records */
  cur_str = (char*)void_stack_pop(path_stack);

  for(i=0; (i < cur->num_values); i++)
  {
    if(strcasecmp(sub->values[i].valuename, cur_str) == 0)
    {
      printValue(&sub->values[i], stack2Path(nk_stack));
      return 0;
    }
  }

  while((sub = regfio_fetch_subkey(f, cur)) != NULL)
  {
    if(strcasecmp(sub->keyname, cur_str) == 0)
    {
      sub_nk_stack = void_stack_new(1024);
      void_stack_push(sub_nk_stack, sub);
      void_stack_push(nk_stack, sub);
      prefix = stack2Path(nk_stack);
      printKeyTree(f, sub_nk_stack, prefix);
      return 0;
    }
  }

  return 1;
}


static void usage(void)
{
  fprintf(stderr, "Usage: readreg [-v] [-s]"
	  " [-p <PATH_FILTER>] [-t <TYPE_FILTER>]"
	  " <REGISTRY_FILE>\n");
  /* XXX: replace version string with Subversion property? */
  fprintf(stderr, "Version: 0.2\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "\t-v\t sets verbose mode.\n");
  fprintf(stderr, "\t-s\t prints security descriptors.\n");
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
  uint32 argi;

  /* Process command line arguments */
  if(argc < 2)
  {
    usage();
    bailOut(1, "ERROR: Requires 1 argument.\n");
  }
  
  for(argi = 1; argi < argc; argi++)
  {
    if (strcmp("-p", argv[argi]) == 0)
    {
      if(++argi > argc)
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
      if(++argi > argc)
      {
	usage();
	bailOut(1, "ERROR: '-t' option requires parameter.\n");
      }
      if((type_filter = type_str2val(argv[argi])) == 0)
      {
	fprintf(stderr, "ERROR: Invalid type specified: %s.\n", argv[argi]);
	bailOut(1, "");
      }

      type_filter_enabled = true;
    }
    else if (strcmp("-s", argv[argi]) == 0)
      print_security = true;
    else if (strcmp("-v", argv[argi]) == 0)
      print_verbose = true;
    else if (argv[argi][0] == '-')
    {
      usage();
      fprintf(stderr, "ERROR: Unrecognized option: %s\n", argv[argi]);
      bailOut(1, "");
    }
    else
    {
      if((registry_file = strdup(argv[argi])) == NULL)
	bailOut(2, "ERROR: Memory allocation problem.\n");
    }
  }

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
