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
#include "../include/regfio.h"
#include "../include/void_stack.h"


char* getStackPath(void_stack* nk_stack)
{
  REGF_NK_REC* cur;
  unsigned int buf_left = 127;
  unsigned int buf_len = buf_left+1;
  unsigned int name_len = 0;
  unsigned int grow_amt;
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

  while((cur = void_stack_iterator_next(iter)) != NULL)
  {
    name_len = strlen(cur->keyname);
    if(name_len+1 > buf_left)
    {
      grow_amt = (unsigned int)(buf_len/3);
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
    buf[buf_len-buf_left-1] = '/';
    buf_left -= 1;
    buf[buf_len-buf_left-1] = '\0';
  }

  /* Cut trailing slash */  
  if(buf[buf_len-buf_left-2] == '/')
    buf[buf_len-buf_left-2] = '\0';

  return buf;
}


void printKeyList(REGF_NK_REC* nk, char* prefix)
{
  unsigned int i;
  const char* str_type;
  
  for(i=0; i < nk->num_values; i++)
  {
    str_type = type_val2str(nk->values[i].type);
    printf("%s/%s:%s=\n", prefix, nk->values[i].valuename, str_type);
  }
}


void printKeyTree(REGF_FILE* f, void_stack* nk_stack)
{
  REGF_NK_REC* cur;
  REGF_NK_REC* sub;
  char* path;

  if((cur = (REGF_NK_REC*)void_stack_cur(nk_stack)) != NULL)
  {
    printf("%s:KEY\n", cur->keyname);
    while((cur = (REGF_NK_REC*)void_stack_cur(nk_stack)) != NULL)
    {
      if((sub = regfio_fetch_subkey(f, cur)) != NULL)
      {
	void_stack_push(nk_stack, sub);
	path = getStackPath(nk_stack);
	if(path != NULL)
	{
	  printKeyList(cur, path);
	  printf("%s:KEY\n", path);
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


int main(int argc, char** argv)
{
  void_stack* nk_stack;
  REGF_FILE* f;
  REGF_NK_REC* root;

  if(argc < 2)
  {
    printf("ERROR: Requires 1 argument.\n");
    return 1;
  }

  f = regfio_open( argv[1] );
  root = regfio_rootkey(f);

  nk_stack = void_stack_new(1024);
  if(void_stack_push(nk_stack, root))
    printKeyTree(f, nk_stack);
  void_stack_destroy(nk_stack);

  regfio_close(f);
/*
REGF_NK_REC*  regfio_rootkey( REGF_FILE *file );
REGF_NK_REC*  regfio_fetch_subkey( REGF_FILE *file, REGF_NK_REC *nk );
*/

  return 0;
}
