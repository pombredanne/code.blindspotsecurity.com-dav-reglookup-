/*
 * A utility to test functionality of Gerald Carter''s regio interface.
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

void printKeyTree(REGF_FILE* f,  REGF_NK_REC* cur, char* prefix)
{
  REGF_NK_REC* sub;
  char* sub_prefix;

  if(prefix != NULL)
  {
    sub_prefix = (char*)zalloc(strlen(prefix)+strlen(cur->keyname)+2);
    strcpy(sub_prefix, prefix);
    strcat(sub_prefix, "/");
  }
  else
    sub_prefix = (char*)zalloc(strlen(cur->keyname)+2);

  strcat(sub_prefix, cur->keyname);

  printf("%s:KEY\n", sub_prefix);
  while ((sub = regfio_fetch_subkey(f, cur)) != NULL)
    printKeyTree(f, sub, sub_prefix);

  free(sub_prefix);
}


int main(int argc, char** argv)
{
  if(argc < 2)
  {
    printf("ERROR: Requires 1 argument.\n");
    return 1;
  }

  REGF_FILE* f = regfio_open( argv[1] );
  REGF_NK_REC* root = regfio_rootkey(f);

  printKeyTree(f, root, NULL);
  regfio_close(f);
/*
REGF_NK_REC*  regfio_rootkey( REGF_FILE *file );
REGF_NK_REC*  regfio_fetch_subkey( REGF_FILE *file, REGF_NK_REC *nk );
*/

  return 0;
}
