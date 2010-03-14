/*
 * A program to stress test regfi under multithreaded use.
 *
 * Copyright (C) 2005-2010 Timothy D. Morgan
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
 * $Id: $
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <pthread.h>
#include "regfi.h"
#include "void_stack.h"

/* Globals, influenced by command line parameters */
bool print_verbose = false;
char* registry_file = NULL;

/* Other globals */
REGFI_FILE* f;


/* XXX: A hack to share some functions with reglookup-recover.c.
 *      Should move these into a proper library at some point.
 */
#include "common.c"




void traverseValueList(REGFI_ITERATOR* iter)
{
  REGFI_VK_REC* value;

  value = regfi_iterator_first_value(iter);
  while(value != NULL)
  {
    printMsgs(iter->f);
    regfi_free_value(value);
    value = regfi_iterator_next_value(iter);
  }
}


void traverseKeyTree(REGFI_ITERATOR* iter)
{
  const REGFI_NK_REC* root = NULL;
  const REGFI_NK_REC* cur = NULL;
  REGFI_NK_REC* sub = NULL;
  const REGFI_SK_REC* sk;
  bool print_this = true;

  root = cur = regfi_iterator_cur_key(iter);
  sub = regfi_iterator_first_subkey(iter);
  printMsgs(iter->f);

  if(root == NULL)
    bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: root cannot be NULL.\n");
  
  do
  {
    if(print_this)
      traverseValueList(iter);
    
    if(sub == NULL)
    {
      if(cur != root)
      {
	/* We're done with this sub-tree, going up and hitting other branches. */
	if(!regfi_iterator_up(iter))
	{
	  printMsgs(iter->f);
	  bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: could not traverse iterator upward.\n");
	}

	cur = regfi_iterator_cur_key(iter);
	/*	fprintf(stderr, "%s\n", cur->keyname);*/
	printMsgs(iter->f);
	sk = regfi_iterator_cur_sk(iter);
	printMsgs(iter->f);
	if(cur == NULL)
	  bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: unexpected NULL for key.\n");
      
	sub = regfi_iterator_next_subkey(iter);
      }
      print_this = false;
    }
    else
    { /* We have unexplored sub-keys.  
       * Let's move down and print this first sub-tree out. 
       */
      if(!regfi_iterator_down(iter))
      {
	printMsgs(iter->f);
	bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: could not traverse iterator downward.\n");
      }

      cur = regfi_iterator_cur_key(iter);
      printMsgs(iter->f);
      regfi_free_key(sub);

      sub = regfi_iterator_first_subkey(iter);
      printMsgs(iter->f);
      print_this = true;
    }
    printMsgs(iter->f);
  } while(!((cur == root) && (sub == NULL)));

  if(print_verbose)
    fprintf(stderr, "INFO: Finished printing key tree.\n");
}


int num_iterations;
void threadLoop(void* file)
{
  REGFI_ITERATOR* iter;
  int i;

  iter = regfi_iterator_new((REGFI_FILE*)f, REGFI_ENCODING_ASCII);
  if(iter == NULL)
  {
    printMsgs(f);
    bailOut(REGLOOKUP_EXIT_OSERR, "ERROR: Couldn't create registry iterator.\n");
  }

  for(i=0; i< num_iterations; i++)
  {
    traverseKeyTree(iter);
    regfi_iterator_to_root(iter);
  }

  regfi_iterator_free(iter);
}


static void usage(void)
{
  fprintf(stderr, "Usage: regfi-threadtest <REGISTRY_FILE>\n");
  fprintf(stderr, "\n");
}


int main(int argc, char** argv)
{
  int fd, tret, i;
  uint32_t argi, arge, num_threads;
  pthread_t* threads;

  num_threads = 10;
  num_iterations = 10;

  /* Process command line arguments */
  if(argc < 2)
  {
    usage();
    bailOut(REGLOOKUP_EXIT_USAGE, "ERROR: Requires at least one argument.\n");
  }
  
  arge = argc-1;
  for(argi = 1; argi < arge; argi++)
  {
    usage();
    fprintf(stderr, "ERROR: Unrecognized option: %s\n", argv[argi]);
    bailOut(REGLOOKUP_EXIT_USAGE, "");
  }

  if((registry_file = strdup(argv[argi])) == NULL)
    bailOut(REGLOOKUP_EXIT_OSERR, "ERROR: Memory allocation problem.\n");

  fd = openHive(registry_file);
  if(fd < 0)
  {
    fprintf(stderr, "ERROR: Couldn't open registry file: %s\n", registry_file);
    bailOut(REGLOOKUP_EXIT_NOINPUT, "");
  }

  f = regfi_alloc(fd);
  if(f == NULL)
  {
    close(fd);
    bailOut(REGLOOKUP_EXIT_NOINPUT, "ERROR: Failed to create REGFI_FILE structure.\n");
  }

  regfi_set_message_mask(f, REGFI_MSG_INFO|REGFI_MSG_WARN|REGFI_MSG_ERROR);

  threads = malloc(sizeof(pthread_t)*num_threads);
  for(i=0; i<num_threads; i++)
  {
    tret = pthread_create(threads+i, NULL, threadLoop, (void*) f);
  }
  
  for(i=0; i<num_threads; i++)
    pthread_join(threads[i], NULL);

  regfi_free(f);
  close(fd);

  return 0;
}
