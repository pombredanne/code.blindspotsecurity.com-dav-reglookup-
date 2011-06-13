/*
 * A program to stress test regfi under multithreaded use.
 *
 * Copyright (C) 2005-2011 Timothy D. Morgan
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

void traverseValueList(REGFI_ITERATOR* iter)
{
  const REGFI_VK* value;
  bool ret;

  for(ret=regfi_iterator_first_value(iter); 
      ret; 
      ret=regfi_iterator_next_value(iter))
  {
    value = regfi_iterator_cur_value(iter);
    printMsgs(iter->f);
    regfi_free_record(iter->f, value);
  }
}


void traverseKeyTree(REGFI_ITERATOR* iter)
{
  const REGFI_NK* root = NULL;
  const REGFI_NK* cur = NULL;
  const REGFI_NK* sub = NULL;
  const REGFI_SK* sk;
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
      traverseValueList(iter);
    
    if(sub == NULL)
    {
      if(!keysEqual(cur,root))
      {
	/* We're done with this sub-tree, going up and hitting other branches. */
        regfi_free_record(iter->f, cur);
        cur = NULL;
	if(!regfi_iterator_up(iter))
	{
	  printMsgs(iter->f);
	  bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: could not traverse iterator upward.\n");
	}

	cur = regfi_iterator_cur_key(iter);
	/*	fprintf(stderr, "%s\n", cur->keyname);*/
	printMsgs(iter->f);
	if(cur == NULL)
	  bailOut(REGLOOKUP_EXIT_DATAERR, "ERROR: unexpected NULL for key.\n");
	sk = regfi_fetch_sk(iter->f, cur);
	printMsgs(iter->f);
        regfi_free_record(iter->f, sk);

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
      printMsgs(iter->f);
      regfi_free_record(iter->f, sub);

      regfi_iterator_first_subkey(iter);
      sub = regfi_iterator_cur_subkey(iter);
      printMsgs(iter->f);
      print_this = true;
    }
    printMsgs(iter->f);
  } while(!(keysEqual(cur,root) && (sub == NULL)));
  if(cur != NULL)
    regfi_free_record(iter->f, cur);
  regfi_free_record(iter->f, root);

  if(print_verbose)
    fprintf(stderr, "INFO: Finished printing key tree.\n");
}


int num_iterations;
void* threadLoop(void* file)
{
  REGFI_ITERATOR* iter;
  int i;

  regfi_log_set_mask(REGFI_LOG_INFO|REGFI_LOG_WARN|REGFI_LOG_ERROR);

  iter = regfi_iterator_new((REGFI_FILE*)f);
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

  return NULL;
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
  registry_file = argv[argi];

  regfi_log_set_mask(REGFI_LOG_INFO|REGFI_LOG_WARN|REGFI_LOG_ERROR);

  fd = openHive(registry_file);
  if(fd < 0)
  {
    fprintf(stderr, "ERROR: Couldn't open registry file: %s\n", registry_file);
    bailOut(REGLOOKUP_EXIT_NOINPUT, "");
  }

  f = regfi_alloc(fd, REGFI_ENCODING_ASCII);
  if(f == NULL)
  {
    close(fd);
    bailOut(REGLOOKUP_EXIT_NOINPUT, "ERROR: Failed to create REGFI_FILE structure.\n");
  }

  threads = malloc(sizeof(pthread_t)*num_threads);
  for(i=0; i<num_threads; i++)
  {
    tret = pthread_create(threads+i, NULL, threadLoop, (void*) f);
  }
  
  for(i=0; i<num_threads; i++)
    pthread_join(threads[i], NULL);

  free(threads);
  regfi_free(f);
  close(fd);

  return 0;
}