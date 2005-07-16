/*
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
#include <stdbool.h>
#include <string.h>

typedef struct _void_stack
{
  void** elements;
  unsigned short max_size;
  unsigned short top;
} void_stack;

typedef struct _void_stack_iterator
{
  void_stack* stack;
  unsigned short cur;
} void_stack_iterator;


void_stack* void_stack_new(unsigned short max_size);
void void_stack_destroy(void_stack* stack);
unsigned short void_stack_size(void_stack* stack);
void* void_stack_pop(void_stack* stack);
bool void_stack_push(void_stack* stack, void* e);
const void* void_stack_cur(void_stack* stack);
void_stack_iterator* void_stack_iterator_new(void_stack* stack);
void void_stack_iterator_destroy(void_stack_iterator* iter);
void* void_stack_iterator_next(void_stack_iterator* iter);
