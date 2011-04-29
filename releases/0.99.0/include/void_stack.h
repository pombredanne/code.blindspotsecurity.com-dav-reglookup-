/*
 * Copyright (C) 2005,2007,2009-2010 Timothy D. Morgan
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

/** 
 *@file
 * 
 * This is a very simple implementation of a stack which stores chunks of
 * memory of any type.
 */


#ifndef _VOID_STACK_H
#define _VOID_STACK_H

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <talloc.h>

/* GCC-specific macro for library exports */
#ifdef _EXPORT
#undef _EXPORT
#endif
#define _EXPORT __attribute__((visibility("default")))

/** XXX: document this. */
typedef struct _void_stack
{
  void** elements;
  unsigned short max_size;
  unsigned short top;
} void_stack;


/** XXX: document this. */
typedef struct _void_stack_iterator
{
  const void_stack* stack;
  unsigned short cur;
} void_stack_iterator;


/** Allocates a new void_stack.
 *
 * @param max_size the maxiumum number of elements 
 *                 which may be pushed onto the stack.
 *
 * @return a pointer to the newly allocated void_stack, 
 *         or NULL if an error occurred.
 */
_EXPORT
void_stack* void_stack_new(unsigned short max_size);


/** Makes a shallow copy of void_stack.
 *
 * @param v the stack to make a copy of.
 *
 * @return a pointer to the duplicate void_stack, or NULL if an error occurred.
 */
_EXPORT
void_stack* void_stack_copy(const void_stack* v);


/** Makes a shallow copy of void_stack in reverse order.
 *
 * @param v the stack to make a copy of.
 *
 * @return a pointer to the duplicate void_stack 
 *         (which will be in reverse order), or NULL if an error occurred.
 */
_EXPORT
void_stack* void_stack_copy_reverse(const void_stack* v);


/** Frees the memory associated with a void_stack, but not the elements held
 *  on the stack.
 *
 * @param stack the stack to be free()d.
 */
_EXPORT
void void_stack_free(void_stack* stack);


/** Frees the memory associated with a void_stack and the elements referenced 
 *  by the stack.  
 *
 * Do not use this function if the elements of the stack 
 * are also free()d elsewhere, or contain pointers to other memory which 
 * cannot be otherwise free()d.
 *
 * @param stack the stack to be free()d.
 */
_EXPORT
void void_stack_free_deep(void_stack* stack);


/** Query the current number of elements on a void_stack()
 *
 * @param stack the void_stack to query
 *
 * @return the number of elements currently on the stack.
 */
_EXPORT
unsigned short void_stack_size(const void_stack* stack);


/** Removes the top element on a void_stack and returns a reference to it.
 *
 * @param stack the void_stack to pop
 *
 * @return a pointer to the popped stack element, or NULL if no elements exist
 *         on the stack.
 */
_EXPORT
void* void_stack_pop(void_stack* stack);


/** Puts a new element on the top of a void_stack.
 *
 * @param stack the void_stack being modified.
 * @param e the element to be added
 *
 * @return true if the element was successfully added, false otherwise.
 */
_EXPORT
bool void_stack_push(void_stack* stack, void* e);


/** Returns a pointer to the current element on the top of the stack.
 *
 * @param stack the void_stack being queried.
 *
 * @return a pointer to the current element on the top of the stack, or NULL if
 *         no elements exist in the stack.
 */
_EXPORT
const void* void_stack_cur(const void_stack* stack);


/** Creates a new iterator for the specified void_stack.
 *
 * @param stack the void_stack to be referenced by the new iterator
 *
 * @return a new void_stack_iterator, or NULL if an error occurred.
 */
_EXPORT
void_stack_iterator* void_stack_iterator_new(const void_stack* stack);


/** Frees a void_stack_iterator.
 *
 * Does not affect the void_stack referenced by the iterator.
 *
 * @param iter the void_stack_iterator to be free()d.
 */
_EXPORT
void void_stack_iterator_free(void_stack_iterator* iter);


/** Returns a pointer to the the next element in the stack.
 *
 * Iterates over elements starting in order from the oldest element (bottom of the stack).
 *
 * @param iter the void_stack_iterator used to lookup the next element.
 *
 * @return a pointer to the next element.
 */
_EXPORT
const void* void_stack_iterator_next(void_stack_iterator* iter);


/* XXX: for completeness, might want to add a void_stack_iterator_first()
 *      function, to return iterator to first element
 */
#endif
