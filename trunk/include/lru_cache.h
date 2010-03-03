/*
 * Copyright (C) 2008-2010 Timothy D. Morgan
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
 * @file
 *
 * A data structure which approximates a least recently used (LRU) cache.
 * Implemented as a basic randomized hash table.
 */


#ifndef LRU_CACHE_H
#define LRU_CACHE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "talloc.h"

struct lru_cache_element;
typedef struct lru_cache_element lru_cache_element; 

struct lru_cache_element
{
  void* index;
  uint32_t index_len;
  void* data;
  lru_cache_element* next;
  lru_cache_element* older;
  lru_cache_element* newer;
};


/** XXX: document this. */
typedef struct _lru_cache
{
  uint32_t secret;
  uint32_t num_keys;
  uint32_t num_buckets;
  uint32_t max_keys;
  lru_cache_element* oldest;
  lru_cache_element* newest;
  lru_cache_element** table;
  bool talloc_data;
} lru_cache;


/**
 * XXX: finish documenting.
 */
lru_cache* lru_cache_create(uint32_t max_keys, uint32_t secret);


/**
 * XXX: finish documenting.
 */
lru_cache* lru_cache_create_ctx(void* talloc_ctx, uint32_t max_keys, 
				uint32_t secret, bool talloc_data);


/**
 * XXX: finish documenting.
 */
void lru_cache_destroy(lru_cache* ht);


/**
 * XXX: finish documenting.
 */
bool lru_cache_update(lru_cache* ht, const void* index, 
		      uint32_t index_len, void* data);

/**
 * XXX: finish documenting.
 *
 * @return A pointer to data previously stored at index.
 *         If no data was found at index, NULL is returned.
 */
void* lru_cache_find(lru_cache* ht, const void* index, 
		     uint32_t index_len);

/**
 * XXX: finish documenting.
 *
 * Removes entry from table at index.
 *
 * @return A pointer to data that was there previously or NULL if no entry is
 *         at index.
 */
bool lru_cache_remove(lru_cache* ht, const void* index, 
		      uint32_t index_len);

#endif
